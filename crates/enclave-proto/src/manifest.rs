//! The root-signed account manifest (`docs/03-identity.md` §3.2).
//!
//! The manifest is the only object the SLH-DSA root signs day to day. It binds
//! every device's composite signing key and ML-KEM auth key, the account X448
//! identity key and the hash of the McEliece vault key to the root. Manifests
//! are hash-chained and versioned, so a server cannot roll a contact back to an
//! older device list.

use crate::codec::{Reader, Writer};
use crate::error::{ProtoError, Result};
use crate::identity::{AccountKeys, DeviceId, DeviceKeys};
use crate::labels;
use enclave_crypto::hash::sha3_512;
use enclave_crypto::kem::{MLKEM_PK_LEN, MlKemPublic, X448Public};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_PK_LEN, CompositePublic, ROOT_SIG_LEN, RootPublic};

/// Maximum devices per account (1 primary + 4 linked).
pub const MAX_DEVICES: usize = 5;
/// Maximum manifest validity (13 months).
pub const MAX_VALIDITY_SECS: u64 = 395 * 24 * 3600;
/// Clock-skew tolerance when checking validity.
pub const SKEW_SECS: u64 = 48 * 3600;
/// Manifest format version.
pub const FORMAT: u16 = 1;

/// Device role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// Holds the root.
    Primary = 1,
    /// Ordinary linked device.
    Linked = 2,
    /// Linked device that may also add devices (holds a copy of the root).
    MayAddDevices = 3,
}

impl Role {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Role::Primary),
            2 => Ok(Role::Linked),
            3 => Ok(Role::MayAddDevices),
            _ => Err(ProtoError::Decode),
        }
    }
}

/// One device in the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Device identifier.
    pub id: DeviceId,
    /// Role.
    pub role: Role,
    /// When the device was added (Unix seconds).
    pub added_at: u64,
    /// Capability bits (protocol features the device supports).
    pub capabilities: u64,
    /// Composite signing key.
    pub signing: CompositePublic,
    /// ML-KEM-1024 authentication key.
    pub auth: MlKemPublicBytes,
}

/// ML-KEM public key bytes kept in the manifest (validated on use).
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemPublicBytes(pub Box<[u8; MLKEM_PK_LEN]>);

impl core::fmt::Debug for MlKemPublicBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlKemPublic(..)")
    }
}

impl MlKemPublicBytes {
    /// Validate and convert.
    pub fn to_key(&self) -> Result<MlKemPublic> {
        Ok(MlKemPublic::from_slice(&self.0[..])?)
    }
}

impl DeviceEntry {
    /// Entry for a device's own keys.
    pub fn for_device(keys: &DeviceKeys, role: Role, added_at: u64) -> Self {
        Self {
            id: keys.id,
            role,
            added_at,
            capabilities: 1,
            signing: keys.signing.public().clone(),
            auth: MlKemPublicBytes(keys.auth_public.0.clone()),
        }
    }
}

/// Unsigned manifest body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Monotonic version, starting at 1.
    pub version: u64,
    /// SHA3-512 of the previous signed manifest (all zeros for version 1).
    pub prev_hash: [u8; 64],
    /// Issue time (Unix seconds).
    pub issued_at: u64,
    /// Expiry (Unix seconds), at most 13 months after issue.
    pub expires_at: u64,
    /// Root public key.
    pub root: RootPublic,
    /// Account X448 identity key.
    pub identity: X448Public,
    /// SHA3-512 of the McEliece vault public key.
    pub vault_hash: [u8; 64],
    /// Request-inbox locator (server id ‖ address), opaque to this layer.
    pub request_inbox: Vec<u8>,
    /// Current bundle epoch (bumps when prekeys are republished).
    pub bundle_epoch: u64,
    /// Devices (at most five).
    pub devices: Vec<DeviceEntry>,
}

impl Manifest {
    /// First manifest for a new account with its primary device.
    pub fn genesis(
        account: &AccountKeys,
        primary: &DeviceKeys,
        now: u64,
        request_inbox: Vec<u8>,
    ) -> Self {
        Self {
            version: 1,
            prev_hash: [0u8; 64],
            issued_at: now,
            expires_at: now + MAX_VALIDITY_SECS,
            root: account.root_public,
            identity: account.identity_public,
            vault_hash: account.vault_hash(),
            request_inbox,
            bundle_epoch: 1,
            devices: vec![DeviceEntry::for_device(primary, Role::Primary, now)],
        }
    }

    /// Canonical encoding (the bytes the root signs).
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.devices.is_empty() || self.devices.len() > MAX_DEVICES {
            return Err(ProtoError::Limit);
        }
        let mut w = Writer::new();
        w.u16(FORMAT)
            .u64(self.version)
            .fixed(&self.prev_hash)
            .u64(self.issued_at)
            .u64(self.expires_at)
            .fixed(&self.root.0)
            .fixed(&self.identity.0)
            .fixed(&self.vault_hash)
            .bytes(&self.request_inbox)
            .u64(self.bundle_epoch)
            .u8(self.devices.len() as u8);
        for d in &self.devices {
            w.fixed(&d.id)
                .u8(d.role as u8)
                .u64(d.added_at)
                .u64(d.capabilities)
                .fixed(&d.signing.to_bytes())
                .fixed(&d.auth.0[..]);
        }
        Ok(w.finish())
    }

    /// Decode a canonical encoding.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u16()? != FORMAT {
            return Err(ProtoError::Decode);
        }
        let version = r.u64()?;
        let prev_hash = r.array::<64>()?;
        let issued_at = r.u64()?;
        let expires_at = r.u64()?;
        let root = RootPublic(r.array::<64>()?);
        let identity = X448Public(r.array::<56>()?);
        let vault_hash = r.array::<64>()?;
        let request_inbox = r.bytes(256)?.to_vec();
        let bundle_epoch = r.u64()?;
        let n = r.u8()? as usize;
        if n == 0 || n > MAX_DEVICES {
            return Err(ProtoError::Limit);
        }
        let mut devices = Vec::with_capacity(n);
        for _ in 0..n {
            let id = r.array::<16>()?;
            let role = Role::from_u8(r.u8()?)?;
            let added_at = r.u64()?;
            let capabilities = r.u64()?;
            let signing = CompositePublic::from_slice(r.fixed(COMPOSITE_PK_LEN)?)?;
            let mut auth = Box::new([0u8; MLKEM_PK_LEN]);
            auth.copy_from_slice(r.fixed(MLKEM_PK_LEN)?);
            devices.push(DeviceEntry {
                id,
                role,
                added_at,
                capabilities,
                signing,
                auth: MlKemPublicBytes(auth),
            });
        }
        r.end()?;
        let m = Self {
            version,
            prev_hash,
            issued_at,
            expires_at,
            root,
            identity,
            vault_hash,
            request_inbox,
            bundle_epoch,
            devices,
        };
        m.check_structure()?;
        Ok(m)
    }

    fn check_structure(&self) -> Result<()> {
        if self.version == 0 || self.expires_at <= self.issued_at {
            return Err(ProtoError::Decode);
        }
        if self.expires_at - self.issued_at > MAX_VALIDITY_SECS {
            return Err(ProtoError::Expired);
        }
        let mut ids: Vec<DeviceId> = self.devices.iter().map(|d| d.id).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.devices.len() {
            return Err(ProtoError::Decode);
        }
        if self
            .devices
            .iter()
            .filter(|d| d.role == Role::Primary)
            .count()
            != 1
        {
            return Err(ProtoError::Decode);
        }
        Ok(())
    }

    /// Find a device.
    pub fn device(&self, id: &DeviceId) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| &d.id == id)
    }

    /// Sign with the root. Slow (SLH-DSA-256s); call from a background task.
    pub fn sign(&self, account: &AccountKeys, rng: &mut HedgedRng) -> Result<SignedManifest> {
        let root = account.root.as_ref().ok_or(ProtoError::Missing)?;
        if root.public() != self.root {
            return Err(ProtoError::BadSignature);
        }
        let body = self.encode()?;
        let sig = root.sign(labels::CTX_MANIFEST.as_bytes(), &body, rng)?;
        Ok(SignedManifest {
            body,
            signature: sig,
        })
    }
}

/// A manifest with its root signature.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedManifest {
    /// Canonical manifest bytes.
    pub body: Vec<u8>,
    /// SLH-DSA-SHAKE-256s signature (29,792 bytes).
    pub signature: Vec<u8>,
}

impl core::fmt::Debug for SignedManifest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SignedManifest({} bytes)",
            self.body.len() + self.signature.len()
        )
    }
}

impl SignedManifest {
    /// SHA3-512 over the full signed encoding, used for hash chaining.
    pub fn hash(&self) -> [u8; 64] {
        sha3_512(&self.to_bytes())
    }

    /// Encode as `body ‖ signature` with a length prefix on the body.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.body).fixed(&self.signature);
        w.finish()
    }

    /// Decode (does not verify).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let body = r.bytes(64 * 1024)?.to_vec();
        let signature = r.fixed(ROOT_SIG_LEN)?.to_vec();
        r.end()?;
        Ok(Self { body, signature })
    }

    /// Verify the signature and validity window, returning the manifest.
    ///
    /// * `expected_root`: the root the caller already trusts (pinned from a QR
    ///   code, invite link, or key-transparency lookup).
    /// * `now`: trusted time (median of witness timestamps).
    pub fn verify(&self, expected_root: &RootPublic, now: u64) -> Result<Manifest> {
        let m = Manifest::decode(&self.body)?;
        if &m.root != expected_root {
            return Err(ProtoError::BadSignature);
        }
        expected_root
            .verify(labels::CTX_MANIFEST.as_bytes(), &self.body, &self.signature)
            .map_err(|_| ProtoError::BadSignature)?;
        if now + SKEW_SECS < m.issued_at || now > m.expires_at + SKEW_SECS {
            return Err(ProtoError::Expired);
        }
        Ok(m)
    }

    /// Verify that `self` is a valid successor of `previous` (anti-rollback).
    pub fn verify_successor(
        &self,
        previous: &SignedManifest,
        expected_root: &RootPublic,
        now: u64,
    ) -> Result<Manifest> {
        let prev = Manifest::decode(&previous.body)?;
        let next = self.verify(expected_root, now)?;
        if next.version <= prev.version {
            return Err(ProtoError::Rollback);
        }
        if next.version == prev.version + 1 && next.prev_hash != previous.hash() {
            return Err(ProtoError::Rollback);
        }
        Ok(next)
    }
}
