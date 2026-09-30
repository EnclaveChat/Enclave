//! Account and device key material (`docs/03-identity.md`).
//!
//! * Account level (shared with linked devices over the linking channel):
//!   the SLH-DSA root (derived from the recovery secret, primary only), the
//!   X448 identity key, and the Classic McEliece "vault" key.
//! * Device level (never leaves the device): a composite Ed448 + ML-DSA-87
//!   signing key and an ML-KEM-1024 "auth" key used for post-quantum
//!   authentication in EQXDH.

use crate::codec::{Reader, Writer};
use crate::error::{ProtoError, Result};
use crate::recovery::RecoverySecret;
use enclave_crypto::kem::{
    MCELIECE_PK_LEN, MCELIECE_SK_LEN, MLKEM_PK_LEN, McEliecePublic, McElieceSecret, MlKemPublic,
    MlKemSecret, X448Public, X448Secret,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SEED_LEN, CompositeSigningKey, RootPublic, RootSigningKey};
use zeroize::Zeroizing;

/// Device identifier (random, 16 bytes).
pub type DeviceId = [u8; 16];

/// Account-level secrets.
pub struct AccountKeys {
    /// Root signing key. `None` on linked devices without "may add devices".
    pub root: Option<RootSigningKey>,
    /// Root public key (always known).
    pub root_public: RootPublic,
    /// Account X448 identity key.
    pub identity: X448Secret,
    /// Account X448 identity public key.
    pub identity_public: X448Public,
    /// Classic McEliece vault key (decapsulation).
    pub vault: McElieceSecret,
    /// Classic McEliece vault public key (1.36 MB; published as an encrypted blob).
    pub vault_public: McEliecePublic,
}

impl AccountKeys {
    /// Create a new account from a recovery secret. Generates the McEliece key,
    /// which takes a few seconds; run in the background during onboarding.
    pub fn create(recovery: &RecoverySecret, rng: &mut HedgedRng) -> Result<Self> {
        let root = RootSigningKey::from_recovery_secret(recovery.as_bytes());
        let root_public = root.public();
        let (identity, identity_public) = X448Secret::generate(rng)?;
        let (vault, vault_public) = McElieceSecret::generate(rng)?;
        Ok(Self {
            root: Some(root),
            root_public,
            identity,
            identity_public,
            vault,
            vault_public,
        })
    }

    /// SHA3-512 of the McEliece vault public key, committed in the manifest.
    pub fn vault_hash(&self) -> [u8; 64] {
        enclave_crypto::hash::sha3_512(&self.vault_public.0[..])
    }
}

/// Device-level secrets.
pub struct DeviceKeys {
    /// Device identifier.
    pub id: DeviceId,
    /// Composite signing key.
    pub signing: CompositeSigningKey,
    /// ML-KEM-1024 authentication key.
    pub auth: MlKemSecret,
    /// ML-KEM-1024 authentication public key.
    pub auth_public: MlKemPublic,
}

impl DeviceKeys {
    /// Generate keys for a new device.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        let id: DeviceId = rng.array("device/id")?;
        let signing = CompositeSigningKey::generate(rng)?;
        let (auth, auth_public) = MlKemSecret::generate(rng)?;
        Ok(Self {
            id,
            signing,
            auth,
            auth_public,
        })
    }
}

impl DeviceKeys {
    /// Serialize for sealed local storage: `id ‖ signing seed ‖ auth secret`.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.fixed(&self.id)
            .fixed(&self.signing.seed()[..])
            .bytes(self.auth.as_bytes());
        w.fixed(&self.auth_public.0[..]);
        Zeroizing::new(w.finish())
    }

    /// Inverse of [`DeviceKeys::export`].
    pub fn import(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let id = r.array()?;
        let seed: Zeroizing<[u8; COMPOSITE_SEED_LEN]> = Zeroizing::new(r.array()?);
        let signing = CompositeSigningKey::from_seed(&seed)?;
        let auth = MlKemSecret::from_slice(r.bytes(8192)?)?;
        let auth_public = MlKemPublic::from_slice(r.fixed(MLKEM_PK_LEN)?)?;
        r.end()?;
        Ok(Self {
            id,
            signing,
            auth,
            auth_public,
        })
    }
}

impl AccountKeys {
    /// Serialize the account keys that linked devices share (identity and
    /// vault). The root is never serialized: it is re-derived from the
    /// recovery secret, which is stored separately behind the app PIN.
    pub fn export_shared(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.fixed(&self.root_public.0)
            .fixed(&self.identity.to_bytes()[..]);
        w.bytes(self.vault.as_bytes())
            .bytes(&self.vault_public.0[..]);
        Zeroizing::new(w.finish())
    }

    /// Inverse of [`AccountKeys::export_shared`]. With `recovery`, the root
    /// signing key is re-derived and checked against the stored public key.
    pub fn import_shared(b: &[u8], recovery: Option<&RecoverySecret>) -> Result<Self> {
        let mut r = Reader::new(b);
        let root_public = RootPublic(r.array()?);
        let identity = X448Secret::from_bytes(r.array()?);
        let identity_public = identity.public();
        let vault = McElieceSecret::from_slice(r.bytes(MCELIECE_SK_LEN)?)?;
        let vault_public = McEliecePublic::from_slice(r.bytes(MCELIECE_PK_LEN)?)?;
        r.end()?;
        let root = match recovery {
            Some(rs) => {
                let k = RootSigningKey::from_recovery_secret(rs.as_bytes());
                if k.public() != root_public {
                    return Err(ProtoError::Recovery);
                }
                Some(k)
            }
            None => None,
        };
        Ok(Self {
            root,
            root_public,
            identity,
            identity_public,
            vault,
            vault_public,
        })
    }
}
