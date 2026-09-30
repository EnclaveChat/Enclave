//! Device attestations on manifest changes (`03-identity.md` §7.1, RT-22).
//!
//! The root signs every manifest, and the root comes from the recovery
//! words, so a thief with the words could sign one that replaces all the
//! owner's devices. A change therefore takes effect at once only with a
//! **co-signature** from a device listed in the manifest it replaces. A
//! change without one waits 72 hours, during which any listed device can
//! **veto** it. Contacts enforce this; servers only store attestations
//! (after checking the signature against the devices they know for the
//! account).

use crate::codec::{Reader, Writer};
use crate::identity::{DeviceId, DeviceKeys};
use crate::labels;
use crate::manifest::Manifest;
use crate::{ProtoError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositePublic;

/// How long a change without a device co-signature waits.
pub const RECOVERY_WAIT_SECS: u64 = 72 * 3600;
/// Largest encoded attestation.
pub const MAX_ATTESTATION: usize = 8192;

/// What a device says about a manifest version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// "This change is ours": it takes effect at once.
    Cosign = 1,
    /// "This change is not ours": contacts never accept it.
    Veto = 2,
}

/// A device's signed statement about one manifest version of an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// Approve or veto.
    pub verdict: Verdict,
    /// Manifest version it is about.
    pub version: u64,
    /// SHA3-512 of that signed manifest.
    pub manifest_hash: [u8; 64],
    /// Signing device (listed in the manifest being replaced).
    pub device: DeviceId,
    /// Composite signature.
    pub signature: Vec<u8>,
}

fn message(root: &[u8; 64], version: u64, hash: &[u8; 64]) -> Vec<u8> {
    [&root[..], &version.to_be_bytes(), &hash[..]].concat()
}

fn ctx(v: Verdict) -> &'static [u8] {
    match v {
        Verdict::Cosign => labels::CTX_MANIFEST_COSIGN.as_bytes(),
        Verdict::Veto => labels::CTX_MANIFEST_VETO.as_bytes(),
    }
}

impl Attestation {
    /// Sign as `device` about `version`/`hash` of the account `root`.
    pub fn sign(
        verdict: Verdict,
        root: &[u8; 64],
        version: u64,
        manifest_hash: [u8; 64],
        device: &DeviceKeys,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let signature =
            device
                .signing
                .sign(ctx(verdict), &message(root, version, &manifest_hash), rng)?;
        Ok(Self {
            verdict,
            version,
            manifest_hash,
            device: device.id,
            signature,
        })
    }

    /// Whether a device listed in `listed` made this statement about
    /// `version`/`hash` of `root`.
    pub fn verify(&self, root: &[u8; 64], listed: &Manifest) -> bool {
        listed
            .device(&self.device)
            .is_some_and(|d| self.verify_key(root, &d.signing))
    }

    /// Whether `key` (the signing device's key) made this statement.
    pub fn verify_key(&self, root: &[u8; 64], key: &CompositePublic) -> bool {
        key.verify(
            ctx(self.verdict),
            &message(root, self.version, &self.manifest_hash),
            &self.signature,
        )
        .is_ok()
    }

    /// Whether it is about exactly this manifest.
    pub fn is_about(&self, version: u64, hash: &[u8; 64]) -> bool {
        self.version == version && &self.manifest_hash == hash
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.verdict as u8)
            .u64(self.version)
            .fixed(&self.manifest_hash)
            .fixed(&self.device)
            .bytes(&self.signature);
        w.finish()
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_ATTESTATION {
            return Err(ProtoError::Decode);
        }
        let mut r = Reader::new(b);
        let verdict = match r.u8()? {
            1 => Verdict::Cosign,
            2 => Verdict::Veto,
            _ => return Err(ProtoError::Decode),
        };
        let a = Self {
            verdict,
            version: r.u64()?,
            manifest_hash: r.array()?,
            device: r.array()?,
            signature: r.bytes(MAX_ATTESTATION)?.to_vec(),
        };
        r.end()?;
        Ok(a)
    }
}

/// Encode a list (as the directory serves it).
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(items.len().min(255) as u8);
    for i in items.iter().take(255) {
        w.bytes(i);
    }
    w.finish()
}

/// Decode a list, skipping entries that don't parse.
pub fn decode_list(b: &[u8]) -> Result<Vec<Attestation>> {
    let mut r = Reader::new(b);
    let n = r.u8()?;
    let mut out = Vec::new();
    for _ in 0..n {
        if let Ok(a) = Attestation::decode(r.bytes(MAX_ATTESTATION)?) {
            out.push(a);
        }
    }
    r.end()?;
    Ok(out)
}
