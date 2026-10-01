//! Changing the recovery words: a migration from one root to another
//! (`docs/03-identity.md` §8.2).
//!
//! Only the root changes; the account's other keys, its devices and their
//! sessions stay. The new root signs the migration together with the hash
//! of the new manifest (the same devices, re-signed), and the old root
//! cross-signs the same payload when it is still at hand. Contacts accept a
//! migration only inside an existing session, from a device the new
//! manifest lists: the signatures alone never are enough, since the reason
//! to migrate is that someone else may hold the old words.

use crate::codec::{Reader, Writer};
use crate::labels;
use crate::manifest::{Manifest, SignedManifest};
use crate::{ProtoError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{ROOT_SIG_LEN, RootPublic, RootSigningKey};

/// Encoded size with both signatures.
pub const MIGRATION_LEN: usize = 1 + 64 + 64 + 64 + 8 + ROOT_SIG_LEN + 1 + ROOT_SIG_LEN;

/// A signed migration from `old` to `new`.
#[derive(Clone, PartialEq, Eq)]
pub struct Migration {
    /// The root being replaced.
    pub old: RootPublic,
    /// The new root.
    pub new: RootPublic,
    /// SHA3-512 of the new signed manifest.
    pub manifest_hash: [u8; 64],
    /// When it was made (Unix seconds).
    pub time: u64,
    /// The new root's signature.
    pub new_sig: Vec<u8>,
    /// The old root's signature, when it was available.
    pub old_sig: Option<Vec<u8>>,
}

impl core::fmt::Debug for Migration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Migration")
            .field("time", &self.time)
            .field("cross_signed", &self.old_sig.is_some())
            .finish_non_exhaustive()
    }
}

fn payload(old: &RootPublic, new: &RootPublic, hash: &[u8; 64], time: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.fixed(&old.0).fixed(&new.0).fixed(hash).u64(time);
    w.finish()
}

impl Migration {
    /// Sign a migration to the root of `manifest` (which `new` signed).
    /// `old` cross-signs when given.
    pub fn sign(
        old: Option<&RootSigningKey>,
        old_public: RootPublic,
        new: &RootSigningKey,
        manifest: &SignedManifest,
        time: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let new_public = new.public();
        let m = Manifest::decode(&manifest.body)?;
        if m.root != new_public || old.is_some_and(|k| k.public() != old_public) {
            return Err(ProtoError::BadSignature);
        }
        let hash = manifest.hash();
        let msg = payload(&old_public, &new_public, &hash, time);
        let ctx = labels::CTX_MIGRATION.as_bytes();
        let new_sig = new.sign(ctx, &msg, rng)?;
        let old_sig = old.map(|k| k.sign(ctx, &msg, rng)).transpose()?;
        Ok(Self {
            old: old_public,
            new: new_public,
            manifest_hash: hash,
            time,
            new_sig,
            old_sig,
        })
    }

    /// Whether the old root signed it too.
    pub fn cross_signed(&self) -> bool {
        self.old_sig.is_some()
    }

    /// Check both signatures, and that `manifest` is the new manifest: it
    /// verifies under the new root and hashes to the signed hash. Returns
    /// the manifest. The caller still checks where the migration came from
    /// (§8.2.3).
    pub fn verify(&self, manifest: &SignedManifest, now: u64) -> Result<Manifest> {
        if self.old == self.new {
            return Err(ProtoError::Decode);
        }
        let msg = payload(&self.old, &self.new, &self.manifest_hash, self.time);
        let ctx = labels::CTX_MIGRATION.as_bytes();
        self.new
            .verify(ctx, &msg, &self.new_sig)
            .map_err(|_| ProtoError::BadSignature)?;
        if let Some(sig) = &self.old_sig {
            self.old
                .verify(ctx, &msg, sig)
                .map_err(|_| ProtoError::BadSignature)?;
        }
        if manifest.hash() != self.manifest_hash {
            return Err(ProtoError::BadSignature);
        }
        manifest.verify(&self.new, now)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.old.0)
            .fixed(&self.new.0)
            .fixed(&self.manifest_hash)
            .u64(self.time)
            .fixed(&self.new_sig);
        match &self.old_sig {
            Some(s) => {
                w.u8(1).fixed(s);
            }
            None => {
                w.u8(0);
            }
        }
        w.finish()
    }

    /// Strict decoding.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let old = RootPublic(r.array()?);
        let new = RootPublic(r.array()?);
        let manifest_hash = r.array()?;
        let time = r.u64()?;
        let new_sig = r.fixed(ROOT_SIG_LEN)?.to_vec();
        let old_sig = match r.u8()? {
            0 => None,
            1 => Some(r.fixed(ROOT_SIG_LEN)?.to_vec()),
            _ => return Err(ProtoError::Decode),
        };
        r.end()?;
        Ok(Self {
            old,
            new,
            manifest_hash,
            time,
            new_sig,
            old_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::identity::{AccountKeys, DeviceKeys};
    use crate::recovery::RecoverySecret;

    #[test]
    fn sign_verify_and_tamper() {
        let mut rng = HedgedRng::new().unwrap();
        let rs = RecoverySecret::generate(&mut rng).unwrap();
        let mut account = AccountKeys::create(&rs, &mut rng).unwrap();
        let device = DeviceKeys::generate(&mut rng).unwrap();
        let now = 1_800_000_000;
        let first = Manifest::genesis(&account, &device, now, vec![1; 32]);
        let first_signed = first.sign(&account, &mut rng).unwrap();

        let old_public = account.root_public;
        let rs2 = RecoverySecret::generate(&mut rng).unwrap();
        let old = account.reroot(&rs2).unwrap();
        let mut next = first.clone();
        next.version = 2;
        next.prev_hash = first_signed.hash();
        next.root = account.root_public;
        let signed = next.sign(&account, &mut rng).unwrap();
        let new = account.root.as_ref().unwrap();

        let m = Migration::sign(Some(&old), old_public, new, &signed, now, &mut rng).unwrap();
        assert!(m.cross_signed());
        let enc = m.encode();
        assert_eq!(enc.len(), MIGRATION_LEN);
        let back = Migration::decode(&enc).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.verify(&signed, now).unwrap(), next);

        // The old manifest isn't the new one.
        assert!(back.verify(&first_signed, now).is_err());
        // Any flipped bit in the payload or a signature fails.
        for i in [1, 70, 140, 200, 300, enc.len() - 5] {
            let mut bad = enc.clone();
            bad[i] ^= 1;
            if let Ok(b) = Migration::decode(&bad) {
                assert!(b.verify(&signed, now).is_err(), "bit at {i}");
            }
        }
        // Without the old root's signature it still verifies, and says so.
        let lone = Migration::sign(None, old_public, new, &signed, now, &mut rng).unwrap();
        let lone = Migration::decode(&lone.encode()).unwrap();
        assert!(!lone.cross_signed());
        lone.verify(&signed, now).unwrap();
        // A cross-signature by some other root doesn't pass as the old one.
        let other = RootSigningKey::from_recovery_secret(&[7; 32]);
        assert!(Migration::sign(Some(&other), old_public, new, &signed, now, &mut rng).is_err());
        // Trailing bytes are refused.
        let mut long = enc;
        long.push(0);
        assert!(Migration::decode(&long).is_err());
    }
}
