//! An account's end (`docs/03-identity.md` §8.5): its root signs that the
//! account is deleted. The home server then withdraws the account's
//! username for good (its key-transparency log shows a tombstone), drops
//! the account's manifest, and refuses new ones for that root.

use crate::codec::{Reader, Writer};
use crate::labels;
use crate::{ProtoError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{ROOT_SIG_LEN, RootPublic, RootSigningKey};

/// A root-signed deletion of the account.
#[derive(Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The account's root.
    pub root: RootPublic,
    /// When (Unix seconds).
    pub time: u64,
    /// The root's signature over `u8(1) ‖ root ‖ u64 time`.
    pub signature: Vec<u8>,
}

impl core::fmt::Debug for Tombstone {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tombstone")
            .field("time", &self.time)
            .finish_non_exhaustive()
    }
}

fn body(root: &RootPublic, time: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(1).fixed(&root.0).u64(time);
    w.finish()
}

impl Tombstone {
    /// Sign the account's deletion.
    pub fn sign(root: &RootSigningKey, time: u64, rng: &mut HedgedRng) -> Result<Self> {
        let public = root.public();
        let signature = root.sign(labels::CTX_TOMBSTONE.as_bytes(), &body(&public, time), rng)?;
        Ok(Self {
            root: public,
            time,
            signature,
        })
    }

    /// Check the signature under the root it names.
    pub fn verify(&self) -> Result<()> {
        self.root
            .verify(
                labels::CTX_TOMBSTONE.as_bytes(),
                &body(&self.root, self.time),
                &self.signature,
            )
            .map_err(|_| ProtoError::BadSignature)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        [body(&self.root, self.time), self.signature.clone()].concat()
    }

    /// Strict decoding (the signature is checked by [`Self::verify`]).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let root = RootPublic(r.array()?);
        let time = r.u64()?;
        let signature = r.fixed(ROOT_SIG_LEN)?.to_vec();
        r.end()?;
        Ok(Self {
            root,
            time,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::identity::AccountKeys;
    use crate::recovery::RecoverySecret;

    #[test]
    fn only_the_root_signs_its_end() {
        let mut rng = HedgedRng::new().unwrap();
        let a =
            AccountKeys::create(&RecoverySecret::generate(&mut rng).unwrap(), &mut rng).unwrap();
        let t = Tombstone::sign(a.root.as_ref().unwrap(), 42, &mut rng).unwrap();
        let e = t.encode();
        let back = Tombstone::decode(&e).unwrap();
        back.verify().unwrap();
        assert_eq!(back, t);
        let mut later = back.clone();
        later.time += 1;
        assert!(later.verify().is_err());
        let b =
            AccountKeys::create(&RecoverySecret::generate(&mut rng).unwrap(), &mut rng).unwrap();
        let mut other = back.clone();
        other.root = b.root_public;
        assert!(other.verify().is_err());
        assert!(Tombstone::decode(&e[..e.len() - 1]).is_err());
    }
}
