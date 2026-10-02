//! Moving an account to another server (`docs/12-servers.md` §4.4).
//!
//! The root signs where the account went: the new server, its domain, and
//! the new request inbox and vault locator, which is everything a card
//! names that changes. The record stays on the server the account left,
//! so someone holding an old card (or an invite link) finds the account
//! there. Contacts don't need it: they are told inside their sessions.

use crate::codec::{Reader, Writer};
use crate::labels;
use crate::{ProtoError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{ROOT_SIG_LEN, RootPublic, RootSigningKey};

/// Longest domain.
pub const MAX_DOMAIN: usize = 253;

/// A root-signed move from server `from` to server `to`.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerMove {
    /// The account's root.
    pub root: RootPublic,
    /// The server left.
    pub from: [u8; 16],
    /// The new home server.
    pub to: [u8; 16],
    /// The new server's domain (empty if unknown).
    pub to_domain: String,
    /// The request inbox on the new server.
    pub request_inbox: [u8; 32],
    /// The vault key's locator on the new server.
    pub vault_locator: [u8; 32],
    /// When it was made (Unix seconds).
    pub time: u64,
    /// The root's signature over everything above.
    pub signature: Vec<u8>,
}

impl core::fmt::Debug for ServerMove {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerMove")
            .field("to_domain", &self.to_domain)
            .field("time", &self.time)
            .finish_non_exhaustive()
    }
}

impl ServerMove {
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.root.0)
            .fixed(&self.from)
            .fixed(&self.to)
            .bytes(self.to_domain.as_bytes())
            .fixed(&self.request_inbox)
            .fixed(&self.vault_locator)
            .u64(self.time);
        w.finish()
    }

    /// Sign a move with the account's root.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        root: &RootSigningKey,
        from: [u8; 16],
        to: [u8; 16],
        to_domain: &str,
        request_inbox: [u8; 32],
        vault_locator: [u8; 32],
        time: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        if from == to || to_domain.len() > MAX_DOMAIN {
            return Err(ProtoError::Decode);
        }
        let mut m = Self {
            root: root.public(),
            from,
            to,
            to_domain: to_domain.to_string(),
            request_inbox,
            vault_locator,
            time,
            signature: Vec::new(),
        };
        m.signature = root.sign(labels::CTX_SERVER_MOVE.as_bytes(), &m.body(), rng)?;
        Ok(m)
    }

    /// Check the signature under the root the record names.
    pub fn verify(&self) -> Result<()> {
        if self.from == self.to {
            return Err(ProtoError::Decode);
        }
        self.root
            .verify(
                labels::CTX_SERVER_MOVE.as_bytes(),
                &self.body(),
                &self.signature,
            )
            .map_err(|_| ProtoError::BadSignature)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Strict decoding (the signature is not checked: see [`Self::verify`]).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let root = RootPublic(r.array()?);
        let from = r.array()?;
        let to = r.array()?;
        let to_domain =
            String::from_utf8(r.bytes(MAX_DOMAIN)?.to_vec()).map_err(|_| ProtoError::Decode)?;
        let request_inbox = r.array()?;
        let vault_locator = r.array()?;
        let time = r.u64()?;
        let signature = r.fixed(ROOT_SIG_LEN)?.to_vec();
        r.end()?;
        Ok(Self {
            root,
            from,
            to,
            to_domain,
            request_inbox,
            vault_locator,
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
    fn signed_by_the_root_and_nothing_else() {
        let mut rng = HedgedRng::new().unwrap();
        let rs = RecoverySecret::generate(&mut rng).unwrap();
        let account = AccountKeys::create(&rs, &mut rng).unwrap();
        let root = account.root.as_ref().unwrap();
        let m = ServerMove::sign(
            root, [1; 16], [2; 16], "b.test", [3; 32], [4; 32], 99, &mut rng,
        )
        .unwrap();
        m.verify().unwrap();
        let e = m.encode();
        assert_eq!(ServerMove::decode(&e).unwrap(), m);
        // Any changed byte breaks it, or doesn't decode.
        for i in [0, 1, 70, 90, 100, e.len() - 1] {
            let mut bad = e.clone();
            bad[i] ^= 1;
            assert!(
                ServerMove::decode(&bad).and_then(|m| m.verify()).is_err(),
                "{i}"
            );
        }
        let mut longer = e.clone();
        longer.push(0);
        assert!(ServerMove::decode(&longer).is_err());
        // Another root's signature doesn't pass for this one.
        let other =
            AccountKeys::create(&RecoverySecret::generate(&mut rng).unwrap(), &mut rng).unwrap();
        let mut forged = m.clone();
        forged.root = other.root_public;
        assert!(forged.verify().is_err());
        assert!(
            ServerMove::sign(root, [1; 16], [1; 16], "", [0; 32], [0; 32], 0, &mut rng).is_err()
        );
    }
}
