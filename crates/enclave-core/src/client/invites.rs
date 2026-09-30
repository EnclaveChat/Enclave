//! Invite links (`docs/03-identity.md` §7.3, §9.2).
//!
//! An invite link is our contact card plus a fresh 256-bit secret. The
//! secret gives
//!
//! * a **one-way PSK** mixed into the session (`eqxdh::invite_psk`): someone
//!   who breaks every KEM but never saw the link still can't read it;
//! * **request-inbox capabilities** (`eqxdh::invite_cap`) whose token hashes
//!   we register at our server, standing in for the proof of work. The
//!   server burns each on use, and cancelling a link removes the rest.
//!
//! A link brings at most `uses` people (default one) and lapses after
//! [`INVITE_TTL_SECS`]. Requests that come through one still wait in
//! Message requests. The plain QR code (no secret) keeps working as before.

use super::Client;
use crate::card::{Invite, MAX_INVITE_USES};
use crate::{CoreError, Result};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::eqxdh;
use enclave_proto::manifest::MAX_DEVICES;
use enclave_rpc::api::{self, FLAG_REVOKE};
use enclave_tokens::token_hash;
use enclave_wire::{Op, RequestHeader};
use zeroize::Zeroizing;

const NS_INVITES: &str = "invites";
/// How long an invite link works.
pub const INVITE_TTL_SECS: u64 = 7 * 86_400;
/// Capabilities per use: one per device of the person joining.
pub(crate) const CAPS_PER_USE: u32 = MAX_DEVICES as u32;

/// An invite's store key and its PSK.
pub(crate) type InvitePsk = ([u8; 32], Zeroizing<[u8; 32]>);

/// An invite link we made that still works.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteInfo {
    /// People it can bring.
    pub uses: u8,
    /// People it has brought.
    pub used: u8,
    /// When it stops working (Unix seconds).
    pub expires: u64,
}

struct Stored {
    secret: Zeroizing<[u8; 32]>,
    uses: u8,
    expires: u64,
    used_by: Vec<[u8; 64]>,
}

impl Stored {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.secret[..])
            .u8(self.uses)
            .u64(self.expires)
            .u8(self.used_by.len() as u8);
        for r in &self.used_by {
            w.fixed(r);
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8().ok()? != 1 {
            return None;
        }
        let secret = Zeroizing::new(r.array().ok()?);
        let uses = r.u8().ok()?;
        let expires = r.u64().ok()?;
        let n = r.u8().ok()?;
        let used_by = (0..n)
            .map(|_| r.array())
            .collect::<std::result::Result<_, _>>()
            .ok()?;
        r.end().ok()?;
        Some(Self {
            secret,
            uses,
            expires,
            used_by,
        })
    }

    fn key(&self) -> [u8; 32] {
        eqxdh::invite_cap(&self.secret, u32::MAX)
    }

    fn cap_hashes(&self) -> Vec<[u8; 32]> {
        (0..u32::from(self.uses) * CAPS_PER_USE)
            .map(|i| token_hash(&eqxdh::invite_cap(&self.secret, i)))
            .collect()
    }
}

impl Client {
    /// A new invite link for up to `uses` people (1 to 20), good for
    /// [`INVITE_TTL_SECS`].
    pub async fn create_invite(&mut self, uses: u8) -> Result<String> {
        let uses = uses.clamp(1, MAX_INVITE_USES);
        let now = self.now();
        let inv = Stored {
            secret: Zeroizing::new(self.rng.array("core/invite")?),
            uses,
            expires: now + INVITE_TTL_SECS,
            used_by: Vec::new(),
        };
        self.register_caps(&inv.cap_hashes(), 0, now).await?;
        self.store
            .put(NS_INVITES, &inv.key(), &inv.encode(), &mut self.rng)?;
        let mut card = self.card();
        card.invite = Some(Invite {
            secret: *inv.secret,
            uses,
        });
        Ok(card.to_link())
    }

    /// Invite links that still work.
    pub fn invites(&self) -> Result<Vec<InviteInfo>> {
        let now = self.now();
        Ok(self
            .stored_invites()?
            .into_iter()
            .filter(|i| i.expires > now && (i.used_by.len() as u8) < i.uses)
            .map(|i| InviteInfo {
                uses: i.uses,
                used: i.used_by.len() as u8,
                expires: i.expires,
            })
            .collect())
    }

    /// Cancel every invite link: our server forgets their capabilities and
    /// we stop accepting their PSKs.
    pub async fn cancel_invites(&mut self) -> Result<()> {
        let now = self.now();
        for inv in self.stored_invites()? {
            self.drop_invite(&inv, now).await?;
        }
        Ok(())
    }

    /// Cancel links that lapsed or brought everyone they could.
    pub(crate) async fn expire_invites(&mut self, now: u64) -> Result<()> {
        for inv in self.stored_invites()? {
            if inv.expires <= now {
                self.drop_invite(&inv, now).await?;
            }
        }
        Ok(())
    }

    /// PSKs of links that still work, with their keys, for opening a
    /// greeting that says it used one.
    pub(crate) fn invite_psks(&self) -> Result<Vec<InvitePsk>> {
        let now = self.now();
        Ok(self
            .stored_invites()?
            .into_iter()
            .filter(|i| i.expires > now)
            .map(|i| (i.key(), eqxdh::invite_psk(&i.secret)))
            .collect())
    }

    /// A greeting from `root` opened with the invite `key`'s PSK. Counts
    /// them against the link; false if it has already brought everyone
    /// it could (the greeting is then dropped). More devices of someone it
    /// already brought are fine. Once a link is used up, its remaining
    /// capabilities are cancelled, so the next person is told at once.
    pub(crate) async fn use_invite(&mut self, key: &[u8; 32], root: &[u8; 64]) -> Result<bool> {
        let Some(b) = self.store.get(NS_INVITES, key)? else {
            return Ok(false);
        };
        let mut inv = Stored::decode(&b).ok_or(CoreError::NotFound)?;
        if inv.used_by.contains(root) {
            return Ok(true);
        }
        if inv.used_by.len() >= usize::from(inv.uses) {
            return Ok(false);
        }
        inv.used_by.push(*root);
        self.store
            .put(NS_INVITES, key, &inv.encode(), &mut self.rng)?;
        if inv.used_by.len() >= usize::from(inv.uses) {
            // Keep the record (its PSK still opens greetings from the other
            // devices of the people it brought) until it lapses.
            let now = self.now();
            self.register_caps(&inv.cap_hashes(), FLAG_REVOKE, now)
                .await?;
        }
        Ok(true)
    }

    fn stored_invites(&self) -> Result<Vec<Stored>> {
        Ok(self
            .store
            .scan(NS_INVITES)?
            .into_iter()
            .filter_map(|(_, v)| Stored::decode(&v))
            .collect())
    }

    async fn drop_invite(&mut self, inv: &Stored, now: u64) -> Result<()> {
        self.register_caps(&inv.cap_hashes(), FLAG_REVOKE, now)
            .await?;
        self.store.delete(NS_INVITES, &inv.key())?;
        Ok(())
    }

    async fn register_caps(&mut self, hashes: &[[u8; 32]], flags: u8, now: u64) -> Result<()> {
        let payload = api::frame(&hashes.concat(), &mut self.rng)?;
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags,
            mailbox: self.profile.request_inbox,
            token: self.profile.request_owner,
        };
        let server = self.profile.server;
        self.rpc
            .call_ok(&server, h, &payload, now, &mut self.rng)
            .await?;
        Ok(())
    }
}
