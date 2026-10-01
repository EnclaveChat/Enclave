//! Pinned messages (`docs/16-features.md`, `docs/07-groups.md` §7.6).
//!
//! Either person in a 1:1 conversation, or any member of a group, can pin
//! a message so it shows above the conversation. Pins travel like
//! reactions: `Content::Pin` in a 1:1 conversation (with a copy for our
//! other devices), a `FLAG_RICH` group message in a group, so they are
//! sealed and authenticated like any message. At most [`MAX_PINS`] stay
//! pinned; pinning another unpins the oldest.
//!
//! Each device keeps the pins it has seen. Someone who joins a group later
//! sees no earlier pins, just as they see no earlier messages, and a pin of
//! a message this device never received is ignored.

use super::Client;
use super::search::Place;
use crate::content::{Content, MsgId};
use crate::{CoreError, Result};
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};

const NS_PINS: &str = "pins";
/// Most pinned messages per conversation.
pub const MAX_PINS: usize = 3;

fn key(place: &Place) -> Vec<u8> {
    match place {
        Place::Contact(r) => [&b"c"[..], &r[..]].concat(),
        Place::Group(g) => [&b"g"[..], &g[..]].concat(),
    }
}

fn encode(ids: &[MsgId]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(ids.len() as u8);
    for i in ids {
        w.fixed(i);
    }
    w.finish()
}

fn decode(b: &[u8]) -> enclave_proto::Result<Vec<MsgId>> {
    let mut r = Reader::new(b);
    let n = usize::from(r.u8()?);
    if n > MAX_PINS {
        return Err(ProtoError::Decode);
    }
    let ids = (0..n)
        .map(|_| r.array())
        .collect::<enclave_proto::Result<_>>()?;
    r.end()?;
    Ok(ids)
}

impl Client {
    /// Ids of the pinned messages in a conversation, most recently pinned
    /// first (they may name messages deleted since).
    pub fn pinned_ids(&self, place: &Place) -> Vec<MsgId> {
        match self.store.get(NS_PINS, &key(place)) {
            Ok(Some(b)) => decode(&b).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Record a pin or unpin of message `id`. Returns whether anything changed.
    pub(crate) fn apply_pin(&mut self, place: &Place, id: &MsgId, on: bool) -> Result<bool> {
        let before = self.pinned_ids(place);
        let mut ids: Vec<MsgId> = before.iter().filter(|i| *i != id).copied().collect();
        if on {
            ids.insert(0, *id);
            ids.truncate(MAX_PINS);
        }
        if ids == before {
            return Ok(false);
        }
        self.store
            .put(NS_PINS, &key(place), &encode(&ids), &mut self.rng)?;
        Ok(true)
    }

    /// Positions of the pinned messages in a conversation, most recently
    /// pinned first. Messages deleted since are left out.
    pub fn pinned(&self, place: &Place) -> Vec<u64> {
        let ids = self.pinned_ids(place);
        if ids.is_empty() {
            return Vec::new();
        }
        let found: Vec<(MsgId, u64)> = match place {
            Place::Contact(root) => self
                .messages(root)
                .unwrap_or_default()
                .into_iter()
                .filter(|m| !m.deleted)
                .map(|m| (m.id, m.seq))
                .collect(),
            Place::Group(gid) => self
                .group_messages(gid)
                .unwrap_or_default()
                .into_iter()
                .filter(|m| !m.deleted)
                .map(|m| (m.id, m.seq))
                .collect(),
        };
        ids.iter()
            .filter_map(|id| found.iter().find(|(i, _)| i == id).map(|&(_, s)| s))
            .collect()
    }

    /// Pin (or unpin) message `seq` of the conversation with `root`, for
    /// both of us.
    pub async fn pin_message(&mut self, root: &[u8; 64], seq: u64, on: bool) -> Result<()> {
        let m = self.get_message(root, seq)?;
        if m.deleted {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        let content = Content::Pin { target: m.id, on };
        self.send_content(root, &content, now).await?;
        self.send_self_copy(root, &content, now).await?;
        self.apply_pin(&Place::Contact(*root), &m.id, on)?;
        Ok(())
    }

    /// Pin (or unpin) message `seq` of group `gid`, for every member.
    pub async fn pin_group_message(&mut self, gid: &[u8; 32], seq: u64, on: bool) -> Result<()> {
        let id = self
            .group_messages(gid)?
            .into_iter()
            .find(|m| m.seq == seq)
            .map(|m| m.id)
            .ok_or(CoreError::NotFound)?;
        self.post_group_pin(gid, &id, on).await?;
        self.apply_pin(&Place::Group(*gid), &id, on)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn list_codec() {
        let ids = vec![[1u8; 16], [2; 16]];
        assert_eq!(decode(&encode(&ids)).unwrap(), ids);
        assert!(decode(&encode(&[[0u8; 16]; 4])).is_err(), "at most three");
        let mut b = encode(&ids);
        b.push(0);
        assert!(decode(&b).is_err(), "trailing bytes");
    }
}
