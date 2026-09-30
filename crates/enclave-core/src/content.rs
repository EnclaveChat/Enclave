//! Message content inside ratchet envelopes (`docs/08-envelope.md`).
//!
//! A small canonical binary format. Every field has a hard limit and decoding
//! rejects trailing bytes. Write tokens, inbox addresses and contact cards
//! travel only here, inside the end-to-end encrypted body, never in anything
//! a server can read.

use crate::card::MAX_NAME;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::{ProtoError, Result};

/// Most write tokens one message may carry.
pub const MAX_TOKENS: usize = 32;
/// Maximum text in one message (bytes of UTF-8). Longer text is refused
/// until continuation units land.
pub const MAX_TEXT: usize = 4096;
/// Largest encoded card accepted.
pub const MAX_CARD: usize = 512;
/// Most cards in one `GroupCards` message.
pub const MAX_CARDS_PER_MESSAGE: usize = 40;
/// Largest group welcome accepted.
pub const MAX_WELCOME: usize = 9_000;
/// Most message ids one read receipt may carry.
pub const MAX_RECEIPTS: usize = 64;
/// Longest reaction (one emoji, possibly with modifiers).
pub const MAX_REACTION: usize = 32;
/// Longest disappearing timer: four weeks.
pub const MAX_TIMER: u32 = 28 * 86_400;
/// Largest encoded attachment reference.
pub const MAX_ATTACHMENT_REF: usize = 1024;

/// A write token for someone's inbox.
pub type Token = [u8; 32];

/// Identifier of a message, chosen by its sender.
pub type MsgId = [u8; 16];

/// Decrypted message content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    /// First message in each direction: where and how to reach the sender.
    Hello {
        /// Sender's home server.
        server: [u8; 16],
        /// Sender's account inbox.
        inbox: [u8; 32],
        /// Write tokens for that inbox.
        tokens: Vec<Token>,
        /// Sender's display name.
        name: String,
        /// Optional first text.
        text: String,
        /// Sender's encoded contact card, so contacts can introduce each
        /// other into groups.
        card: Vec<u8>,
        /// Set when a group introduced us: the receiver accepts automatically
        /// if the sender is a member of that group.
        group: Option<[u8; 32]>,
        /// Id of the first text.
        id: MsgId,
    },
    /// A text message, optionally carrying fresh tokens.
    Text {
        /// Write tokens for the sender's inbox.
        tokens: Vec<Token>,
        /// The text.
        text: String,
        /// Message id.
        id: MsgId,
        /// Disappearing timer in seconds (0 = off).
        expires: u32,
    },
    /// Token refill with no user-visible content.
    Tokens(Vec<Token>),
    /// You were added to a group (`enclave_proto::group::Group::welcome`).
    GroupWelcome(Vec<u8>),
    /// Contact cards of a group's members, so members can reach each other.
    GroupCards {
        /// Group.
        group_id: [u8; 32],
        /// Encoded cards.
        cards: Vec<Vec<u8>>,
    },
    /// A file (`crate::files::Attachment`, encoded) with an optional caption.
    Attachment {
        /// Message id.
        id: MsgId,
        /// Encoded attachment reference.
        attachment: Vec<u8>,
        /// Caption.
        caption: String,
        /// Disappearing timer.
        expires: u32,
    },
    /// Set (or, with an empty emoji, remove) our reaction to a message.
    React {
        /// Target message.
        target: MsgId,
        /// Emoji.
        emoji: String,
    },
    /// Replace the text of one of our messages (advisory, 24 h).
    Edit {
        /// Target message.
        target: MsgId,
        /// New text.
        text: String,
    },
    /// Delete one of our messages for everyone (advisory).
    Delete {
        /// Target message.
        target: MsgId,
    },
    /// Read receipts.
    Read(Vec<MsgId>),
    /// The conversation's disappearing timer changed.
    Timer(u32),
    /// The sender's device list changed: fetch its manifest, at least this
    /// version, and stop encrypting to devices no longer in it.
    Devices(u64),
    /// Our message history, as a sealed file reference (own devices only).
    History(Vec<u8>),
    /// A device of the sender vetoes a change to the sender's account
    /// (an encoded `Attestation`).
    Veto(Vec<u8>),
    /// Our signed key-transparency head for an epoch where the sender's
    /// gossip disagreed, as a sealed file reference (RT-04).
    KtHead(Vec<u8>),
    /// A copy, for our other devices, of content we sent to `to`.
    SelfCopy {
        /// The conversation it belongs to.
        to: [u8; 64],
        /// The content we sent (encoded).
        content: Vec<u8>,
    },
}

const K_HELLO: u8 = 1;
const K_TEXT: u8 = 2;
const K_TOKENS: u8 = 3;
const K_GROUP_WELCOME: u8 = 4;
const K_GROUP_CARDS: u8 = 5;
const K_ATTACHMENT: u8 = 6;
const K_REACT: u8 = 7;
const K_EDIT: u8 = 8;
const K_DELETE: u8 = 9;
const K_READ: u8 = 10;
const K_TIMER: u8 = 11;
const K_SELF_COPY: u8 = 12;
const K_DEVICES: u8 = 13;
const K_HISTORY: u8 = 14;
const K_VETO: u8 = 15;
const K_KT_HEAD: u8 = 16;
/// Largest content a self-copy can wrap.
pub const MAX_SELF_COPY: usize = 9_000;

fn put_tokens(w: &mut Writer, t: &[Token]) {
    w.u8(t.len() as u8);
    for x in t {
        w.fixed(x);
    }
}

fn get_tokens(r: &mut Reader<'_>) -> Result<Vec<Token>> {
    let n = r.u8()? as usize;
    if n > MAX_TOKENS {
        return Err(ProtoError::Decode);
    }
    (0..n).map(|_| r.array()).collect()
}

fn get_str(r: &mut Reader<'_>, max: usize) -> Result<String> {
    String::from_utf8(r.bytes(max)?.to_vec()).map_err(|_| ProtoError::Decode)
}

fn timer(secs: u32) -> Result<u32> {
    if secs > MAX_TIMER {
        Err(ProtoError::Decode)
    } else {
        Ok(secs)
    }
}

impl Content {
    /// Encode. Fails if a limit is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let too_large = Err(ProtoError::TooLarge);
        match self {
            Content::Hello {
                server,
                inbox,
                tokens,
                name,
                text,
                card,
                group,
                id,
            } => {
                if tokens.len() > MAX_TOKENS
                    || name.len() > MAX_NAME
                    || text.len() > MAX_TEXT
                    || card.len() > MAX_CARD
                {
                    return too_large;
                }
                w.u8(K_HELLO).fixed(server).fixed(inbox);
                put_tokens(&mut w, tokens);
                w.bytes(name.as_bytes()).bytes(text.as_bytes()).bytes(card);
                match group {
                    Some(g) => w.u8(1).fixed(g),
                    None => w.u8(0),
                };
                w.fixed(id);
            }
            Content::Text {
                tokens,
                text,
                id,
                expires,
            } => {
                if tokens.len() > MAX_TOKENS || text.len() > MAX_TEXT || *expires > MAX_TIMER {
                    return too_large;
                }
                w.u8(K_TEXT);
                put_tokens(&mut w, tokens);
                w.bytes(text.as_bytes()).fixed(id).u32(*expires);
            }
            Content::Tokens(tokens) => {
                if tokens.len() > MAX_TOKENS {
                    return too_large;
                }
                w.u8(K_TOKENS);
                put_tokens(&mut w, tokens);
            }
            Content::GroupWelcome(b) => {
                if b.len() > MAX_WELCOME {
                    return too_large;
                }
                w.u8(K_GROUP_WELCOME).bytes(b);
            }
            Content::GroupCards { group_id, cards } => {
                if cards.len() > MAX_CARDS_PER_MESSAGE || cards.iter().any(|c| c.len() > MAX_CARD) {
                    return too_large;
                }
                w.u8(K_GROUP_CARDS).fixed(group_id).u8(cards.len() as u8);
                for c in cards {
                    w.bytes(c);
                }
            }
            Content::Attachment {
                id,
                attachment,
                caption,
                expires,
            } => {
                if attachment.len() > MAX_ATTACHMENT_REF
                    || caption.len() > MAX_TEXT
                    || *expires > MAX_TIMER
                {
                    return too_large;
                }
                w.u8(K_ATTACHMENT)
                    .fixed(id)
                    .bytes(attachment)
                    .bytes(caption.as_bytes())
                    .u32(*expires);
            }
            Content::React { target, emoji } => {
                if emoji.len() > MAX_REACTION {
                    return too_large;
                }
                w.u8(K_REACT).fixed(target).bytes(emoji.as_bytes());
            }
            Content::Edit { target, text } => {
                if text.len() > MAX_TEXT {
                    return too_large;
                }
                w.u8(K_EDIT).fixed(target).bytes(text.as_bytes());
            }
            Content::Delete { target } => {
                w.u8(K_DELETE).fixed(target);
            }
            Content::Read(ids) => {
                if ids.len() > MAX_RECEIPTS {
                    return too_large;
                }
                w.u8(K_READ).u8(ids.len() as u8);
                for i in ids {
                    w.fixed(i);
                }
            }
            Content::Timer(secs) => {
                if *secs > MAX_TIMER {
                    return too_large;
                }
                w.u8(K_TIMER).u32(*secs);
            }
            Content::Devices(version) => {
                w.u8(K_DEVICES).u64(*version);
            }
            Content::History(att) => {
                if att.len() > MAX_ATTACHMENT_REF {
                    return too_large;
                }
                w.u8(K_HISTORY).bytes(att);
            }
            Content::Veto(a) => {
                if a.len() > enclave_proto::attest::MAX_ATTESTATION {
                    return too_large;
                }
                w.u8(K_VETO).bytes(a);
            }
            Content::KtHead(att) => {
                if att.len() > MAX_ATTACHMENT_REF {
                    return too_large;
                }
                w.u8(K_KT_HEAD).bytes(att);
            }
            Content::SelfCopy { to, content } => {
                if content.len() > MAX_SELF_COPY || content.first() == Some(&K_SELF_COPY) {
                    return too_large;
                }
                w.u8(K_SELF_COPY).fixed(to).bytes(content);
            }
        }
        Ok(w.finish())
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let c = match r.u8()? {
            K_HELLO => Content::Hello {
                server: r.array()?,
                inbox: r.array()?,
                tokens: get_tokens(&mut r)?,
                name: get_str(&mut r, MAX_NAME)?,
                text: get_str(&mut r, MAX_TEXT)?,
                card: r.bytes(MAX_CARD)?.to_vec(),
                group: match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(ProtoError::Decode),
                },
                id: r.array()?,
            },
            K_TEXT => Content::Text {
                tokens: get_tokens(&mut r)?,
                text: get_str(&mut r, MAX_TEXT)?,
                id: r.array()?,
                expires: timer(r.u32()?)?,
            },
            K_TOKENS => Content::Tokens(get_tokens(&mut r)?),
            K_GROUP_WELCOME => Content::GroupWelcome(r.bytes(MAX_WELCOME)?.to_vec()),
            K_GROUP_CARDS => {
                let group_id = r.array()?;
                let n = r.u8()? as usize;
                if n > MAX_CARDS_PER_MESSAGE {
                    return Err(ProtoError::Decode);
                }
                let cards = (0..n)
                    .map(|_| r.bytes(MAX_CARD).map(<[u8]>::to_vec))
                    .collect::<Result<_>>()?;
                Content::GroupCards { group_id, cards }
            }
            K_ATTACHMENT => Content::Attachment {
                id: r.array()?,
                attachment: r.bytes(MAX_ATTACHMENT_REF)?.to_vec(),
                caption: get_str(&mut r, MAX_TEXT)?,
                expires: timer(r.u32()?)?,
            },
            K_REACT => Content::React {
                target: r.array()?,
                emoji: get_str(&mut r, MAX_REACTION)?,
            },
            K_EDIT => Content::Edit {
                target: r.array()?,
                text: get_str(&mut r, MAX_TEXT)?,
            },
            K_DELETE => Content::Delete { target: r.array()? },
            K_READ => {
                let n = r.u8()? as usize;
                if n > MAX_RECEIPTS {
                    return Err(ProtoError::Decode);
                }
                Content::Read((0..n).map(|_| r.array()).collect::<Result<_>>()?)
            }
            K_TIMER => Content::Timer(timer(r.u32()?)?),
            K_DEVICES => Content::Devices(r.u64()?),
            K_HISTORY => Content::History(r.bytes(MAX_ATTACHMENT_REF)?.to_vec()),
            K_VETO => Content::Veto(r.bytes(enclave_proto::attest::MAX_ATTESTATION)?.to_vec()),
            K_KT_HEAD => Content::KtHead(r.bytes(MAX_ATTACHMENT_REF)?.to_vec()),
            K_SELF_COPY => {
                let to = r.array()?;
                let content = r.bytes(MAX_SELF_COPY)?.to_vec();
                if content.first() == Some(&K_SELF_COPY) {
                    return Err(ProtoError::Decode);
                }
                Content::SelfCopy { to, content }
            }
            _ => return Err(ProtoError::Decode),
        };
        r.end()?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roundtrip_and_limits() {
        let all = [
            Content::Hello {
                server: [1; 16],
                inbox: [2; 32],
                tokens: vec![[3; 32]; 16],
                name: "Sam".into(),
                text: "hi".into(),
                card: vec![1; 180],
                group: Some([4; 32]),
                id: [8; 16],
            },
            Content::Text {
                tokens: vec![],
                text: "héllo 👋".into(),
                id: [1; 16],
                expires: 3600,
            },
            Content::Tokens(vec![[9; 32]; 8]),
            Content::GroupWelcome(vec![5; 7000]),
            Content::GroupCards {
                group_id: [6; 32],
                cards: vec![vec![7; 180]; 30],
            },
            Content::Attachment {
                id: [2; 16],
                attachment: vec![3; 300],
                caption: "look".into(),
                expires: 0,
            },
            Content::React {
                target: [4; 16],
                emoji: "👍🏽".into(),
            },
            Content::Edit {
                target: [4; 16],
                text: "fixed".into(),
            },
            Content::Delete { target: [4; 16] },
            Content::Read(vec![[5; 16]; 10]),
            Content::Timer(86_400),
            Content::SelfCopy {
                to: [9; 64],
                content: vec![K_TEXT, 0, 0, 0, 0, 0],
            },
        ];
        for c in all {
            let e = c.encode().unwrap();
            assert!(
                e.len() <= enclave_wire::direct::CONTENT_CAPACITY,
                "fits one unit"
            );
            assert_eq!(Content::decode(&e).unwrap(), c);
            let mut longer = e.clone();
            longer.push(0);
            assert!(Content::decode(&longer).is_err());
        }
        let long = "x".repeat(MAX_TEXT + 1);
        assert!(
            Content::Text {
                tokens: vec![],
                text: long,
                id: [0; 16],
                expires: 0
            }
            .encode()
            .is_err()
        );
        assert!(Content::Timer(MAX_TIMER + 1).encode().is_err());
        assert!(
            Content::Tokens(vec![[0; 32]; MAX_TOKENS + 1])
                .encode()
                .is_err()
        );
        assert!(
            Content::decode(&[K_TEXT, 0, 0, 0, 0, 1, 0xff]).is_err(),
            "invalid UTF-8"
        );
    }
}
