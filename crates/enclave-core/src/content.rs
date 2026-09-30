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
/// until continuation units land (M9).
pub const MAX_TEXT: usize = 4096;
/// Largest encoded card accepted.
pub const MAX_CARD: usize = 512;
/// Most cards in one `GroupCards` message.
pub const MAX_CARDS_PER_MESSAGE: usize = 40;
/// Largest group welcome accepted.
pub const MAX_WELCOME: usize = 9_000;

/// A write token for someone's inbox.
pub type Token = [u8; 32];

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
    },
    /// A text message, optionally carrying fresh tokens.
    Text {
        /// Write tokens for the sender's inbox.
        tokens: Vec<Token>,
        /// The text.
        text: String,
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
}

const K_HELLO: u8 = 1;
const K_TEXT: u8 = 2;
const K_TOKENS: u8 = 3;
const K_GROUP_WELCOME: u8 = 4;
const K_GROUP_CARDS: u8 = 5;

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

impl Content {
    /// Encode. Fails if a limit is exceeded.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        match self {
            Content::Hello {
                server,
                inbox,
                tokens,
                name,
                text,
                card,
                group,
            } => {
                if tokens.len() > MAX_TOKENS
                    || name.len() > MAX_NAME
                    || text.len() > MAX_TEXT
                    || card.len() > MAX_CARD
                {
                    return Err(ProtoError::TooLarge);
                }
                w.u8(K_HELLO).fixed(server).fixed(inbox);
                put_tokens(&mut w, tokens);
                w.bytes(name.as_bytes()).bytes(text.as_bytes()).bytes(card);
                match group {
                    Some(g) => w.u8(1).fixed(g),
                    None => w.u8(0),
                };
            }
            Content::Text { tokens, text } => {
                if tokens.len() > MAX_TOKENS || text.len() > MAX_TEXT {
                    return Err(ProtoError::TooLarge);
                }
                w.u8(K_TEXT);
                put_tokens(&mut w, tokens);
                w.bytes(text.as_bytes());
            }
            Content::Tokens(tokens) => {
                if tokens.len() > MAX_TOKENS {
                    return Err(ProtoError::TooLarge);
                }
                w.u8(K_TOKENS);
                put_tokens(&mut w, tokens);
            }
            Content::GroupWelcome(b) => {
                if b.len() > MAX_WELCOME {
                    return Err(ProtoError::TooLarge);
                }
                w.u8(K_GROUP_WELCOME).bytes(b);
            }
            Content::GroupCards { group_id, cards } => {
                if cards.len() > MAX_CARDS_PER_MESSAGE || cards.iter().any(|c| c.len() > MAX_CARD) {
                    return Err(ProtoError::TooLarge);
                }
                w.u8(K_GROUP_CARDS).fixed(group_id).u8(cards.len() as u8);
                for c in cards {
                    w.bytes(c);
                }
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
            },
            K_TEXT => Content::Text {
                tokens: get_tokens(&mut r)?,
                text: get_str(&mut r, MAX_TEXT)?,
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
            },
            Content::Text {
                tokens: vec![],
                text: "héllo 👋".into(),
            },
            Content::Tokens(vec![[9; 32]; 8]),
            Content::GroupWelcome(vec![5; 7000]),
            Content::GroupCards {
                group_id: [6; 32],
                cards: vec![vec![7; 180]; 30],
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
        assert!(
            Content::Text {
                tokens: vec![],
                text: "x".repeat(MAX_TEXT + 1)
            }
            .encode()
            .is_err()
        );
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
