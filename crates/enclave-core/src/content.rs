//! Message content inside ratchet envelopes (`docs/08-envelope.md`).
//!
//! A small canonical binary format. Every field has a hard limit and decoding
//! rejects trailing bytes. Write tokens and inbox addresses travel only here,
//! inside the end-to-end encrypted body, never in anything a server can read.

use crate::card::MAX_NAME;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::{ProtoError, Result};

/// Most write tokens one message may carry.
pub const MAX_TOKENS: usize = 32;
/// Maximum text in one message (bytes of UTF-8). Longer text is refused
/// until continuation units land (M9).
pub const MAX_TEXT: usize = 4096;

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
}

const K_HELLO: u8 = 1;
const K_TEXT: u8 = 2;
const K_TOKENS: u8 = 3;

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
            } => {
                if tokens.len() > MAX_TOKENS || name.len() > MAX_NAME || text.len() > MAX_TEXT {
                    return Err(ProtoError::TooLarge);
                }
                w.u8(K_HELLO).fixed(server).fixed(inbox);
                put_tokens(&mut w, tokens);
                w.bytes(name.as_bytes()).bytes(text.as_bytes());
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
            },
            K_TEXT => Content::Text {
                tokens: get_tokens(&mut r)?,
                text: get_str(&mut r, MAX_TEXT)?,
            },
            K_TOKENS => Content::Tokens(get_tokens(&mut r)?),
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
            },
            Content::Text {
                tokens: vec![],
                text: "héllo 👋".into(),
            },
            Content::Tokens(vec![[9; 32]; 8]),
        ];
        for c in all {
            let e = c.encode().unwrap();
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
