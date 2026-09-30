//! Contact cards: what a QR code or invite link carries (`docs/03-identity.md`).
//!
//! Links look like `enclave:add#<base64url>`. The secret part lives in the
//! fragment so it never reaches a web server if the link is opened in a
//! browser. Device-linking codes use a different scheme (`enclave:link#`)
//! and are refused here, so the general scanner can never start a link.

use enclave_proto::codec::{Reader, Writer};

/// URI prefix of contact links.
pub const ADD_PREFIX: &str = "enclave:add#";
/// URI prefix of device-link codes (only accepted in Settings → Your devices).
pub const LINK_PREFIX: &str = "enclave:link#";
/// Maximum display-name length in bytes.
pub const MAX_NAME: usize = 64;
const CARD_VERSION: u8 = 1;

/// Why a link could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// Not an Enclave link.
    #[error("not an Enclave link")]
    NotEnclave,
    /// A device-link code scanned in the wrong place.
    #[error("this code links a device; only scan it from Settings → Your devices")]
    DeviceLinkCode,
    /// An in-person code used where an invite was expected.
    #[error("this is an in-person code; open Meet in person to use it")]
    MeetCode,
    /// The person scanned their own code.
    #[error("this is your own code")]
    OwnCode,
    /// Corrupt or unsupported.
    #[error("the link is damaged or from a newer version")]
    Malformed,
}

/// Everything needed to start a conversation with someone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactCard {
    /// Root public key (their identity).
    pub root: [u8; 64],
    /// Home server.
    pub server: [u8; 16],
    /// Request inbox address.
    pub request_inbox: [u8; 32],
    /// Directory locator of the encrypted McEliece vault key.
    pub vault_locator: [u8; 32],
    /// Key that decrypts the vault blob. Only holders of the card can fetch
    /// and recognize it, so the directory cannot tell whose key is read.
    pub vault_key: [u8; 32],
    /// Display name the owner chose (unverified; shown as a suggestion).
    pub name: String,
}

impl ContactCard {
    /// Binary form.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(CARD_VERSION)
            .fixed(&self.root)
            .fixed(&self.server)
            .fixed(&self.request_inbox)
            .fixed(&self.vault_locator)
            .fixed(&self.vault_key)
            .bytes(self.name.as_bytes());
        w.finish()
    }

    /// Parse the binary form.
    pub fn decode(b: &[u8]) -> Result<Self, LinkError> {
        let mut r = Reader::new(b);
        let m = |_| LinkError::Malformed;
        if r.u8().map_err(m)? != CARD_VERSION {
            return Err(LinkError::Malformed);
        }
        let card = Self {
            root: r.array().map_err(m)?,
            server: r.array().map_err(m)?,
            request_inbox: r.array().map_err(m)?,
            vault_locator: r.array().map_err(m)?,
            vault_key: r.array().map_err(m)?,
            name: String::from_utf8(r.bytes(MAX_NAME).map_err(m)?.to_vec())
                .map_err(|_| LinkError::Malformed)?,
        };
        r.end().map_err(m)?;
        Ok(card)
    }

    /// `enclave:add#…` link.
    pub fn to_link(&self) -> String {
        format!("{ADD_PREFIX}{}", b64url_encode(&self.encode()))
    }

    /// Parse a scanned or pasted link.
    pub fn from_link(s: &str) -> Result<Self, LinkError> {
        let s = s.trim();
        if s.starts_with(LINK_PREFIX) {
            return Err(LinkError::DeviceLinkCode);
        }
        if s.starts_with(crate::client::MEET_PREFIX) {
            return Err(LinkError::MeetCode);
        }
        let body = s.strip_prefix(ADD_PREFIX).ok_or(LinkError::NotEnclave)?;
        Self::decode(&b64url_decode(body).ok_or(LinkError::Malformed)?)
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
pub fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// Inverse of [`b64url_encode`]; rejects padding, other alphabets and
/// non-canonical trailing bits.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| B64.iter().position(|&x| x == c).map(|p| p as u32);
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        let full = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Unused low bits must be zero (one canonical encoding per value).
        let unused = match produced {
            1 => n & 0xffff,
            2 => n & 0xff,
            _ => 0,
        };
        if unused != 0 {
            return None;
        }
        out.extend_from_slice(&full[..produced]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn base64url_roundtrip_and_strictness() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64url_decode(&b64url_encode(&data)).unwrap(), data);
        }
        assert_eq!(b64url_encode(b"foob"), "Zm9vYg");
        assert!(
            b64url_decode("Zm9vYh").is_none(),
            "non-canonical trailing bits"
        );
        assert!(b64url_decode("Zm9vYg==").is_none(), "padding refused");
        assert!(b64url_decode("Z").is_none());
    }

    #[test]
    fn card_links() {
        let card = ContactCard {
            root: [1; 64],
            server: [2; 16],
            request_inbox: [3; 32],
            vault_locator: [4; 32],
            vault_key: [5; 32],
            name: "Sam".into(),
        };
        let link = card.to_link();
        assert!(link.starts_with("enclave:add#"));
        assert_eq!(ContactCard::from_link(&link).unwrap(), card);
        assert_eq!(
            ContactCard::from_link("enclave:link#AAAA"),
            Err(LinkError::DeviceLinkCode)
        );
        assert_eq!(
            ContactCard::from_link("https://example.com"),
            Err(LinkError::NotEnclave)
        );
        let mut bad = link.clone();
        bad.push('A');
        assert!(ContactCard::from_link(&bad).is_err());
    }
}
