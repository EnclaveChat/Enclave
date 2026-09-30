//! Encodings of client records kept in the sealed store.

use crate::card::ContactCard;
use crate::client::{Contact, ContactState, Message};
use crate::content::Token;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::manifest::Manifest;
use enclave_proto::{ProtoError, Result};

pub(crate) const NS_PROFILE: &str = "profile";
pub(crate) const NS_SECRETS: &str = "secrets";
pub(crate) const NS_CONTACTS: &str = "contacts";
pub(crate) const NS_SESSIONS: &str = "sessions";
pub(crate) const NS_ISSUERS: &str = "issuers";
pub(crate) const NS_REPLAY: &str = "replay";
pub(crate) const NS_SETTINGS: &str = "settings";

/// Namespace holding one contact's messages.
pub(crate) fn msg_ns(root: &[u8; 64]) -> String {
    let mut s = String::from("m/");
    for b in &root[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Where this account lives and how to read it.
pub(crate) struct Profile {
    pub server: [u8; 16],
    pub inbox: [u8; 32],
    pub inbox_owner: [u8; 32],
    pub request_inbox: [u8; 32],
    pub request_owner: [u8; 32],
    pub vault_locator: [u8; 32],
    pub vault_key: [u8; 32],
    pub name: String,
    pub cursor: u64,
    pub request_cursor: u64,
    pub created_at: u64,
}

impl Profile {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.server)
            .fixed(&self.inbox)
            .fixed(&self.inbox_owner)
            .fixed(&self.request_inbox)
            .fixed(&self.request_owner)
            .fixed(&self.vault_locator)
            .fixed(&self.vault_key)
            .bytes(self.name.as_bytes())
            .u64(self.cursor)
            .u64(self.request_cursor)
            .u64(self.created_at);
        w.finish()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let p = Self {
            server: r.array()?,
            inbox: r.array()?,
            inbox_owner: r.array()?,
            request_inbox: r.array()?,
            request_owner: r.array()?,
            vault_locator: r.array()?,
            vault_key: r.array()?,
            name: String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?,
            cursor: r.u64()?,
            request_cursor: r.u64()?,
            created_at: r.u64()?,
        };
        r.end()?;
        Ok(p)
    }
}

fn state_byte(s: ContactState) -> u8 {
    match s {
        ContactState::Pending => 0,
        ContactState::Request => 1,
        ContactState::Accepted => 2,
    }
}

pub(crate) fn encode_contact(c: &Contact) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u8(1)
        .fixed(&c.root)
        .bytes(c.name.as_bytes())
        .u8(state_byte(c.state));
    w.u8(u8::from(c.verified))
        .fixed(&c.server)
        .fixed(&c.request_inbox);
    match &c.inbox {
        Some(i) => w.u8(1).fixed(i),
        None => w.u8(0),
    };
    w.u16(c.tokens.len() as u16);
    for t in &c.tokens {
        w.fixed(t);
    }
    w.bytes(&c.manifest.encode()?);
    w.u64(c.next_seq)
        .u32(c.received_since_refill)
        .u32(c.unread)
        .u64(c.added_at);
    w.bytes(&c.card.as_ref().map(ContactCard::encode).unwrap_or_default());
    w.u8(u8::from(c.group_only));
    Ok(w.finish())
}

pub(crate) fn decode_contact(b: &[u8]) -> Result<Contact> {
    let mut r = Reader::new(b);
    if r.u8()? != 1 {
        return Err(ProtoError::Decode);
    }
    let root = r.array()?;
    let name = String::from_utf8(r.bytes(256)?.to_vec()).map_err(|_| ProtoError::Decode)?;
    let state = match r.u8()? {
        0 => ContactState::Pending,
        1 => ContactState::Request,
        2 => ContactState::Accepted,
        _ => return Err(ProtoError::Decode),
    };
    let verified = r.u8()? == 1;
    let server = r.array()?;
    let request_inbox = r.array()?;
    let inbox = match r.u8()? {
        0 => None,
        1 => Some(r.array()?),
        _ => return Err(ProtoError::Decode),
    };
    let n = r.u16()? as usize;
    let tokens: Vec<Token> = (0..n).map(|_| r.array()).collect::<Result<_>>()?;
    let manifest = Manifest::decode(r.bytes(1 << 20)?)?;
    let c = Contact {
        root,
        name,
        state,
        verified,
        server,
        request_inbox,
        inbox,
        tokens,
        manifest,
        next_seq: r.u64()?,
        received_since_refill: r.u32()?,
        unread: r.u32()?,
        added_at: r.u64()?,
        card: {
            let b = r.bytes(crate::content::MAX_CARD)?;
            if b.is_empty() {
                None
            } else {
                Some(ContactCard::decode(b).map_err(|_| ProtoError::Decode)?)
            }
        },
        group_only: r.u8()? == 1,
    };
    r.end()?;
    Ok(c)
}

pub(crate) fn encode_message(m: &Message) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(1)
        .u64(m.seq)
        .u8(u8::from(m.outgoing))
        .u8(u8::from(m.delivered))
        .u64(m.at);
    w.bytes(m.text.as_bytes());
    w.finish()
}

pub(crate) fn decode_message(b: &[u8]) -> Result<Message> {
    let mut r = Reader::new(b);
    if r.u8()? != 1 {
        return Err(ProtoError::Decode);
    }
    let m = Message {
        seq: r.u64()?,
        outgoing: r.u8()? == 1,
        delivered: r.u8()? == 1,
        at: r.u64()?,
        text: String::from_utf8(r.bytes(1 << 16)?.to_vec()).map_err(|_| ProtoError::Decode)?,
    };
    r.end()?;
    Ok(m)
}

/// Seal a large public object (the McEliece vault key) for the directory.
pub(crate) fn seal_large(key: &SealKey, data: &[u8], rng: &mut HedgedRng) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 60_000 * 72 + 72);
    let n = data.len().div_ceil(60_000);
    for (i, seg) in data.chunks(60_000).enumerate() {
        let ad = [&(i as u64).to_be_bytes()[..], &[u8::from(i + 1 == n)]].concat();
        let s = seal::seal(key, &ad, seg, rng)?;
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(&s);
    }
    Ok(out)
}

/// Inverse of [`seal_large`]; truncation is caught by the last-segment flag.
pub(crate) fn open_large(key: &SealKey, data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut i = 0u64;
    while off < data.len() {
        let len: [u8; 4] = data
            .get(off..off + 4)
            .ok_or(ProtoError::Decode)?
            .try_into()
            .map_err(|_| ProtoError::Decode)?;
        off += 4;
        let n = u32::from_be_bytes(len) as usize;
        let seg = data.get(off..off + n).ok_or(ProtoError::Decode)?;
        off += n;
        let ad = [&i.to_be_bytes()[..], &[u8::from(off == data.len())]].concat();
        out.extend_from_slice(&seal::open(key, &ad, seg)?);
        i += 1;
    }
    if i == 0 {
        return Err(ProtoError::Decode);
    }
    Ok(out)
}
