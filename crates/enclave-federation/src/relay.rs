//! Call-relay descriptors (`docs/12-servers.md` §5).
//!
//! ```text
//! relay id   = first 16 B of SHAKE256("enclave/v1/calls/relay-id" ‖ identity public key)
//! descriptor = u8(1) ‖ identity pk (2,649) ‖ bytes(operator) ‖ bytes(family)
//!            ‖ bytes(UDP address) ‖ link key (56)
//!            ‖ u8(n) ‖ n × (u32(day) ‖ X448 (56) ‖ ML-KEM-1024 (1,568))     ticket keys
//!            ‖ u64(published) ‖ u64(expires)
//!            ‖ CompositeSign(identity, "enclave/v1/calls/relay-descriptor", all of the above)
//! ```
//!
//! Callers pick relays from operator families different from each other's.

use crate::codec::{Reader, Writer};
use crate::{FedError, MAX_ADDRESS, MAX_NAME, Result, read_composite, read_sig, utf8};
use enclave_crypto::hash::shake256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};

/// Signature context of a relay descriptor.
pub const CTX_RELAY_DESCRIPTOR: &str = "enclave/v1/calls/relay-descriptor";
/// Label of the relay id.
pub const RELAY_ID_LABEL: &str = "enclave/v1/calls/relay-id";
/// Bytes of one ticket key: `u32 day ‖ X448 ‖ ML-KEM-1024`.
pub const TICKET_KEY_LEN: usize = 4 + 56 + 1568;
const VERSION: u8 = 1;
const MAX_TICKET_KEYS: usize = 3;

/// A relay id from its identity key.
pub fn relay_id(identity: &CompositePublic) -> [u8; 16] {
    let h: [u8; 32] = shake256(&[RELAY_ID_LABEL.as_bytes(), &identity.to_bytes()].concat());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// What a relay says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDescriptor {
    /// Identity public key; the relay id is derived from it.
    pub identity: CompositePublic,
    /// Operator.
    pub operator: String,
    /// Operator family.
    pub family: String,
    /// UDP address (`host:port`).
    pub addr: String,
    /// X448 public key for relay↔relay links.
    pub link_key: [u8; 56],
    /// Ticket keys (`u32 day ‖ X448 ‖ ML-KEM-1024` each): today's and the
    /// next day's.
    pub ticket_keys: Vec<Vec<u8>>,
    /// When signed.
    pub published: u64,
    /// Valid until.
    pub expires: u64,
    signature: Vec<u8>,
}

impl RelayDescriptor {
    /// The relay id.
    pub fn id(&self) -> [u8; 16] {
        relay_id(&self.identity)
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(VERSION)
            .fixed(&self.identity.to_bytes())
            .bytes(self.operator.as_bytes())
            .bytes(self.family.as_bytes())
            .bytes(self.addr.as_bytes())
            .fixed(&self.link_key)
            .u8(self.ticket_keys.len() as u8);
        for k in &self.ticket_keys {
            w.fixed(k);
        }
        w.u64(self.published).u64(self.expires);
        w.finish()
    }

    /// Build and sign.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity: &CompositeSigningKey,
        operator: &str,
        family: &str,
        addr: &str,
        link_key: [u8; 56],
        ticket_keys: Vec<Vec<u8>>,
        published: u64,
        expires: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        if family.is_empty()
            || operator.len() > MAX_NAME
            || family.len() > MAX_NAME
            || addr.is_empty()
            || addr.len() > MAX_ADDRESS
            || ticket_keys.is_empty()
            || ticket_keys.len() > MAX_TICKET_KEYS
            || ticket_keys.iter().any(|k| k.len() != TICKET_KEY_LEN)
            || expires <= published
        {
            return Err(FedError::Malformed);
        }
        let mut d = Self {
            identity: identity.public().clone(),
            operator: operator.into(),
            family: family.into(),
            addr: addr.into(),
            link_key,
            ticket_keys,
            published,
            expires,
            signature: Vec::new(),
        };
        d.signature = identity
            .sign(CTX_RELAY_DESCRIPTOR.as_bytes(), &d.body(), rng)
            .map_err(|_| FedError::Crypto)?;
        Ok(d)
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode (without checking the signature).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != VERSION {
            return Err(FedError::Malformed);
        }
        let identity = read_composite(&mut r)?;
        let operator = utf8(r.bytes(MAX_NAME)?)?;
        let family = utf8(r.bytes(MAX_NAME)?)?;
        let addr = utf8(r.bytes(MAX_ADDRESS)?)?;
        let link_key = r.array::<56>()?;
        let n = usize::from(r.u8()?);
        if n == 0 || n > MAX_TICKET_KEYS {
            return Err(FedError::Malformed);
        }
        let ticket_keys = (0..n)
            .map(|_| Ok(r.fixed(TICKET_KEY_LEN)?.to_vec()))
            .collect::<Result<Vec<_>>>()?;
        let d = Self {
            identity,
            operator,
            family,
            addr,
            link_key,
            ticket_keys,
            published: r.u64()?,
            expires: r.u64()?,
            signature: read_sig(&mut r)?.to_vec(),
        };
        r.end()?;
        Ok(d)
    }

    /// Check the self-signature and the validity window.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.identity
            .verify(
                CTX_RELAY_DESCRIPTOR.as_bytes(),
                &self.body(),
                &self.signature,
            )
            .map_err(|_| FedError::Signature)?;
        if now >= self.expires {
            return Err(FedError::Expired);
        }
        Ok(())
    }
}
