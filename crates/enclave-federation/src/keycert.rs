//! Request-key certificates (`docs/12-servers.md` §4.2).
//!
//! ```text
//! KeyCert   = u8(1) ‖ server_id (16) ‖ ServerKey (1,628) ‖ u64(not_before) ‖ u64(not_after)
//!             ‖ CompositeSign(identity, "enclave/v1/net/request-key-cert", all of the above)
//! KeyBundle = u8(1) ‖ identity public key (2,649) ‖ u8(n) ‖ n × KeyCert
//! ```
//!
//! A day's key is valid from the start of its day to the end of the next
//! one (the server keeps yesterday's key a day for late requests). A
//! server answers a zero-length request with a bundle of today's and
//! tomorrow's certificates.

use crate::codec::{Reader, Writer};
use crate::{FedError, Result, read_composite, read_sig, server_id};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SIG_LEN, CompositePublic, CompositeSigningKey};
use enclave_rpc::ServerKey;

/// Signature context of a key certificate.
pub const CTX_KEY_CERT: &str = "enclave/v1/net/request-key-cert";
const VERSION: u8 = 1;
/// Encoded size of a certificate.
pub const CERT_LEN: usize = 1 + 16 + ServerKey::ENCODED_LEN + 8 + 8 + COMPOSITE_SIG_LEN;
/// Most certificates in a bundle.
pub const MAX_CERTS: usize = 4;

/// A signed request key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCert {
    /// The server.
    pub server: [u8; 16],
    /// The key (its `key_id` is its day).
    pub key: ServerKey,
    /// Valid from (Unix seconds).
    pub not_before: u64,
    /// Valid until (Unix seconds, exclusive).
    pub not_after: u64,
    signature: Vec<u8>,
}

fn body(server: &[u8; 16], key: &ServerKey, not_before: u64, not_after: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(VERSION)
        .fixed(server)
        .fixed(&key.to_bytes())
        .u64(not_before)
        .u64(not_after);
    w.finish()
}

impl KeyCert {
    /// Certify `key` (its day is `key.key_id`): valid through the next day.
    pub fn sign(
        identity: &CompositeSigningKey,
        key: &ServerKey,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let server = server_id(identity.public());
        let not_before = u64::from(key.key_id) * 86_400;
        let not_after = not_before + 2 * 86_400;
        let signature = identity
            .sign(
                CTX_KEY_CERT.as_bytes(),
                &body(&server, key, not_before, not_after),
                rng,
            )
            .map_err(|_| FedError::Crypto)?;
        Ok(Self {
            server,
            key: key.clone(),
            not_before,
            not_after,
            signature,
        })
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = body(&self.server, &self.key, self.not_before, self.not_after);
        b.extend_from_slice(&self.signature);
        b
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        if r.u8()? != VERSION {
            return Err(FedError::Malformed);
        }
        let server = r.array::<16>()?;
        let key = ServerKey::from_bytes(r.fixed(ServerKey::ENCODED_LEN)?)
            .map_err(|_| FedError::Malformed)?;
        let not_before = r.u64()?;
        let not_after = r.u64()?;
        let signature = read_sig(r)?.to_vec();
        Ok(Self {
            server,
            key,
            not_before,
            not_after,
            signature,
        })
    }

    /// Decode (without checking the signature).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let c = Self::read(&mut r)?;
        r.end()?;
        Ok(c)
    }

    /// Check the signature under `identity` and that the certificate names
    /// that identity's server.
    pub fn verify(&self, identity: &CompositePublic) -> Result<()> {
        if self.server != server_id(identity) {
            return Err(FedError::WrongId);
        }
        identity
            .verify(
                CTX_KEY_CERT.as_bytes(),
                &body(&self.server, &self.key, self.not_before, self.not_after),
                &self.signature,
            )
            .map_err(|_| FedError::Signature)
    }

    /// Whether `now` is inside the validity window.
    pub fn valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// A server's identity key and its current certificates: the reply to a
/// zero-length request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    /// The server's identity public key.
    pub identity: CompositePublic,
    /// Certificates, oldest first.
    pub certs: Vec<KeyCert>,
}

impl KeyBundle {
    /// Certify `keys` (oldest first) under `identity`.
    pub fn sign(
        identity: &CompositeSigningKey,
        keys: &[ServerKey],
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        if keys.is_empty() || keys.len() > MAX_CERTS {
            return Err(FedError::Malformed);
        }
        Ok(Self {
            identity: identity.public().clone(),
            certs: keys
                .iter()
                .map(|k| KeyCert::sign(identity, k, rng))
                .collect::<Result<Vec<_>>>()?,
        })
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(VERSION)
            .fixed(&self.identity.to_bytes())
            .u8(self.certs.len() as u8);
        let mut b = w.finish();
        for c in &self.certs {
            b.extend_from_slice(&c.encode());
        }
        b
    }

    /// Decode (without checking signatures).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != VERSION {
            return Err(FedError::Malformed);
        }
        let identity = read_composite(&mut r)?;
        let n = usize::from(r.u8()?);
        if n == 0 || n > MAX_CERTS {
            return Err(FedError::Malformed);
        }
        let certs = (0..n)
            .map(|_| KeyCert::read(&mut r))
            .collect::<Result<Vec<_>>>()?;
        r.end()?;
        Ok(Self { identity, certs })
    }

    /// Check the bundle against the server id the client expects, and
    /// return the key to use at `now` (the newest certificate valid then).
    /// A bundle from any other server, or with a certificate that doesn't
    /// verify, is refused whole.
    pub fn verify(&self, expected: &[u8; 16], now: u64) -> Result<ServerKey> {
        if server_id(&self.identity) != *expected {
            return Err(FedError::WrongId);
        }
        for c in &self.certs {
            c.verify(&self.identity)?;
        }
        self.certs
            .iter()
            .filter(|c| c.valid_at(now))
            .max_by_key(|c| c.not_before)
            .map(|c| c.key.clone())
            .ok_or(FedError::Expired)
    }
}
