//! Witness descriptors (`docs/12-servers.md` §3.3).
//!
//! ```text
//! witness id = first 16 B of SHAKE256("enclave/v1/kt/witness-id" ‖ public key)
//! descriptor = u8(1) ‖ public key (2,649) ‖ bytes(operator) ‖ bytes(family) ‖ bytes(url)
//!            ‖ u64(published) ‖ u64(expires)
//!            ‖ CompositeSign(key, "enclave/v1/kt/witness-descriptor", all of the above)
//! ```

use crate::codec::{Reader, Writer};
use crate::{FedError, MAX_ADDRESS, MAX_NAME, Result, read_composite, read_sig, utf8};
use enclave_crypto::hash::shake256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};

/// Signature context of a witness descriptor.
pub const CTX_WITNESS_DESCRIPTOR: &str = "enclave/v1/kt/witness-descriptor";
/// Label of the witness id.
pub const WITNESS_ID_LABEL: &str = "enclave/v1/kt/witness-id";
const VERSION: u8 = 1;

/// A witness id from its cosigning key.
pub fn witness_id(key: &CompositePublic) -> [u8; 16] {
    let h: [u8; 32] = shake256(&[WITNESS_ID_LABEL.as_bytes(), &key.to_bytes()].concat());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    id
}

/// What a witness says about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessDescriptor {
    /// Cosigning key.
    pub key: CompositePublic,
    /// Operator (a witness never counts for a log run by the same operator).
    pub operator: String,
    /// Operator family.
    pub family: String,
    /// HTTPS base URL of the cosigning API.
    pub url: String,
    /// When signed.
    pub published: u64,
    /// Valid until.
    pub expires: u64,
    signature: Vec<u8>,
}

impl WitnessDescriptor {
    /// The witness id.
    pub fn id(&self) -> [u8; 16] {
        witness_id(&self.key)
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(VERSION)
            .fixed(&self.key.to_bytes())
            .bytes(self.operator.as_bytes())
            .bytes(self.family.as_bytes())
            .bytes(self.url.as_bytes())
            .u64(self.published)
            .u64(self.expires);
        w.finish()
    }

    /// Build and sign.
    pub fn sign(
        key: &CompositeSigningKey,
        operator: &str,
        family: &str,
        url: &str,
        published: u64,
        expires: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        if operator.is_empty()
            || operator.len() > MAX_NAME
            || family.len() > MAX_NAME
            || url.len() > MAX_ADDRESS
            || expires <= published
        {
            return Err(FedError::Malformed);
        }
        let mut d = Self {
            key: key.public().clone(),
            operator: operator.into(),
            family: family.into(),
            url: url.into(),
            published,
            expires,
            signature: Vec::new(),
        };
        d.signature = key
            .sign(CTX_WITNESS_DESCRIPTOR.as_bytes(), &d.body(), rng)
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
        let d = Self {
            key: read_composite(&mut r)?,
            operator: utf8(r.bytes(MAX_NAME)?)?,
            family: utf8(r.bytes(MAX_NAME)?)?,
            url: utf8(r.bytes(MAX_ADDRESS)?)?,
            published: r.u64()?,
            expires: r.u64()?,
            signature: read_sig(&mut r)?.to_vec(),
        };
        r.end()?;
        Ok(d)
    }

    /// Check the self-signature and the validity window.
    pub fn verify(&self, now: u64) -> Result<()> {
        self.key
            .verify(
                CTX_WITNESS_DESCRIPTOR.as_bytes(),
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
