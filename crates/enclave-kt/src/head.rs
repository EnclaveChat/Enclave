//! Signed tree heads, witness cosignatures and the client's quorum check.

use crate::{KtError, Result};
use enclave_crypto::hash::shake256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};

/// Context for server head signatures.
pub const CTX_HEAD: &[u8] = b"enclave/v1/kt/head";
/// Context for witness cosignatures.
pub const CTX_COSIGN: &[u8] = b"enclave/v1/kt/cosign";
/// Heads older than this are refused by clients.
pub const MAX_HEAD_AGE_SECS: u64 = 24 * 3600;

/// A tree head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeHead {
    /// Server identifier.
    pub server: [u8; 16],
    /// Epoch number.
    pub epoch: u64,
    /// akd root hash.
    pub root: [u8; 32],
    /// Server time when published (Unix seconds).
    pub time: u64,
}

impl TreeHead {
    /// Canonical encoding.
    pub fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..16].copy_from_slice(&self.server);
        b[16..24].copy_from_slice(&self.epoch.to_be_bytes());
        b[24..56].copy_from_slice(&self.root);
        b[56..].copy_from_slice(&self.time.to_be_bytes());
        b
    }

    /// 32-byte digest gossiped between contacts in message padding.
    pub fn gossip_digest(&self) -> [u8; 32] {
        let mut v = b"enclave/v1/kt/gossip".to_vec();
        v.extend_from_slice(&self.encode());
        shake256(&v)
    }
}

/// A witness cosignature over a head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    /// Witness identifier.
    pub witness: [u8; 16],
    /// Witness time when cosigning.
    pub time: u64,
    /// Composite signature over `head ‖ time`.
    pub signature: Vec<u8>,
}

/// A head with the server's signature and witness cosignatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    /// The head.
    pub head: TreeHead,
    /// Server composite signature.
    pub signature: Vec<u8>,
    /// Cosignatures.
    pub cosignatures: Vec<Cosignature>,
}

impl SignedHead {
    /// Server signs a head.
    pub fn sign(head: TreeHead, key: &CompositeSigningKey, rng: &mut HedgedRng) -> Result<Self> {
        let signature = key
            .sign(CTX_HEAD, &head.encode(), rng)
            .map_err(|_| KtError::Signature)?;
        Ok(Self {
            head,
            signature,
            cosignatures: Vec::new(),
        })
    }

    /// Verify the server's signature.
    pub fn verify_server(&self, server_key: &CompositePublic) -> Result<()> {
        server_key
            .verify(CTX_HEAD, &self.head.encode(), &self.signature)
            .map_err(|_| KtError::Signature)
    }
}

pub(crate) fn cosign_message(head: &TreeHead, time: u64) -> Vec<u8> {
    let mut m = head.encode().to_vec();
    m.extend_from_slice(&time.to_be_bytes());
    m
}

/// A client's witness policy: pinned witnesses and the required quorum.
#[derive(Clone)]
pub struct WitnessPolicy {
    /// Pinned witnesses: `(id, key, operator)`. Cosignatures from witnesses run
    /// by the same operator as the server do not count.
    pub witnesses: Vec<([u8; 16], CompositePublic, String)>,
    /// Required number of valid cosignatures.
    pub threshold: usize,
}

impl WitnessPolicy {
    /// Check the server signature and the witness quorum, and return trusted
    /// time (the median witness timestamp).
    pub fn check(
        &self,
        sh: &SignedHead,
        server_key: &CompositePublic,
        server_operator: &str,
        now: u64,
    ) -> Result<u64> {
        sh.verify_server(server_key)?;
        let mut times = Vec::new();
        let mut seen = Vec::new();
        for c in &sh.cosignatures {
            if seen.contains(&c.witness) {
                continue;
            }
            let Some((_, key, operator)) =
                self.witnesses.iter().find(|(id, _, _)| *id == c.witness)
            else {
                continue;
            };
            if operator == server_operator {
                continue;
            }
            if key
                .verify(CTX_COSIGN, &cosign_message(&sh.head, c.time), &c.signature)
                .is_ok()
            {
                seen.push(c.witness);
                times.push(c.time);
            }
        }
        if times.len() < self.threshold || times.is_empty() {
            return Err(KtError::Quorum);
        }
        times.sort_unstable();
        let trusted = times[times.len() / 2];
        if now > sh.head.time + MAX_HEAD_AGE_SECS + 3600
            || trusted + MAX_HEAD_AGE_SECS < sh.head.time
        {
            return Err(KtError::Stale);
        }
        Ok(trusted)
    }
}
