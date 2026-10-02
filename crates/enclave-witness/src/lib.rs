//! Enclave's key-transparency witness as a service (`docs/12-servers.md`
//! §3.3).
//!
//! A witness cosigns a log's newest head only after checking that it
//! extends the head it cosigned last for that log (append-only proof from
//! akd), and it remembers what it cosigned across restarts. It witnesses
//! only the logs in the foundation's server list, under the head key the
//! list pins for each: nobody can enroll a log the foundation didn't list,
//! or present a listed log under a different key.
//!
//! HTTP API (served over the Enclave TLS profile, `enclave-tls`):
//!
//! ```text
//! GET  /witness/v1/descriptor        the signed WitnessDescriptor
//! GET  /witness/v1/last/<server hex> the 64-byte head last cosigned for that log (404: none)
//! GET  /witness/v1/checkpoint/<server hex>
//!                                    that head as a C2SP checkpoint with this witness's
//!                                    cosignature/v1 line (text; `enclave_kt::c2sp`)
//! GET  /witness/v1/c2sp-key          the verifier keys of those notes, one per line
//!                                    (Ed25519 cosignature/v1, ML-DSA-44)
//! POST /witness/v1/cosign            CosignRequest → Cosignature
//!                                    (403 log not listed or bad signature,
//!                                     409 not append-only, 400 malformed)
//! POST /witness/v1/equivocation      Equivocation (two heads of a listed log, one epoch,
//!                                    two roots) → 201 new, 200 held; 403 unlisted or
//!                                    bad signature. The log is never cosigned again
//!                                    (cosign answers 410).
//! GET  /witness/v1/equivocation/<server hex>
//!                                    the proof held (404: none)
//! CosignRequest = u8(1) ‖ u32(n) ‖ n × (u32 len ‖ SignedHead) ‖ u8(has proof) [‖ u32 len ‖ AppendOnlyProof (akd protobuf)]
//! ```
//!
//! Servers reach witnesses with [`HttpWitness`], an
//! [`enclave_kt::WitnessClient`].
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod service;

pub use client::{HttpWitness, LazyWitness};
pub use service::WitnessService;

use akd::AppendOnlyProof;
use enclave_kt::{KtError, SignedHead};
use protobuf::Message;

/// Longest request accepted.
pub const MAX_REQUEST: usize = 8 << 20;
/// Most heads in one request.
pub const MAX_HEADS: usize = 4096;

/// A cosigning request.
pub struct CosignRequest {
    /// Consecutive heads, oldest first; the newest is cosigned.
    pub heads: Vec<SignedHead>,
    /// Append-only proof from the head the witness last cosigned.
    pub proof: Option<AppendOnlyProof>,
}

impl CosignRequest {
    /// Encode.
    pub fn encode(&self) -> Result<Vec<u8>, KtError> {
        let mut v = vec![1u8];
        v.extend_from_slice(&(self.heads.len() as u32).to_be_bytes());
        for h in &self.heads {
            let b = h.encode();
            v.extend_from_slice(&(b.len() as u32).to_be_bytes());
            v.extend_from_slice(&b);
        }
        match &self.proof {
            Some(p) => {
                let b = akd::proto::specs::types::AppendOnlyProof::from(p)
                    .write_to_bytes()
                    .map_err(|_| KtError::Malformed)?;
                v.push(1);
                v.extend_from_slice(&(b.len() as u32).to_be_bytes());
                v.extend_from_slice(&b);
            }
            None => v.push(0),
        }
        Ok(v)
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self, KtError> {
        let bad = || KtError::Malformed;
        let mut r = b;
        let mut take = |n: usize| -> Result<&[u8], KtError> {
            if r.len() < n {
                return Err(bad());
            }
            let (a, rest) = r.split_at(n);
            r = rest;
            Ok(a)
        };
        if take(1)?[0] != 1 {
            return Err(bad());
        }
        let u32_of = |s: &[u8]| -> Result<usize, KtError> {
            Ok(u32::from_be_bytes(s.try_into().map_err(|_| bad())?) as usize)
        };
        let n = u32_of(take(4)?)?;
        if n == 0 || n > MAX_HEADS {
            return Err(bad());
        }
        let mut heads = Vec::with_capacity(n);
        for _ in 0..n {
            let len = u32_of(take(4)?)?;
            heads.push(SignedHead::decode(take(len)?)?);
        }
        let proof = match take(1)?[0] {
            0 => None,
            1 => {
                let len = u32_of(take(4)?)?;
                let pb = akd::proto::specs::types::AppendOnlyProof::parse_from_bytes(take(len)?)
                    .map_err(|_| bad())?;
                Some(AppendOnlyProof::try_from(&pb).map_err(|_| bad())?)
            }
            _ => return Err(bad()),
        };
        if !r.is_empty() {
            return Err(bad());
        }
        Ok(Self { heads, proof })
    }
}

/// Hex encoding of a server id (URL path segment).
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
