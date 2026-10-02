//! Wire formats for usernames: the server's published KT parameters, signed
//! username claims, and lookup replies (signed head plus an akd lookup proof in
//! akd's protobuf encoding).

use crate::head::{Cursor, SignedHead, WitnessPolicy, arr};
use crate::{KtError, Result};
use akd::LookupProof;
use enclave_crypto::sig::CompositePublic;
use protobuf::Message;

/// Context for a device's signature on a username claim.
pub const CTX_CLAIM: &[u8] = b"enclave/v1/kt/claim";
/// Largest KT value (root key plus a contact card).
pub const MAX_VALUE: usize = 2048;
/// Largest lookup proof accepted.
pub const MAX_PROOF: usize = 64 * 1024;
/// Length of an account root key, which starts every value.
pub const ROOT_LEN: usize = 64;

/// What a client pins for a server's log. Shipped with the app's server list
/// (or the server's descriptor), never learned from the server at lookup time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KtInfo {
    /// Server identifier.
    pub server: [u8; 16],
    /// Domain in `@name@domain` addresses.
    pub domain: String,
    /// Operator (witnesses run by the same operator don't count).
    pub operator: String,
    /// Head-signing key.
    pub head_key: CompositePublic,
    /// akd VRF public key.
    pub vrf_public: Vec<u8>,
}

impl KtInfo {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.server.to_vec();
        for f in [
            self.domain.as_bytes(),
            self.operator.as_bytes(),
            &self.head_key.to_bytes(),
            &self.vrf_public,
        ] {
            v.extend_from_slice(&(f.len() as u32).to_be_bytes());
            v.extend_from_slice(f);
        }
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Cursor(b);
        let server = arr(r.take(16)?)?;
        let text = |r: &mut Cursor<'_>| -> Result<String> {
            String::from_utf8(r.bytes(253)?.to_vec()).map_err(|_| KtError::Malformed)
        };
        let domain = text(&mut r)?;
        let operator = text(&mut r)?;
        let head_key =
            CompositePublic::from_slice(r.bytes(8192)?).map_err(|_| KtError::Malformed)?;
        let vrf_public = r.bytes(64)?.to_vec();
        if !r.0.is_empty() {
            return Err(KtError::Malformed);
        }
        Ok(Self {
            server,
            domain,
            operator,
            head_key,
            vrf_public,
        })
    }
}

/// A signed request to bind `name` to `value` on one server. `value` starts
/// with the account's 64-byte root key; the server checks `signature` against
/// a device in the root-signed manifest it holds for that root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsernameClaim {
    /// Requested name (normalized by the server).
    pub name: String,
    /// `root(64) ‖ payload` (the payload is a contact card).
    pub value: Vec<u8>,
    /// Signing device.
    pub device: [u8; 16],
    /// Claim time; the server refuses claims far from its clock or older than
    /// the last accepted claim for the name.
    pub time: u64,
    /// Composite signature over [`UsernameClaim::message`].
    pub signature: Vec<u8>,
}

impl UsernameClaim {
    /// The signed message, bound to the server.
    pub fn message(server: &[u8; 16], name: &str, value: &[u8], time: u64) -> Vec<u8> {
        let mut m = server.to_vec();
        m.extend_from_slice(&(name.len() as u32).to_be_bytes());
        m.extend_from_slice(name.as_bytes());
        m.extend_from_slice(&(value.len() as u32).to_be_bytes());
        m.extend_from_slice(value);
        m.extend_from_slice(&time.to_be_bytes());
        m
    }

    /// The account root the value names.
    pub fn root(&self) -> Option<[u8; ROOT_LEN]> {
        self.value.get(..ROOT_LEN)?.try_into().ok()
    }

    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for f in [self.name.as_bytes(), &self.value, &self.signature] {
            v.extend_from_slice(&(f.len() as u32).to_be_bytes());
            v.extend_from_slice(f);
        }
        v.extend_from_slice(&self.device);
        v.extend_from_slice(&self.time.to_be_bytes());
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Cursor(b);
        let name = String::from_utf8(r.bytes(64)?.to_vec()).map_err(|_| KtError::Malformed)?;
        let value = r.bytes(MAX_VALUE)?.to_vec();
        let signature = r.bytes(8192)?.to_vec();
        let device = arr(r.take(16)?)?;
        let time = u64::from_be_bytes(arr(r.take(8)?)?);
        if !r.0.is_empty() || value.len() < ROOT_LEN {
            return Err(KtError::Malformed);
        }
        Ok(Self {
            name,
            value,
            device,
            time,
            signature,
        })
    }
}

/// A lookup reply: the signed head and a proof against its root.
#[derive(Clone, Debug)]
pub struct LookupReply {
    /// Head the proof is against, with witness cosignatures.
    pub head: SignedHead,
    /// akd lookup proof.
    pub proof: LookupProof,
}

impl LookupReply {
    /// Encode: `u32 len ‖ head ‖ u32 len ‖ proof (akd protobuf)`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let head = self.head.encode();
        let proof = akd::proto::specs::types::LookupProof::from(&self.proof)
            .write_to_bytes()
            .map_err(|_| KtError::Malformed)?;
        let mut v = Vec::with_capacity(8 + head.len() + proof.len());
        v.extend_from_slice(&(head.len() as u32).to_be_bytes());
        v.extend_from_slice(&head);
        v.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        v.extend_from_slice(&proof);
        Ok(v)
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Cursor(b);
        let head = SignedHead::decode(r.bytes(64 * 1024)?)?;
        let pb = akd::proto::specs::types::LookupProof::parse_from_bytes(r.bytes(MAX_PROOF)?)
            .map_err(|_| KtError::Malformed)?;
        let proof = LookupProof::try_from(&pb).map_err(|_| KtError::Malformed)?;
        if !r.0.is_empty() {
            return Err(KtError::Malformed);
        }
        Ok(Self { head, proof })
    }
}

/// Everything a client pins for usernames: each server's log parameters and
/// the witnesses whose cosignatures count. Ships with the app's server list.
#[derive(Clone)]
pub struct KtPolicy {
    /// Pinned logs.
    pub servers: Vec<KtInfo>,
    /// Pinned witnesses and quorum.
    pub witnesses: WitnessPolicy,
}

impl KtPolicy {
    /// The pins for every listed server that runs a log, with the listed
    /// witnesses and threshold (`12-servers.md` §4.1). Witness ids are
    /// derived from their keys.
    pub fn from_server_list(list: &enclave_federation::ServerList) -> Self {
        Self {
            servers: list
                .servers
                .iter()
                .filter_map(|s| {
                    s.kt.as_ref().map(|k| KtInfo {
                        server: s.id(),
                        domain: s.domain.clone(),
                        operator: s.operator.clone(),
                        head_key: k.head_key.clone(),
                        vrf_public: k.vrf_public.clone(),
                    })
                })
                .collect(),
            witnesses: crate::WitnessPolicy {
                witnesses: list
                    .witnesses
                    .iter()
                    .map(|w| (w.id(), w.key.clone(), w.operator.clone()))
                    .collect(),
                threshold: usize::from(list.witness_threshold.max(1)),
            },
        }
    }

    /// The pinned log for `domain`.
    pub fn by_domain(&self, domain: &str) -> Option<&KtInfo> {
        self.servers
            .iter()
            .find(|s| s.domain.eq_ignore_ascii_case(domain))
    }

    /// The pinned log for a server id.
    pub fn by_server(&self, server: &[u8; 16]) -> Option<&KtInfo> {
        self.servers.iter().find(|s| &s.server == server)
    }

    /// Add another policy's logs and witnesses (the quorum is the larger).
    pub fn merge(&mut self, other: KtPolicy) {
        for s in other.servers {
            if self.by_server(&s.server).is_none() {
                self.servers.push(s);
            }
        }
        for w in other.witnesses.witnesses {
            if !self.witnesses.witnesses.iter().any(|x| x.0 == w.0) {
                self.witnesses.witnesses.push(w);
            }
        }
        self.witnesses.threshold = self.witnesses.threshold.max(other.witnesses.threshold);
    }

    /// Encode (for a pin file).
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![1, self.witnesses.threshold.min(255) as u8];
        v.extend_from_slice(&(self.servers.len() as u32).to_be_bytes());
        for s in &self.servers {
            let b = s.encode();
            v.extend_from_slice(&(b.len() as u32).to_be_bytes());
            v.extend_from_slice(&b);
        }
        v.extend_from_slice(&(self.witnesses.witnesses.len() as u32).to_be_bytes());
        for (id, key, op) in &self.witnesses.witnesses {
            v.extend_from_slice(id);
            for f in [&key.to_bytes()[..], op.as_bytes()] {
                v.extend_from_slice(&(f.len() as u32).to_be_bytes());
                v.extend_from_slice(f);
            }
        }
        v
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Cursor(b);
        let h = r.take(2)?;
        if h[0] != 1 {
            return Err(KtError::Malformed);
        }
        let threshold = h[1] as usize;
        let n = u32::from_be_bytes(arr(r.take(4)?)?) as usize;
        if n > 1024 {
            return Err(KtError::Malformed);
        }
        let servers = (0..n)
            .map(|_| KtInfo::decode(r.bytes(16 * 1024)?))
            .collect::<Result<Vec<_>>>()?;
        let n = u32::from_be_bytes(arr(r.take(4)?)?) as usize;
        if n > 1024 {
            return Err(KtError::Malformed);
        }
        let mut witnesses = Vec::with_capacity(n);
        for _ in 0..n {
            let id = arr(r.take(16)?)?;
            let key =
                CompositePublic::from_slice(r.bytes(8192)?).map_err(|_| KtError::Malformed)?;
            let op = String::from_utf8(r.bytes(253)?.to_vec()).map_err(|_| KtError::Malformed)?;
            witnesses.push((id, key, op));
        }
        if !r.0.is_empty() {
            return Err(KtError::Malformed);
        }
        Ok(Self {
            servers,
            witnesses: WitnessPolicy {
                witnesses,
                threshold,
            },
        })
    }
}
