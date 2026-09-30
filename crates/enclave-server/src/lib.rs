//! The Enclave server (`docs/12-servers.md`).
//!
//! A server is an untrusted mailbox. It holds opaque fixed-size envelopes,
//! prekey publications, encrypted blobs and a key-transparency log. It keeps no
//! accounts, no phone numbers and no IP addresses (in production it is reached
//! only through the mixnet), and it cannot tell who writes to whom:
//!
//! * writes to an inbox need a single-use token whose hash the owner
//!   registered; the server burns it and learns nothing else;
//! * reading needs a credential only the owner has;
//! * first contact goes to a separate request inbox and costs an Equi-X proof
//!   of work;
//! * every request and reply is sealed end to end to the server's daily
//!   X448 + ML-KEM-1024 key ([`enclave_rpc`]).
//!
//! [`Server::handle`] maps one sealed request to one sealed reply. It is
//! transport-agnostic: the dev binary serves it over TCP, `enclave-net`
//! serves it over Nym.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_crypto::hash::{sha3_512, shake256};
use enclave_crypto::rng::HedgedRng;
use enclave_proto::bundle::{Bundle, Publication};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_rpc::api::{
    self, DirAction, DirKind, DirReply, DirRequest, FLAG_CREATE, FLAG_FOUND, FLAG_MORE,
    FLAG_REQUEST_INBOX, Status,
};
use enclave_rpc::{ServerKey, ServerSecret};
use enclave_tokens::{PowProof, token_hash};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Server policy.
#[derive(Clone, Debug)]
pub struct Config {
    /// Server identifier.
    pub id: [u8; 16],
    /// Proof-of-work effort for request-inbox writes.
    pub effort_request: u32,
    /// Proof-of-work effort for claiming a bundle.
    pub effort_claim: u32,
    /// Proof-of-work effort for blob uploads.
    pub effort_blob: u32,
    /// Maximum stored envelopes per inbox.
    pub inbox_quota: usize,
    /// Maximum pending requests per request inbox.
    pub request_quota: usize,
    /// Maximum registered unspent tokens per inbox.
    pub token_quota: usize,
    /// Time-to-live for envelopes and blobs.
    pub ttl_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            id: [0; 16],
            effort_request: 64,
            effort_claim: 8,
            effort_blob: 1,
            inbox_quota: 5_000,
            request_quota: 100,
            token_quota: 4_096,
            ttl_secs: 30 * 24 * 3600,
        }
    }
}

struct Inbox {
    owner: [u8; 32],
    read: [u8; 32],
    request: bool,
    tokens: HashSet<[u8; 32]>,
    messages: BTreeMap<u64, (Vec<u8>, u64)>,
    next_seq: u64,
}

struct DeviceBundles {
    publication: Publication,
    next_opk: usize,
}

#[derive(Default)]
struct Upload {
    total: u32,
    chunks: BTreeMap<u32, Vec<u8>>,
}

/// Aggregate counters (no per-user data), for operators and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Requests handled.
    pub requests: u64,
    /// Cover requests dropped.
    pub cover: u64,
    /// Stored envelopes.
    pub stored: u64,
    /// Tokens burned.
    pub tokens_burned: u64,
    /// Denied requests.
    pub denied: u64,
}

/// An Enclave server.
pub struct Server {
    cfg: Config,
    keys: VecDeque<ServerSecret>,
    inboxes: HashMap<[u8; 32], Inbox>,
    manifests: HashMap<[u8; 32], (u64, Vec<u8>)>,
    bundles: HashMap<[u8; 16], DeviceBundles>,
    claims: HashMap<[u8; 32], (Vec<u8>, u64)>,
    vaults: HashMap<[u8; 32], ([u8; 32], Vec<u8>)>,
    blobs: HashMap<[u8; 32], (Vec<u8>, u64)>,
    uploads: HashMap<(u8, [u8; 32]), Upload>,
    stats: Stats,
    /// Every object ever stored, by length, for invariant checks in tests.
    stored_lengths: HashSet<usize>,
    rng: HedgedRng,
}

/// Directory key for a root public key.
pub fn manifest_key(root: &[u8; 64]) -> [u8; 32] {
    shake256(&[b"enclave/v1/dir/manifest".as_slice(), root].concat())
}

/// Directory key for a device.
pub fn device_key(device: &[u8; 16]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(device);
    k
}

impl Server {
    /// Create a server with today's request key.
    pub fn new(cfg: Config, day: u32) -> enclave_crypto::Result<Self> {
        let mut rng = HedgedRng::new()?;
        let mut keys = VecDeque::new();
        keys.push_front(
            ServerSecret::generate(day, &mut rng).map_err(|_| enclave_crypto::Error::Rng)?,
        );
        Ok(Self {
            cfg,
            keys,
            inboxes: HashMap::new(),
            manifests: HashMap::new(),
            bundles: HashMap::new(),
            claims: HashMap::new(),
            vaults: HashMap::new(),
            blobs: HashMap::new(),
            uploads: HashMap::new(),
            stats: Stats::default(),
            stored_lengths: HashSet::new(),
            rng,
        })
    }

    /// Current public request key (published in the server descriptor).
    pub fn public_key(&self) -> Option<ServerKey> {
        self.keys.front().map(|k| k.public().clone())
    }

    /// Rotate to a new daily key; keep yesterday's for late requests and delete
    /// anything older (forward secrecy for request metadata).
    pub fn rotate(&mut self, day: u32) -> enclave_crypto::Result<()> {
        let k =
            ServerSecret::generate(day, &mut self.rng).map_err(|_| enclave_crypto::Error::Rng)?;
        self.keys.push_front(k);
        while self.keys.len() > 2 {
            self.keys.pop_back();
        }
        Ok(())
    }

    /// Counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Lengths of every envelope and blob chunk ever stored.
    pub fn stored_lengths(&self) -> &HashSet<usize> {
        &self.stored_lengths
    }

    /// Delete expired envelopes, blobs and claims.
    pub fn expire(&mut self, now: u64) {
        let ttl = self.cfg.ttl_secs;
        for ib in self.inboxes.values_mut() {
            ib.messages.retain(|_, (_, t)| now <= *t + ttl);
        }
        self.blobs.retain(|_, (_, t)| now <= *t + ttl);
        self.claims.retain(|_, (_, t)| now <= *t + 600);
    }

    /// Handle one sealed request (unit or poll) and return the sealed reply.
    /// Undecryptable input gets a random reply of the same size, so the
    /// network cannot tell rejected requests from accepted ones.
    pub fn handle(&mut self, request: &[u8], now: u64) -> Vec<u8> {
        self.stats.requests += 1;
        let keys: Vec<&ServerSecret> = self.keys.iter().collect();
        let opened = match enclave_rpc::open_request(&keys, request) {
            Ok(o) => o,
            Err(_) => {
                let mut r = vec![0u8; enclave_wire::UNIT_LEN];
                if self.rng.fill("server/garbage-reply", &mut r).is_err() {
                    r.fill(0);
                }
                return r;
            }
        };
        let (status, extra_flags, reply_token, payload) =
            self.dispatch(&opened.header, &opened.envelope, now);
        if status == Status::Denied {
            self.stats.denied += 1;
        }
        let reply_header = RequestHeader {
            op: opened.header.op,
            flags: status as u8 | extra_flags,
            mailbox: opened.header.mailbox,
            token: reply_token,
        };
        let envelope = match payload {
            Reply::Envelope(e) => e,
            Reply::Payload(p) => {
                api::frame(&p, &mut self.rng).unwrap_or_else(|_| vec![0u8; ENVELOPE_LEN])
            }
            Reply::Empty => {
                api::frame(&[], &mut self.rng).unwrap_or_else(|_| vec![0u8; ENVELOPE_LEN])
            }
        };
        opened
            .exchange
            .seal_reply(&reply_header, &envelope, &mut self.rng)
            .unwrap_or_else(|_| vec![0u8; enclave_wire::UNIT_LEN])
    }

    fn dispatch(
        &mut self,
        h: &RequestHeader,
        env: &[u8],
        now: u64,
    ) -> (Status, u8, [u8; 32], Reply) {
        let none = [0u8; 32];
        match h.op {
            Op::Cover => {
                self.stats.cover += 1;
                (Status::Ok, 0, none, Reply::Empty)
            }
            Op::RegisterTokens => (self.register_tokens(h, env), 0, none, Reply::Empty),
            Op::Write => (self.write(h, env, now), 0, none, Reply::Empty),
            Op::WriteRequest => (self.write_request(h, env, now), 0, none, Reply::Empty),
            Op::Poll => self.poll(h),
            Op::Ack => (self.ack(h), 0, none, Reply::Empty),
            Op::BlobPut => (self.blob_put(h, env, now), 0, none, Reply::Empty),
            Op::BlobGet => match self.blobs.get(&h.mailbox) {
                Some((b, _)) => (Status::Ok, 0, none, Reply::Envelope(b.clone())),
                None => (Status::NotFound, 0, none, Reply::Empty),
            },
            Op::Directory => match api::unframe(env).and_then(DirRequest::decode) {
                Ok(req) => {
                    let (s, p) = self.directory(req, now);
                    (s, 0, none, p)
                }
                Err(_) => (Status::Malformed, 0, none, Reply::Empty),
            },
            Op::KeyTransparency => (Status::NotFound, 0, none, Reply::Empty),
        }
    }

    fn register_tokens(&mut self, h: &RequestHeader, env: &[u8]) -> Status {
        let owner_hash = api::credential_hash(&h.token);
        if h.flags & FLAG_CREATE != 0 {
            if self.inboxes.contains_key(&h.mailbox) {
                return Status::Denied;
            }
            let mut owner = [0u8; 32];
            owner.copy_from_slice(&h.token);
            let read = api::credential_hash(&api::read_credential(&owner));
            self.inboxes.insert(
                h.mailbox,
                Inbox {
                    owner: owner_hash,
                    read,
                    request: h.flags & FLAG_REQUEST_INBOX != 0,
                    tokens: HashSet::new(),
                    messages: BTreeMap::new(),
                    next_seq: 1,
                },
            );
            return Status::Ok;
        }
        let Some(ib) = self.inboxes.get_mut(&h.mailbox) else {
            return Status::NotFound;
        };
        if ib.owner != owner_hash {
            return Status::Denied;
        }
        let Ok(p) = api::unframe(env) else {
            return Status::Malformed;
        };
        if p.len() % 32 != 0 {
            return Status::Malformed;
        }
        if ib.tokens.len() + p.len() / 32 > self.cfg.token_quota {
            return Status::Quota;
        }
        for c in p.chunks_exact(32) {
            let mut t = [0u8; 32];
            t.copy_from_slice(c);
            ib.tokens.insert(t);
        }
        Status::Ok
    }

    fn store(&mut self, mailbox: &[u8; 32], env: &[u8], now: u64) -> Status {
        let quota = self.cfg.inbox_quota;
        let Some(ib) = self.inboxes.get_mut(mailbox) else {
            return Status::NotFound;
        };
        if ib.messages.len() >= quota {
            if ib.request {
                // Request inboxes drop their oldest pending request.
                if let Some(k) = ib.messages.keys().next().copied() {
                    ib.messages.remove(&k);
                }
            } else {
                return Status::Quota;
            }
        }
        let seq = ib.next_seq;
        ib.next_seq += 1;
        ib.messages.insert(seq, (env.to_vec(), now));
        self.stats.stored += 1;
        self.stored_lengths.insert(env.len());
        Status::Ok
    }

    fn write(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let Some(ib) = self.inboxes.get_mut(&h.mailbox) else {
            return Status::NotFound;
        };
        if ib.request {
            return Status::Denied;
        }
        let th = token_hash(&h.token);
        if !ib.tokens.remove(&th) {
            return Status::Denied;
        }
        self.stats.tokens_burned += 1;
        self.store(&h.mailbox, env, now)
    }

    fn write_request(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let Some(ib) = self.inboxes.get(&h.mailbox) else {
            return Status::NotFound;
        };
        if !ib.request {
            return Status::Denied;
        }
        let ctx = api::pow_context_request(&h.mailbox, &sha3_512(env));
        if !enclave_tokens::verify(&ctx, self.cfg.effort_request, &PowProof(h.token)) {
            return Status::Pow;
        }
        let q = self.cfg.request_quota;
        let saved = self.cfg.inbox_quota;
        self.cfg.inbox_quota = q;
        let s = self.store(&h.mailbox, env, now);
        self.cfg.inbox_quota = saved;
        s
    }

    fn check_read(&self, h: &RequestHeader) -> Option<&Inbox> {
        let ib = self.inboxes.get(&h.mailbox)?;
        (api::credential_hash(&h.token[..24]) == ib.read).then_some(ib)
    }

    fn poll(&mut self, h: &RequestHeader) -> (Status, u8, [u8; 32], Reply) {
        let none = [0u8; 32];
        let Some(ib) = self.check_read(h) else {
            return (Status::Denied, 0, none, Reply::Empty);
        };
        let mut cursor = [0u8; 8];
        cursor.copy_from_slice(&h.token[24..]);
        let cursor = u64::from_be_bytes(cursor);
        let mut it = ib.messages.range(cursor + 1..);
        match it.next() {
            Some((seq, (env, _))) => {
                let more = if it.next().is_some() { FLAG_MORE } else { 0 };
                let mut tok = [0u8; 32];
                tok[24..].copy_from_slice(&seq.to_be_bytes());
                (
                    Status::Ok,
                    FLAG_FOUND | more,
                    tok,
                    Reply::Envelope(env.clone()),
                )
            }
            None => (Status::Ok, 0, none, Reply::Empty),
        }
    }

    fn ack(&mut self, h: &RequestHeader) -> Status {
        if self.check_read(h).is_none() {
            return Status::Denied;
        }
        let mut w = [0u8; 8];
        w.copy_from_slice(&h.token[24..]);
        let watermark = u64::from_be_bytes(w);
        if let Some(ib) = self.inboxes.get_mut(&h.mailbox) {
            ib.messages.retain(|seq, _| *seq > watermark);
        }
        Status::Ok
    }

    fn blob_put(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        if self.blobs.contains_key(&h.mailbox) {
            return Status::Denied;
        }
        let ctx = api::pow_context_blob(&h.mailbox, &sha3_512(env));
        if !enclave_tokens::verify(&ctx, self.cfg.effort_blob, &PowProof(h.token)) {
            return Status::Pow;
        }
        self.stored_lengths.insert(env.len());
        self.blobs.insert(h.mailbox, (env.to_vec(), now));
        Status::Ok
    }

    fn directory(&mut self, req: DirRequest, now: u64) -> (Status, Reply) {
        match (req.kind, req.action) {
            (_, DirAction::Put) => self.dir_put(req, now),
            (DirKind::Manifest, DirAction::Get) => match self.manifests.get(&req.key) {
                Some((_, bytes)) => Self::chunk_reply(bytes, req.index, [0; 32]),
                None => (Status::NotFound, Reply::Empty),
            },
            (DirKind::Vault, DirAction::Get) => match self.vaults.get(&req.key) {
                Some((_, bytes)) => Self::chunk_reply(bytes, req.index, [0; 32]),
                None => (Status::NotFound, Reply::Empty),
            },
            (DirKind::Bundle, DirAction::Claim) => self.claim_bundle(&req, now),
            (DirKind::Bundle, DirAction::Get) => match self.claims.get(&req.key) {
                Some((bytes, _)) => Self::chunk_reply(bytes, req.index, req.key),
                None => (Status::NotFound, Reply::Empty),
            },
            _ => (Status::Malformed, Reply::Empty),
        }
    }

    fn chunk_reply(bytes: &[u8], index: u32, claim: [u8; 32]) -> (Status, Reply) {
        let chunks = api::chunks(bytes);
        match chunks.get(index as usize) {
            Some(c) => (
                Status::Ok,
                Reply::Payload(
                    DirReply {
                        total: chunks.len() as u32,
                        claim,
                        data: c.to_vec(),
                    }
                    .encode(),
                ),
            ),
            None => (Status::NotFound, Reply::Empty),
        }
    }

    fn claim_bundle(&mut self, req: &DirRequest, now: u64) -> (Status, Reply) {
        let day = now / 86_400;
        let ctx = api::pow_context_claim(&req.key, day);
        if !enclave_tokens::verify(&ctx, self.cfg.effort_claim, &PowProof(req.proof)) {
            return (Status::Pow, Reply::Empty);
        }
        let mut device = [0u8; 16];
        device.copy_from_slice(&req.key[..16]);
        let Some(db) = self.bundles.get_mut(&device) else {
            return (Status::NotFound, Reply::Empty);
        };
        let p = &db.publication;
        let opk = if db.next_opk < p.opks.len() {
            let o = p.opks[db.next_opk].clone();
            db.next_opk += 1;
            Some((p.batch.clone(), o))
        } else {
            None
        };
        let bundle = Bundle {
            spk: p.spk.clone(),
            opk,
            last_resort: p.last_resort.clone(),
        };
        let bytes = bundle.encode();
        let claim: [u8; 32] = match self.rng.array("server/claim-id") {
            Ok(c) => c,
            Err(_) => return (Status::Malformed, Reply::Empty),
        };
        self.claims.insert(claim, (bytes.clone(), now));
        Self::chunk_reply(&bytes, 0, claim)
    }

    fn dir_put(&mut self, req: DirRequest, now: u64) -> (Status, Reply) {
        if req.total == 0 || req.total > 200 || req.index >= req.total {
            return (Status::Malformed, Reply::Empty);
        }
        let slot = (req.kind as u8, req.key);
        let up = self.uploads.entry(slot).or_default();
        if up.total != 0 && up.total != req.total {
            self.uploads.remove(&slot);
            return (Status::Malformed, Reply::Empty);
        }
        up.total = req.total;
        up.chunks.insert(req.index, req.data);
        if up.chunks.len() < up.total as usize {
            return (Status::Ok, Reply::Empty);
        }
        let Some(up) = self.uploads.remove(&slot) else {
            return (Status::Malformed, Reply::Empty);
        };
        let object: Vec<u8> = up.chunks.into_values().flatten().collect();
        let status = match req.kind {
            DirKind::Manifest => self.accept_manifest(&req.key, object, now),
            DirKind::Bundle => self.accept_publication(&req.key, object, now),
            DirKind::Vault => self.accept_vault(&req.key, &req.proof, object),
        };
        (status, Reply::Empty)
    }

    fn accept_manifest(&mut self, key: &[u8; 32], bytes: Vec<u8>, now: u64) -> Status {
        let Ok(sm) = SignedManifest::from_bytes(&bytes) else {
            return Status::Malformed;
        };
        let Ok(m) = Manifest::decode(&sm.body) else {
            return Status::Malformed;
        };
        if &manifest_key(&m.root.0) != key {
            return Status::Invalid;
        }
        if sm.verify(&m.root, now).is_err() {
            return Status::Invalid;
        }
        if let Some((v, _)) = self.manifests.get(key)
            && m.version <= *v
        {
            return Status::Invalid;
        }
        self.manifests.insert(*key, (m.version, bytes));
        Status::Ok
    }

    fn accept_publication(&mut self, key: &[u8; 32], bytes: Vec<u8>, now: u64) -> Status {
        let Ok(p) = Publication::decode(&bytes) else {
            return Status::Malformed;
        };
        // The device must appear in a stored manifest, and sign the publication.
        let device = p.spk.device;
        if device_key(&device) != *key {
            return Status::Invalid;
        }
        let signer = self.manifests.values().find_map(|(_, mb)| {
            let sm = SignedManifest::from_bytes(mb).ok()?;
            let m = Manifest::decode(&sm.body).ok()?;
            m.device(&device).map(|d| d.signing.clone())
        });
        let Some(signer) = signer else {
            return Status::NotFound;
        };
        if p.verify(&signer, now).is_err() {
            return Status::Invalid;
        }
        self.bundles.insert(
            device,
            DeviceBundles {
                publication: p,
                next_opk: 0,
            },
        );
        Status::Ok
    }

    fn accept_vault(&mut self, key: &[u8; 32], owner_secret: &[u8; 32], bytes: Vec<u8>) -> Status {
        let owner = api::credential_hash(owner_secret);
        if let Some((o, _)) = self.vaults.get(key)
            && *o != owner
        {
            return Status::Denied;
        }
        self.vaults.insert(*key, (owner, bytes));
        Status::Ok
    }
}

enum Reply {
    Envelope(Vec<u8>),
    Payload(Vec<u8>),
    Empty,
}
