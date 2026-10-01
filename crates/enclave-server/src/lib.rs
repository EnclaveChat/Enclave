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

use enclave_crypto::hash::sha3_512;
use enclave_crypto::rng::HedgedRng;
use enclave_kt::{KtInfo, KtService, UsernameClaim};
use enclave_proto::bundle::{Bundle, Publication};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_rpc::api::{
    self, DirAction, DirKind, DirReply, DirRequest, FLAG_CREATE, FLAG_FOUND, FLAG_GROUP,
    FLAG_INVITE, FLAG_MORE, FLAG_REQUEST_INBOX, FLAG_REVOKE, Status,
};
use enclave_rpc::{ServerKey, ServerSecret};
use enclave_tokens::{PowProof, token_hash};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Width of a push window.
pub const PUSH_WINDOW_SECS: u64 = 60;
/// Latest offset of a wake into its window.
pub const PUSH_JITTER_SECS: u64 = 30;
/// Largest sealed push token accepted.
const MAX_PUSH_TOKEN: usize = 4096;

/// A scheduled wake.
struct Wake {
    window: u64,
    release: u64,
    sealed: Vec<u8>,
    sent: bool,
}

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
    /// Proof-of-work effort for claiming a username.
    pub effort_username: u32,
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
            effort_username: 64,
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
    group: bool,
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
    /// Every device an account's manifests have listed. Attestations must
    /// come from one of them.
    devices_seen: HashMap<[u8; 32], Vec<SeenDevice>>,
    /// Device attestations per manifest key, newest last.
    attestations: HashMap<[u8; 32], Vec<Vec<u8>>>,
    bundles: HashMap<[u8; 16], DeviceBundles>,
    claims: HashMap<[u8; 32], (Vec<u8>, u64)>,
    vaults: HashMap<[u8; 32], ([u8; 32], Vec<u8>)>,
    blobs: HashMap<[u8; 32], (Vec<u8>, u64)>,
    uploads: HashMap<(u8, [u8; 32]), Upload>,
    kt: Option<KtService>,
    /// Sealed push tokens by inbox (`docs/10-push.md`).
    push: HashMap<[u8; 32], Vec<u8>>,
    /// Scheduled wakes by sealed-token hash.
    wakes: HashMap<[u8; 32], Wake>,
    /// A second log shown instead of `kt` (test hook, RT-04).
    #[cfg(feature = "test-hooks")]
    kt_fork: Option<KtService>,
    #[cfg(feature = "test-hooks")]
    kt_serve_fork: bool,
    /// name → (owning root, time of the last accepted claim)
    usernames: HashMap<String, ([u8; 64], u64)>,
    /// root → its current name
    names_by_root: HashMap<[u8; 64], String>,
    /// Chunked lookup replies by reply id.
    kt_replies: HashMap<[u8; 32], (Vec<u8>, u64)>,
    stats: Stats,
    /// User reports for the operator, oldest first (`docs/13-operators.md`).
    reports: VecDeque<Report>,
    /// Every object ever stored, by length, for invariant checks in tests.
    stored_lengths: HashSet<usize>,
    rng: HedgedRng,
}

pub use enclave_rpc::api::{device_key, manifest_key};

/// Most reports kept for the operator; older ones are dropped.
pub const MAX_REPORTS: usize = 1000;

/// A user report as the operator sees it: the reported account's request
/// inbox, the day it arrived, and what the reporter chose to include.
/// Nothing names the reporter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The reported account's request inbox (from its contact card).
    pub request_inbox: [u8; 32],
    /// Day it arrived (Unix days).
    pub day: u64,
    /// Reason and quotes.
    pub body: api::ReportBody,
}

/// A device some manifest of an account listed.
struct SeenDevice {
    root: [u8; 64],
    id: [u8; 16],
    key: enclave_crypto::sig::CompositePublic,
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
            devices_seen: HashMap::new(),
            attestations: HashMap::new(),
            bundles: HashMap::new(),
            claims: HashMap::new(),
            vaults: HashMap::new(),
            blobs: HashMap::new(),
            uploads: HashMap::new(),
            kt: None,
            push: HashMap::new(),
            wakes: HashMap::new(),
            #[cfg(feature = "test-hooks")]
            kt_fork: None,
            #[cfg(feature = "test-hooks")]
            kt_serve_fork: false,
            usernames: HashMap::new(),
            names_by_root: HashMap::new(),
            kt_replies: HashMap::new(),
            stats: Stats::default(),
            reports: VecDeque::new(),
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
        self.kt_replies.retain(|_, (_, t)| now <= *t + 600);
    }

    /// Attach a key-transparency log, enabling usernames.
    pub fn enable_kt(&mut self, kt: KtService) {
        self.kt = Some(kt);
    }

    /// **Test hook**: a second log (`KtService::start_dev_twins`) this
    /// server can show instead of its real one, as an equivocating server
    /// would.
    #[cfg(feature = "test-hooks")]
    pub fn enable_kt_fork(&mut self, fork: KtService) {
        self.kt_fork = Some(fork);
    }

    /// **Test hook**: bind a name in the fork only.
    #[cfg(feature = "test-hooks")]
    pub fn kt_fork_force(&mut self, name: &str, value: Vec<u8>, now: u64) -> bool {
        self.kt_fork
            .as_ref()
            .is_some_and(|k| k.publish(name, value, now).is_ok())
    }

    /// **Test hook**: answer lookups from the fork (true) or the real log.
    #[cfg(feature = "test-hooks")]
    pub fn kt_serve_fork(&mut self, on: bool) {
        self.kt_serve_fork = on;
    }

    /// The log lookups are answered from.
    fn kt_lookups(&self) -> Option<&KtService> {
        #[cfg(feature = "test-hooks")]
        if self.kt_serve_fork {
            return self.kt_fork.as_ref();
        }
        self.kt.as_ref()
    }

    /// **Tests only**: bind `name` to `value` in the log without any of the
    /// checks, as a dishonest operator could. Returns whether it published.
    #[cfg(feature = "test-hooks")]
    pub fn kt_force(&mut self, name: &str, value: Vec<u8>, now: u64) -> bool {
        self.kt
            .as_ref()
            .is_some_and(|k| k.publish(name, value, now).is_ok())
    }

    /// What clients pin for this server's log, if usernames are enabled.
    pub fn kt_info(&self) -> Option<KtInfo> {
        self.kt.as_ref().map(|k| k.info().clone())
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
            Op::PushRegister => (self.push_register(h, env), 0, none, Reply::Empty),
            Op::Report => (self.report(h, env, now), 0, none, Reply::Empty),
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
                    group: false,
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
        if h.flags & FLAG_REVOKE != 0 {
            for c in p.chunks_exact(32) {
                let mut t = [0u8; 32];
                t.copy_from_slice(c);
                ib.tokens.remove(&t);
            }
            return Status::Ok;
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

    /// Set or clear the sealed push token of an inbox (its owner only).
    /// The server can't open it: only the push relay can.
    fn push_register(&mut self, h: &RequestHeader, env: &[u8]) -> Status {
        let Some(ib) = self.inboxes.get(&h.mailbox) else {
            return Status::NotFound;
        };
        if ib.owner != api::credential_hash(&h.token) || ib.group {
            return Status::Denied;
        }
        let Ok(sealed) = api::unframe(env) else {
            return Status::Malformed;
        };
        if sealed.is_empty() {
            self.push.remove(&h.mailbox);
        } else if sealed.len() > MAX_PUSH_TOKEN {
            return Status::Malformed;
        } else {
            self.push.insert(h.mailbox, sealed.to_vec());
        }
        Status::Ok
    }

    /// A write reached `mailbox`: schedule its wake, at most one per sealed
    /// token per window. The wake goes out in the *next* 60 s window at a
    /// random 0–30 s offset, so its time says little about the write's.
    fn schedule_wake(&mut self, mailbox: &[u8; 32], now: u64) {
        let Some(sealed) = self.push.get(mailbox) else {
            return;
        };
        let id = sha3_512(sealed);
        let mut key = [0u8; 32];
        key.copy_from_slice(&id[..32]);
        let window = now / PUSH_WINDOW_SECS + 1;
        if self.wakes.get(&key).is_some_and(|w| w.window >= window) {
            return;
        }
        let jitter = self
            .rng
            .array::<1>("server/push-jitter")
            .map(|b| u64::from(b[0]) % (PUSH_JITTER_SECS + 1))
            .unwrap_or(0);
        self.wakes.insert(
            key,
            Wake {
                window,
                release: window * PUSH_WINDOW_SECS + jitter,
                sealed: sealed.clone(),
                sent: false,
            },
        );
    }

    /// Sealed tokens whose wake is due, for the push relay. Each is
    /// returned once.
    pub fn due_wakes(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for w in self.wakes.values_mut() {
            if !w.sent && w.release <= now {
                w.sent = true;
                out.push(w.sealed.clone());
            }
        }
        self.wakes
            .retain(|_, w| !w.sent || w.window * PUSH_WINDOW_SECS + 2 * PUSH_WINDOW_SECS > now);
        out
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
        self.schedule_wake(mailbox, now);
        Status::Ok
    }

    fn write(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        if h.flags & FLAG_GROUP != 0 {
            return self.write_group(h, env, now);
        }
        let Some(ib) = self.inboxes.get_mut(&h.mailbox) else {
            return Status::NotFound;
        };
        if ib.request || ib.group {
            return Status::Denied;
        }
        let th = token_hash(&h.token);
        if !ib.tokens.remove(&th) {
            return Status::Denied;
        }
        self.stats.tokens_burned += 1;
        self.store(&h.mailbox, env, now)
    }

    fn write_group(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let owner_hash = api::credential_hash(&h.token);
        match self.inboxes.get(&h.mailbox) {
            None => {
                let read = api::credential_hash(&api::read_credential(&h.token));
                self.inboxes.insert(
                    h.mailbox,
                    Inbox {
                        owner: owner_hash,
                        read,
                        request: false,
                        group: true,
                        tokens: HashSet::new(),
                        messages: BTreeMap::new(),
                        next_seq: 1,
                    },
                );
            }
            Some(ib) if ib.group && ib.owner == owner_hash => {}
            Some(_) => return Status::Denied,
        }
        self.store(&h.mailbox, env, now)
    }

    fn write_request(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        let Some(ib) = self.inboxes.get_mut(&h.mailbox) else {
            return Status::NotFound;
        };
        if !ib.request {
            return Status::Denied;
        }
        if h.flags & FLAG_INVITE != 0 {
            // An invite capability stands in for the proof of work.
            if !ib.tokens.remove(&token_hash(&h.token)) {
                return Status::Denied;
            }
            self.stats.tokens_burned += 1;
        } else {
            let ctx = api::pow_context_request(&h.mailbox, &sha3_512(env));
            if !enclave_tokens::verify(&ctx, self.cfg.effort_request, &PowProof(h.token)) {
                return Status::Pow;
            }
        }
        let q = self.cfg.request_quota;
        let saved = self.cfg.inbox_quota;
        self.cfg.inbox_quota = q;
        let s = self.store(&h.mailbox, env, now);
        self.cfg.inbox_quota = saved;
        s
    }

    /// A user report about the account whose request inbox is `h.mailbox`
    /// (it must be one of ours). Costs a proof of work; the queue keeps the
    /// newest [`MAX_REPORTS`].
    fn report(&mut self, h: &RequestHeader, env: &[u8], now: u64) -> Status {
        if !self.inboxes.get(&h.mailbox).is_some_and(|ib| ib.request) {
            return Status::NotFound;
        }
        let ctx = api::pow_context_report(&h.mailbox, &sha3_512(env));
        if !enclave_tokens::verify(&ctx, self.cfg.effort_request, &PowProof(h.token)) {
            return Status::Pow;
        }
        let Ok(body) = api::unframe(env).and_then(api::ReportBody::decode) else {
            return Status::Malformed;
        };
        if self.reports.len() >= MAX_REPORTS {
            self.reports.pop_front();
        }
        self.reports.push_back(Report {
            request_inbox: h.mailbox,
            day: now / 86_400,
            body,
        });
        Status::Ok
    }

    /// Reports waiting for the operator, oldest first.
    pub fn reports(&self) -> impl Iterator<Item = &Report> {
        self.reports.iter()
    }

    /// Hand the waiting reports to the operator and forget them here.
    pub fn take_reports(&mut self) -> Vec<Report> {
        self.reports.drain(..).collect()
    }

    /// Operator action on a report: close the account's request inbox, so
    /// nobody can send it new requests and it can't receive replies to them.
    /// Returns whether it existed.
    pub fn disable_request_inbox(&mut self, request_inbox: &[u8; 32]) -> bool {
        self.inboxes
            .remove(request_inbox)
            .is_some_and(|ib| ib.request)
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
            (DirKind::Attest, DirAction::Get) => match self.attestations.get(&req.key) {
                Some(list) => Self::chunk_reply(
                    &enclave_proto::attest::encode_list(list),
                    req.index,
                    [0; 32],
                ),
                None => (Status::NotFound, Reply::Empty),
            },
            (DirKind::Username, DirAction::Get) if req.index == 0 => {
                self.lookup_username(&req, now)
            }
            (DirKind::Username, DirAction::Get) => match self.kt_replies.get(&req.key) {
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
            DirKind::Username => self.accept_username(&req.key, &req.proof, &object, now),
            DirKind::Attest => self.accept_attestation(&req.key, object),
        };
        (status, Reply::Empty)
    }

    fn lookup_username(&mut self, req: &DirRequest, now: u64) -> (Status, Reply) {
        let Some(kt) = self.kt_lookups() else {
            return (Status::NotFound, Reply::Empty);
        };
        let Some(name) = api::key_name(&req.key) else {
            return (Status::Malformed, Reply::Empty);
        };
        let Ok(bytes) = kt.lookup(&name, now) else {
            return (Status::NotFound, Reply::Empty);
        };
        let Ok(id) = self.rng.array::<32>("server/kt-reply-id") else {
            return (Status::Malformed, Reply::Empty);
        };
        let r = Self::chunk_reply(&bytes, 0, id);
        self.kt_replies.insert(id, (bytes, now));
        r
    }

    /// Bind a username to an account. The claim must carry proof of work, be
    /// signed by a device in the account's root-signed manifest held here, be
    /// fresh, and not take a name another account holds. One name per
    /// account: claiming a new one publishes a tombstone (the bare root) for
    /// the old, which stays reserved for the same account.
    fn accept_username(
        &mut self,
        key: &[u8; 32],
        proof: &[u8; 32],
        object: &[u8],
        now: u64,
    ) -> Status {
        let Some(kt) = &self.kt else {
            return Status::NotFound;
        };
        let ctx = api::pow_context_username(key, now / 86_400);
        if !enclave_tokens::verify(&ctx, self.cfg.effort_username, &PowProof(*proof)) {
            return Status::Pow;
        }
        let Ok(claim) = UsernameClaim::decode(object) else {
            return Status::Malformed;
        };
        let (Some(keyed), Ok(name)) = (
            api::key_name(key),
            enclave_kt::username::normalize(&claim.name),
        ) else {
            return Status::Invalid;
        };
        if keyed != claim.name || claim.name != name || claim.time.abs_diff(now) > 3600 {
            return Status::Invalid;
        }
        let Some(root) = claim.root() else {
            return Status::Malformed;
        };
        let Some((_, mbytes)) = self.manifests.get(&manifest_key(&root)) else {
            return Status::NotFound;
        };
        let Some(m) = SignedManifest::from_bytes(mbytes)
            .ok()
            .and_then(|sm| Manifest::decode(&sm.body).ok())
        else {
            return Status::Invalid;
        };
        let msg = UsernameClaim::message(&self.cfg.id, &claim.name, &claim.value, claim.time);
        let signed = m.devices.iter().any(|d| {
            d.id == claim.device
                && d.signing
                    .verify(enclave_kt::wire::CTX_CLAIM, &msg, &claim.signature)
                    .is_ok()
        });
        if !signed {
            return Status::Invalid;
        }
        if let Some((owner, last)) = self.usernames.get(&name) {
            if *owner != root {
                return Status::Denied;
            }
            if *last >= claim.time {
                return Status::Invalid;
            }
        }
        if let Some(old) = self.names_by_root.get(&root)
            && *old != name
            && kt.publish(old, root.to_vec(), now).is_err()
        {
            return Status::Invalid;
        }
        if kt.publish(&name, claim.value.clone(), now).is_err() {
            return Status::Denied;
        }
        self.usernames.insert(name.clone(), (root, claim.time));
        self.names_by_root.insert(root, name);
        Status::Ok
    }

    /// Keep a device attestation if a device the account has ever listed
    /// signed it. At most 16 per account, newest last.
    fn accept_attestation(&mut self, key: &[u8; 32], bytes: Vec<u8>) -> Status {
        let Ok(a) = enclave_proto::attest::Attestation::decode(&bytes) else {
            return Status::Malformed;
        };
        let signed = self.devices_seen.get(key).is_some_and(|seen| {
            seen.iter()
                .any(|s| s.id == a.device && a.verify_key(&s.root, &s.key))
        });
        if !signed {
            return Status::Invalid;
        }
        let list = self.attestations.entry(*key).or_default();
        if !list.contains(&bytes) {
            list.push(bytes);
            if list.len() > 16 {
                list.remove(0);
            }
        }
        Status::Ok
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
        let seen = self.devices_seen.entry(*key).or_default();
        for d in &m.devices {
            if !seen.iter().any(|s| s.id == d.id) && seen.len() < 256 {
                seen.push(SeenDevice {
                    root: m.root.0,
                    id: d.id,
                    key: d.signing.clone(),
                });
            }
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
