//! Fuzz targets (`docs/20-assurance.md`).
//!
//! Every function here feeds untrusted bytes to one parser or state machine
//! and must never panic, whatever the input: release builds abort on panic,
//! so a panic on hostile input would take a server or client down. The same
//! targets run three ways:
//!
//! * `cargo test -p enclave-fuzz`: a seeded mutation smoke test over valid
//!   samples and random bytes (stable toolchain, runs in CI);
//! * `fuzz/` (cargo-fuzz, nightly): coverage-guided fuzzing, and OSS-Fuzz;
//! * ad hoc, from a crash reproducer: `enclave_fuzz::run(name, bytes)`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_crypto::rng::HedgedRng;
use std::cell::RefCell;

/// A named target.
pub type Target = (&'static str, fn(&[u8]));

thread_local! {
    static SERVER: RefCell<Option<enclave_server::Server>> = const { RefCell::new(None) };
    static RELAY: RefCell<Option<enclave_relay::Relay>> = const { RefCell::new(None) };
}

fn wire(d: &[u8]) {
    let _ = enclave_wire::RequestHeader::decode(d);
    let _ = enclave_wire::WireUnit::decode(d);
    let _ = enclave_wire::PollRequest::decode(d);
    let _ = enclave_wire::unpad_content(d);
    if !d.is_empty() {
        let _ = enclave_wire::bucket_for(u32::from(d[0]) as usize * 1000);
    }
}

fn proto(d: &[u8]) {
    use enclave_proto::*;
    let _ = manifest::Manifest::decode(d);
    let _ = manifest::SignedManifest::from_bytes(d);
    let _ = bundle::Bundle::decode(d);
    let _ = bundle::Publication::decode(d);
    let _ = bundle::PrekeyStore::import(d);
    let _ = eqxdh::InitialMessage::decode(d);
    let _ = envelope::request_initial(d);
    let _ = identity::DeviceKeys::import(d);
    let _ = ratchet::Session::import(d);
    let _ = group::GroupState::decode(d);
    let _ = group::Group::import(d);
    let _ = attest::Attestation::decode(d);
    let _ = attest::decode_list(d);
    let _ = recovery::RecoverySecret::from_words(&String::from_utf8_lossy(d));
}

fn rpc(d: &[u8]) {
    let _ = enclave_rpc::api::unframe(d);
    let _ = enclave_rpc::api::DirRequest::decode(d);
    let _ = enclave_rpc::api::DirReply::decode(d);
    // Key transparency: everything a client decodes from a server or pin file.
    let _ = enclave_kt::LookupReply::decode(d);
    let _ = enclave_kt::SignedHead::decode(d);
    let _ = enclave_kt::KtInfo::decode(d);
    let _ = enclave_kt::KtPolicy::decode(d);
    let _ = enclave_kt::UsernameClaim::decode(d);
}

fn content(d: &[u8]) {
    let _ = enclave_core::content::Content::decode(d);
    let _ = enclave_core::ContactCard::decode(d);
    let _ = enclave_core::ContactCard::from_link(&String::from_utf8_lossy(d));
    let _ = enclave_core::card::b64url_decode(&String::from_utf8_lossy(d));
    let _ = enclave_core::files::Attachment::decode(d);
}

fn calls(d: &[u8]) {
    use enclave_calls::*;
    let _ = signal::Offer::decode(d);
    let _ = signal::Answer::decode(d);
    let _ = sframe::parse_header(d);
    let _ = shape::decode_plaintext(d);
    let mut r = shape::Reassembler::default();
    for part in d.chunks(9) {
        let _ = r.push(part);
    }
    let mut rx = sframe::Receiver::new(0, &[7; 32]);
    let _ = rx.unprotect(d, b"");
}

/// The server's whole request path: unit or poll parsing, KEM decapsulation,
/// dispatch. One server per thread, reused across inputs so state builds up.
fn server(d: &[u8]) {
    SERVER.with(|s| {
        let mut s = s.borrow_mut();
        if s.is_none() {
            *s = enclave_server::Server::new(enclave_server::Config::default(), 20_000).ok();
        }
        if let Some(srv) = s.as_mut() {
            let _ = srv.handle(d, 1_790_000_000);
            // Also as a full-size unit and as a poll, so decoding goes deep.
            for len in [enclave_wire::UNIT_LEN, enclave_wire::POLL_LEN] {
                let mut b = d.to_vec();
                b.resize(len, 0);
                let _ = srv.handle(&b, 1_790_000_000);
            }
        }
    });
}

fn relay(d: &[u8]) {
    RELAY.with(|r| {
        let mut r = r.borrow_mut();
        if r.is_none() {
            let addr = "127.0.0.1:9".parse().ok();
            *r = addr.and_then(|a| enclave_relay::Relay::new([1; 16], "f", a, 20_000).ok());
        }
        if let (Some(relay), Ok(from)) = (r.as_mut(), "192.0.2.1:5000".parse()) {
            let _ = relay.handle(from, d, 1_790_000_000);
            let _ = relay.issue_ticket(d, 1_790_000_000, |_| true);
        }
    });
}

/// Group message opening with real keys: exercises the header keystream,
/// MAC vector and body paths on mutated units.
fn group_open(d: &[u8]) {
    thread_local! {
        static G: RefCell<Option<enclave_proto::group::Group>> = const { RefCell::new(None) };
    }
    G.with(|g| {
        let mut g = g.borrow_mut();
        if g.is_none()
            && let Ok(mut rng) = HedgedRng::new()
        {
            *g = enclave_proto::group::Group::create("fuzz", [1; 64], [2; 16], 0, &mut rng).ok();
        }
        if let Some(g) = g.as_mut() {
            let mut unit = d.to_vec();
            unit.resize(enclave_wire::ENVELOPE_LEN, 0);
            unit[0] = 1;
            unit[1] = enclave_wire::EnvelopeKind::Group as u8;
            unit[4..8].fill(0);
            let _ = g.open(&unit);
            let _ = g.rekey_sender(&unit);
        }
    });
}

/// Messages between the UI and vault processes, in both directions.
fn ipc(d: &[u8]) {
    let _ = enclave_ipc::Cmd::decode(d);
    let _ = enclave_ipc::Out::decode(d);
    let _ = enclave_ipc::Snapshot::decode(d);
}

/// Every target.
pub const TARGETS: &[Target] = &[
    ("wire", wire),
    ("proto", proto),
    ("rpc", rpc),
    ("content", content),
    ("calls", calls),
    ("server", server),
    ("relay", relay),
    ("group_open", group_open),
    ("ipc", ipc),
];

/// Run one target by name (for reproducers).
pub fn run(name: &str, data: &[u8]) -> bool {
    match TARGETS.iter().find(|(n, _)| *n == name) {
        Some((_, f)) => {
            f(data);
            true
        }
        None => false,
    }
}

/// Deterministic xorshift generator for the smoke test (no OS randomness,
/// so failures reproduce from the seed alone).
pub struct Xorshift(pub u64);

impl Xorshift {
    /// Next value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }
}

/// Mutate `input` a few times: bit flips, byte sets, truncation, extension,
/// duplication of a slice, interesting values.
pub fn mutate(input: &[u8], rng: &mut Xorshift) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = [0x00, 0xff, 0x7f, 0x80, 0x01][rng.below(5)];
            }
            2 if !v.is_empty() => {
                let n = rng.below(v.len());
                v.truncate(n);
            }
            3 => {
                for _ in 0..rng.below(64) {
                    v.push(rng.next_u64() as u8);
                }
            }
            4 if v.len() > 4 => {
                let a = rng.below(v.len());
                let b = (a + rng.below(64)).min(v.len());
                let slice = v[a..b].to_vec();
                let at = rng.below(v.len());
                v.splice(at..at, slice);
            }
            5 if v.len() >= 4 => {
                // A length field set to something huge.
                let i = rng.below(v.len() - 3);
                v[i..i + 4].copy_from_slice(&[0xff, 0xff, 0xff, (rng.next_u64() as u8) | 0xf0]);
            }
            _ => {
                let i = rng.below(v.len() + 1);
                v.insert(i, rng.next_u64() as u8);
            }
        }
    }
    v
}
