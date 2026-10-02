//! A sealed request is processed once (`docs/09-transport.md` §2.3): the
//! same bytes again, even after a restart, get the random reply of a
//! request that doesn't open, and change nothing. Replay ids are dropped
//! with the day's key. Proofs of work are spent once. On every storage
//! backend (`common::stores`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::Store;

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, FLAG_CREATE, Status};
use enclave_rpc::seal_request;
use enclave_server::db;
use enclave_server::keys::ServerKeys;
use enclave_server::{Config, Server};
use enclave_wire::{Op, RequestHeader};
use std::path::Path;

const DAY: u32 = 20_600;
const NOW: u64 = DAY as u64 * 86_400 + 60;

fn open(d: &Path, store: &Store) -> Server {
    let keys = ServerKeys::load(&d.join("keys")).unwrap();
    let cfg = Config {
        id: keys.id(),
        ..Config::default()
    };
    Server::open(cfg, store.open(), keys.chain.keys()).unwrap()
}

#[test]
fn a_request_is_processed_once() {
    let d = std::env::temp_dir().join(format!("enclave-replay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    for store in common::stores("a_request_is_processed_once", &d) {
        eprintln!("on {}", store.name());
        let _ = std::fs::remove_dir_all(d.join("keys"));
        ServerKeys::init(&d.join("keys"), DAY).unwrap();
        processed_once(&d, &store);
    }
    let _ = std::fs::remove_dir_all(&d);
}

fn processed_once(d: &Path, store: &Store) {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = open(d, store);
    let key = s.public_key().unwrap();

    // Creating an inbox takes a proof of work for its address.
    let h = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE,
        mailbox: [5; 32],
        token: [6; 32],
    };
    let none = api::frame(&[], &mut rng).unwrap();
    let (bytes, ex) = seal_request(&key, &h, &none, &mut rng).unwrap();
    let (rh, _) = ex.open_reply(&s.handle(&bytes, NOW)).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Pow, "no proof");
    let effort = Config::default().effort_inbox;
    let other = api::pow_context_inbox(&[7; 32], NOW / 86_400);
    let wrong = enclave_tokens::solve(&other, effort, &mut rng).unwrap();
    let env = api::frame(&wrong.0, &mut rng).unwrap();
    let (bytes, ex) = seal_request(&key, &h, &env, &mut rng).unwrap();
    let (rh, _) = ex.open_reply(&s.handle(&bytes, NOW)).unwrap();
    assert_eq!(
        Status::from_u8(rh.flags),
        Status::Pow,
        "another address's proof"
    );
    let stale = api::pow_context_inbox(&h.mailbox, NOW / 86_400 - 2);
    let stale = enclave_tokens::solve(&stale, effort, &mut rng).unwrap();
    let env = api::frame(&stale.0, &mut rng).unwrap();
    let (bytes, ex) = seal_request(&key, &h, &env, &mut rng).unwrap();
    let (rh, _) = ex.open_reply(&s.handle(&bytes, NOW)).unwrap();
    assert_eq!(
        Status::from_u8(rh.flags),
        Status::Pow,
        "a proof from two days ago"
    );
    // Yesterday's proof still counts (a client near midnight).
    let ctx = api::pow_context_inbox(&h.mailbox, NOW / 86_400 - 1);
    let proof = enclave_tokens::solve(&ctx, effort, &mut rng).unwrap();

    // The inbox is created; the same sealed bytes again don't open.
    let env = api::frame(&proof.0, &mut rng).unwrap();
    let (bytes, ex) = seal_request(&key, &h, &env, &mut rng).unwrap();
    let (rh, _) = ex.open_reply(&s.handle(&bytes, NOW)).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);
    assert!(ex.open_reply(&s.handle(&bytes, NOW)).is_err(), "replayed");
    assert_eq!(s.stats().replays, 1);

    // A new sealing of the same request is a new request, not a replay;
    // its proof of work was spent.
    let (again, ex2) = seal_request(&key, &h, &env, &mut rng).unwrap();
    let (rh, _) = ex2.open_reply(&s.handle(&again, NOW)).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Pow);
    // With a fresh proof: the inbox exists.
    let fresh = enclave_tokens::solve(&ctx, effort, &mut rng).unwrap();
    let env2 = api::frame(&fresh.0, &mut rng).unwrap();
    let (b3, ex3) = seal_request(&key, &h, &env2, &mut rng).unwrap();
    let (rh, _) = ex3.open_reply(&s.handle(&b3, NOW)).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Denied);

    // After a restart the replay is still refused.
    drop(s);
    let mut s = open(d, store);
    assert!(ex.open_reply(&s.handle(&bytes, NOW)).is_err());

    // Two rotations later the day's key is gone, and with it its ids.
    let count = |s: &Server| {
        s.db()
            .read(|r| Ok(r.scan(db::REPLAYS, &DAY.to_be_bytes())?.len()))
            .unwrap()
    };
    assert_eq!(count(&s), 6);
    for day in [DAY + 1, DAY + 2] {
        s.rotate(day).unwrap();
    }
    assert_eq!(count(&s), 0);
}
