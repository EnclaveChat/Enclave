//! Where an account went (`docs/12-servers.md` §4.4): the server it left
//! keeps a root-signed `ServerMove` under the account's manifest key and
//! serves it to anyone. It takes one only for an account it holds, signed
//! by that account's root, leaving this server, recent, and newer than the
//! one it has.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::Manifest;
use enclave_proto::recovery::RecoverySecret;
use enclave_proto::server_move::ServerMove;
use enclave_rpc::api::{self, DirAction, DirKind, DirReply, DirRequest, Status, manifest_key};
use enclave_rpc::seal_request;
use enclave_server::{Config, Server};
use enclave_wire::{Op, RequestHeader};

const DAY: u32 = 20_700;
const NOW: u64 = DAY as u64 * 86_400 + 60;
const HERE: [u8; 16] = [7; 16];

fn dir(s: &mut Server, req: DirRequest, rng: &mut HedgedRng) -> (Status, Option<DirReply>) {
    let key = s.public_key().unwrap();
    let h = RequestHeader {
        op: Op::Directory,
        flags: 0,
        mailbox: [0; 32],
        token: [0; 32],
    };
    let env = api::frame(&req.encode(), rng).unwrap();
    let (bytes, ex) = seal_request(&key, &h, &env, rng).unwrap();
    let reply = s.handle(&bytes, NOW);
    let (rh, renv) = ex.open_reply(&reply).unwrap();
    let r = api::unframe(&renv)
        .ok()
        .filter(|p| !p.is_empty())
        .and_then(|p| DirReply::decode(p).ok());
    (Status::from_u8(rh.flags), r)
}

/// Upload `data` in chunks; the status of the last one.
fn put(s: &mut Server, kind: DirKind, key: [u8; 32], data: &[u8], rng: &mut HedgedRng) -> Status {
    let chunks = api::chunks(data);
    let total = chunks.len() as u32;
    let mut last = Status::Ok;
    for (i, c) in chunks.iter().enumerate() {
        let req = DirRequest {
            kind,
            action: DirAction::Put,
            key,
            index: i as u32,
            total,
            proof: [0; 32],
            data: c.to_vec(),
        };
        last = dir(s, req, rng).0;
    }
    last
}

fn fetch(s: &mut Server, key: [u8; 32], rng: &mut HedgedRng) -> Option<Vec<u8>> {
    let get = |index| DirRequest {
        kind: DirKind::Moved,
        action: DirAction::Get,
        key,
        index,
        total: 0,
        proof: [0; 32],
        data: Vec::new(),
    };
    let (st, first) = dir(s, get(0), rng);
    if st != Status::Ok {
        return None;
    }
    let first = first.unwrap();
    let mut out = first.data;
    for i in 1..first.total {
        out.extend(dir(s, get(i), rng).1.unwrap().data);
    }
    Some(out)
}

fn account(rng: &mut HedgedRng) -> (AccountKeys, Vec<u8>) {
    let rs = RecoverySecret::generate(rng).unwrap();
    let account = AccountKeys::create(&rs, rng).unwrap();
    let device = DeviceKeys::generate(rng).unwrap();
    let m = Manifest::genesis(&account, &device, NOW, vec![1; 32]);
    let signed = m.sign(&account, rng).unwrap().to_bytes();
    (account, signed)
}

fn record(a: &AccountKeys, from: [u8; 16], time: u64, rng: &mut HedgedRng) -> Vec<u8> {
    let root = a.root.as_ref().unwrap();
    ServerMove::sign(root, from, [8; 16], "b.test", [2; 32], [3; 32], time, rng)
        .unwrap()
        .encode()
}

#[test]
fn a_move_is_kept_only_from_its_root_leaving_here() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Server::new(
        Config {
            id: HERE,
            ..Default::default()
        },
        DAY,
    )
    .unwrap();
    let (ada, manifest) = account(&mut rng);
    let key = manifest_key(&ada.root_public.0);
    let good = record(&ada, HERE, NOW, &mut rng);

    // Not an account of this server (yet): nothing to say where it went.
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &good, &mut rng),
        Status::NotFound
    );
    assert_eq!(fetch(&mut s, key, &mut rng), None);
    assert_eq!(
        put(&mut s, DirKind::Manifest, key, &manifest, &mut rng),
        Status::Ok
    );

    // Signed by someone else's root, or filed under another account.
    let (eve, _) = account(&mut rng);
    let forged = record(&eve, HERE, NOW, &mut rng);
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &forged, &mut rng),
        Status::Invalid
    );
    // Leaving another server, or stale.
    let elsewhere = record(&ada, [9; 16], NOW, &mut rng);
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &elsewhere, &mut rng),
        Status::Invalid
    );
    let stale = record(&ada, HERE, NOW - 3 * 86_400, &mut rng);
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &stale, &mut rng),
        Status::Invalid
    );
    // A damaged signature.
    let mut bad = good.clone();
    let n = bad.len() - 1;
    bad[n] ^= 1;
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &bad, &mut rng),
        Status::Invalid
    );

    // The real one is kept and served to anyone, whole.
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &good, &mut rng),
        Status::Ok
    );
    assert_eq!(fetch(&mut s, key, &mut rng), Some(good.clone()));
    // An older or equal one doesn't replace it; a newer one does.
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &good, &mut rng),
        Status::Invalid
    );
    let later = record(&ada, HERE, NOW + 60, &mut rng);
    assert_eq!(
        put(&mut s, DirKind::Moved, key, &later, &mut rng),
        Status::Ok
    );
    assert_eq!(fetch(&mut s, key, &mut rng), Some(later));
}
