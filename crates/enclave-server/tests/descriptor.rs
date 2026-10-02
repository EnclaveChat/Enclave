//! The server's descriptor and the mirrored server list are served in
//! chunks over sealed directory requests, and can't be uploaded
//! (`docs/12-servers.md` §4.1, §4.3).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, DirAction, DirKind, DirReply, DirRequest, Status};
use enclave_rpc::seal_request;
use enclave_server::{Config, Server};
use enclave_wire::{Op, RequestHeader};

const DAY: u32 = 20_700;
const NOW: u64 = DAY as u64 * 86_400 + 60;

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

fn get(kind: DirKind, index: u32) -> DirRequest {
    DirRequest {
        kind,
        action: DirAction::Get,
        key: [0; 32],
        index,
        total: 0,
        proof: [0; 32],
        data: Vec::new(),
    }
}

/// Fetch every chunk of `kind`.
fn fetch(s: &mut Server, kind: DirKind, rng: &mut HedgedRng) -> Option<Vec<u8>> {
    let (st, first) = dir(s, get(kind, 0), rng);
    if st != Status::Ok {
        return None;
    }
    let first = first.unwrap();
    let mut out = first.data;
    for i in 1..first.total {
        let (st, r) = dir(s, get(kind, i), rng);
        assert_eq!(st, Status::Ok);
        out.extend(r.unwrap().data);
    }
    Some(out)
}

#[test]
fn descriptor_and_list_are_served_not_uploaded() {
    let mut rng = HedgedRng::new().unwrap();
    let mut s = Server::new(Config::default(), DAY).unwrap();
    assert_eq!(fetch(&mut s, DirKind::Descriptor, &mut rng), None);
    assert_eq!(fetch(&mut s, DirKind::ServerList, &mut rng), None);

    // Bigger than one chunk, like a real descriptor (about 20 KB).
    let descriptor: Vec<u8> = (0..20_500u32).map(|i| (i % 251) as u8).collect();
    let list: Vec<u8> = (0..40_000u32).map(|i| (i % 241) as u8).collect();
    s.set_descriptor(descriptor.clone());
    s.set_server_list(list.clone());
    assert_eq!(
        fetch(&mut s, DirKind::Descriptor, &mut rng),
        Some(descriptor)
    );
    assert_eq!(fetch(&mut s, DirKind::ServerList, &mut rng), Some(list));

    for kind in [DirKind::Descriptor, DirKind::ServerList] {
        let put = DirRequest {
            kind,
            action: DirAction::Put,
            key: [0; 32],
            index: 0,
            total: 1,
            proof: [0; 32],
            data: vec![1; 100],
        };
        assert_eq!(dir(&mut s, put, &mut rng).0, Status::Denied);
    }
}
