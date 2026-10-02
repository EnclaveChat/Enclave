//! End-to-end simulation (M3 exit gate): two servers, Alice with one device,
//! Bob with two, first contact through a request inbox, a conversation over
//! token-authorized inbox writes, and the server-side invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_rpc::api::{self, Status};
use enclave_sim::{Network, SimUser};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};

#[test]
fn two_servers_three_devices_end_to_end() {
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let s_alice = [1u8; 16];
    let s_bob = [2u8; 16];
    net.add_server(s_alice, 4);
    net.add_server(s_bob, 4);

    let mut alice = SimUser::create(&mut net, s_alice, 1, &mut rng);
    let mut bob = SimUser::create(&mut net, s_bob, 2, &mut rng);
    let a_root = alice.account.root_public.0;
    let b_root = bob.account.root_public.0;

    // Alice scans Bob's QR code and writes to each of his devices.
    alice.add_contact(&mut net, &bob.card(), b"hi bob, it's alice", &mut rng);
    // Bob learns Alice's manifest (in production: fetched from the locator in
    // the sealed identity block; here handed over directly).
    bob.contacts.insert(a_root, alice.manifest.clone());
    for d in 0..2 {
        let texts = bob.process_requests(&mut net, d, &mut rng);
        assert_eq!(texts, vec![b"hi bob, it's alice".to_vec()], "device {d}");
    }

    // Bob's device 0 answers, handing Alice tokens for Bob's inbox.
    let tokens = bob.issue_tokens(&mut net, a_root, 16, &mut rng);
    let reply = enclave_sim::encode_hello(&bob.server, &bob.inbox, &tokens, b"hello alice");
    assert_eq!(bob.send(&mut net, 0, a_root, &reply, &mut rng), Status::Ok);
    let got = alice.receive(&mut net, 0, &mut rng);
    assert_eq!(got.len(), 1);
    assert_eq!(alice.accept_hello(b_root, &got[0]), b"hello alice");

    // Bob's device 1 also answers (so Alice's session with it can send).
    let reply1 = enclave_sim::encode_hello(&bob.server, &bob.inbox, &[], b"hello from my laptop");
    assert_eq!(bob.send(&mut net, 1, a_root, &reply1, &mut rng), Status::Ok);
    let got = alice.receive(&mut net, 0, &mut rng);
    assert_eq!(alice.accept_hello(b_root, &got[0]), b"hello from my laptop");

    // One envelope from Alice reaches both of Bob's devices.
    for i in 0..3 {
        let text = format!("message {i}");
        assert_eq!(
            alice.send(&mut net, 0, b_root, text.as_bytes(), &mut rng),
            Status::Ok
        );
        for d in 0..2 {
            assert_eq!(
                bob.receive(&mut net, d, &mut rng),
                vec![text.as_bytes().to_vec()],
                "device {d}"
            );
        }
    }

    // --- Server-side invariants -------------------------------------------
    for (id, server) in &net.servers {
        // Every stored object is exactly one envelope long.
        assert!(
            server.stored_lengths().iter().all(|l| *l == ENVELOPE_LEN),
            "server {id:?}"
        );
    }
    let bob_server = &net.servers[&s_bob];
    assert!(bob_server.stats().tokens_burned >= 3);

    // A spent token cannot be reused (replay of a write).
    let spent = RequestHeader {
        op: Op::Write,
        flags: 0,
        mailbox: bob.inbox,
        token: [0xAB; 32],
    };
    let (s, ..) = net.call(&s_bob, spent, &vec![0u8; ENVELOPE_LEN], &mut rng);
    assert_eq!(s, Status::Denied);

    // Reading needs the owner's credential.
    let mut token = [0u8; 32];
    token[..24].copy_from_slice(&api::read_credential(&[9; 32]));
    let h = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox: bob.inbox,
        token,
    };
    assert_eq!(net.call(&s_bob, h, &[], &mut rng).0, Status::Denied);

    // A request-inbox write without enough proof of work is refused.
    let h = RequestHeader {
        op: Op::WriteRequest,
        flags: 0,
        mailbox: bob.request_inbox,
        token: [0; 32],
    };
    assert_eq!(
        net.call(&s_bob, h, &vec![0u8; ENVELOPE_LEN], &mut rng).0,
        Status::Pow
    );

    // Garbage bytes get a random reply of the normal size.
    let reply = net
        .servers
        .get_mut(&s_bob)
        .unwrap()
        .handle(&vec![7u8; enclave_wire::UNIT_LEN], net.now);
    assert_eq!(reply.len(), enclave_wire::UNIT_LEN);
}

#[test]
fn manifest_rollback_is_refused_by_the_directory() {
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let s = [3u8; 16];
    net.add_server(s, 1);
    let user = SimUser::create(&mut net, s, 1, &mut rng);
    // Re-uploading the same (or an older) version is refused.
    let key = enclave_server::manifest_key(&user.account.root_public.0);
    let st = net.dir_put(
        &s,
        enclave_rpc::api::DirKind::Manifest,
        key,
        [0; 32],
        &user.signed.to_bytes(),
        &mut rng,
    );
    assert_eq!(st, Status::Invalid);
}

/// A bundle claim costs a proof of work, and a proof claims once: one
/// solution can't drain a device's one-time prekeys (RT-06).
#[test]
fn rt06_opk_claim_requires_pow() {
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let s = [1u8; 16];
    net.add_server(s, 4);
    let bob = SimUser::create(&mut net, s, 1, &mut rng);
    let key = api::device_key(&bob.manifest.devices[0].id);
    let claim = |net: &mut Network, proof: [u8; 32], rng: &mut HedgedRng| {
        net.dir_get(
            &s,
            api::DirKind::Bundle,
            api::DirAction::Claim,
            key,
            proof,
            rng,
        )
    };
    assert!(claim(&mut net, [0; 32], &mut rng).is_none(), "no proof");
    let day = net.now / 86_400;
    let proof = enclave_tokens::solve(&api::pow_context_claim(&key, day), 1, &mut rng).unwrap();
    assert!(claim(&mut net, proof.0, &mut rng).is_some());
    assert!(claim(&mut net, proof.0, &mut rng).is_none(), "spent");
    let other = enclave_tokens::solve(&api::pow_context_claim(&key, day), 1, &mut rng).unwrap();
    assert!(claim(&mut net, other.0, &mut rng).is_some(), "a new proof");
}

/// A request-inbox write needs a proof of work or an invite capability, and
/// a proof writes once: the same envelope can't be written again and again
/// to push real requests out (RT-25).
#[test]
fn rt25_request_requires_pow_or_capability() {
    let mut rng = HedgedRng::new().unwrap();
    let mut net = Network::new();
    let s = [1u8; 16];
    net.add_server(s, 4);
    let bob = SimUser::create(&mut net, s, 1, &mut rng);
    let inbox = bob.card().request_inbox;
    let env = vec![7u8; ENVELOPE_LEN];
    let ctx = api::pow_context_request(
        &inbox,
        net.now / 86_400,
        &enclave_crypto::hash::sha3_512(&env),
    );
    let proof = enclave_tokens::solve(&ctx, 4, &mut rng).unwrap();
    let write = |net: &mut Network, token: [u8; 32], rng: &mut HedgedRng| {
        let h = RequestHeader {
            op: Op::WriteRequest,
            flags: 0,
            mailbox: inbox,
            token,
        };
        net.call(&s, h, &env, rng).0
    };
    assert_eq!(write(&mut net, [0; 32], &mut rng), Status::Pow, "no proof");
    assert_eq!(write(&mut net, proof.0, &mut rng), Status::Ok);
    assert_eq!(write(&mut net, proof.0, &mut rng), Status::Pow, "spent");
    // An invite capability stands in for the proof only if it's registered.
    let h = RequestHeader {
        op: Op::WriteRequest,
        flags: api::FLAG_INVITE,
        mailbox: inbox,
        token: [9; 32],
    };
    assert_eq!(
        net.call(&s, h, &env, &mut rng).0,
        Status::Denied,
        "unknown capability"
    );
}
