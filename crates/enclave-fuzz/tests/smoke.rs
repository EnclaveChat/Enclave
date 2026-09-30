//! Seeded mutation smoke test over every fuzz target. A failure prints the
//! target, seed and iteration; `enclave_fuzz::run` reproduces it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_fuzz::{TARGETS, Xorshift, mutate};

/// Valid encodings to mutate, so mutations reach past the first length check.
fn samples() -> Vec<Vec<u8>> {
    let mut rng = HedgedRng::new().unwrap();
    let mut out = vec![Vec::new(), vec![0; 72], vec![0xff; 200]];
    // Content, cards, attachments.
    use enclave_core::content::Content;
    out.push(
        Content::Text {
            tokens: vec![[1; 32]; 3],
            text: "hello".into(),
            id: [2; 16],
            expires: 60,
        }
        .encode()
        .unwrap(),
    );
    out.push(Content::Read(vec![[3; 16]; 4]).encode().unwrap());
    out.push(
        Content::GroupCards {
            group_id: [4; 32],
            cards: vec![vec![5; 50]; 3],
        }
        .encode()
        .unwrap(),
    );
    let card = enclave_core::ContactCard {
        root: [6; 64],
        server: [7; 16],
        request_inbox: [8; 32],
        vault_locator: [9; 32],
        vault_key: [10; 32],
        name: "Sam".into(),
    };
    out.push(card.encode());
    out.push(card.to_link().into_bytes());
    let (att, _) =
        enclave_core::files::seal_file(b"file", "a.txt", "text/plain", [1; 16], &mut rng).unwrap();
    out.push(att.encode());
    // Group state and group persistence.
    let mut g = enclave_proto::group::Group::create("g", [1; 64], [2; 16], 0, &mut rng).unwrap();
    out.push(g.state.encode());
    g.rotate(&[], None, 0, &mut rng).unwrap();
    out.push(g.export().to_vec());
    out.push(g.seal(b"hi", 0, &mut rng).unwrap());
    // Wire and RPC.
    let h = enclave_wire::RequestHeader {
        op: enclave_wire::Op::Poll,
        flags: 0,
        mailbox: [1; 32],
        token: [2; 32],
    };
    out.push(h.encode().to_vec());
    let req = enclave_rpc::api::DirRequest {
        kind: enclave_rpc::api::DirKind::Manifest,
        action: enclave_rpc::api::DirAction::Get,
        key: [3; 32],
        index: 0,
        total: 1,
        proof: [0; 32],
        data: vec![1, 2, 3],
    };
    out.push(req.encode());
    out.push(enclave_rpc::api::frame(&req.encode(), &mut rng).unwrap());
    // Calls.
    let p = enclave_calls::signal::offer(
        enclave_calls::signal::Media::Audio,
        enclave_calls::signal::Route::Relay,
        vec![1; 10],
        0,
        &mut rng,
    )
    .unwrap();
    out.push(p.offer().encode());
    let mut tx = enclave_calls::sframe::Sender::new(0, &[7; 32]);
    out.push(tx.protect(0, b"", &[0; 111]).unwrap());
    out
}

#[test]
fn every_target_survives_mutated_and_random_input() {
    let samples = samples();
    let iterations: usize = std::env::var("ENCLAVE_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500);
    for (name, f) in TARGETS {
        // The server and relay targets do KEM work per input; fewer rounds.
        let n = if matches!(*name, "server" | "relay") {
            iterations / 10
        } else {
            iterations
        };
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64);
        for i in 0..n {
            let base = &samples[rng.below(samples.len())];
            let input = if rng.below(8) == 0 {
                (0..rng.below(20_000)).map(|_| rng.next() as u8).collect()
            } else {
                mutate(base, &mut rng)
            };
            let r = std::panic::catch_unwind(|| f(&input));
            assert!(
                r.is_ok(),
                "target {name} panicked at iteration {i} (input {} bytes)",
                input.len()
            );
        }
    }
}
