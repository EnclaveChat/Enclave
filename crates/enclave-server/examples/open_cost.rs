//! Where a request's time goes (development aid for `scale`).
#![allow(clippy::unwrap_used)]
use enclave_crypto::rng::HedgedRng;
use enclave_rpc::{ServerSecret, seal_request};
use enclave_wire::{ENVELOPE_LEN, Op, RequestHeader};
use std::time::Instant;

fn main() {
    let mut rng = HedgedRng::new().unwrap();
    let sk = ServerSecret::generate(20_000, &mut rng).unwrap();
    let pk = sk.public().clone();
    let h = RequestHeader {
        op: Op::Cover,
        flags: 0,
        mailbox: [0; 32],
        token: [0; 32],
    };
    let env = vec![0u8; ENVELOPE_LEN];
    let n = 500;
    let reqs: Vec<_> = (0..n)
        .map(|_| seal_request(&pk, &h, &env, &mut rng).unwrap().0)
        .collect();
    let t = Instant::now();
    for r in &reqs {
        let _ = enclave_rpc::open_request(&[&sk], r).unwrap();
    }
    println!(
        "open: {:.3} ms",
        t.elapsed().as_secs_f64() * 1000.0 / n as f64
    );
    let t = Instant::now();
    let mut buf = vec![0u8; 16_384];
    for _ in 0..n {
        rng.fill("bench", &mut buf).unwrap();
    }
    println!(
        "16 KiB hedged random: {:.3} ms",
        t.elapsed().as_secs_f64() * 1000.0 / n as f64
    );
    let (a, _) = enclave_crypto::kem::X448Secret::generate(&mut rng).unwrap();
    let (_, bp) = enclave_crypto::kem::X448Secret::generate(&mut rng).unwrap();
    let t = Instant::now();
    for _ in 0..n {
        let _ = a.diffie_hellman(&bp).unwrap();
    }
    println!(
        "X448: {:.3} ms",
        t.elapsed().as_secs_f64() * 1000.0 / n as f64
    );
    let (ks, kp) = enclave_crypto::kem::MlKemSecret::generate(&mut rng).unwrap();
    let (ct, _) = kp.encapsulate(&mut rng).unwrap();
    let t = Instant::now();
    for _ in 0..n {
        let _ = ks.decapsulate(&ct);
    }
    println!(
        "ML-KEM-1024 decaps: {:.3} ms",
        t.elapsed().as_secs_f64() * 1000.0 / n as f64
    );
}
