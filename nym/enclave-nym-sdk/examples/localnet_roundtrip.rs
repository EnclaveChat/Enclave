//! On a local mixnet (`ci/nym-localnet`): an ingress-role client and a
//! device client connect, the device sends requests with reply blocks for a
//! full reply, and the ingress answers each over them.
//!
//! ```text
//! ENCLAVE_NYM_TOPOLOGY=network.json ENCLAVE_NYM_API=http://127.0.0.1:8000/ \
//!   cargo run -p enclave-nym-sdk --example localnet_roundtrip
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_nym::MixnetDriver;
use enclave_nym::frame::{REPLY_LEN, Reply, Request};
use enclave_nym_sdk::{Network, NymDriver, Options, Role};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    // RUST_LOG for nym-sdk's own logs (warnings by default).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let network = Network::from_env(true);
    assert!(
        matches!(network, Network::Local { .. }),
        "set ENCLAVE_NYM_TOPOLOGY"
    );
    let dir = std::env::temp_dir().join(format!("enclave-localnet-{}", std::process::id()));
    let t = Instant::now();
    let ingress = NymDriver::connect(Options {
        role: Role::Ingress { dir: dir.clone() },
        gateway: None,
        network: network.clone(),
    })
    .await
    .expect("ingress connects");
    let device = NymDriver::connect(Options {
        role: Role::Client,
        gateway: None,
        network,
    })
    .await
    .expect("device connects");
    println!(
        "connected in {:?}: ingress {}",
        t.elapsed(),
        ingress.address()
    );

    let to = ingress.address();
    for n in 0..3u8 {
        let t = Instant::now();
        let req = Request::for_sealed([n; 16], vec![n; enclave_wire::POLL_LEN]).unwrap();
        device.send(&to, req.encode(), REPLY_LEN).await.unwrap();
        let m = tokio::time::timeout(Duration::from_secs(60), ingress.recv())
            .await
            .expect("request arrives")
            .unwrap();
        let got = Request::decode(&m.data).unwrap();
        assert_eq!(got, req);
        let reply = Reply {
            id: got.id,
            data: Some(vec![n ^ 0xff; enclave_wire::UNIT_LEN]),
        };
        ingress
            .reply(m.reply.expect("reply blocks came"), reply.encode().unwrap())
            .await
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(60), device.recv())
            .await
            .expect("reply arrives")
            .unwrap();
        let r = Reply::decode(&r.data).unwrap();
        assert_eq!(r, reply);
        println!("round trip {n}: {:?}", t.elapsed());
    }
    let _ = std::fs::remove_dir_all(dir);
    println!("ok");
}
