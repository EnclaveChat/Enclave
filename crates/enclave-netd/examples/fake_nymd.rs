//! A stand-in for `enclave-nymd` in tests: an in-process mixnet holding the
//! device's client (served on stdin/stdout like the real nymd) and an
//! ingress in front of the server at `$ENCLAVE_FAKE_NYMD_SERVER`, reachable
//! at the Nym address `ingress`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_nym::MixnetDriver;
use enclave_nym::fake::FakeMixnet;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let server = std::env::var("ENCLAVE_FAKE_NYMD_SERVER")
        .unwrap()
        .parse()
        .unwrap();
    let net = FakeMixnet::default();
    let ingress: Arc<dyn MixnetDriver> = Arc::new(net.client("ingress"));
    tokio::spawn(enclave_ingress::serve(
        ingress,
        server,
        Arc::new(enclave_ingress::Stats::default()),
    ));
    let phone: Arc<dyn MixnetDriver> = Arc::new(net.client("phone"));
    enclave_nym::pipe::serve(phone, tokio::io::stdin(), tokio::io::stdout()).await;
}
