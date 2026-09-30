//! Run a call relay on a UDP address.
//!
//! `enclave-relay ADDR FAMILY [PEER_DESCRIPTOR_HEX ...]`
//!
//! Prints this relay's descriptor (hex) for peers to configure. Tickets are
//! requested over the mixnet in production; this binary serves the data
//! plane only.
#![forbid(unsafe_code)]

use enclave_relay::{Descriptor, Relay, serve};
use std::sync::Arc;
use tokio::sync::Mutex;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `id(16) ‖ link_key(56) ‖ addr (utf-8)`.
fn encode(d: &Descriptor) -> String {
    hex(&[&d.id[..], &d.link_key[..], d.addr.to_string().as_bytes()].concat())
}

fn decode(s: &str, family: &str) -> Option<Descriptor> {
    let b = unhex(s)?;
    let addr = std::str::from_utf8(b.get(72..)?).ok()?.parse().ok()?;
    Some(Descriptor {
        id: b.get(..16)?.try_into().ok()?,
        family: family.into(),
        addr,
        link_key: b.get(16..72)?.try_into().ok()?,
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (Some(addr), Some(family)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: enclave-relay ADDR FAMILY [PEER_DESCRIPTOR_HEX ...]");
        std::process::exit(2);
    };
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    let local = socket.local_addr()?;
    let day = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / 86_400) as u32;
    let id: [u8; 16] = {
        let mut rng = enclave_crypto::rng::HedgedRng::new()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        rng.array("relay/id")
            .map_err(|e| std::io::Error::other(e.to_string()))?
    };
    let mut relay =
        Relay::new(id, family, local, day).map_err(|e| std::io::Error::other(e.to_string()))?;
    for p in &args[3..] {
        match decode(p, "peer") {
            Some(d) => relay
                .add_peer(&d)
                .map_err(|e| std::io::Error::other(e.to_string()))?,
            None => eprintln!("ignoring malformed peer descriptor"),
        }
    }
    println!("{}", encode(relay.descriptor()));
    eprintln!("enclave-relay ({family}) on {local}");
    serve(Arc::new(Mutex::new(relay)), socket).await
}
