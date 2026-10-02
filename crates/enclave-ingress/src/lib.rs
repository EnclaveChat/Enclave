//! The Nym ingress (`docs/09-transport.md` §1, `docs/12-servers.md` §6).
//!
//! The key-holding server never links a mixnet client: this sidecar does.
//! It takes each mixframe (`enclave_nym::frame::Request`) off the mixnet,
//! hands the sealed bytes to the server over the stack's internal network
//! with the server's own framing (`u32 len ‖ bytes`; a zero-length request
//! asks for the key bundle), and answers over the sender's reply blocks.
//! It sees only sealed bytes and never learns who sent them: the mixnet
//! gives it a single-use tag, not an address. Anything that doesn't parse,
//! or comes without reply blocks, is dropped.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_nym::frame::{Reply, Request};
use enclave_nym::{Incoming, MixnetDriver};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long the server gets to answer.
pub const SERVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Counters (aggregates only: no addresses, no timing per sender).
#[derive(Debug, Default)]
pub struct Stats {
    /// Requests forwarded and answered.
    pub answered: AtomicU64,
    /// Requests the server didn't answer.
    pub failed: AtomicU64,
    /// Messages dropped: malformed or without reply blocks.
    pub dropped: AtomicU64,
}

/// Forward everything `driver` receives to the server at `server` until the
/// driver shuts down.
pub async fn serve(driver: Arc<dyn MixnetDriver>, server: SocketAddr, stats: Arc<Stats>) {
    while let Some(m) = driver.recv().await {
        let driver = Arc::clone(&driver);
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            handle(driver.as_ref(), server, m, &stats).await;
        });
    }
}

async fn handle(driver: &dyn MixnetDriver, server: SocketAddr, m: Incoming, stats: &Stats) {
    let (Ok(req), Some(tag)) = (Request::decode(&m.data), m.reply) else {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let data = tokio::time::timeout(SERVER_TIMEOUT, roundtrip(server, &req.body))
        .await
        .ok()
        .and_then(Result::ok);
    let counter = if data.is_some() {
        &stats.answered
    } else {
        &stats.failed
    };
    counter.fetch_add(1, Ordering::Relaxed);
    let Ok(frame) = (Reply { id: req.id, data }).encode() else {
        return;
    };
    // The reply blocks may be gone (the client gave up); nothing to do.
    let _ = driver.reply(tag, frame).await;
}

/// One request on the server's framing.
async fn roundtrip(server: SocketAddr, body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(server).await?;
    s.write_all(&u32::try_from(body.len()).unwrap_or(0).to_be_bytes())
        .await?;
    s.write_all(body).await?;
    s.flush().await?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > enclave_wire::UNIT_LEN {
        return Err(std::io::Error::other("reply too long"));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}
