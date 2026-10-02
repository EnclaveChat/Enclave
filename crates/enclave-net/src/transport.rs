//! Transports carry one sealed request to a server and bring back one sealed
//! reply (single-use-reply-block semantics in Nym).
//!
//! * [`TcpTransport`]: the development transport (`enclave-server` dev binary).
//!   Never used in production builds.
//! * `NymTransport` / `TorTransport`: production, behind the `nym` and `tor`
//!   features. The M4 feasibility spike (`docs/spikes/m4-network.md`) records
//!   what could and could not be validated.

use crate::{NetError, Result};
use enclave_rpc::ServerKey;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Server identifier.
pub type ServerId = [u8; 16];

/// Carries sealed requests to servers.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Send one sealed request and wait for the sealed reply.
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>>;
    /// Like [`Transport::exchange`] for something that may be dropped
    /// rather than ever add traffic (a typing indicator): a shaping
    /// transport sends it only in a slot that would otherwise carry cover.
    async fn exchange_droppable(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.exchange(server, request).await
    }
    /// Start (`true`) or end a bulk transfer: a shaping transport may then
    /// send without waiting for the clock (a large file, catch-up, account
    /// setup), where its profile allows. Calls nest.
    fn set_bulk(&self, _on: bool) {}
    /// The server's current request key, authenticated as `server`'s: a
    /// network transport checks the signed key bundle against the id
    /// ([`verify_key_bundle`]).
    async fn server_key(&self, server: &ServerId) -> Result<ServerKey>;
    /// Current time, Unix seconds. The system clock, except in simulations
    /// that move time forward.
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Encode `key_id ‖ x448 ‖ mlkem` (inverse of [`decode_server_key`]).
pub fn encode_server_key(k: &ServerKey) -> Vec<u8> {
    k.to_bytes()
}

/// Decode `key_id ‖ x448 ‖ mlkem` as served by the dev transport.
pub fn decode_server_key(b: &[u8]) -> Result<ServerKey> {
    ServerKey::from_bytes(b).map_err(|_| NetError::BadReply)
}

/// Parse `HEXID=HOST:PORT` (a 32-hex-digit server id and its address), the
/// form `--server` takes in the app, the vault and netd.
pub fn parse_server(s: &str) -> Option<(ServerId, SocketAddr)> {
    let (hex, addr) = s.split_once('=')?;
    if hex.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some((id, addr.parse().ok()?))
}

/// Check a key bundle (the reply to a zero-length request) against the id
/// the client expects and return the request key valid at `now`.
pub fn verify_key_bundle(server: &ServerId, bundle: &[u8], now: u64) -> Result<ServerKey> {
    enclave_federation::KeyBundle::decode(bundle)
        .and_then(|b| b.verify(server, now))
        .map_err(NetError::Untrusted)
}

/// Development transport: length-prefixed frames over TCP.
pub struct TcpTransport {
    addrs: HashMap<ServerId, SocketAddr>,
}

impl TcpTransport {
    /// New transport with a static address book.
    pub fn new(addrs: HashMap<ServerId, SocketAddr>) -> Self {
        Self { addrs }
    }

    async fn roundtrip(&self, server: &ServerId, frame: &[u8]) -> Result<Vec<u8>> {
        let addr = self
            .addrs
            .get(server)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))?;
        let mut s = TcpStream::connect(addr).await?;
        s.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        s.write_all(frame).await?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > enclave_wire::UNIT_LEN {
            return Err(NetError::BadReply);
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

#[async_trait::async_trait]
impl Transport for TcpTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.roundtrip(server, &request).await
    }

    async fn server_key(&self, server: &ServerId) -> Result<ServerKey> {
        let bundle = self.roundtrip(server, &[]).await?;
        verify_key_bundle(server, &bundle, self.now())
    }
}

/// Tor transport (arti, embedded): the consented fallback route when the
/// mixnet is unreachable, and the underlay for Nym. Servers are addressed by
/// onion service. Requires the `tor` feature.
#[cfg(feature = "tor")]
pub struct TorTransport {
    client: std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
    addrs: HashMap<ServerId, (String, u16)>,
}

#[cfg(feature = "tor")]
impl TorTransport {
    /// Bootstrap an embedded Tor client. `addrs` maps servers to their onion
    /// service `(host, port)`.
    pub async fn bootstrap(addrs: HashMap<ServerId, (String, u16)>) -> Result<Self> {
        let cfg = arti_client::TorClientConfig::default();
        let client = arti_client::TorClient::create_bootstrapped(cfg)
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))?;
        Ok(Self { client, addrs })
    }

    async fn roundtrip(&self, server: &ServerId, frame: &[u8]) -> Result<Vec<u8>> {
        let (host, port) = self
            .addrs
            .get(server)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))?;
        let mut s = self
            .client
            .connect((host.as_str(), *port))
            .await
            .map_err(|e| NetError::Unreachable(e.to_string()))?;
        s.write_all(&(frame.len() as u32).to_be_bytes()).await?;
        s.write_all(frame).await?;
        s.flush().await?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > enclave_wire::UNIT_LEN {
            return Err(NetError::BadReply);
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

#[cfg(feature = "tor")]
#[async_trait::async_trait]
impl Transport for TorTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.roundtrip(server, &request).await
    }

    async fn server_key(&self, server: &ServerId) -> Result<ServerKey> {
        let bundle = self.roundtrip(server, &[]).await?;
        verify_key_bundle(server, &bundle, self.now())
    }
}

/// Nym transport (nym-sdk mixnet client with SURB replies). Requires the
/// `nym` feature.
#[cfg(feature = "nym")]
pub struct NymTransport;
