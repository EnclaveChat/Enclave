//! Transports carry one sealed request to a server and bring back one sealed
//! reply (single-use-reply-block semantics in Nym).
//!
//! * [`TcpTransport`]: the development transport (`enclave-server` dev binary).
//!   Never used in production builds.
//! * `NymTransport` / `TorTransport`: production, behind the `nym` and `tor`
//!   features. The M4 feasibility spike (`docs/spikes/m4-network.md`) records
//!   what could and could not be validated.

use crate::{NetError, Result};
use enclave_crypto::kem::{MlKemPublic, X448Public};
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
    /// Fetch the server's current request key (from its descriptor).
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
    let mut v = Vec::with_capacity(4 + 56 + 1568);
    v.extend_from_slice(&k.key_id.to_be_bytes());
    v.extend_from_slice(&k.x448.0);
    v.extend_from_slice(&k.mlkem.0[..]);
    v
}

/// Decode `key_id ‖ x448 ‖ mlkem` as served by the dev transport.
pub fn decode_server_key(b: &[u8]) -> Result<ServerKey> {
    if b.len() != 4 + 56 + 1568 {
        return Err(NetError::BadReply);
    }
    let key_id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    let mut x = [0u8; 56];
    x.copy_from_slice(&b[4..60]);
    let mlkem = MlKemPublic::from_slice(&b[60..]).map_err(|_| NetError::BadReply)?;
    Ok(ServerKey {
        key_id,
        x448: X448Public(x),
        mlkem,
    })
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
        decode_server_key(&self.roundtrip(server, &[]).await?)
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
        decode_server_key(&self.roundtrip(server, &[]).await?)
    }
}

/// Nym transport (nym-sdk mixnet client with SURB replies). Requires the
/// `nym` feature.
#[cfg(feature = "nym")]
pub struct NymTransport;
