//! An in-process [`Transport`]: real sealed requests to real servers, with
//! the network replaced by a function call. Used by `enclave-core` tests and
//! the desktop app's offline demo mode.

use enclave_net::NetError;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::ServerKey;
use enclave_server::Server;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Servers shared by every client in one process.
#[derive(Clone, Default)]
pub struct LocalTransport {
    servers: Arc<Mutex<HashMap<ServerId, Server>>>,
    /// Seconds added to the system clock (to simulate time passing).
    offset: Arc<Mutex<u64>>,
}

impl LocalTransport {
    /// No servers yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a server with `config` (its `id` is the address).
    pub fn add_server(&self, config: enclave_server::Config) -> enclave_crypto::Result<()> {
        let day = (self.now() / 86_400) as u32;
        let id = config.id;
        let server = Server::new(config, day)?;
        if let Ok(mut m) = self.servers.lock() {
            m.insert(id, server);
        }
        Ok(())
    }

    /// Current simulated time.
    pub fn now(&self) -> u64 {
        let sys = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        sys + self.offset.lock().map(|o| *o).unwrap_or(0)
    }

    /// Run `f` with a server (for inspecting what it stores).
    pub fn with_server<R>(&self, id: &ServerId, f: impl FnOnce(&mut Server) -> R) -> Option<R> {
        let mut m = self.servers.lock().ok()?;
        m.get_mut(id).map(f)
    }
}

#[async_trait::async_trait]
impl Transport for LocalTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        let now = self.now();
        let mut m = self
            .servers
            .lock()
            .map_err(|_| NetError::Unavailable("poisoned"))?;
        let s = m
            .get_mut(server)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))?;
        Ok(s.handle(&request, now))
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<ServerKey> {
        let m = self
            .servers
            .lock()
            .map_err(|_| NetError::Unavailable("poisoned"))?;
        m.get(server)
            .and_then(Server::public_key)
            .ok_or_else(|| NetError::Unreachable("unknown server".into()))
    }
}
