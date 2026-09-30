//! The vault's side of `netd` (`docs/15-client.md` §1.1a).
//!
//! In server mode the vault starts `enclave-netd` (from next to its own
//! binary) before it confines itself, and talks to it over the child's stdin
//! and stdout. After that the vault denies itself every TCP connection
//! (Landlock), so the process holding the keys can't reach the network at
//! all: only sealed requests and replies cross to and from netd.

use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use enclave_net::NetError;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::ServerKey;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<Vec<u8>, String>>>>>;

/// A [`Transport`] that forwards to a netd child process.
pub struct PipeTransport {
    next: AtomicU32,
    out: mpsc::UnboundedSender<Vec<u8>>,
    pending: Pending,
    // Kept so the child is killed when the transport goes away.
    _child: Mutex<Child>,
}

/// Where `enclave-netd` should be: next to this executable.
pub fn netd_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("enclave-netd{}", std::env::consts::EXE_SUFFIX));
    p.exists().then_some(p)
}

impl PipeTransport {
    /// Start netd for the dev server at `addr` (the only server in server
    /// mode for now). Must run inside a tokio runtime.
    pub fn spawn(bin: &std::path::Path, server: ServerId, addr: &str) -> std::io::Result<Self> {
        let hex: String = server.iter().map(|b| format!("{b:02x}")).collect();
        let mut child = Command::new(bin)
            .args(["--server", &format!("{hex}={addr}")])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let (out, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdin, &body).await.is_err() {
                    break;
                }
            }
        });
        let p = Arc::clone(&pending);
        tokio::spawn(async move {
            while let Ok(body) = frame::read_frame(&mut stdout).await {
                let Ok(reply) = NetReply::decode(&body) else {
                    break;
                };
                if let Some(tx) = p.lock().await.remove(&reply.id) {
                    let _ = tx.send(reply.result);
                }
            }
            // netd went away: fail everything still waiting.
            p.lock().await.clear();
        });
        Ok(Self {
            next: AtomicU32::new(1),
            out,
            pending,
            _child: Mutex::new(child),
        })
    }

    async fn call(&self, make: impl FnOnce(u32) -> NetRequest) -> enclave_net::Result<Vec<u8>> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        self.out
            .send(make(id).encode())
            .map_err(|_| NetError::Unavailable("netd stopped"))?;
        match rx.await {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(e)) => Err(NetError::Unreachable(e)),
            Err(_) => Err(NetError::Unavailable("netd stopped")),
        }
    }
}

#[async_trait::async_trait]
impl Transport for PipeTransport {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        let server = *server;
        self.call(|id| NetRequest::Exchange {
            id,
            server,
            bytes: request,
        })
        .await
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<ServerKey> {
        let server = *server;
        let b = self.call(|id| NetRequest::ServerKey { id, server }).await?;
        enclave_net::transport::decode_server_key(&b)
    }
}
