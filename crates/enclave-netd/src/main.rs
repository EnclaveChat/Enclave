//! `enclave-netd --server HEXID=nym:ADDRESS … --server HEXID=HOST:PORT … [--nymd PATH] [--nym-env]`
//!
//! Started by the vault, never by hand. Holds no keys: it carries sealed
//! requests from the vault (stdin) to servers and their sealed replies back
//! (stdout), and fetches servers' public request keys. A server named by a
//! Nym address is reached over the mixnet (`NymTransport`) through
//! `enclave-nymd`, a mixnet client netd starts next to itself (nym-sdk
//! can't be linked here: `docs/09-transport.md` §1); others over the
//! development TCP transport. The vault adds or changes routes as it
//! learns them (`NetRequest::SetRoute`: the server list, descriptors); a
//! Nym route needs the mixnet client, which netd starts only when a Nym
//! route is given at start. It confines itself first: no core dumps, not
//! dumpable, `no_new_privs`, and (Linux) no filesystem access at all, after
//! starting nymd.

#![forbid(unsafe_code)]

use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use enclave_net::transport::{
    NymTransport, Route, ServerId, TcpTransport, Transport, encode_server_key,
};
use std::collections::{HashMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

/// `--server` routes: TCP addresses and Nym addresses.
fn parse_servers(
    args: &[String],
) -> (
    HashMap<ServerId, std::net::SocketAddr>,
    HashMap<ServerId, String>,
) {
    let mut tcp = HashMap::new();
    let mut nym = HashMap::new();
    for p in args.windows(2).filter(|p| p[0] == "--server") {
        match enclave_net::transport::parse_route(&p[1]) {
            Some((id, Route::Tcp(a))) => {
                tcp.insert(id, a);
            }
            Some((id, Route::Nym(a))) => {
                nym.insert(id, a);
            }
            None => eprintln!("enclave-netd: --server {}: not a route", p[1]),
        }
    }
    (tcp, nym)
}

/// Each server over the transport its route names.
struct Routed {
    tcp: TcpTransport,
    nym: Option<NymTransport>,
    over_nym: std::sync::RwLock<HashSet<ServerId>>,
}

impl Routed {
    fn pick(&self, server: &ServerId) -> &dyn Transport {
        let over_nym = self
            .over_nym
            .read()
            .map(|s| s.contains(server))
            .unwrap_or(false);
        match &self.nym {
            Some(n) if over_nym => n,
            _ => &self.tcp,
        }
    }
}

#[async_trait::async_trait]
impl Transport for Routed {
    async fn exchange(&self, server: &ServerId, request: Vec<u8>) -> enclave_net::Result<Vec<u8>> {
        self.pick(server).exchange(server, request).await
    }

    async fn server_key(&self, server: &ServerId) -> enclave_net::Result<enclave_rpc::ServerKey> {
        self.pick(server).server_key(server).await
    }

    fn set_route(&self, server: ServerId, route: Route) {
        let nym = matches!(route, Route::Nym(_));
        // A Nym route without the mixnet client can't be used: the
        // server stays on the route it had.
        if nym && self.nym.is_none() {
            return;
        }
        if let Ok(mut s) = self.over_nym.write() {
            if nym {
                s.insert(server);
            } else {
                s.remove(&server);
            }
        }
        match &self.nym {
            Some(n) if nym => n.set_route(server, route),
            _ => self.tcp.set_route(server, route),
        }
    }
}

/// Start `enclave-nymd` and drive it over its stdin and stdout.
async fn start_nymd(
    bin: &std::path::Path,
    env: bool,
) -> Result<(enclave_nym::pipe::PipeDriver, tokio::process::Child), String> {
    let mut cmd = tokio::process::Command::new(bin);
    if env {
        cmd.arg("--env");
    }
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err("no pipes to enclave-nymd".into());
    };
    let driver = enclave_nym::pipe::PipeDriver::new(stdout, stdin)
        .await
        .map_err(|e| format!("enclave-nymd: {e}"))?;
    Ok((driver, child))
}

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (tcp, over_nym) = parse_servers(&args);
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    // The mixnet client starts before the sandbox forbids starting programs.
    let nymd = if over_nym.is_empty() {
        None
    } else {
        let bin = args
            .iter()
            .position(|a| a == "--nymd")
            .and_then(|i| args.get(i + 1))
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::current_exe().ok().map(|e| {
                    e.with_file_name(format!("enclave-nymd{}", std::env::consts::EXE_SUFFIX))
                })
            });
        match bin {
            Some(bin) => match rt.block_on(start_nymd(&bin, args.iter().any(|a| a == "--nym-env")))
            {
                Ok(n) => Some(n),
                Err(e) => {
                    eprintln!("enclave-netd: {e}");
                    None
                }
            },
            None => None,
        }
    };
    // Nothing on disk is needed from here on.
    let _ = enclave_sandbox::filesystem(&[], &[], false);
    // IPv4 and IPv6 sockets only; no programs, no debugging.
    let _ = enclave_sandbox::syscalls(enclave_sandbox::Profile::Netd, false);
    let (nym, _child) = match nymd {
        Some((driver, child)) => {
            let n = rt.block_on(async {
                NymTransport::new(Arc::new(driver), over_nym.clone(), NymTransport::TIMEOUT)
            });
            (Some(n), Some(child))
        }
        None => (None, None),
    };
    let transport = Arc::new(Routed {
        tcp: TcpTransport::new(tcp),
        over_nym: std::sync::RwLock::new(match nym {
            Some(_) => over_nym.keys().copied().collect(),
            None => HashSet::new(),
        }),
        nym,
    });
    rt.block_on(async move {
        let mut stdin = tokio::io::stdin();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            let mut stdout = tokio::io::stdout();
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdout, &body).await.is_err() {
                    break;
                }
            }
        });
        while let Ok(body) = frame::read_frame(&mut stdin).await {
            let req = match NetRequest::decode(&body) {
                Ok(NetRequest::SetRoute { server, route }) => {
                    match Route::parse(&route) {
                        Some(r) => transport.set_route(server, r),
                        None => eprintln!("enclave-netd: {route}: not a route"),
                    }
                    continue;
                }
                Ok(r) => r,
                Err(_) => break,
            };
            let t = Arc::clone(&transport);
            let tx = tx.clone();
            // Requests run concurrently; replies carry their request's id.
            tokio::spawn(async move {
                let (id, result) = match req {
                    NetRequest::Exchange { id, server, bytes } => (
                        id,
                        t.exchange(&server, bytes).await.map_err(|e| e.to_string()),
                    ),
                    NetRequest::ServerKey { id, server } => (
                        id,
                        t.server_key(&server)
                            .await
                            .map(|k| encode_server_key(&k))
                            .map_err(|e| e.to_string()),
                    ),
                    NetRequest::SetRoute { .. } => return,
                };
                let _ = tx.send(NetReply { id, result }.encode());
            });
        }
        drop(tx);
        let _ = writer.await;
    });
    ExitCode::SUCCESS
}
