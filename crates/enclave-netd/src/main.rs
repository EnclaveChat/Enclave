//! `enclave-netd --server HEXID=HOST:PORT …`
//!
//! Started by the vault, never by hand. Holds no keys: it carries sealed
//! requests from the vault (stdin) to servers and their sealed replies back
//! (stdout), and fetches servers' public request keys. It confines itself
//! first: no core dumps, not dumpable, `no_new_privs`, and (Linux) no
//! filesystem access at all.

#![forbid(unsafe_code)]

use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use enclave_net::transport::{TcpTransport, Transport, encode_server_key};
use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

fn parse_servers(args: &[String]) -> HashMap<[u8; 16], std::net::SocketAddr> {
    let mut map = HashMap::new();
    for pair in args.windows(2) {
        if pair[0] != "--server" {
            continue;
        }
        let Some((hex, addr)) = pair[1].split_once('=') else {
            continue;
        };
        let (Ok(addr), true) = (addr.parse(), hex.len() == 32) else {
            continue;
        };
        let mut id = [0u8; 16];
        let ok = (0..16).all(|i| {
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map(|b| id[i] = b)
                .is_ok()
        });
        if ok {
            map.insert(id, addr);
        }
    }
    map
}

fn main() -> ExitCode {
    let _ = enclave_sandbox::process();
    // Nothing on disk is needed from here on.
    let _ = enclave_sandbox::filesystem(&[], &[], false);
    // IPv4 and IPv6 sockets only; no programs, no debugging.
    let _ = enclave_sandbox::syscalls(enclave_sandbox::Profile::Netd, false);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let transport = Arc::new(TcpTransport::new(parse_servers(&args)));
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
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
            let Ok(req) = NetRequest::decode(&body) else {
                break;
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
                };
                let _ = tx.send(NetReply { id, result }.encode());
            });
        }
        drop(tx);
        let _ = writer.await;
    });
    ExitCode::SUCCESS
}
