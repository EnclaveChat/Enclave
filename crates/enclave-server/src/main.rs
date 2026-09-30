//! Development transport for the Enclave server: length-prefixed frames over
//! TCP. **Not for production**: production servers are reachable only through
//! the Nym mixnet (`enclave-net`), never on a clearnet port.
//!
//! Frame: `u32 BE length ‖ bytes`. A zero-length frame asks for the server's
//! current request key; any other frame is a sealed request.
//!
//! `enclave-server [ADDR] [--domain NAME] [--kt-pins FILE]` also runs a
//! development key-transparency log (in memory, with in-process witnesses) so
//! usernames work, and writes what clients must pin to `FILE`.
//!
//! `--push-relay HOST:PORT` forwards due push wakes (sealed tokens) to a
//! development push relay over TCP; production servers reach the relay
//! through Nym.

use enclave_server::{Config, Server};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode a server key as `key_id ‖ x448 ‖ mlkem`.
fn encode_key(k: &enclave_rpc::ServerKey) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 56 + 1568);
    v.extend_from_slice(&k.key_id.to_be_bytes());
    v.extend_from_slice(&k.x448.0);
    v.extend_from_slice(&k.mlkem.0[..]);
    v
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let addr = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7443".to_string());
    let day = (now() / 86_400) as u32;
    let cfg = Config::default();
    let id = cfg.id;
    let mut server = Server::new(cfg, day).map_err(|e| std::io::Error::other(e.to_string()))?;
    let domain = flag("--domain").unwrap_or_else(|| "localhost".to_string());
    match enclave_kt::KtService::start_dev(id, &domain) {
        Ok((kt, policy)) => {
            server.enable_kt(kt);
            if let Some(path) = flag("--kt-pins") {
                std::fs::write(&path, policy.encode())?;
                eprintln!("usernames on @{domain}; clients pin {path}");
            }
        }
        Err(e) => eprintln!("usernames disabled: {e}"),
    }
    let server = Arc::new(Mutex::new(server));
    // Daily request-key rotation (the old key is kept one day, then deleted)
    // and expiry of stored objects past their TTL.
    {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            let mut current = day;
            loop {
                tick.tick().await;
                let now = now();
                let today = (now / 86_400) as u32;
                let mut s = server.lock().await;
                if today != current {
                    if let Err(e) = s.rotate(today) {
                        eprintln!("key rotation failed: {e}");
                    } else {
                        current = today;
                    }
                }
                s.expire(now);
            }
        });
    }
    if let Some(relay) = flag("--push-relay") {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                let due = server.lock().await.due_wakes(now());
                if due.is_empty() {
                    continue;
                }
                match tokio::net::TcpStream::connect(&relay).await {
                    Ok(mut s) => {
                        for sealed in due {
                            let _ = s.write_all(&(sealed.len() as u32).to_be_bytes()).await;
                            let _ = s.write_all(&sealed).await;
                        }
                    }
                    Err(e) => eprintln!("push relay unreachable: {e}"),
                }
            }
        });
    }
    let listener = TcpListener::bind(&addr).await?;
    eprintln!("enclave-server (dev transport) listening on {addr}");
    loop {
        let (mut sock, _) = listener.accept().await?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n > enclave_wire::UNIT_LEN {
                    return;
                }
                let mut buf = vec![0u8; n];
                if sock.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let reply = {
                    let mut s = server.lock().await;
                    if n == 0 {
                        s.public_key().map(|k| encode_key(&k)).unwrap_or_default()
                    } else {
                        s.handle(&buf, now())
                    }
                };
                if sock
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .is_err()
                    || sock.write_all(&reply).await.is_err()
                {
                    return;
                }
            }
        });
    }
}
