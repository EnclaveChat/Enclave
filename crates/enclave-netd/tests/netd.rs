//! netd carries requests and replies, and holds nothing else.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::frame;
use enclave_ipc::net::{NetReply, NetRequest};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BIN: &str = env!("CARGO_BIN_EXE_enclave-netd");

/// RT-14 (`docs/15-client.md` §1.2): netd must not link the store, the
/// client engine or the protocol. Walks the path dependencies (not
/// dev-dependencies) from this crate's manifest.
#[test]
fn rt14_netd_has_no_key_material() {
    fn deps(dir: &Path, seen: &mut BTreeSet<String>) {
        let toml = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        let mut in_deps = false;
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_deps = t.ends_with("dependencies]") && !t.contains("dev-");
                continue;
            }
            if !in_deps {
                continue;
            }
            if let Some(i) = t.find("path = \"") {
                let rel = &t[i + 8..];
                let rel = &rel[..rel.find('"').unwrap()];
                let name = t.split_whitespace().next().unwrap().to_string();
                if seen.insert(name) {
                    deps(&dir.join(rel), seen);
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    deps(Path::new(env!("CARGO_MANIFEST_DIR")), &mut seen);
    assert!(seen.contains("enclave-net"), "{seen:?}");
    for banned in [
        "enclave-store",
        "enclave-core",
        "enclave-proto",
        "enclave-vault",
    ] {
        assert!(!seen.contains(banned), "netd depends on {banned}: {seen:?}");
    }
}

/// A server that answers the dev framing: an empty request gets a key
/// (`key_id ‖ x448 ‖ mlkem`), anything else comes back reversed.
async fn fake_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                loop {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
                    s.read_exact(&mut buf).await.unwrap();
                    let reply = if buf.is_empty() {
                        [&7u32.to_be_bytes()[..], &[1u8; 56], &[2u8; 1568]].concat()
                    } else {
                        buf.iter().rev().copied().collect()
                    };
                    s.write_all(&(reply.len() as u32).to_be_bytes())
                        .await
                        .unwrap();
                    s.write_all(&reply).await.unwrap();
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn carries_requests_and_keys() {
    let addr = fake_server().await;
    let server = [0xab; 16];
    let hex: String = server.iter().map(|b| format!("{b:02x}")).collect();
    let mut child = tokio::process::Command::new(BIN)
        .args(["--server", &format!("{hex}={addr}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let requests = [
        NetRequest::Exchange {
            id: 1,
            server,
            bytes: vec![1, 2, 3],
        },
        NetRequest::ServerKey { id: 2, server },
        // Unknown server: an error reply, not a crash.
        NetRequest::Exchange {
            id: 3,
            server: [0; 16],
            bytes: vec![9],
        },
    ];
    for r in &requests {
        frame::write_frame(&mut stdin, &r.encode()).await.unwrap();
    }
    let mut replies = Vec::new();
    for _ in 0..requests.len() {
        let b = frame::read_frame(&mut stdout).await.unwrap();
        replies.push(NetReply::decode(&b).unwrap());
    }
    replies.sort_by_key(|r| r.id);
    assert_eq!(replies[0].result, Ok(vec![3, 2, 1]));
    let key = replies[1].result.as_ref().unwrap();
    assert_eq!(key.len(), 4 + 56 + 1568);
    assert_eq!(&key[..4], &7u32.to_be_bytes());
    assert!(replies[2].result.is_err());

    // Garbage from the vault ends netd rather than confusing it.
    frame::write_frame(&mut stdin, &[0xff, 0, 0]).await.unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
}
