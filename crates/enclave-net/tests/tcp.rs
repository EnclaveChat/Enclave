//! Round trip over the TCP development transport against the real server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_net::transport::{TcpTransport, Transport};
use enclave_rpc::api::{self, FLAG_CREATE, Status};
use enclave_server::{Config, Server};
use enclave_wire::{Op, RequestHeader};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

async fn spawn_server() -> std::net::SocketAddr {
    let server = Arc::new(Mutex::new(Server::new(Config::default(), 20_000).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                let mut buf = vec![0u8; n];
                sock.read_exact(&mut buf).await.unwrap();
                let reply = {
                    let mut s = server.lock().await;
                    if n == 0 {
                        let k = s.public_key().unwrap();
                        let mut v = k.key_id.to_be_bytes().to_vec();
                        v.extend_from_slice(&k.x448.0);
                        v.extend_from_slice(&k.mlkem.0[..]);
                        v
                    } else {
                        s.handle(&buf, 1_790_000_000)
                    }
                };
                sock.write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
                sock.write_all(&reply).await.unwrap();
            });
        }
    });
    addr
}

#[tokio::test]
async fn tcp_roundtrip_creates_inbox_and_polls() {
    let addr = spawn_server().await;
    let id = [5u8; 16];
    let t = TcpTransport::new(HashMap::from([(id, addr)]));
    let key = t.server_key(&id).await.unwrap();
    let mut rng = HedgedRng::new().unwrap();

    let owner = [8u8; 32];
    let h = RequestHeader {
        op: Op::RegisterTokens,
        flags: FLAG_CREATE,
        mailbox: [6; 32],
        token: owner,
    };
    let (req, ex) =
        enclave_rpc::seal_request(&key, &h, &api::frame(&[], &mut rng).unwrap(), &mut rng).unwrap();
    let reply = t.exchange(&id, req).await.unwrap();
    let (rh, _) = ex.open_reply(&reply).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);

    let mut token = [0u8; 32];
    token[..24].copy_from_slice(&api::read_credential(&owner));
    let h = RequestHeader {
        op: Op::Poll,
        flags: 0,
        mailbox: [6; 32],
        token,
    };
    let (req, ex) = enclave_rpc::seal_poll(&key, &h, &mut rng).unwrap();
    let reply = t.exchange(&id, req).await.unwrap();
    let (rh, _) = ex.open_reply(&reply).unwrap();
    assert_eq!(Status::from_u8(rh.flags), Status::Ok);
}
