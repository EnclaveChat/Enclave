//! `enclave-push-relay --listen HOST:PORT [--epoch N]`
//!
//! Development relay: prints its public key (hex) and accepts wakes from
//! servers over TCP (`u32 BE length ‖ sealed token` per wake), forwarding
//! UnifiedPush wakes. Production servers reach it through Nym.

use enclave_push_relay::{Platform, Relay, RelaySecret, SEALED_LEN, deliver_unified_push};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let listen = arg("--listen").unwrap_or_else(|| "127.0.0.1:7443".into());
    let epoch = arg("--epoch").and_then(|e| e.parse().ok()).unwrap_or(1);
    let Ok(mut rng) = enclave_crypto::rng::HedgedRng::new() else {
        return ExitCode::FAILURE;
    };
    let Ok(key) = RelaySecret::generate(epoch, &mut rng) else {
        return ExitCode::FAILURE;
    };
    let hex: String = key
        .public()
        .encode()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("relay key: {hex}");
    let relay = Arc::new(Mutex::new(Relay::new(vec![key])));
    let Ok(listener) = tokio::net::TcpListener::bind(&listen).await else {
        eprintln!("can't listen on {listen}");
        return ExitCode::FAILURE;
    };
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let relay = Arc::clone(&relay);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                if u32::from_be_bytes(len) as usize != SEALED_LEN {
                    return;
                }
                let mut sealed = vec![0u8; SEALED_LEN];
                if sock.read_exact(&mut sealed).await.is_err() {
                    return;
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let d = relay.lock().await.wake(&sealed, now);
                if let Some(d) = d
                    && d.platform == Platform::UnifiedPush
                    && let Ok(url) = String::from_utf8(d.token)
                {
                    let _ = deliver_unified_push(&url).await;
                }
            }
        });
    }
}
