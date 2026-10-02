//! `enclave-ingress`: a stack's Nym client in front of its server
//! (`enclave_ingress`, `docs/12-servers.md` §6).
//!
//! ```text
//! enclave-ingress run [--server HOST:PORT] [--dir DIR] [--public DIR] [--gateway ID] [--env]
//! enclave-ingress healthcheck [--public DIR]
//! ```
//!
//! `run` connects to the mixnet with the identity kept in `--dir` (created
//! the first time), writes its Nym address to `PUBLIC/ingress.addr` (the
//! server puts it in its descriptor), and forwards every request to the
//! server on the stack's internal network. `--env` takes the network from
//! `NYM_*` variables (a local mixnet, the sandbox) instead of mainnet.
//! Defaults: `--server server:7443`, `--dir /var/lib/enclave/ingress`,
//! `--public /var/lib/enclave/public`.

use enclave_ingress::Stats;
use enclave_nym::MixnetDriver;
use enclave_nym_sdk::{NymDriver, Options, Role};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let public =
        PathBuf::from(flag(&args, "--public").unwrap_or_else(|| "/var/lib/enclave/public".into()));
    let result = match args.first().map(String::as_str) {
        Some("run") => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(run(&args, &public))),
        Some("healthcheck") => {
            if public.join("ingress.addr").exists() {
                Ok(())
            } else {
                Err("not connected to the mixnet yet".into())
            }
        }
        _ => Err("usage: enclave-ingress run|healthcheck [options] (see the module docs)".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-ingress: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: &[String], public: &std::path::Path) -> Result<(), String> {
    let server = flag(args, "--server").unwrap_or_else(|| "server:7443".into());
    let dir =
        PathBuf::from(flag(args, "--dir").unwrap_or_else(|| "/var/lib/enclave/ingress".into()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let driver = NymDriver::connect(Options {
        role: Role::Ingress { dir },
        gateway: flag(args, "--gateway"),
        from_env: args.iter().any(|a| a == "--env"),
    })
    .await
    .map_err(|e| e.to_string())?;
    let address = driver.address();
    std::fs::create_dir_all(public).map_err(|e| format!("{}: {e}", public.display()))?;
    std::fs::write(public.join("ingress.addr"), format!("{address}\n"))
        .map_err(|e| format!("{}: {e}", public.display()))?;
    eprintln!("enclave-ingress: {address} → {server}");
    // The server's address is resolved on the stack's network.
    let server_addr = server
        .to_socket_addrs()
        .map_err(|e| format!("{server}: {e}"))?
        .next()
        .ok_or_else(|| format!("{server}: no address"))?;
    let stats = Arc::new(Stats::default());
    {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                eprintln!(
                    "enclave-ingress: answered {} failed {} dropped {}",
                    stats.answered.load(Ordering::Relaxed),
                    stats.failed.load(Ordering::Relaxed),
                    stats.dropped.load(Ordering::Relaxed)
                );
            }
        });
    }
    let driver: Arc<dyn MixnetDriver> = Arc::new(driver);
    tokio::select! {
        () = enclave_ingress::serve(driver, server_addr, stats) => Err("the mixnet client stopped".into()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
