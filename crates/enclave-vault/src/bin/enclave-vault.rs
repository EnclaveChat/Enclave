//! `enclave-vault --connect SOCKET [--server HOST:PORT --profile DIR
//! [--kt-pins FILE] | --demo] [--report]`
//!
//! Started by the Enclave UI, never by hand. Hardens itself (no core dumps,
//! not dumpable, `no_new_privs`), reads the connection token (hex) from
//! stdin, connects to the UI's socket, proves itself with the token, starts
//! `enclave-netd` for the network (server mode), confines itself to its
//! profile directory with no TCP at all (Landlock) and runs the engine until
//! the UI disconnects. `--report` prints what hardening took effect.

use std::io::BufRead;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut report = enclave_vault::harden::process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "--report");
    let Some(socket) = args
        .iter()
        .position(|a| a == "--connect")
        .and_then(|i| args.get(i + 1))
        .cloned()
    else {
        eprintln!("enclave-vault is started by the Enclave app");
        return ExitCode::from(2);
    };
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return ExitCode::from(2);
    }
    let Some(token) = enclave_ipc::frame::token_from_hex(&line) else {
        return ExitCode::from(2);
    };
    let mode = enclave_vault::Mode::from_args(&args);
    // McEliece key generation needs a deep stack.
    let worker = std::thread::Builder::new()
        .name("enclave-vault".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let ok = run(&socket, mode, token, &mut report);
            if verbose {
                eprintln!("enclave-vault: {report:?}");
            }
            ok
        });
    match worker.map(|h| h.join()) {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

#[cfg(unix)]
fn run(
    socket: &str,
    mode: enclave_vault::Mode,
    token: [u8; 32],
    report: &mut enclave_vault::harden::Report,
) -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(async {
        match tokio::net::UnixStream::connect(socket).await {
            Ok(s) => {
                // The network lives in netd; start it while we still may.
                let net = start_netd(&mode);
                if net.is_some() {
                    report.network = "netd";
                }
                // From here on only the profile is reachable, and (with
                // netd) no TCP connection can be opened.
                let (rw, ro) = enclave_vault::harden::paths_for(&mode);
                report.filesystem = enclave_vault::harden::filesystem(&rw, &ro, net.is_some());
                enclave_vault::serve_with(mode, net, s, &token)
                    .await
                    .is_ok()
            }
            Err(e) => {
                eprintln!("enclave-vault: can't reach the app: {e}");
                false
            }
        }
    })
}

#[cfg(unix)]
fn start_netd(
    mode: &enclave_vault::Mode,
) -> Option<std::sync::Arc<dyn enclave_net::transport::Transport>> {
    let enclave_vault::Mode::Server { addr, .. } = mode else {
        return None;
    };
    let bin = enclave_vault::netd::netd_binary()?;
    let id = enclave_server::Config::default().id;
    match enclave_vault::netd::PipeTransport::spawn(&bin, id, &addr.to_string()) {
        Ok(t) => Some(std::sync::Arc::new(t)),
        Err(e) => {
            eprintln!("enclave-vault: netd didn't start ({e}); using the network directly");
            None
        }
    }
}

#[cfg(not(unix))]
fn run(
    _: &str,
    _: enclave_vault::Mode,
    _: [u8; 32],
    _: &mut enclave_vault::harden::Report,
) -> bool {
    eprintln!("enclave-vault: separate vault process not supported on this platform yet");
    false
}
