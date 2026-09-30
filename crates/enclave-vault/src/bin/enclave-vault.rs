//! `enclave-vault --connect SOCKET [--server HOST:PORT --profile DIR
//! [--kt-pins FILE] | --demo]`
//!
//! Started by the Enclave UI, never by hand. Reads the connection token (hex)
//! from stdin, connects to the UI's socket, proves itself with the token and
//! runs the engine until the UI disconnects.

use std::io::BufRead;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
        .spawn(move || run(&socket, mode, token));
    match worker.map(|h| h.join()) {
        Ok(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

#[cfg(unix)]
fn run(socket: &str, mode: enclave_vault::Mode, token: [u8; 32]) -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(async {
        match tokio::net::UnixStream::connect(socket).await {
            Ok(s) => enclave_vault::serve(mode, s, &token).await.is_ok(),
            Err(e) => {
                eprintln!("enclave-vault: can't reach the app: {e}");
                false
            }
        }
    })
}

#[cfg(not(unix))]
fn run(_: &str, _: enclave_vault::Mode, _: [u8; 32]) -> bool {
    eprintln!("enclave-vault: separate vault process not supported on this platform yet");
    false
}
