//! `enclave-nymd [--env] [--gateway ID]`
//!
//! A device's mixnet client. Started by `enclave-netd`, never by hand: it
//! connects to the mixnet with a fresh identity and serves
//! `enclave_nym::pipe` on its stdin and stdout, so netd drives it as a
//! mixnet client without linking nym-sdk (which needs another SQLite than
//! arti, `docs/09-transport.md` §1). It holds no Enclave keys and sees only
//! sealed requests. `--env` takes the network from `NYM_*` variables (a
//! local mixnet, the sandbox) instead of mainnet.

use enclave_nym::MixnetDriver;
use enclave_nym_sdk::{NymDriver, Options, Role};
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    // No core dumps, not dumpable, no new privileges.
    let _ = enclave_sandbox::process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let gateway = args
        .iter()
        .position(|a| a == "--gateway")
        .and_then(|i| args.get(i + 1).cloned());
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    rt.block_on(async move {
        let driver = match NymDriver::connect(Options {
            role: Role::Client,
            gateway,
            from_env: args.iter().any(|a| a == "--env"),
        })
        .await
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("enclave-nymd: {e}");
                return ExitCode::FAILURE;
            }
        };
        let driver: Arc<dyn MixnetDriver> = Arc::new(driver);
        enclave_nym::pipe::serve(driver, tokio::io::stdin(), tokio::io::stdout()).await;
        ExitCode::SUCCESS
    })
}
