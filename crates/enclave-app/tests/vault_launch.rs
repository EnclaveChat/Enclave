//! The app's own launcher starts the real vault binary, authenticates it and
//! relays commands and snapshots.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::{Cmd, Out};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn launcher_talks_to_a_real_vault() {
    // target/<profile>/deps/<test> → target/<profile>/enclave-vault
    let exe = std::env::current_exe().unwrap();
    let bin = exe
        .parent()
        .and_then(|d| d.parent())
        .unwrap()
        .join("enclave-vault");
    if !bin.exists() {
        // Built by `cargo test --workspace`; not by `-p enclave-app` alone.
        eprintln!("skipping: {} not built", bin.display());
        return;
    }
    let (tx, mut rx) = enclave_app::vault::spawn_process(&bin, &enclave_vault::Mode::Demo).unwrap();
    tx.send(Cmd::Create("Robin".into())).unwrap();
    let found = tokio::time::timeout(Duration::from_secs(300), async {
        while let Some(o) = rx.recv().await {
            if let Out::Snapshot(s) = o
                && s.my_name == "Robin"
            {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(found, "the vault answered through the launcher");
}
