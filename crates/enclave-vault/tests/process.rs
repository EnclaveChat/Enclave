//! The real vault binary over a Unix socket: token handshake, commands in,
//! snapshots out, and recovery words only on request.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::frame::{self, TOKEN_LEN};
use enclave_ipc::{Cmd, Out, Snapshot};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::net::UnixListener;

const BIN: &str = env!("CARGO_BIN_EXE_enclave-vault");

async fn next_snapshot<R: tokio::io::AsyncRead + Unpin>(
    rd: &mut R,
    want: impl Fn(&Snapshot) -> bool,
) -> Snapshot {
    loop {
        let body = tokio::time::timeout(Duration::from_secs(300), frame::read_frame(rd))
            .await
            .expect("vault answered in time")
            .unwrap();
        if let Out::Snapshot(s) = Out::decode(&body).unwrap()
            && want(&s)
        {
            return *s;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn vault_process_serves_the_ui() {
    let dir = std::env::temp_dir().join(format!("enclave-vault-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("v.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let token = [0x5a; TOKEN_LEN];

    let mut child = Command::new(BIN)
        .arg("--connect")
        .arg(&sock)
        .arg("--demo")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", frame::token_hex(&token)).unwrap();

    let (stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut rd, mut wr) = tokio::io::split(stream);
    frame::check_token(&mut rd, &token).await.unwrap();

    let send = |c: Cmd| c.encode();
    frame::write_frame(&mut wr, &send(Cmd::Create("Robin".into())))
        .await
        .unwrap();
    let s = next_snapshot(&mut rd, |s| s.my_name == "Robin" && !s.requests.is_empty()).await;
    assert!(s.recovery_words.is_empty(), "words stay in the vault");
    assert_eq!(s.requests[0].name, "Sam (demo)");

    frame::write_frame(&mut wr, &send(Cmd::RevealWords(true)))
        .await
        .unwrap();
    frame::write_frame(&mut wr, &send(Cmd::Select(String::new())))
        .await
        .unwrap();
    let s = next_snapshot(&mut rd, |s| !s.recovery_words.is_empty()).await;
    assert_eq!(s.recovery_words.len(), 24);
    frame::write_frame(&mut wr, &send(Cmd::RevealWords(false)))
        .await
        .unwrap();
    frame::write_frame(&mut wr, &send(Cmd::Select(String::new())))
        .await
        .unwrap();
    next_snapshot(&mut rd, |s| s.recovery_words.is_empty()).await;

    // The UI goes away: the vault exits.
    drop(rd);
    drop(wr);
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success(), "{status:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_refuses_to_start_without_a_token() {
    let mut child = Command::new(BIN)
        .args(["--connect", "/nonexistent", "--demo"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "not-a-token").unwrap();
    assert!(!child.wait().unwrap().success());
    let status = Command::new(BIN).status().unwrap();
    assert!(!status.success());
}
