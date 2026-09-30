//! Start the vault process and talk to it (`docs/15-client.md` §1).
//!
//! The UI creates a private directory (mode 0700), listens on a Unix socket
//! inside it, and starts `enclave-vault` from next to its own executable with
//! a fresh 32-byte token on the child's stdin. The first connection must
//! present that token; the socket is then unlinked, so nothing else can
//! connect. Commands and outputs cross as [`enclave_ipc`] frames. If the vault
//! exits, the UI shows that instead of pretending to work.

use enclave_ipc::{Cmd, Out, Snapshot};
use enclave_vault::Mode;
use tokio::sync::mpsc;

/// Channels to the engine: commands in, outputs out.
pub type Channels = (mpsc::UnboundedSender<Cmd>, mpsc::UnboundedReceiver<Out>);

/// Where the vault binary should be: next to this executable.
pub fn vault_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("enclave-vault{}", std::env::consts::EXE_SUFFIX));
    p.exists().then_some(p)
}

/// Start the engine: as a separate process when possible, otherwise on a
/// thread. Returns the channels and whether the vault is a separate process.
pub fn start(mode: Mode, single_process: bool) -> (Channels, bool) {
    if !single_process && let Some(bin) = vault_binary() {
        match spawn_process(&bin, &mode) {
            Ok(ch) => return (ch, true),
            Err(e) => eprintln!("enclave: vault process unavailable ({e}); running in-process"),
        }
    }
    (enclave_vault::spawn(mode), false)
}

#[cfg(unix)]
fn spawn_process(bin: &std::path::Path, mode: &Mode) -> std::io::Result<Channels> {
    use enclave_ipc::frame;
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;

    let mut rng = enclave_crypto::rng::HedgedRng::new().map_err(std::io::Error::other)?;
    let token: [u8; frame::TOKEN_LEN] = rng
        .array("app/vault-token")
        .map_err(std::io::Error::other)?;
    let nonce: [u8; 8] = rng.array("app/vault-dir").map_err(std::io::Error::other)?;
    let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("enclave-{name}"));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let sock = dir.join("vault.sock");

    let std_listener = std::os::unix::net::UnixListener::bind(&sock)?;
    std_listener.set_nonblocking(true)?;
    let mut child = std::process::Command::new(bin)
        .arg("--connect")
        .arg(&sock)
        .args(mode.to_args())
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{}", frame::token_hex(&token))?;
    }

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Out>();
    std::thread::Builder::new()
        .name("enclave-vault-link".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                let result: enclave_ipc::Result<()> = async {
                    let listener = tokio::net::UnixListener::from_std(std_listener)?;
                    let accepted =
                        tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept())
                            .await
                            .map_err(|_| std::io::Error::other("vault did not connect"))?;
                    // One connection only: nothing else can reach us now.
                    drop(listener);
                    let _ = std::fs::remove_file(&sock);
                    let _ = std::fs::remove_dir(&dir);
                    let (stream, _) = accepted?;
                    let (mut rd, mut wr) = tokio::io::split(stream);
                    frame::check_token(&mut rd, &token).await?;
                    loop {
                        tokio::select! {
                            cmd = cmd_rx.recv() => {
                                let Some(cmd) = cmd else { return Ok(()) };
                                frame::write_frame(&mut wr, &cmd.encode()).await?;
                            }
                            body = frame::read_frame(&mut rd) => {
                                let out = Out::decode(&body?)?;
                                if out_tx.send(out).is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
                .await;
                let _ = std::fs::remove_file(&sock);
                let _ = std::fs::remove_dir(&dir);
                let _ = child.kill();
                let _ = child.wait();
                if let Err(e) = result {
                    let _ = out_tx.send(Out::Snapshot(Box::new(Snapshot {
                        status: format!("Enclave's vault stopped ({e}). Restart Enclave."),
                        ..Default::default()
                    })));
                }
            });
        })?;
    Ok((cmd_tx, out_rx))
}

#[cfg(not(unix))]
fn spawn_process(_: &std::path::Path, _: &Mode) -> std::io::Result<Channels> {
    Err(std::io::Error::other("not supported on this platform yet"))
}
