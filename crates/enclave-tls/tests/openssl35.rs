//! Interoperability with OpenSSL 3.5 (its own SecP384r1MLKEM1024), both
//! ways: OpenSSL's client against the Enclave profile, and the Enclave
//! client against OpenSSL's server, each agreeing on the hybrid and
//! carrying data; OpenSSL offering only X25519 is refused.
//!
//! Runs when `ENCLAVE_OPENSSL` names the OpenSSL 3.5 command (CI's
//! `tls-interop` job: `docker run --rm -i --network host -v /tmp:/tmp
//! enclave-openssl35 openssl`); otherwise it says so and passes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn openssl() -> Option<Vec<String>> {
    let cmd = std::env::var("ENCLAVE_OPENSSL").ok()?;
    Some(cmd.split_whitespace().map(String::from).collect())
}

fn command(prefix: &[String], args: &[&str]) -> Command {
    let mut c = Command::new(&prefix[0]);
    c.args(&prefix[1..]).args(args);
    c
}

struct Pki {
    dir: std::path::PathBuf,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// A self-signed certificate for `localhost`, also written as PEM under
/// /tmp (shared with an OpenSSL in a container).
fn pki(name: &str) -> Pki {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("enclave-openssl-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.key_pair.serialize_pem()).unwrap();
    Pki {
        dir,
        cert: ck.cert.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der())),
    }
}

/// OpenSSL's `s_client` against an Enclave-profile server.
#[tokio::test(flavor = "multi_thread")]
async fn openssl_client_to_enclave_server() {
    let Some(prefix) = openssl() else {
        assert!(
            std::env::var_os("ENCLAVE_REQUIRE_INTEROP").is_none(),
            "ENCLAVE_OPENSSL must be set"
        );
        eprintln!("ENCLAVE_OPENSSL not set: runs in CI's tls-interop job");
        return;
    };
    let p = pki("server");
    let cfg = enclave_tls::server_config(vec![p.cert.clone()], p.key.clone_key()).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut s) = acceptor.accept(sock).await {
                    let mut b = [0u8; 4];
                    if s.read_exact(&mut b).await.is_ok() && &b == b"ping" {
                        let _ = s.write_all(b"pong from enclave\n").await;
                        let _ = s.shutdown().await;
                    }
                }
            });
        }
    });
    let ca = p.dir.join("cert.pem");
    let ca = ca.to_str().unwrap();
    let connect = format!("127.0.0.1:{port}");
    let run = |groups: &'static str| {
        let prefix = prefix.clone();
        let (ca, connect) = (ca.to_string(), connect.clone());
        tokio::task::spawn_blocking(move || {
            let mut child = command(
                &prefix,
                &[
                    "s_client",
                    "-connect",
                    &connect,
                    "-servername",
                    "localhost",
                    "-tls1_3",
                    "-groups",
                    groups,
                    "-ciphersuites",
                    "TLS_AES_256_GCM_SHA384",
                    "-CAfile",
                    &ca,
                    "-verify_return_error",
                    "-ign_eof",
                ],
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
            child.stdin.take().unwrap().write_all(b"ping").unwrap();
            let out = child.wait_with_output().unwrap();
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned()
                    + &String::from_utf8_lossy(&out.stderr),
            )
        })
    };
    let (ok, out) = run("SecP384r1MLKEM1024").await.unwrap();
    assert!(ok, "{out}");
    assert!(out.contains("pong from enclave"), "{out}");
    assert!(
        out.contains("SecP384r1MLKEM1024"),
        "group not reported: {out}"
    );
    assert!(out.contains("TLS_AES_256_GCM_SHA384"), "{out}");
    assert!(out.contains("Verify return code: 0"), "{out}");

    let (_, out) = run("X25519").await.unwrap();
    assert!(
        !out.contains("pong from enclave"),
        "classical-only client served: {out}"
    );
    let _ = std::fs::remove_dir_all(&p.dir);
}

/// The Enclave client against OpenSSL's `s_server`.
#[tokio::test(flavor = "multi_thread")]
async fn enclave_client_to_openssl_server() {
    let Some(prefix) = openssl() else {
        assert!(
            std::env::var_os("ENCLAVE_REQUIRE_INTEROP").is_none(),
            "ENCLAVE_OPENSSL must be set"
        );
        eprintln!("ENCLAVE_OPENSSL not set: runs in CI's tls-interop job");
        return;
    };
    let p = pki("client");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cert = p.dir.join("cert.pem");
    let key = p.dir.join("key.pem");
    let mut server = command(
        &prefix,
        &[
            "s_server",
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-tls1_3",
            "-groups",
            "SecP384r1MLKEM1024",
            "-ciphersuites",
            "TLS_AES_256_GCM_SHA384",
            "-cert",
            cert.to_str().unwrap(),
            "-key",
            key.to_str().unwrap(),
            "-www",
            // One connection, then exit (no container left behind).
            "-naccept",
            "1",
        ],
    )
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(p.cert.clone()).unwrap();
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(enclave_tls::client_config(roots).unwrap()));
    // The server (or its container) takes a moment to listen.
    let mut sock = None;
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            sock = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let result = async {
        let sock = sock.ok_or("s_server never listened")?;
        let mut s = connector
            .connect(ServerName::try_from("localhost").unwrap(), sock)
            .await
            .map_err(|e| e.to_string())?;
        let (_, conn) = s.get_ref();
        let group = conn
            .negotiated_key_exchange_group()
            .map(|g| g.name())
            .ok_or("no group")?;
        if group != rustls::NamedGroup::from(enclave_tls::SECP384R1_MLKEM1024_ID) {
            return Err(format!("negotiated {group:?}"));
        }
        s.write_all(b"GET / HTTP/1.0\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        let mut body = Vec::new();
        let _ = s.read_to_end(&mut body).await;
        let body = String::from_utf8_lossy(&body).into_owned();
        if !body.contains("TLS_AES_256_GCM_SHA384") {
            return Err(format!("unexpected page: {body}"));
        }
        Ok::<_, String>(body)
    }
    .await;
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&p.dir);
    result.unwrap();
}
