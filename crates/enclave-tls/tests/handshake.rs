//! The Enclave TLS profile end to end: a client and a server agree on
//! SecP384r1MLKEM1024 and AES-256-GCM-SHA384 and carry data; a client that
//! only offers classical groups is refused; a damaged key share fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_tls::{SECP384R1_MLKEM1024, SECP384R1_MLKEM1024_ID};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{CipherSuite, NamedGroup, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["front.test".into()]).unwrap();
    (
        ck.cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der())),
    )
}

async fn server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> std::net::SocketAddr {
    let cfg = enclave_tls::server_config(vec![cert], key).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut s) = acceptor.accept(sock).await {
                    let mut b = [0u8; 5];
                    if s.read_exact(&mut b).await.is_ok() {
                        b.reverse();
                        let _ = s.write_all(&b).await;
                        let _ = s.shutdown().await;
                    }
                }
            });
        }
    });
    addr
}

fn roots(cert: &CertificateDer<'static>) -> RootCertStore {
    let mut r = RootCertStore::empty();
    r.add(cert.clone()).unwrap();
    r
}

#[tokio::test]
async fn hybrid_handshake_carries_data() {
    let (c, k) = cert();
    let addr = server(c.clone(), k).await;
    let connector = TlsConnector::from(Arc::new(enclave_tls::client_config(roots(&c)).unwrap()));
    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut s = connector
        .connect(ServerName::try_from("front.test").unwrap(), sock)
        .await
        .unwrap();
    let (_, conn) = s.get_ref();
    assert_eq!(
        conn.negotiated_key_exchange_group().map(|g| g.name()),
        Some(NamedGroup::Unknown(SECP384R1_MLKEM1024_ID))
    );
    assert_eq!(
        conn.negotiated_cipher_suite().map(|c| c.suite()),
        Some(CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
    s.write_all(b"hello").await.unwrap();
    let mut back = Vec::new();
    s.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"olleh");
}

#[tokio::test]
async fn classical_only_clients_are_refused() {
    let (c, k) = cert();
    let addr = server(c.clone(), k).await;
    // rustls's default groups (X25519, P-256, P-384, X25519MLKEM768 …) but
    // not the profile's hybrid.
    let classical =
        rustls::ClientConfig::builder_with_provider(Arc::new(enclave_tls::compat_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots(&c))
            .with_no_client_auth();
    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let r = TlsConnector::from(Arc::new(classical))
        .connect(ServerName::try_from("front.test").unwrap(), sock)
        .await;
    assert!(r.is_err(), "a handshake without the hybrid must fail");
}

#[test]
fn damaged_shares_fail() {
    // Server side: a client share of the wrong length, or with a point not
    // on the curve, is refused.
    assert!(SECP384R1_MLKEM1024.start_and_complete(&[4; 10]).is_err());
    let client = SECP384R1_MLKEM1024.start().unwrap();
    let mut share = client.pub_key().to_vec();
    share[1] ^= 0xff; // break the point's x-coordinate
    assert!(SECP384R1_MLKEM1024.start_and_complete(&share).is_err());

    // Both sides derive the same secret from good shares, and a client
    // fed a damaged server share gets a different one (or an error).
    let client = SECP384R1_MLKEM1024.start().unwrap();
    let done = SECP384R1_MLKEM1024
        .start_and_complete(client.pub_key())
        .unwrap();
    let client2 = SECP384R1_MLKEM1024.start().unwrap();
    let done2 = SECP384R1_MLKEM1024
        .start_and_complete(client2.pub_key())
        .unwrap();
    let ours = client.complete(&done.pub_key).unwrap();
    assert_eq!(ours.secret_bytes(), done.secret.secret_bytes());
    assert_eq!(ours.secret_bytes().len(), 48 + 32);
    let mut bad = done2.pub_key.clone();
    let n = bad.len();
    bad[n - 1] ^= 1; // the ML-KEM ciphertext: implicit rejection
    let theirs = client2.complete(&bad).unwrap();
    assert_ne!(theirs.secret_bytes(), done2.secret.secret_bytes());
}
