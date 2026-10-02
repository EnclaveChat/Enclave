//! Enclave's TLS profile (`docs/09-transport.md` §8).
//!
//! The front (server descriptors), witnesses and update endpoints speak TLS
//! 1.3 with one cipher suite, `TLS_AES_256_GCM_SHA384`, and one key
//! exchange, **SecP384r1MLKEM1024** (codepoint 0x11ED,
//! draft-ietf-tls-ecdhe-mlkem): a P-384 ECDH share and an ML-KEM-1024 share,
//! classical first, the shared secret `ECDH ‖ ML-KEM`. A recorded handshake
//! stays confidential if either half holds.
//!
//! The hybrid is built here from two pure-Rust halves: ML-KEM-1024 from
//! `enclave-crypto` (libcrux, the same code that seals every message) and
//! P-384 from RustCrypto's `p384`. rustls (with `ring` for AES-GCM and
//! certificate signatures) runs the protocol.
//!
//! [`provider`] is the profile for anything Enclave runs, inbound and
//! outbound between Enclave services. [`compat_provider`] is rustls's
//! default and exists only for talking to the outside world that doesn't
//! offer the hybrid yet (the ACME CA when the front fetches its
//! certificate).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod kx;

pub use kx::{SECP384R1_MLKEM1024, SECP384R1_MLKEM1024_ID};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// The Enclave profile: TLS 1.3, `TLS_AES_256_GCM_SHA384`, SecP384r1MLKEM1024.
pub fn provider() -> CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    CryptoProvider {
        cipher_suites: vec![rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![SECP384R1_MLKEM1024],
        ..base
    }
}

/// rustls's default profile, for the outside world only (the ACME CA).
pub fn compat_provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// A server configuration with the Enclave profile.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

/// A client configuration with the Enclave profile, trusting `roots`.
pub fn client_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig, rustls::Error> {
    let mut c = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}
