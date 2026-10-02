//! Certificates from an ACME CA (Let's Encrypt by default) by HTTP-01.
//!
//! The account key and the certificate are kept in the front's data
//! directory; the certificate is renewed when it has less than
//! [`RENEW_DAYS`] left. ACME traffic goes to the CA with rustls's default
//! profile (the CA doesn't offer the hybrid key exchange); everything the
//! front serves uses the Enclave profile.

use crate::{CertStore, Challenges};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use std::path::PathBuf;

/// Renew a certificate with fewer days than this left.
pub const RENEW_DAYS: i64 = 30;

/// Where and how to get certificates.
#[derive(Clone, Debug)]
pub struct AcmeConfig {
    /// The domain to certify.
    pub domain: String,
    /// Contact address for the CA (optional).
    pub email: Option<String>,
    /// ACME directory URL.
    pub directory: String,
    /// A PEM root to trust for the CA itself (a test CA such as pebble);
    /// the public web's roots otherwise.
    pub ca_root: Option<PathBuf>,
    /// Account key and certificate.
    pub data_dir: PathBuf,
}

/// Let's Encrypt's production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

fn err(e: impl core::fmt::Display) -> String {
    format!("acme: {e}")
}

/// Days until the first certificate in `chain_pem` expires.
pub fn days_left(chain_pem: &str, now: i64) -> Option<i64> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let der = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()?
        .ok()?;
    Some((not_after(&der)? - now).div_euclid(86_400))
}

/// One DER element: (tag, contents, what follows).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, b) = b.split_first()?;
    let (len, b) = if first < 0x80 {
        (usize::from(first), b)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let len = b[..n]
            .iter()
            .fold(0usize, |a, &x| (a << 8) | usize::from(x));
        (len, &b[n..])
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// A certificate's notAfter (RFC 5280 §4.1.2.5) as Unix seconds.
fn not_after(der: &[u8]) -> Option<i64> {
    let (0x30, cert, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(cert)? else {
        return None;
    };
    let (tag, _, mut rest) = tlv(tbs)?;
    if tag == 0xa0 {
        // version; the serial number follows
        rest = tlv(rest)?.2;
    }
    let rest = tlv(rest)?.2; // signature algorithm
    let rest = tlv(rest)?.2; // issuer
    let (0x30, validity, _) = tlv(rest)? else {
        return None;
    };
    let (_, _, validity) = tlv(validity)?; // notBefore
    let (tag, t, _) = tlv(validity)?;
    let t = std::str::from_utf8(t).ok()?;
    let digits = |s: &str| -> Option<i64> {
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (year, t) = match tag {
        // UTCTime YYMMDDHHMMSSZ: 50–99 are 19xx
        0x17 if t.len() == 13 => {
            let y = digits(&t[..2])?;
            (if y >= 50 { 1900 + y } else { 2000 + y }, &t[2..])
        }
        // GeneralizedTime YYYYMMDDHHMMSSZ
        0x18 if t.len() == 15 => (digits(&t[..4])?, &t[4..]),
        _ => return None,
    };
    if !t.ends_with('Z') {
        return None;
    }
    let (mo, d) = (digits(&t[0..2])?, digits(&t[2..4])?);
    let (h, mi, s) = (digits(&t[4..6])?, digits(&t[6..8])?, digits(&t[8..10])?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if mo <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// The HTTPS client for the CA: rustls's default profile
/// ([`enclave_tls::compat_provider`]), the public web's roots plus
/// `ca_root`.
fn ca_client(cfg: &AcmeConfig) -> Result<Box<dyn instant_acme::HttpClient>, String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(p) = &cfg.ca_root {
        let pem = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots
                .add(c.map_err(|e| format!("{}: {e}", p.display()))?)
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        enclave_tls::compat_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(err)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, instant_acme::BodyWrapper<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    Ok(Box::new(client))
}

async fn account(cfg: &AcmeConfig) -> Result<Account, String> {
    let builder = Account::builder_with_http(ca_client(cfg)?);
    let path = cfg.data_dir.join("acme-account.json");
    if let Ok(b) = std::fs::read(&path) {
        let creds: AccountCredentials = serde_json::from_slice(&b).map_err(err)?;
        return builder.from_credentials(creds).await.map_err(err);
    }
    let contact: Vec<String> = cfg.email.iter().map(|e| format!("mailto:{e}")).collect();
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = builder
        .create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            cfg.directory.clone(),
            None,
        )
        .await
        .map_err(err)?;
    let json = serde_json::to_vec(&creds).map_err(err)?;
    enclave_service::keyfile::write_secret(&path, &json).map_err(err)?;
    Ok(account)
}

/// Get a new certificate for `cfg.domain`, answering the CA's HTTP-01
/// challenge through `challenges` (served on port 80). Returns the PEM
/// chain and key.
pub async fn obtain(cfg: &AcmeConfig, challenges: &Challenges) -> Result<(String, String), String> {
    let account = account(cfg).await?;
    let ids = [Identifier::Dns(cfg.domain.clone())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await.map_err(err)?;
    let mut tokens = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(a) = authorizations.next().await {
            let mut a = a.map_err(err)?;
            if a.status == AuthorizationStatus::Valid {
                continue;
            }
            let mut ch = a
                .challenge(ChallengeType::Http01)
                .ok_or("acme: the CA offers no HTTP-01 challenge")?;
            let token = ch.token.clone();
            let answer = ch.key_authorization().as_str().to_string();
            if let Ok(mut m) = challenges.write() {
                m.insert(token.clone(), answer);
            }
            tokens.push(token);
            ch.set_ready().await.map_err(err)?;
        }
    }
    let result = async {
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(err)?;
        if status != OrderStatus::Ready {
            return Err(format!("acme: order ended {status:?}"));
        }
        let key = order.finalize().await.map_err(err)?;
        let chain = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(err)?;
        Ok((chain, key))
    }
    .await;
    if let Ok(mut m) = challenges.write() {
        for t in &tokens {
            m.remove(t);
        }
    }
    result
}

/// Make sure `certs` holds a certificate with more than [`RENEW_DAYS`]
/// left: the one on disk if it's fresh enough, otherwise a new one from
/// the CA (written to disk, key mode 0600).
pub async fn ensure(
    cfg: &AcmeConfig,
    challenges: &Challenges,
    certs: &CertStore,
    now: i64,
) -> Result<(), String> {
    let cert_path = cfg.data_dir.join("cert.pem");
    let key_path = cfg.data_dir.join("key.pem");
    if let (Ok(chain), Ok(key)) = (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) && days_left(&chain, now).is_some_and(|d| d > RENEW_DAYS)
    {
        if !certs.ready() {
            certs.set_pem(&chain, &key)?;
        }
        return Ok(());
    }
    let (chain, key) = obtain(cfg, challenges).await?;
    certs.set_pem(&chain, &key)?;
    enclave_service::keyfile::write_secret(&key_path, key.as_bytes()).map_err(err)?;
    std::fs::write(&cert_path, &chain).map_err(err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_until(y: i32, m: u8, d: u8) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["a.test".into()]).unwrap();
        p.not_after = rcgen::date_time_ymd(y, m, d);
        p.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn expiry_read_from_utc_and_generalized_time() {
        // 2030-03-01T00:00:00Z (UTCTime) and 2060-01-01 (GeneralizedTime).
        let c = cert_until(2030, 3, 1);
        assert_eq!(days_left(&c, 1_898_553_600), Some(0));
        assert_eq!(days_left(&c, 1_898_553_600 - 40 * 86_400), Some(40));
        assert_eq!(days_left(&c, 1_898_553_600 + 1), Some(-1));
        let g = cert_until(2060, 1, 1);
        assert_eq!(days_left(&g, 2_840_140_800), Some(0));
        assert_eq!(days_left("no certificate", 0), None);
        assert_eq!(not_after(&[0x30, 0x81]), None);
    }
}
