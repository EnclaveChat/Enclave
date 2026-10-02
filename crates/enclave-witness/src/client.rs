//! Reaching a witness from a log's server: [`HttpWitness`].

use crate::{CosignRequest, hex};
use akd::AppendOnlyProof;
use bytes::Bytes;
use enclave_crypto::sig::CompositePublic;
use enclave_federation::WitnessDescriptor;
use enclave_kt::{Cosignature, KtError, SignedHead, TreeHead, WitnessClient};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::time::Duration;

type Http = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// How long a witness gets to answer.
const TIMEOUT: Duration = Duration::from_secs(20);

/// A witness reached over HTTPS (the Enclave TLS profile). Plain `http://`
/// is accepted for a witness on the same host or private network.
pub struct HttpWitness {
    base: String,
    id: [u8; 16],
    descriptor: Option<WitnessDescriptor>,
    http: Http,
}

impl HttpWitness {
    /// Fetch the witness's descriptor from `base` (for example
    /// `https://witness.example`), check it, and remember its id. `extra_ca`
    /// is a PEM file of roots to trust besides the public web's (a test or
    /// private CA).
    pub async fn connect(
        base: &str,
        extra_ca: Option<&std::path::Path>,
        now: u64,
    ) -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(p) = extra_ca {
            use rustls::pki_types::CertificateDer;
            use rustls::pki_types::pem::PemObject;
            let pem = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            for c in CertificateDer::pem_slice_iter(&pem) {
                roots
                    .add(c.map_err(|e| format!("{}: {e}", p.display()))?)
                    .map_err(|e| format!("{}: {e}", p.display()))?;
            }
        }
        let mut tls = enclave_tls::client_config(roots).map_err(|e| e.to_string())?;
        // hyper-rustls sets ALPN itself.
        tls.alpn_protocols.clear();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        let http = Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector);
        let mut w = Self {
            base: base.trim_end_matches('/').to_string(),
            id: [0; 16],
            descriptor: None,
            http,
        };
        let (status, body) = w.request("GET", "/witness/v1/descriptor", None).await?;
        if status != 200 {
            return Err(format!("{base}: descriptor: HTTP {status}"));
        }
        let d = WitnessDescriptor::decode(&body).map_err(|e| format!("{base}: descriptor: {e}"))?;
        d.verify(now)
            .map_err(|e| format!("{base}: descriptor: {e}"))?;
        w.id = d.id();
        w.descriptor = Some(d);
        Ok(w)
    }

    /// The descriptor fetched at connection (key, operator, family).
    pub fn descriptor(&self) -> Option<&WitnessDescriptor> {
        self.descriptor.as_ref()
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), String> {
        let req = hyper::Request::builder()
            .method(method)
            .uri(format!("{}{path}", self.base))
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .map_err(|e| e.to_string())?;
        let res = tokio::time::timeout(TIMEOUT, self.http.request(req))
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())?;
        let status = res.status().as_u16();
        let bytes = tokio::time::timeout(TIMEOUT, res.into_body().collect())
            .await
            .map_err(|_| "timeout".to_string())?
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
}

#[async_trait::async_trait]
impl WitnessClient for HttpWitness {
    fn witness_id(&self) -> [u8; 16] {
        self.id
    }

    async fn last_epoch(&mut self, server: &[u8; 16]) -> Option<u64> {
        let (status, body) = self
            .request("GET", &format!("/witness/v1/last/{}", hex(server)), None)
            .await
            .ok()?;
        if status != 200 {
            return None;
        }
        TreeHead::decode(&body)
            .ok()
            .filter(|h| h.server == *server)
            .map(|h| h.epoch)
    }

    async fn cosign(
        &mut self,
        _server_key: &CompositePublic,
        heads: &[SignedHead],
        proof: Option<AppendOnlyProof>,
        _now: u64,
    ) -> Result<Cosignature, KtError> {
        let body = CosignRequest {
            heads: heads.to_vec(),
            proof,
        }
        .encode()?;
        let (status, reply) = self
            .request("POST", "/witness/v1/cosign", Some(body))
            .await
            .map_err(KtError::Directory)?;
        match status {
            200 => {
                let c = Cosignature::decode(&reply)?;
                if c.witness != self.id {
                    return Err(KtError::Signature);
                }
                Ok(c)
            }
            409 => Err(KtError::NotAppendOnly),
            403 => Err(KtError::Signature),
            s => Err(KtError::Directory(format!("witness answered HTTP {s}"))),
        }
    }
}

/// A witness reached over HTTPS, connected on first use and again after a
/// failed connection: a server starts whether or not its witnesses are up,
/// and heads get their cosignatures once they are.
pub struct LazyWitness {
    base: String,
    extra_ca: Option<std::path::PathBuf>,
    inner: Option<HttpWitness>,
}

impl LazyWitness {
    /// A witness at `base`, trusting `extra_ca` besides the public roots.
    pub fn new(base: &str, extra_ca: Option<&std::path::Path>) -> Self {
        Self {
            base: base.to_string(),
            extra_ca: extra_ca.map(std::path::Path::to_path_buf),
            inner: None,
        }
    }

    /// The connected witness, connecting (and checking its descriptor) if
    /// needed.
    async fn get(&mut self, now: u64) -> Result<&mut HttpWitness, String> {
        if self.inner.is_none() {
            let w = HttpWitness::connect(&self.base, self.extra_ca.as_deref(), now).await?;
            self.inner = Some(w);
        }
        self.inner
            .as_mut()
            .ok_or_else(|| "not connected".to_string())
    }

    /// The witness's descriptor, once connected.
    pub fn descriptor(&self) -> Option<&WitnessDescriptor> {
        self.inner.as_ref().and_then(HttpWitness::descriptor)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait::async_trait]
impl WitnessClient for LazyWitness {
    /// All zeros until connected (the id comes from its descriptor).
    fn witness_id(&self) -> [u8; 16] {
        self.inner.as_ref().map_or([0; 16], |w| w.id)
    }

    async fn last_epoch(&mut self, server: &[u8; 16]) -> Option<u64> {
        let now = unix_now();
        self.get(now).await.ok()?.last_epoch(server).await
    }

    async fn cosign(
        &mut self,
        server_key: &CompositePublic,
        heads: &[SignedHead],
        proof: Option<AppendOnlyProof>,
        now: u64,
    ) -> Result<Cosignature, KtError> {
        let base = self.base.clone();
        let w = self
            .get(now)
            .await
            .map_err(|e| KtError::Directory(format!("witness {base}: {e}")))?;
        w.cosign(server_key, heads, proof, now).await
    }
}
