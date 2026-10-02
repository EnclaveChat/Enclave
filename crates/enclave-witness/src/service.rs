//! The witness side: state, the HTTP routes, and serving them (plain HTTP
//! behind a front, or HTTPS with the Enclave TLS profile).

use crate::{CosignRequest, MAX_REQUEST, hex};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use enclave_crypto::sig::CompositePublic;
use enclave_federation::ServerList;
use enclave_kt::{KtError, Witness};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A witness and the logs it agrees to witness.
pub struct WitnessService {
    inner: Mutex<Inner>,
    clock: fn() -> u64,
}

struct Inner {
    witness: Witness,
    /// Listed logs: server id → head-signing key.
    logs: HashMap<[u8; 16], CompositePublic>,
    descriptor: Vec<u8>,
}

fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl WitnessService {
    /// A service around `witness` (give it a store, `Witness::with_store`,
    /// so it remembers what it cosigned), serving `descriptor`.
    pub fn new(witness: Witness, descriptor: Vec<u8>) -> Self {
        Self::with_clock(witness, descriptor, system_now)
    }

    /// Like [`WitnessService::new`] with another clock (tests).
    pub fn with_clock(witness: Witness, descriptor: Vec<u8>, clock: fn() -> u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                witness,
                logs: HashMap::new(),
                descriptor,
            }),
            clock,
        }
    }

    /// Witness the logs of the servers in `list` (those that run one),
    /// under the head keys it pins. Replaces the previous set.
    pub async fn set_logs(&self, list: &ServerList) -> usize {
        let logs: HashMap<_, _> = list
            .servers
            .iter()
            .filter_map(|s| s.kt.as_ref().map(|k| (s.id(), k.head_key.clone())))
            .collect();
        let n = logs.len();
        self.inner.lock().await.logs = logs;
        n
    }

    /// Replace the descriptor served.
    pub async fn set_descriptor(&self, descriptor: Vec<u8>) {
        self.inner.lock().await.descriptor = descriptor;
    }

    /// Handle a cosigning request; the encoded cosignature, or the HTTP
    /// status to refuse with.
    pub async fn cosign(&self, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
        let req = CosignRequest::decode(body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let server = req
            .heads
            .last()
            .map(|h| h.head.server)
            .ok_or(StatusCode::BAD_REQUEST)?;
        let now = (self.clock)();
        let mut inner = self.inner.lock().await;
        let key = inner
            .logs
            .get(&server)
            .cloned()
            .ok_or(StatusCode::FORBIDDEN)?;
        let mut rng =
            enclave_crypto::rng::HedgedRng::new().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        match inner
            .witness
            .cosign(&key, &req.heads, req.proof, now, &mut rng)
            .await
        {
            Ok(c) => Ok(c.encode()),
            Err(KtError::NotAppendOnly) => Err(StatusCode::CONFLICT),
            Err(KtError::Signature) => Err(StatusCode::FORBIDDEN),
            Err(KtError::Directory(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }

    /// The head last cosigned for `server`.
    pub async fn last(&self, server: &[u8; 16]) -> Option<[u8; 64]> {
        self.inner
            .lock()
            .await
            .witness
            .last_head(server)
            .map(|h| h.encode())
    }

    /// The HTTP routes.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/witness/v1/descriptor", get(descriptor))
            .route("/witness/v1/last/{server}", get(last))
            .route("/witness/v1/cosign", post(cosign))
            .layer(DefaultBodyLimit::max(MAX_REQUEST))
            .with_state(self)
    }
}

async fn descriptor(State(s): State<Arc<WitnessService>>) -> Result<Vec<u8>, StatusCode> {
    let d = s.inner.lock().await.descriptor.clone();
    if d.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(d)
}

async fn last(
    State(s): State<Arc<WitnessService>>,
    Path(server): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let id: [u8; 16] = enclave_service::config::unhex(&server)
        .and_then(|b| b.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    s.last(&id)
        .await
        .map(|h| h.to_vec())
        .ok_or(StatusCode::NOT_FOUND)
}

async fn cosign(State(s): State<Arc<WitnessService>>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    s.cosign(&body).await
}

/// Serve `router` on `listener`: HTTPS with the Enclave TLS profile when
/// `tls` is given, plain HTTP otherwise (behind a front, or in tests).
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> std::io::Result<()> {
    let Some(tls) = tls else {
        return axum::serve(listener, router).await;
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let (sock, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(sock).await else {
                return;
            };
            let svc = hyper_util::service::TowerToHyperService::new(router);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
}

/// Load a PEM certificate chain and private key for [`serve`].
pub fn load_tls(
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let read = |p: &std::path::Path| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_slice_iter(&read(cert)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&read(key)?)
        .map_err(|e| format!("{}: {e}", key.display()))?;
    enclave_tls::server_config(certs, key)
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

/// Server id from a hex path segment (for logs).
pub fn id_hex(id: &[u8; 16]) -> String {
    hex(id)
}
