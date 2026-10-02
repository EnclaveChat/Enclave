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
use enclave_kt::c2sp::C2spKey;
use enclave_kt::{KtError, Witness};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A witness and the logs it agrees to witness.
pub struct WitnessService {
    inner: Mutex<Inner>,
    clock: fn() -> u64,
    c2sp: Option<C2spKey>,
}

struct Inner {
    witness: Witness,
    /// Listed logs: server id → head-signing key.
    logs: HashMap<[u8; 16], CompositePublic>,
    descriptor: Vec<u8>,
    /// The C2SP note of the head last cosigned, per log.
    notes: HashMap<[u8; 16], String>,
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
                notes: HashMap::new(),
            }),
            clock,
            c2sp: None,
        }
    }

    /// Also cosign every head in the C2SP `cosignature/v1` format with
    /// `key` (`enclave_kt::c2sp`), served at `/witness/v1/checkpoint/…`.
    pub fn with_c2sp(mut self, key: C2spKey) -> Self {
        self.c2sp = Some(key);
        self
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
        let inner = &mut *inner;
        match inner
            .witness
            .cosign(&key, &req.heads, req.proof, now, &mut rng)
            .await
        {
            Ok(c) => {
                if let (Some(k), Some(h)) = (&self.c2sp, req.heads.last())
                    && let Ok(note) = k.cosign(&h.head, c.time, &mut rng)
                {
                    inner.notes.insert(server, note);
                }
                Ok(c.encode())
            }
            Err(KtError::NotAppendOnly) => Err(StatusCode::CONFLICT),
            Err(KtError::Equivocated) => Err(StatusCode::GONE),
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

    /// Take a proof that a listed log equivocated: `201` if new, `200` if
    /// already held; the log is never cosigned again (`410` from then on).
    pub async fn equivocation(&self, body: &[u8]) -> Result<StatusCode, StatusCode> {
        let e = enclave_kt::Equivocation::decode(body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut inner = self.inner.lock().await;
        let key = inner
            .logs
            .get(&e.server())
            .cloned()
            .ok_or(StatusCode::FORBIDDEN)?;
        match inner.witness.record_equivocation(&key, &e) {
            Ok(true) => {
                eprintln!(
                    "log {} equivocated at epoch {}: no longer witnessed",
                    hex(&e.server()),
                    e.epoch()
                );
                Ok(StatusCode::CREATED)
            }
            Ok(false) => Ok(StatusCode::OK),
            Err(KtError::Directory(_)) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            Err(_) => Err(StatusCode::FORBIDDEN),
        }
    }

    /// The proof held that `server`'s log equivocated.
    pub async fn equivocation_of(&self, server: &[u8; 16]) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .await
            .witness
            .equivocation(server)
            .map(enclave_kt::Equivocation::encode)
    }

    /// The C2SP signed note for the head last cosigned for `server`
    /// (signed afresh after a restart: it's still the newest).
    pub async fn checkpoint(&self, server: &[u8; 16]) -> Option<String> {
        let k = self.c2sp.as_ref()?;
        let now = (self.clock)();
        let mut inner = self.inner.lock().await;
        if let Some(n) = inner.notes.get(server) {
            return Some(n.clone());
        }
        let head = inner.witness.last_head(server)?;
        let mut rng = enclave_crypto::rng::HedgedRng::new().ok()?;
        let note = k.cosign(&head, now, &mut rng).ok()?;
        inner.notes.insert(*server, note.clone());
        Some(note)
    }

    /// The HTTP routes.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/witness/v1/descriptor", get(descriptor))
            .route("/witness/v1/c2sp-key", get(c2sp_key))
            .route("/witness/v1/checkpoint/{server}", get(checkpoint))
            .route("/witness/v1/last/{server}", get(last))
            .route("/witness/v1/cosign", post(cosign))
            .route("/witness/v1/equivocation", post(equivocation))
            .route("/witness/v1/equivocation/{server}", get(equivocation_of))
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

async fn c2sp_key(State(s): State<Arc<WitnessService>>) -> Result<String, StatusCode> {
    s.c2sp
        .as_ref()
        .map(|k| k.vkeys().iter().map(|v| format!("{v}\n")).collect())
        .ok_or(StatusCode::NOT_FOUND)
}

async fn checkpoint(
    State(s): State<Arc<WitnessService>>,
    Path(server): Path<String>,
) -> Result<String, StatusCode> {
    let id: [u8; 16] = enclave_service::config::unhex(&server)
        .and_then(|b| b.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    s.checkpoint(&id).await.ok_or(StatusCode::NOT_FOUND)
}

async fn equivocation(State(s): State<Arc<WitnessService>>, body: Bytes) -> StatusCode {
    s.equivocation(&body).await.unwrap_or_else(|e| e)
}

async fn equivocation_of(
    State(s): State<Arc<WitnessService>>,
    Path(server): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let id: [u8; 16] = enclave_service::config::unhex(&server)
        .and_then(|b| b.try_into().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    s.equivocation_of(&id).await.ok_or(StatusCode::NOT_FOUND)
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
