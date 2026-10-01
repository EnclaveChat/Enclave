//! The vault's side of `mediad` (`docs/15-client.md` §1.1a).
//!
//! Pictures are decoded and re-encoded in `enclave-mediad`, a confined
//! process with no keys, no files and no sockets, started (like netd)
//! before the vault confines itself. Where it is missing, the same code runs
//! in the vault on a blocking thread and the hardening report says so.

use enclave_ipc::frame;
use enclave_ipc::media::{MediaOp, MediaOut, MediaReply, MediaRequest};
use enclave_media::{Format, Rgba, Sanitized};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<MediaOut, String>>>>>;

/// Spare `mediad` processes started with the first: the vault can't start
/// programs once it is confined, so a helper that dies (a picture that
/// crashes the decoder, say) is replaced by a spare that is already
/// running. When all are gone, pictures fail until the app restarts.
pub const SPARES: usize = 2;

/// Where pictures are handled.
pub struct Media {
    /// The helpers, first live one used; empty means in this process.
    procs: Vec<Proc>,
}

struct Proc {
    next: AtomicU32,
    out: mpsc::UnboundedSender<Vec<u8>>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    _child: Mutex<Child>,
}

/// Where `enclave-mediad` should be: next to this executable.
pub fn mediad_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.with_file_name(format!("enclave-mediad{}", std::env::consts::EXE_SUFFIX));
    p.exists().then_some(p)
}

impl Proc {
    fn spawn(bin: &std::path::Path) -> std::io::Result<Self> {
        let mut child = Command::new(bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("no stdin"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("no stdout"))?;
        let (out, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(async move {
            while let Some(body) = rx.recv().await {
                if frame::write_frame(&mut stdin, &body).await.is_err() {
                    break;
                }
            }
        });
        let p = Arc::clone(&pending);
        let a = Arc::clone(&alive);
        tokio::spawn(async move {
            while let Ok(body) = frame::read_frame(&mut stdout).await {
                let Ok(reply) = MediaReply::decode(&body) else {
                    break;
                };
                if let Some(tx) = p.lock().await.remove(&reply.id) {
                    let _ = tx.send(reply.result);
                }
            }
            // This helper stopped: what was waiting on it fails, and the
            // next call goes to a spare.
            a.store(false, Ordering::SeqCst);
            p.lock().await.clear();
        });
        Ok(Self {
            next: AtomicU32::new(1),
            out,
            pending,
            alive,
            _child: Mutex::new(child),
        })
    }
}

impl Media {
    /// Decode in this process (demo, tests, or no mediad).
    pub fn in_process() -> Self {
        Self { procs: Vec::new() }
    }

    /// Whether pictures are handled by a separate process.
    pub fn separate(&self) -> bool {
        !self.procs.is_empty()
    }

    /// Helpers still running.
    pub fn alive(&self) -> usize {
        self.procs
            .iter()
            .filter(|p| p.alive.load(Ordering::SeqCst))
            .count()
    }

    /// Start `mediad` and `spares` more. Must run inside a tokio runtime,
    /// before the vault confines itself.
    pub fn spawn(bin: &std::path::Path, spares: usize) -> std::io::Result<Self> {
        let bins = vec![bin.to_path_buf(); spares + 1];
        Self::spawn_each(&bins)
    }

    /// Start one helper per program, in order of use (the first must start;
    /// a spare that doesn't is skipped). `spawn` uses the same program for
    /// all; tests use this to start a helper that dies at once.
    pub fn spawn_each(bins: &[std::path::PathBuf]) -> std::io::Result<Self> {
        let (first, rest) = bins
            .split_first()
            .ok_or_else(|| std::io::Error::other("no helper"))?;
        let mut procs = vec![Proc::spawn(first)?];
        procs.extend(rest.iter().filter_map(|b| Proc::spawn(b).ok()));
        Ok(Self { procs })
    }

    async fn call(&self, op: MediaOp, bytes: Vec<u8>) -> Result<MediaOut, String> {
        if self.procs.is_empty() {
            return tokio::task::spawn_blocking(move || local(op, &bytes))
                .await
                .map_err(|_| "the decoder stopped".to_string())?;
        }
        let Some(p) = self.procs.iter().find(|p| p.alive.load(Ordering::SeqCst)) else {
            return Err("mediad stopped".into());
        };
        let id = p.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        p.pending.lock().await.insert(id, tx);
        // The reader marks a helper dead before failing what's pending, so
        // a request added after that is caught here instead of waiting
        // forever.
        if !p.alive.load(Ordering::SeqCst) {
            p.pending.lock().await.remove(&id);
            return Err("mediad stopped".into());
        }
        if p.out.send(MediaRequest { id, op, bytes }.encode()).is_err() {
            p.alive.store(false, Ordering::SeqCst);
            return Err("mediad stopped".into());
        }
        rx.await.map_err(|_| "mediad stopped".to_string())?
    }

    /// Re-encode a picture for sending.
    pub async fn sanitize(&self, bytes: Vec<u8>) -> Result<Sanitized, String> {
        match self.call(MediaOp::Sanitize, bytes).await? {
            MediaOut::Sanitized {
                png,
                width,
                height,
                bytes,
            } => Ok(Sanitized {
                format: if png { Format::Png } else { Format::Jpeg },
                width,
                height,
                bytes,
            }),
            MediaOut::Rgba { .. } => Err("unexpected reply".into()),
        }
    }

    /// Re-encode a picture at most `side` pixels on the long side (a sticker).
    pub async fn shrink(&self, bytes: Vec<u8>, side: u16) -> Result<Sanitized, String> {
        match self.call(MediaOp::Shrink(side), bytes).await? {
            MediaOut::Sanitized {
                png,
                width,
                height,
                bytes,
            } => Ok(Sanitized {
                format: if png { Format::Png } else { Format::Jpeg },
                width,
                height,
                bytes,
            }),
            MediaOut::Rgba { .. } => Err("unexpected reply".into()),
        }
    }

    /// Decode a picture to at most `side` pixels on the long side.
    pub async fn thumbnail(&self, bytes: Vec<u8>, side: u16) -> Result<Rgba, String> {
        match self.call(MediaOp::Thumbnail(side), bytes).await? {
            MediaOut::Rgba {
                width,
                height,
                pixels,
            } => Ok(Rgba {
                width,
                height,
                pixels,
            }),
            MediaOut::Sanitized { .. } => Err("unexpected reply".into()),
        }
    }
}

fn local(op: MediaOp, bytes: &[u8]) -> Result<MediaOut, String> {
    match op {
        MediaOp::Sanitize => enclave_media::sanitize(bytes).map(|s| MediaOut::Sanitized {
            png: s.format == Format::Png,
            width: s.width,
            height: s.height,
            bytes: s.bytes,
        }),
        MediaOp::Shrink(side) => {
            enclave_media::sanitize_max(bytes, u32::from(side)).map(|s| MediaOut::Sanitized {
                png: s.format == Format::Png,
                width: s.width,
                height: s.height,
                bytes: s.bytes,
            })
        }
        MediaOp::Thumbnail(side) => {
            enclave_media::thumbnail(bytes, u32::from(side)).map(|t| MediaOut::Rgba {
                width: t.width,
                height: t.height,
                pixels: t.pixels,
            })
        }
    }
    .map_err(|e| e.to_string())
}
