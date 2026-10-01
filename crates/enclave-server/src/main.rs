//! The Enclave server binary (`docs/12-servers.md` §1, `ops/compose`).
//!
//! ```text
//! enclave-server init        [--config FILE]   create keys; print the server id
//! enclave-server run         [--config FILE]   serve (state in redb, keys from disk)
//! enclave-server show-id     [--config FILE]   print the server id
//! enclave-server backup DIR  [--config FILE]   write a consistent snapshot now
//! enclave-server healthcheck [--config FILE]   exit 0 if the server answers
//! enclave-server dev [ADDR] [--domain NAME] [--kt-pins FILE] [--push-relay ADDR]
//! ```
//!
//! `run` listens on `server.listen` with the length-prefixed frame
//! transport (`u32 BE length ‖ bytes`; a zero-length frame asks for the
//! current request key). In production that port is reachable only from
//! the Nym ingress on the stack's internal network, never from outside.
//!
//! `dev` is the old all-in-memory development server: random keys every
//! start, nothing persisted. It is what a bare `enclave-server [ADDR]`
//! runs, for local development and the test suites.

use enclave_server::config::FileConfig;
use enclave_server::db::Db;
use enclave_server::keys::ServerKeys;
use enclave_server::{Config, Server};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn today() -> u32 {
    (now() / 86_400) as u32
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn flag(args: &[String], k: &str) -> Option<String> {
    args.iter()
        .position(|a| a == k)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn load_config(args: &[String]) -> Result<FileConfig, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    FileConfig::load(path.as_deref(), std::env::vars()).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("dev");
    let result = match cmd {
        "init" => init(&args),
        "run" => runtime().and_then(|rt| rt.block_on(run(&args))),
        "show-id" => show_id(&args),
        "backup" => backup_now(&args),
        "healthcheck" => runtime().and_then(|rt| rt.block_on(healthcheck(&args))),
        "dev" => runtime().and_then(|rt| rt.block_on(dev(&args[1.min(args.len())..]))),
        "--help" | "-h" | "help" => {
            eprintln!(
                "usage: enclave-server init|run|show-id|healthcheck [--config FILE]\n       enclave-server backup DIR [--config FILE]\n       enclave-server dev [ADDR] [--domain NAME] [--kt-pins FILE] [--push-relay ADDR]"
            );
            Ok(())
        }
        // `enclave-server [ADDR] [--flags]`: the development server.
        _ => runtime().and_then(|rt| rt.block_on(dev(&args))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

fn init(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = ServerKeys::init(&cfg.server.keys_dir, today()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cfg.server.data_dir).map_err(|e| e.to_string())?;
    println!("{}", hex(&keys.id()));
    eprintln!(
        "keys created in {}; back this directory up somewhere safe and offline",
        cfg.server.keys_dir.display()
    );
    Ok(())
}

fn show_id(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let keys = ServerKeys::load(&cfg.server.keys_dir).map_err(|e| e.to_string())?;
    println!("{}", hex(&keys.id()));
    Ok(())
}

fn db_path(cfg: &FileConfig) -> PathBuf {
    cfg.server.data_dir.join("server.redb")
}

/// Write `server-<unix time>.redb` into `dir` and keep the newest `keep`.
fn snapshot(db: &Db, dir: &Path, keep: usize) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("server-{}.redb", now()));
    db.snapshot(&path).map_err(|e| e.to_string())?;
    let mut old: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("server-") && n.ends_with(".redb"))
        })
        .collect();
    old.sort();
    while old.len() > keep.max(1) {
        let p = old.remove(0);
        let _ = std::fs::remove_file(p);
    }
    Ok(path)
}

fn backup_now(args: &[String]) -> Result<(), String> {
    let dir = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .ok_or("usage: enclave-server backup DIR")?;
    let cfg = load_config(args)?;
    // redb allows one process per file: this works only while `run` is
    // stopped; a running server takes its own snapshots (`[backup]`).
    let db = Db::open(&db_path(&cfg)).map_err(|e| e.to_string())?;
    let p = snapshot(&db, Path::new(dir), usize::MAX)?;
    println!("{}", p.display());
    Ok(())
}

async fn healthcheck(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut s = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(cfg.server.listen),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e.to_string())?;
    s.write_all(&0u32.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut len = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut len))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if u32::from_be_bytes(len) == 0 {
        return Err("no request key".into());
    }
    Ok(())
}

async fn run(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let mut keys = ServerKeys::load(&cfg.server.keys_dir).map_err(|e| e.to_string())?;
    keys.chain.advance_to(today()).map_err(|e| e.to_string())?;
    let id = keys.id();
    std::fs::create_dir_all(&cfg.server.data_dir).map_err(|e| e.to_string())?;
    let db = Db::open(&db_path(&cfg)).map_err(|e| e.to_string())?;
    let mut server =
        Server::open(cfg.policy(id), db, keys.chain.keys()).map_err(|e| e.to_string())?;
    if cfg.kt.enabled {
        match enclave_kt::KtService::start_dev(id, &cfg.server.domain) {
            Ok((kt, policy)) => {
                server.enable_kt(kt);
                let _ = std::fs::create_dir_all(&cfg.server.public_dir);
                let pins = cfg.server.public_dir.join("kt-pins.bin");
                if let Err(e) = std::fs::write(&pins, policy.encode()) {
                    eprintln!("couldn't write {}: {e}", pins.display());
                }
            }
            Err(e) => eprintln!("usernames disabled: {e}"),
        }
    }
    eprintln!(
        "enclave-server {} ({}) listening on {}",
        hex(&id),
        cfg.server.domain,
        cfg.server.listen
    );
    let server = Arc::new(Mutex::new(server));
    let keys = Arc::new(Mutex::new(keys));

    // Once a minute: step the request-key chain at midnight UTC (yesterday's
    // seed is kept a day, older ones are erased) and expire old objects.
    {
        let server = Arc::clone(&server);
        let keys = Arc::clone(&keys);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let mut k = keys.lock().await;
                match k.chain.advance_to(today()) {
                    Ok(true) => {
                        let mut s = server.lock().await;
                        for key in k.chain.keys().into_iter().rev() {
                            s.install_key(key);
                        }
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("request-key rotation failed: {e}"),
                }
                drop(k);
                server.lock().await.expire(now());
            }
        });
    }
    if let Some(dir) = cfg.backup.dir.clone() {
        let server = Arc::clone(&server);
        let every = Duration::from_secs(cfg.backup.interval_hours.max(1) * 3600);
        let keep = cfg.backup.keep;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let s = server.lock().await;
                match snapshot(s.db(), &dir, keep) {
                    Ok(p) => eprintln!("backup written: {}", p.display()),
                    Err(e) => eprintln!("backup failed: {e}"),
                }
            }
        });
    }
    if let Some(fwd) = cfg.push.forward {
        spawn_push_forwarder(Arc::clone(&server), fwd.to_string());
    }
    let listener = TcpListener::bind(cfg.server.listen)
        .await
        .map_err(|e| e.to_string())?;
    let accept = serve(listener, Arc::clone(&server));
    tokio::select! {
        r = accept => r,
        _ = shutdown_signal() => {
            // Every request commits before its reply, so taking the lock
            // waits for the one in flight; then the process can stop.
            let _ = server.lock().await;
            eprintln!("enclave-server: stopped");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn spawn_push_forwarder(server: Arc<Mutex<Server>>, to: String) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let due = server.lock().await.due_wakes(now());
            if due.is_empty() {
                continue;
            }
            match tokio::net::TcpStream::connect(&to).await {
                Ok(mut s) => {
                    for sealed in due {
                        let _ = s.write_all(&(sealed.len() as u32).to_be_bytes()).await;
                        let _ = s.write_all(&sealed).await;
                    }
                }
                Err(e) => eprintln!("push forwarder unreachable: {e}"),
            }
        }
    });
}

async fn serve(listener: TcpListener, server: Arc<Mutex<Server>>) -> Result<(), String> {
    loop {
        let (mut sock, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 4];
                if sock.read_exact(&mut len).await.is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n > enclave_wire::UNIT_LEN {
                    return;
                }
                let mut buf = vec![0u8; n];
                if sock.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let reply = {
                    let mut s = server.lock().await;
                    if n == 0 {
                        s.public_key().map(|k| k.to_bytes()).unwrap_or_default()
                    } else {
                        s.handle(&buf, now())
                    }
                };
                if sock
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .await
                    .is_err()
                    || sock.write_all(&reply).await.is_err()
                {
                    return;
                }
            }
        });
    }
}

/// The in-memory development server (`enclave-server [ADDR] …`).
async fn dev(args: &[String]) -> Result<(), String> {
    let addr = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7443".to_string());
    let day = today();
    let cfg = Config::default();
    let id = cfg.id;
    let mut server = Server::new(cfg, day).map_err(|e| e.to_string())?;
    let domain = flag(args, "--domain").unwrap_or_else(|| "localhost".to_string());
    match enclave_kt::KtService::start_dev(id, &domain) {
        Ok((kt, policy)) => {
            server.enable_kt(kt);
            if let Some(path) = flag(args, "--kt-pins") {
                std::fs::write(&path, policy.encode()).map_err(|e| e.to_string())?;
                eprintln!("usernames on @{domain}; clients pin {path}");
            }
        }
        Err(e) => eprintln!("usernames disabled: {e}"),
    }
    let server = Arc::new(Mutex::new(server));
    {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            let mut current = day;
            loop {
                tick.tick().await;
                let today = today();
                let mut s = server.lock().await;
                if today != current {
                    if let Err(e) = s.rotate(today) {
                        eprintln!("key rotation failed: {e}");
                    } else {
                        current = today;
                    }
                }
                s.expire(now());
            }
        });
    }
    if let Some(relay) = flag(args, "--push-relay") {
        spawn_push_forwarder(Arc::clone(&server), relay);
    }
    let listener = TcpListener::bind(&addr).await.map_err(|e| e.to_string())?;
    eprintln!("enclave-server (dev transport, in memory) listening on {addr}");
    serve(listener, server).await
}
