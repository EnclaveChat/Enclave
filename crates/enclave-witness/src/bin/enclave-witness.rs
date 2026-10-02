//! The witness service (`docs/12-servers.md` §3.3).
//!
//! ```text
//! enclave-witness init           [--config FILE]   create the cosigning key; print the witness id
//! enclave-witness run            [--config FILE]   serve
//! enclave-witness descriptor OUT [--config FILE]   write the signed descriptor for the server list
//! enclave-witness show-id        [--config FILE]   print the witness id
//! enclave-witness healthcheck    [--config FILE]   exit 0 if the descriptor is served
//! ```
//!
//! `run` witnesses the logs of the foundation's server list
//! (`witness.server_list`, checked with `witness.foundation` and re-read
//! when it changes) and keeps what it cosigned in `data_dir/witness.redb`.
//! With `tls_cert` and `tls_key` it serves HTTPS with the Enclave TLS
//! profile; without, plain HTTP for a front on the same network.

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SEED_LEN, CompositeSigningKey};
use enclave_federation::{FoundationPublic, ServerList, WitnessDescriptor, witness_id};
use enclave_kt::{KtStore, Witness};
use enclave_service::config::{ConfigError, flag, hex};
use enclave_service::keyfile::{create_key_dir, create_secret, read_array};
use enclave_witness::WitnessService;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FileConfig {
    witness: WitnessSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct WitnessSection {
    listen: SocketAddr,
    keys_dir: PathBuf,
    data_dir: PathBuf,
    /// Operator name: a witness never counts for a log of the same operator.
    operator: String,
    family: String,
    /// Public base URL (in the descriptor).
    url: String,
    /// The foundation's public key.
    foundation: Option<PathBuf>,
    /// The foundation's signed server list: which logs to witness.
    server_list: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
}

impl Default for WitnessSection {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 7446)),
            keys_dir: PathBuf::from("/var/lib/enclave/witness-keys"),
            data_dir: PathBuf::from("/var/lib/enclave/witness"),
            operator: String::new(),
            family: String::new(),
            url: String::new(),
            foundation: None,
            server_list: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

const KEY_FILE: &str = "witness.key";

fn load_config(args: &[String]) -> Result<FileConfig, String> {
    let path = flag(args, "--config").map(PathBuf::from);
    let c: FileConfig = enclave_service::config::load(path.as_deref(), std::env::vars())
        .map_err(|e: ConfigError| e.to_string())?;
    if c.witness.operator.is_empty() {
        return Err("set witness.operator".into());
    }
    Ok(c)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("init") => init(&args),
        Some("run") => runtime().and_then(|rt| rt.block_on(run(&args))),
        Some("descriptor") => write_descriptor(&args),
        Some("show-id") => {
            load_key(&args).map(|(_, k)| println!("{}", hex(&witness_id(k.public()))))
        }
        Some("healthcheck") => runtime().and_then(|rt| rt.block_on(healthcheck(&args))),
        _ => Err(
            "usage: enclave-witness init|run|descriptor OUT|show-id|healthcheck [--config FILE]"
                .into(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-witness: {e}");
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
    let dir = &cfg.witness.keys_dir;
    create_key_dir(dir).map_err(|e| e.to_string())?;
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let key = CompositeSigningKey::generate(&mut rng).map_err(|e| e.to_string())?;
    create_secret(&dir.join(KEY_FILE), key.seed().as_slice()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&cfg.witness.data_dir).map_err(|e| e.to_string())?;
    println!("{}", hex(&witness_id(key.public())));
    Ok(())
}

fn load_key(args: &[String]) -> Result<(FileConfig, CompositeSigningKey), String> {
    let cfg = load_config(args)?;
    let path = cfg.witness.keys_dir.join(KEY_FILE);
    let seed = read_array::<COMPOSITE_SEED_LEN>(&path).map_err(|e| e.to_string())?;
    let key = CompositeSigningKey::from_seed(&seed)
        .map_err(|_| format!("{} is damaged", path.display()))?;
    Ok((cfg, key))
}

fn descriptor(cfg: &FileConfig, key: &CompositeSigningKey) -> Result<WitnessDescriptor, String> {
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let t = now();
    WitnessDescriptor::sign(
        key,
        &cfg.witness.operator,
        &cfg.witness.family,
        &cfg.witness.url,
        t,
        t + 3 * 86_400,
        &mut rng,
    )
    .map_err(|e| e.to_string())
}

fn write_descriptor(args: &[String]) -> Result<(), String> {
    let out = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .ok_or("usage: enclave-witness descriptor OUT")?;
    let (cfg, key) = load_key(args)?;
    let d = descriptor(&cfg, &key)?;
    std::fs::write(out, d.encode()).map_err(|e| format!("{out}: {e}"))?;
    println!("{}", hex(&d.id()));
    Ok(())
}

/// Read and check the server list; `held` is the sequence number in use.
fn read_list(cfg: &FileConfig, held: u64) -> Result<Option<ServerList>, String> {
    let (Some(fpath), Some(lpath)) = (&cfg.witness.foundation, &cfg.witness.server_list) else {
        return Err("set witness.foundation and witness.server_list".into());
    };
    let key = std::fs::read(fpath)
        .map_err(|e| format!("{}: {e}", fpath.display()))
        .and_then(|b| {
            FoundationPublic::decode(&b).map_err(|e| format!("{}: {e}", fpath.display()))
        })?;
    let bytes = std::fs::read(lpath).map_err(|e| format!("{}: {e}", lpath.display()))?;
    match ServerList::verify(&bytes, &key, now(), held) {
        Ok(l) => Ok(Some(l)),
        Err(enclave_federation::FedError::Stale) => Ok(None),
        Err(e) => Err(format!("{}: {e}", lpath.display())),
    }
}

async fn run(args: &[String]) -> Result<(), String> {
    let (cfg, key) = load_key(args)?;
    std::fs::create_dir_all(&cfg.witness.data_dir).map_err(|e| e.to_string())?;
    let store =
        KtStore::open(&cfg.witness.data_dir.join("witness.redb")).map_err(|e| e.to_string())?;
    let id = witness_id(key.public());
    let d = descriptor(&cfg, &key)?;
    let key_copy = CompositeSigningKey::from_seed(key.seed()).map_err(|_| "key".to_string())?;
    let witness = Witness::with_store(id, &cfg.witness.operator, key_copy, store)
        .map_err(|e| e.to_string())?;
    let svc = Arc::new(WitnessService::new(witness, d.encode()));
    let list = read_list(&cfg, 0)?.ok_or("server list is empty")?;
    let mut seq = list.seq;
    let n = svc.set_logs(&list).await;
    let tls = match (&cfg.witness.tls_cert, &cfg.witness.tls_key) {
        (Some(c), Some(k)) => Some(enclave_witness::service::load_tls(c, k)?),
        (None, None) => None,
        _ => return Err("set both witness.tls_cert and witness.tls_key, or neither".into()),
    };
    eprintln!(
        "enclave-witness {} ({}) witnessing {n} logs (list {seq}) on {}{}",
        hex(&id),
        cfg.witness.operator,
        cfg.witness.listen,
        if tls.is_some() { " (TLS)" } else { "" }
    );
    // Every minute: a newer list, if the file changed; a fresh descriptor daily.
    {
        let svc = Arc::clone(&svc);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            let mut signed = now();
            loop {
                tick.tick().await;
                match read_list(&cfg, seq) {
                    Ok(Some(l)) => {
                        seq = l.seq;
                        let n = svc.set_logs(&l).await;
                        eprintln!("server list {seq}: witnessing {n} logs");
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("server list: {e}"),
                }
                if now() >= signed + 86_400 {
                    match descriptor(&cfg, &key) {
                        Ok(d) => {
                            svc.set_descriptor(d.encode()).await;
                            signed = now();
                        }
                        Err(e) => eprintln!("descriptor: {e}"),
                    }
                }
            }
        });
    }
    let listener = tokio::net::TcpListener::bind(cfg_listen(args)?)
        .await
        .map_err(|e| e.to_string())?;
    tokio::select! {
        r = enclave_witness::service::serve(listener, Arc::clone(&svc).router(), tls) => r.map_err(|e| e.to_string()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

fn cfg_listen(args: &[String]) -> Result<SocketAddr, String> {
    Ok(load_config(args)?.witness.listen)
}

async fn healthcheck(args: &[String]) -> Result<(), String> {
    let cfg = load_config(args)?;
    let scheme = if cfg.witness.tls_cert.is_some() {
        "https"
    } else {
        "http"
    };
    let base = format!("{scheme}://{}", cfg.witness.listen);
    // A TLS front's certificate names the public host, not the listen
    // address: check the plain listener, or trust the configured cert.
    let ca = cfg.witness.tls_cert.as_deref();
    enclave_witness::HttpWitness::connect(&base, ca, now())
        .await
        .map(|_| ())
}
