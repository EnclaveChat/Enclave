//! `enclave-admin`: tools for the foundation and for operators
//! (`docs/12-servers.md` §4, `docs/13-operators.md`).
//!
//! ```text
//! enclave-admin foundation-keygen SECRET_OUT PUBLIC_OUT
//! enclave-admin server-list build SPEC.toml --key SECRET --out LIST [--now UNIX]
//! enclave-admin server-list verify LIST --foundation PUBLIC [--held-seq N] [--now UNIX]
//! enclave-admin kt-pins LIST --foundation PUBLIC --out PINS [--now UNIX]
//! enclave-admin descriptor verify server|witness|relay FILE [--id HEX] [--now UNIX]
//! ```
//!
//! The list is built from the signed descriptors operators submit: each is
//! verified (signature, validity, and for servers every key certificate)
//! before its long-lived facts go into the list. The spec names the
//! descriptor files, relative to the spec:
//!
//! ```toml
//! seq = 12
//! valid_days = 30
//! witness_threshold = 2
//!
//! [[server]]
//! descriptor = "ops/a/descriptor.bin"
//! weight = 3
//!
//! [[witness]]
//! descriptor = "ops/w1/witness.bin"
//!
//! [[relay]]
//! descriptor = "ops/r1/relay.bin"
//!
//! [[push]]
//! nym_address = "…"
//! keys = "push/push-relay-keys.bin"
//! ```
#![forbid(unsafe_code)]

use enclave_crypto::rng::HedgedRng;
use enclave_federation::{
    FoundationKey, FoundationPublic, ListedRelay, ListedServer, ListedWitness, PushRelayEntry,
    RelayDescriptor, ServerDescriptor, ServerList, WitnessDescriptor,
};
use enclave_service::config::{flag, hex, unhex};
use enclave_service::keyfile;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Bytes of one push-relay key: `u32 epoch ‖ X448 ‖ ML-KEM-1024`.
const PUSH_KEY_LEN: usize = 4 + 56 + 1568;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    seq: u64,
    valid_days: u64,
    witness_threshold: u8,
    #[serde(default)]
    server: Vec<ServerSpec>,
    #[serde(default)]
    witness: Vec<FileSpec>,
    #[serde(default)]
    relay: Vec<FileSpec>,
    #[serde(default)]
    push: Vec<PushSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerSpec {
    descriptor: PathBuf,
    weight: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    descriptor: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PushSpec {
    nym_address: String,
    keys: PathBuf,
}

fn now_or(args: &[String]) -> Result<u64, String> {
    match flag(args, "--now") {
        Some(t) => t.parse().map_err(|_| format!("--now {t}: not a number")),
        None => Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("missing {name}"))
}

fn positional(args: &[String], i: usize, what: &str) -> Result<String, String> {
    args.get(i)
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("missing {what}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().take(2).map(String::as_str).collect();
    let result = match words.as_slice() {
        ["foundation-keygen", ..] => foundation_keygen(&args),
        ["server-list", "build", ..] => build(&args),
        ["server-list", "verify", ..] => verify(&args),
        ["kt-pins", ..] => kt_pins(&args),
        ["descriptor", "verify", ..] => verify_descriptor(&args),
        _ => Err("usage: enclave-admin foundation-keygen | server-list build|verify | kt-pins | descriptor verify (see the module docs)".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("enclave-admin: {e}");
            ExitCode::FAILURE
        }
    }
}

fn foundation_keygen(args: &[String]) -> Result<(), String> {
    let secret = PathBuf::from(positional(args, 1, "SECRET_OUT")?);
    let public = PathBuf::from(positional(args, 2, "PUBLIC_OUT")?);
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let key = FoundationKey::generate(&mut rng).map_err(|e| e.to_string())?;
    keyfile::create_secret(&secret, &key.to_bytes()).map_err(|e| e.to_string())?;
    if public.exists() {
        return Err(format!("{} exists", public.display()));
    }
    std::fs::write(&public, key.public().encode())
        .map_err(|e| format!("{}: {e}", public.display()))?;
    eprintln!(
        "foundation key written to {}; keep it offline. Its public key ({}) is built into every client.",
        secret.display(),
        public.display()
    );
    Ok(())
}

fn foundation(args: &[String]) -> Result<FoundationPublic, String> {
    FoundationPublic::decode(&read(Path::new(&need(args, "--foundation")?))?)
        .map_err(|e| format!("foundation public key: {e}"))
}

fn build(args: &[String]) -> Result<(), String> {
    let spec_path = PathBuf::from(positional(args, 2, "SPEC.toml")?);
    let base = spec_path.parent().unwrap_or(Path::new("."));
    let text =
        std::fs::read_to_string(&spec_path).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let spec: Spec = toml::from_str(&text).map_err(|e| format!("{}: {e}", spec_path.display()))?;
    let now = now_or(args)?;
    let key = FoundationKey::from_bytes(
        &keyfile::read_secret(Path::new(&need(args, "--key")?)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("foundation key: {e}"))?;
    if spec.valid_days == 0 || spec.valid_days > 90 {
        return Err("valid_days must be 1 to 90".into());
    }
    let mut servers = Vec::new();
    for s in &spec.server {
        let p = base.join(&s.descriptor);
        let d =
            ServerDescriptor::decode(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        d.verify(now).map_err(|e| format!("{}: {e}", p.display()))?;
        if servers
            .iter()
            .any(|x: &ListedServer| x.id() == d.id() || x.domain.eq_ignore_ascii_case(&d.domain))
        {
            return Err(format!("{}: server or domain listed twice", p.display()));
        }
        servers.push(ListedServer {
            identity: d.identity.clone(),
            domain: d.domain.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            weight: s.weight,
            kt: d.kt.clone(),
        });
    }
    let mut witnesses = Vec::new();
    for w in &spec.witness {
        let p = base.join(&w.descriptor);
        let d =
            WitnessDescriptor::decode(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        d.verify(now).map_err(|e| format!("{}: {e}", p.display()))?;
        witnesses.push(ListedWitness {
            key: d.key.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            url: d.url.clone(),
        });
    }
    if usize::from(spec.witness_threshold) > witnesses.len() {
        return Err(format!(
            "witness_threshold {} but only {} witnesses",
            spec.witness_threshold,
            witnesses.len()
        ));
    }
    let mut relays = Vec::new();
    for r in &spec.relay {
        let p = base.join(&r.descriptor);
        let d = RelayDescriptor::decode(&read(&p)?).map_err(|e| format!("{}: {e}", p.display()))?;
        d.verify(now).map_err(|e| format!("{}: {e}", p.display()))?;
        relays.push(ListedRelay {
            identity: d.identity.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            addr: d.addr.clone(),
            link_key: d.link_key,
        });
    }
    let mut push = Vec::new();
    for x in &spec.push {
        let p = base.join(&x.keys);
        let b = read(&p)?;
        if b.is_empty() || b.len() % PUSH_KEY_LEN != 0 {
            return Err(format!("{}: not a push-relay key file", p.display()));
        }
        push.push(PushRelayEntry {
            nym_address: x.nym_address.clone(),
            keys: b.chunks(PUSH_KEY_LEN).map(<[u8]>::to_vec).collect(),
        });
    }
    let list = ServerList {
        seq: spec.seq,
        issued: now,
        expires: now + spec.valid_days * 86_400,
        witness_threshold: spec.witness_threshold,
        servers,
        witnesses,
        relays,
        push,
    };
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    let signed = list.sign(&key, &mut rng).map_err(|e| e.to_string())?;
    // Check what was written verifies, before anyone ships it.
    ServerList::verify(&signed, &key.public(), now, 0).map_err(|e| e.to_string())?;
    let out = need(args, "--out")?;
    std::fs::write(&out, &signed).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "server list seq {} with {} servers, {} witnesses, {} relays, {} push relays → {out}",
        list.seq,
        list.servers.len(),
        list.witnesses.len(),
        list.relays.len(),
        list.push.len()
    );
    Ok(())
}

fn load_list(args: &[String]) -> Result<ServerList, String> {
    let path = positional(args, if args[0] == "kt-pins" { 1 } else { 2 }, "LIST")?;
    let held = match flag(args, "--held-seq") {
        Some(n) => n
            .parse()
            .map_err(|_| format!("--held-seq {n}: not a number"))?,
        None => 0,
    };
    ServerList::verify(
        &read(Path::new(&path))?,
        &foundation(args)?,
        now_or(args)?,
        held,
    )
    .map_err(|e| format!("{path}: {e}"))
}

fn verify(args: &[String]) -> Result<(), String> {
    let l = load_list(args)?;
    println!(
        "seq {}  issued {}  expires {}  witness threshold {}",
        l.seq, l.issued, l.expires, l.witness_threshold
    );
    for s in &l.servers {
        println!(
            "server  {}  {}  {} ({})  weight {}{}",
            hex(&s.id()),
            s.domain,
            s.operator,
            s.family,
            s.weight,
            if s.kt.is_some() { "  kt" } else { "" }
        );
    }
    for w in &l.witnesses {
        println!(
            "witness {}  {} ({})  {}",
            hex(&w.id()),
            w.operator,
            w.family,
            w.url
        );
    }
    for r in &l.relays {
        println!(
            "relay   {}  {} ({})  {}",
            hex(&enclave_federation::relay_id(&r.identity)),
            r.operator,
            r.family,
            r.addr
        );
    }
    for p in &l.push {
        println!("push    {}  {} keys", p.nym_address, p.keys.len());
    }
    Ok(())
}

fn kt_pins(args: &[String]) -> Result<(), String> {
    let l = load_list(args)?;
    let pins = enclave_kt::KtPolicy::from_server_list(&l);
    let out = need(args, "--out")?;
    std::fs::write(&out, pins.encode()).map_err(|e| format!("{out}: {e}"))?;
    eprintln!(
        "pins for {} logs and {} witnesses (threshold {}) → {out}",
        pins.servers.len(),
        pins.witnesses.witnesses.len(),
        pins.witnesses.threshold
    );
    Ok(())
}

fn verify_descriptor(args: &[String]) -> Result<(), String> {
    let kind = positional(args, 2, "server|witness|relay")?;
    let path = positional(args, 3, "FILE")?;
    let b = read(Path::new(&path))?;
    let now = now_or(args)?;
    let id = match kind.as_str() {
        "server" => {
            let d = ServerDescriptor::decode(&b).map_err(|e| e.to_string())?;
            d.verify(now).map_err(|e| e.to_string())?;
            println!(
                "server {} {} ({}, {})",
                hex(&d.id()),
                d.domain,
                d.operator,
                d.family
            );
            d.id()
        }
        "witness" => {
            let d = WitnessDescriptor::decode(&b).map_err(|e| e.to_string())?;
            d.verify(now).map_err(|e| e.to_string())?;
            println!(
                "witness {} {} ({}) {}",
                hex(&d.id()),
                d.operator,
                d.family,
                d.url
            );
            d.id()
        }
        "relay" => {
            let d = RelayDescriptor::decode(&b).map_err(|e| e.to_string())?;
            d.verify(now).map_err(|e| e.to_string())?;
            println!(
                "relay {} {} ({}) {}",
                hex(&d.id()),
                d.operator,
                d.family,
                d.addr
            );
            d.id()
        }
        other => return Err(format!("{other}: expected server, witness or relay")),
    };
    if let Some(want) = flag(args, "--id")
        && unhex(&want).as_deref() != Some(&id[..])
    {
        return Err(format!("{path} is {}, not {want}", hex(&id)));
    }
    Ok(())
}
