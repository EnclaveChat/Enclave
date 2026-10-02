//! Release builds name the foundation's public key and the server list to
//! ship with (`ENCLAVE_FOUNDATION_PUB`, `ENCLAVE_SERVER_LIST`: paths to the
//! files `enclave-admin` writes). Without them the build has neither, and a
//! server-mode profile needs `--foundation` / `--server-list` to use one.

use std::path::{Path, PathBuf};

/// Stop the build: a release asked for files that aren't there.
fn fail(msg: &str) -> ! {
    eprintln!("enclave-vault build: {msg}");
    std::process::exit(1)
}

fn embed(var: &str, name: &str, out: &Path, code: &mut String) {
    println!("cargo:rerun-if-env-changed={var}");
    let value = match std::env::var(var) {
        Ok(p) if !p.is_empty() => {
            println!("cargo:rerun-if-changed={p}");
            let dest = out.join(name.to_lowercase());
            if let Err(e) = std::fs::copy(&p, &dest) {
                fail(&format!("{var}={p}: {e}"));
            }
            format!("Some(include_bytes!({:?}))", dest.display().to_string())
        }
        _ => "None".to_string(),
    };
    code.push_str(&format!(
        "/// Built in from `{var}`, if set.\npub const {name}: Option<&[u8]> = {value};\n"
    ));
}

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    let mut code = String::new();
    embed("ENCLAVE_FOUNDATION_PUB", "FOUNDATION_PUB", &out, &mut code);
    embed("ENCLAVE_SERVER_LIST", "SERVER_LIST", &out, &mut code);
    if let Err(e) = std::fs::write(out.join("federation.rs"), code) {
        fail(&format!("federation.rs: {e}"));
    }
}
