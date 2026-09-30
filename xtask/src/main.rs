//! `cargo xtask <task>`: repository checks that are not unit tests.
//!
//! * `labels`: every `enclave/v1/...` string literal in `crates/` is listed in
//!   `docs/label-registry.md`, and no label is defined twice in code.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "labels" => labels(),
        _ => {
            eprintln!("usage: cargo xtask labels");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Extract `"enclave/v1/..."` literals from source text.
fn labels_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let needle = "\"enclave/v1/";
    let mut rest = text;
    while let Some(i) = rest.find(needle) {
        let after = &rest[i + 1..];
        if let Some(end) = after.find('"') {
            let lit = &after[..end];
            if lit
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/-_.".contains(c))
            {
                found.push(lit.to_string());
            }
            rest = &after[end + 1..];
        } else {
            break;
        }
    }
    found
}

fn labels() -> ExitCode {
    let root = root();
    let registry = fs::read_to_string(root.join("docs/label-registry.md")).unwrap_or_default();
    let registered: BTreeSet<String> = registry
        .split(|c: char| c == '`' || c.is_whitespace() || c == '|')
        .filter(|s| s.starts_with("enclave/v1/"))
        .map(str::to_string)
        .collect();

    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    // label -> files that define it as a `pub const`
    let mut defs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    for f in &files {
        let Ok(text) = fs::read_to_string(f) else {
            continue;
        };
        for line in text.lines() {
            let is_def = line.trim_start().starts_with("pub const")
                || line.trim_start().starts_with("const");
            for l in labels_in(line) {
                used.insert(l.clone());
                if is_def {
                    defs.entry(l).or_default().push(f.display().to_string());
                }
            }
        }
    }

    let mut ok = true;
    for (label, where_) in &defs {
        if where_.len() > 1 {
            eprintln!("label {label} defined more than once: {where_:?}");
            ok = false;
        }
    }
    if registered.is_empty() {
        eprintln!("docs/label-registry.md is missing or lists no labels");
        return ExitCode::FAILURE;
    }
    for l in &used {
        if !registered.contains(l) {
            eprintln!("label {l} is used in code but missing from docs/label-registry.md");
            ok = false;
        }
    }
    if ok {
        println!(
            "labels ok: {} used, {} registered",
            used.len(),
            registered.len()
        );
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
