//! Configuration files with environment overrides.
//!
//! Every key of a service's TOML file can be overridden from the
//! environment as `ENCLAVE_<SECTION>__<KEY>` (for example
//! `ENCLAVE_SERVER__DOMAIN=a.example`); that is how the compose file sets
//! per-deployment values. Integers and `true`/`false` keep their type; a
//! value in brackets (`[a, b]`) is a list of strings. Services deserialize
//! with `#[serde(deny_unknown_fields)]`, so a typo is an error, not a
//! silent default.

use serde::de::DeserializeOwned;
use std::path::Path;

/// A configuration problem, with where it was found.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// Read `path` (if given), apply `ENCLAVE_*` overrides from `env`, and
/// deserialize the result.
pub fn load<T: DeserializeOwned>(
    path: Option<&Path>,
    env: impl IntoIterator<Item = (String, String)>,
) -> Result<T, ConfigError> {
    let mut table: toml::Table = match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| ConfigError(format!("{}: {e}", p.display())))?;
            text.parse()
                .map_err(|e| ConfigError(format!("{}: {e}", p.display())))?
        }
        None => toml::Table::new(),
    };
    for (k, v) in env {
        let Some(rest) = k.strip_prefix("ENCLAVE_") else {
            continue;
        };
        let Some((section, key)) = rest.split_once("__") else {
            continue;
        };
        let (section, key) = (section.to_lowercase(), key.to_lowercase());
        let entry = table
            .entry(section.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        let toml::Value::Table(t) = entry else {
            return Err(ConfigError(format!("[{section}] is not a section")));
        };
        t.insert(key, env_value(&v));
    }
    toml::Value::Table(table)
        .try_into()
        .map_err(|e| ConfigError(format!("configuration: {e}")))
}

/// An environment value as TOML.
fn env_value(v: &str) -> toml::Value {
    if let Ok(i) = v.parse::<i64>() {
        return toml::Value::Integer(i);
    }
    match v {
        "true" => return toml::Value::Boolean(true),
        "false" => return toml::Value::Boolean(false),
        _ => {}
    }
    if let Some(inner) = v.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return toml::Value::Array(
            inner
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| toml::Value::String(s.to_string()))
                .collect(),
        );
    }
    toml::Value::String(v.to_string())
}

/// The value of `--flag VALUE` in `args`.
pub fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Hex encoding.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Hex decoding.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[derive(serde::Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct C {
        a: A,
    }
    #[derive(serde::Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct A {
        n: i64,
        b: bool,
        s: String,
        l: Vec<String>,
    }

    #[test]
    fn env_overrides_types_and_typos() {
        let c: C = load(
            None,
            [
                ("ENCLAVE_A__N".into(), "5".into()),
                ("ENCLAVE_A__B".into(), "true".into()),
                ("ENCLAVE_A__S".into(), "x".into()),
                ("ENCLAVE_A__L".into(), "[p, q]".into()),
                ("OTHER".into(), "1".into()),
            ],
        )
        .unwrap();
        assert_eq!((c.a.n, c.a.b, c.a.s.as_str()), (5, true, "x"));
        assert_eq!(c.a.l, ["p", "q"]);
        let bad: Result<C, _> = load(
            None,
            [
                ("ENCLAVE_A__N".into(), "5".into()),
                ("ENCLAVE_A__B".into(), "true".into()),
                ("ENCLAVE_A__S".into(), "x".into()),
                ("ENCLAVE_A__L".into(), "[]".into()),
                ("ENCLAVE_A__TYPO".into(), "1".into()),
            ],
        );
        assert!(bad.is_err());
        assert_eq!(unhex(&hex(&[0, 255, 16])).unwrap(), [0, 255, 16]);
        assert!(unhex("abc").is_none());
    }
}
