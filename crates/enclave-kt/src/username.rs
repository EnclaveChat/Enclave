//! Username rules (`docs/12-servers.md`): lowercase `a–z`, `0–9` and `_`,
//! 3–32 characters, not starting with a digit, and unique up to a *confusable
//! skeleton* so `pau1` cannot impersonate `paul`.

use crate::{KtError, Result};

/// Names nobody can register.
pub const RESERVED: &[&str] = &[
    "admin", "enclave", "support", "security", "root", "help", "official", "system",
];

/// Validate and normalize a username (trims and lowercases ASCII).
pub fn normalize(name: &str) -> Result<String> {
    let n = name.trim().to_ascii_lowercase();
    let ok_len = (3..=32).contains(&n.len());
    let ok_chars = n
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    let ok_start = n.bytes().next().is_some_and(|b| b.is_ascii_lowercase());
    if !(ok_len && ok_chars && ok_start) {
        return Err(KtError::Username);
    }
    if RESERVED.iter().any(|r| skeleton(r) == skeleton(&n)) {
        return Err(KtError::Username);
    }
    Ok(n)
}

/// Confusable skeleton: maps look-alike characters and sequences to one form.
pub fn skeleton(name: &str) -> String {
    let s = name
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace('_', "");
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' | 'j' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '6' => 'b',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            'u' => 'v',
            'y' => 'v',
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert_eq!(normalize("  Alice_99 ").unwrap(), "alice_99");
        assert!(normalize("ab").is_err());
        assert!(normalize("9lives").is_err());
        assert!(normalize("bad-name").is_err());
        assert!(
            normalize("adm1n").is_err(),
            "confusable with a reserved name"
        );
        assert_eq!(skeleton("pau1"), skeleton("paul"));
        assert_eq!(skeleton("rnary"), skeleton("mary"));
        assert_ne!(skeleton("anna"), skeleton("hanna"));
    }
}
