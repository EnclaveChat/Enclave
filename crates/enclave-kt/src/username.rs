//! Username rules (`docs/12-servers.md` §3.5).
//!
//! Names are Unicode: NFKC-normalized and lowercased, made of characters
//! UTS #39 allows in identifiers (letters and digits of living scripts, and
//! `_`), from one script (UTS #39 *highly restrictive*: one script, or Latin
//! with Han and Japanese kana, Han with Bopomofo, or Han with Hangul),
//! starting with a letter, 2 to 32 characters and at most 32 bytes of UTF-8
//! (the directory key is 32 bytes). They are unique up to a *confusable
//! skeleton*, so `pau1` can't impersonate `paul` and Cyrillic `раul` can't
//! either.
//!
//! A *tombstone* is the value a withdrawn name holds in the log
//! ([`tombstone`]): by its owner when the account was deleted, or by the
//! operator for breaking its policy. A tombstoned name is never claimed
//! again.

use crate::{KtError, Result};
use unicode_normalization::UnicodeNormalization;
use unicode_security::{GeneralSecurityProfile, RestrictionLevel, RestrictionLevelDetection};

/// Names nobody can register.
pub const RESERVED: &[&str] = &[
    "admin", "enclave", "support", "security", "root", "help", "official", "system",
];

/// Longest name, in bytes of UTF-8.
pub const MAX_BYTES: usize = 32;

/// Prefix of a tombstone value (a name's value is otherwise a 64-byte root,
/// optionally followed by a contact card).
pub const TOMBSTONE_PREFIX: &[u8] = b"\xfftombstone";

/// Why a name was withdrawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Withdrawn {
    /// Its account was deleted (by the account's root).
    Deleted = 1,
    /// The operator withdrew it for breaking its policy.
    ByOperator = 2,
}

/// The log value of a tombstone.
pub fn tombstone(why: Withdrawn) -> Vec<u8> {
    [TOMBSTONE_PREFIX, &[why as u8]].concat()
}

/// Whether `value` is a tombstone, and why.
pub fn as_tombstone(value: &[u8]) -> Option<Withdrawn> {
    match value.strip_prefix(TOMBSTONE_PREFIX)? {
        [1] => Some(Withdrawn::Deleted),
        [2] => Some(Withdrawn::ByOperator),
        _ => None,
    }
}

/// Validate and normalize a username.
pub fn normalize(name: &str) -> Result<String> {
    let lower: String = name.trim().nfkc().flat_map(char::to_lowercase).collect();
    // Lowercasing can leave a string that isn't NFKC (some case mappings
    // decompose): normalize again.
    let n: String = lower.nfkc().collect();
    let chars = n.chars().count();
    let ok_len = (2..=MAX_BYTES).contains(&chars) && n.len() <= MAX_BYTES && n.len() >= 3;
    let ok_chars = n
        .chars()
        .all(|c| (c.is_alphanumeric() || c == '_') && c.identifier_allowed());
    let ok_start = n.chars().next().is_some_and(char::is_alphabetic);
    let ok_script = n
        .as_str()
        .check_restriction_level(RestrictionLevel::HighlyRestrictive);
    if !(ok_len && ok_chars && ok_start && ok_script) {
        return Err(KtError::Username);
    }
    if RESERVED.iter().any(|r| skeleton(r) == skeleton(&n)) {
        return Err(KtError::Username);
    }
    Ok(n)
}

/// Confusable skeleton: the UTS #39 skeleton (every character mapped to its
/// prototype in Unicode's confusables table), lowercased, then the
/// look-alikes Unicode's table leaves apart in lowercase Latin text: single
/// characters, then pairs.
pub fn skeleton(name: &str) -> String {
    let uts: String = unicode_security::skeleton(name)
        .flat_map(char::to_lowercase)
        .collect();
    // Single characters first, so a pair they make is caught too (`uu`
    // becomes `vv`, then `w`).
    let s: String = uts
        .chars()
        .filter(|c| *c != '_')
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
        .collect();
    s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn ascii_rules() {
        assert_eq!(normalize("  Alice_99 ").unwrap(), "alice_99");
        assert!(normalize("ab").is_err(), "too short");
        assert!(normalize("9lives").is_err(), "starts with a digit");
        assert!(normalize("bad-name").is_err());
        assert!(normalize("bad name").is_err());
        assert!(normalize(&"a".repeat(33)).is_err(), "too long");
        assert!(
            normalize("adm1n").is_err(),
            "confusable with a reserved name"
        );
        assert_eq!(skeleton("pau1"), skeleton("paul"));
        assert_eq!(skeleton("rnary"), skeleton("mary"));
        assert_eq!(skeleton("uuendy"), skeleton("wendy"));
        assert_eq!(skeleton("c1aire"), skeleton("daire"));
        assert_ne!(skeleton("anna"), skeleton("hanna"));
    }

    #[test]
    fn unicode_names() {
        // NFKC and lowercase: fullwidth and case variants are one name.
        assert_eq!(normalize("ＡＬＩＣＥ").unwrap(), "alice");
        assert_eq!(normalize("Zoë").unwrap(), "zoë");
        assert_eq!(normalize("Zoe\u{308}").unwrap(), "zoë", "composed by NFKC");
        // Other scripts.
        assert_eq!(normalize("Мария").unwrap(), "мария");
        assert_eq!(normalize("محمد").unwrap(), "محمد");
        assert_eq!(normalize("田中").unwrap(), "田中", "two CJK characters");
        assert_eq!(normalize("たなか").unwrap(), "たなか");
        assert!(normalize("田中tanaka").is_ok(), "Latin with Han is allowed");
        assert!(normalize("田").is_err(), "one character");
        // Too many bytes, however few characters.
        assert!(normalize("田中田中田中田中田中田中").is_err());
        // Mixed scripts that could fool someone: Latin with Cyrillic.
        assert!(normalize("pаypal").is_err(), "Cyrillic а in Latin");
        // Not identifier characters: symbols, emoji, invisible ones.
        assert!(normalize("alice♥").is_err());
        assert!(normalize("bob😀").is_err());
        assert!(normalize("al\u{200b}ice").is_err());
        // Confusable across scripts: an all-Cyrillic look-alike of a Latin
        // name has the same skeleton, so it can't sit beside it.
        assert_eq!(skeleton("рaul"), skeleton("paul"));
        assert_eq!(skeleton("раул"), skeleton("раул"));
        let cyr = normalize("рое").unwrap();
        assert_eq!(skeleton(&cyr), skeleton("poe"));
        // Reserved names in any script.
        assert!(normalize("ѕупроrt").is_err());
        assert!(normalize("аdmin").is_err());
    }

    #[test]
    fn tombstones() {
        for why in [Withdrawn::Deleted, Withdrawn::ByOperator] {
            assert_eq!(as_tombstone(&tombstone(why)), Some(why));
        }
        assert_eq!(as_tombstone(&[7; 64]), None);
        assert_eq!(as_tombstone(b"\xfftombstone\x09"), None);
        assert!(tombstone(Withdrawn::Deleted).len() < 64, "never a root");
    }
}
