//! SHA3-512, SHAKE256 and the root fingerprint used by security codes.

use crate::kmac::kmac256;
use crate::labels;
use cshake::digest::{ExtendableOutput, Update, XofReader};
use sha3::Digest;

/// SHA3-512 of `data`.
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut h = sha3::Sha3_512::new();
    Digest::update(&mut h, data);
    h.finalize().into()
}

/// SHA3-512 over length-framed parts (injective concatenation).
pub fn sha3_512_parts(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = sha3::Sha3_512::new();
    for p in parts {
        Digest::update(&mut h, (p.len() as u64).to_be_bytes());
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// SHAKE256 with `N` bytes of output.
pub fn shake256<const N: usize>(data: &[u8]) -> [u8; N] {
    // cSHAKE256 with empty function name and customization is SHAKE256.
    let mut h = cshake::CShake256::new_with_function_name(b"", b"");
    Update::update(&mut h, data);
    let mut out = [0u8; N];
    h.finalize_xof().read(&mut out);
    out
}

/// Number of hash iterations in a root fingerprint (slows down brute-force
/// search for a colliding fingerprint prefix).
pub const FINGERPRINT_ITERATIONS: u32 = 5200;

/// Per-side fingerprint of a root public key: 30 decimal digits plus the full
/// 64-byte digest (the QR code carries the digest).
pub struct Fingerprint {
    /// Full digest, carried in QR codes.
    pub digest: [u8; 64],
    /// 30 decimal digits for display, grouped by the UI into 6 groups of 5.
    pub digits: String,
}

/// Compute the fingerprint of a root public key.
pub fn root_fingerprint(root_pk: &[u8]) -> Fingerprint {
    let mut d: [u8; 64] = kmac256(root_pk, b"", labels::FP_ROOT);
    for _ in 0..FINGERPRINT_ITERATIONS {
        let mut buf = Vec::with_capacity(64 + root_pk.len());
        buf.extend_from_slice(&d);
        buf.extend_from_slice(root_pk);
        d = sha3_512(&buf);
    }
    let mut digits = String::with_capacity(30);
    // Six 5-digit groups, each from 5 bytes reduced mod 100000.
    for chunk in d.chunks_exact(5).take(6) {
        let mut v: u64 = 0;
        for b in chunk {
            v = (v << 8) | u64::from(*b);
        }
        digits.push_str(&format!("{:05}", v % 100_000));
    }
    Fingerprint { digest: d, digits }
}

/// The 60-digit security code for a pair of accounts: the two fingerprints in
/// ascending digest order, so both sides show the same code.
pub fn security_code(root_a: &[u8], root_b: &[u8]) -> String {
    let fa = root_fingerprint(root_a);
    let fb = root_fingerprint(root_b);
    if fa.digest <= fb.digest {
        format!("{}{}", fa.digits, fb.digits)
    } else {
        format!("{}{}", fb.digits, fa.digits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sha3_512_empty() {
        assert_eq!(
            sha3_512(b""),
            hex!(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
                "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )
        );
    }

    #[test]
    fn shake256_empty() {
        let out: [u8; 32] = shake256(b"");
        assert_eq!(
            out,
            hex!("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
    }

    #[test]
    fn security_code_is_symmetric_and_60_digits() {
        let a = [1u8; 64];
        let b = [2u8; 64];
        let c1 = security_code(&a, &b);
        let c2 = security_code(&b, &a);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 60);
        assert!(c1.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(security_code(&a, &[3u8; 64]), c1);
    }
}
