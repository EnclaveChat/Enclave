//! KMAC256 and KMACXOF256 (NIST SP 800-185), built on cSHAKE256.
//!
//! This is the only KDF, PRF and MAC used by Enclave. It is implemented here
//! (about 100 lines) rather than taken from a crate so that the encoding rules
//! are auditable in one place; tests check it against the NIST sample vectors
//! and against independent implementations.

use cshake::CShake256;
use cshake::digest::{ExtendableOutput, Update, XofReader};

/// cSHAKE256 rate in bytes, used by `bytepad`.
const RATE: usize = 136;

/// `left_encode(x)` from SP 800-185 §2.3.1.
fn left_encode(x: u64, out: &mut [u8; 9]) -> &[u8] {
    let bytes = x.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(7);
    let n = 8 - skip;
    out[0] = n as u8;
    out[1..=n].copy_from_slice(&bytes[skip..]);
    &out[..=n]
}

/// `right_encode(x)` from SP 800-185 §2.3.1.
fn right_encode(x: u64, out: &mut [u8; 9]) -> &[u8] {
    let bytes = x.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(7);
    let n = 8 - skip;
    out[..n].copy_from_slice(&bytes[skip..]);
    out[n] = n as u8;
    &out[..=n]
}

/// Streaming KMAC256 state. Use [`kmac256`] for one-shot calls.
pub struct Kmac256 {
    inner: CShake256,
}

impl Kmac256 {
    /// Start a KMAC256 computation with key `key` and customization `custom`.
    pub fn new(key: &[u8], custom: &[u8]) -> Self {
        let mut inner = CShake256::new_with_function_name(b"KMAC", custom);
        // bytepad(encode_string(K), 136)
        let mut buf = [0u8; 9];
        let mut written = 0usize;
        let w = left_encode(RATE as u64, &mut buf);
        inner.update(w);
        written += w.len();
        let w = left_encode((key.len() as u64) * 8, &mut buf);
        inner.update(w);
        written += w.len();
        inner.update(key);
        written += key.len();
        let pad = (RATE - written % RATE) % RATE;
        inner.update(&[0u8; RATE][..pad]);
        Self { inner }
    }

    /// Absorb message bytes.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Absorb `data` preceded by its 64-bit big-endian length. Use this for every
    /// variable-length field so that concatenations are injective.
    pub fn update_framed(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(&(data.len() as u64).to_be_bytes());
        self.inner.update(data);
        self
    }

    /// Finish as KMAC256 with output length `out.len()` bytes.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        let mut buf = [0u8; 9];
        let w = right_encode((out.len() as u64) * 8, &mut buf);
        self.inner.update(w);
        self.inner.finalize_xof().read(out);
    }

    /// Finish as KMACXOF256 (arbitrary-length output).
    pub fn finalize_xof(mut self) -> KmacReader {
        let mut buf = [0u8; 9];
        let w = right_encode(0, &mut buf);
        self.inner.update(w);
        KmacReader {
            reader: self.inner.finalize_xof(),
        }
    }
}

/// Output stream of KMACXOF256.
pub struct KmacReader {
    reader: cshake::CShake256Reader,
}

impl KmacReader {
    /// Read the next `out.len()` bytes of output.
    pub fn read(&mut self, out: &mut [u8]) {
        self.reader.read(out);
    }
}

/// One-shot KMAC256(key, data, L = 8 * N, S = label).
pub fn kmac256<const N: usize>(key: &[u8], data: &[u8], label: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut k = Kmac256::new(key, label.as_bytes());
    k.update(data);
    k.finalize_into(&mut out);
    out
}

/// One-shot KMAC256 over several framed parts (each part length-prefixed).
pub fn kmac256_parts<const N: usize>(key: &[u8], parts: &[&[u8]], label: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let mut k = Kmac256::new(key, label.as_bytes());
    for p in parts {
        k.update_framed(p);
    }
    k.finalize_into(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const KEY: [u8; 32] = hex!("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");

    fn kmac_raw(key: &[u8], data: &[u8], s: &[u8], l: usize) -> Vec<u8> {
        let mut out = vec![0u8; l];
        let mut k = Kmac256::new(key, s);
        k.update(data);
        k.finalize_into(&mut out);
        out
    }

    // NIST SP 800-185 KMAC samples #4, #5, #6.
    #[test]
    fn nist_kmac256_sample_4() {
        let out = kmac_raw(&KEY, &hex!("00010203"), b"My Tagged Application", 64);
        assert_eq!(
            out,
            hex!(
                "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
                "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
            )
        );
    }

    #[test]
    fn nist_kmac256_sample_5() {
        let data: Vec<u8> = (0u8..200).collect();
        let out = kmac_raw(&KEY, &data, b"", 64);
        assert_eq!(
            out,
            hex!(
                "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691"
                "589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69"
            )
        );
    }

    #[test]
    fn nist_kmac256_sample_6() {
        let data: Vec<u8> = (0u8..200).collect();
        let out = kmac_raw(&KEY, &data, b"My Tagged Application", 64);
        assert_eq!(
            out,
            hex!(
                "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9"
                "70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965"
            )
        );
    }

    #[test]
    fn encodings() {
        let mut b = [0u8; 9];
        assert_eq!(left_encode(0, &mut b), &[1, 0]);
        assert_eq!(left_encode(136, &mut b), &[1, 136]);
        assert_eq!(left_encode(256, &mut b), &[2, 1, 0]);
        assert_eq!(right_encode(0, &mut b), &[0, 1]);
        assert_eq!(right_encode(512, &mut b), &[2, 0, 2]);
    }

    #[test]
    fn framing_is_injective() {
        let a: [u8; 32] = kmac256_parts(b"k", &[b"ab", b"c"], "t");
        let b: [u8; 32] = kmac256_parts(b"k", &[b"a", b"bc"], "t");
        assert_ne!(a, b);
    }

    #[test]
    fn xof_prefix_consistency() {
        let mut r1 = Kmac256::new(b"key", b"s").finalize_xof();
        let mut r2 = Kmac256::new(b"key", b"s").finalize_xof();
        let mut a = [0u8; 100];
        let mut b1 = [0u8; 40];
        let mut b2 = [0u8; 60];
        r1.read(&mut a);
        r2.read(&mut b1);
        r2.read(&mut b2);
        assert_eq!(&a[..40], &b1);
        assert_eq!(&a[40..], &b2);
    }
}
