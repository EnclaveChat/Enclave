//! Canonical binary encoding for signed and hashed protocol objects.
//!
//! Fixed-width big-endian integers, fixed-length byte arrays written raw, and
//! variable-length byte strings prefixed with a `u32` length. There is exactly
//! one encoding for every value, so signatures and transcript hashes are
//! unambiguous. Decoding rejects trailing bytes.

use crate::error::{ProtoError, Result};

/// Canonical writer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Empty writer.
    pub fn new() -> Self {
        Self::default()
    }
    /// Write a `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    /// Write a `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Write a `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Write a `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    /// Write fixed-length bytes (length known to the reader).
    pub fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    /// Write length-prefixed bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
        self
    }
    /// Finish.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
    /// Borrow the bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Canonical reader.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Read from `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(ProtoError::Decode);
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }
    /// Read a `u8`.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// Read a `u16`.
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    /// Read a `u32`.
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// Read a `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    /// Read a fixed-length array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }
    /// Read `n` raw bytes.
    pub fn fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
    /// Read length-prefixed bytes, refusing lengths above `max`.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(ProtoError::Decode);
        }
        self.take(n)
    }
    /// Require that all input was consumed.
    pub fn end(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(ProtoError::Decode)
        }
    }
    /// Remaining unread bytes.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_strictness() {
        let mut w = Writer::new();
        w.u8(1).u16(2).u32(3).u64(4).fixed(&[5; 3]).bytes(b"hello");
        let v = w.finish();
        let mut r = Reader::new(&v);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 2);
        assert_eq!(r.u32().unwrap(), 3);
        assert_eq!(r.u64().unwrap(), 4);
        assert_eq!(r.array::<3>().unwrap(), [5; 3]);
        assert_eq!(r.bytes(10).unwrap(), b"hello");
        r.end().unwrap();
        let mut r = Reader::new(&v);
        r.fixed(18).unwrap();
        assert!(r.bytes(4).is_err(), "length above max is rejected");
    }
}
