//! The canonical encoding of `enclave_proto::codec`, kept here so that the
//! network process (`enclave-netd`, which checks key bundles) doesn't link
//! the protocol crate: fixed-width big-endian integers, raw fixed-length
//! arrays, `u32`-length-prefixed byte strings, trailing bytes refused.

use crate::{FedError, Result};

/// Canonical writer.
#[derive(Default)]
pub(crate) struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
        self
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Canonical reader.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(FedError::Malformed);
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(a))
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    pub(crate) fn fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
    pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(FedError::Malformed);
        }
        self.take(n)
    }
    pub(crate) fn end(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(FedError::Malformed)
        }
    }
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len()
    }
}
