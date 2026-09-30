//! A minimal length-prefixed codec with strict bounds.

use crate::{IpcError, Result};

/// Longest string field (message text, previews, link codes).
pub const MAX_STR: usize = 64 * 1024;
/// Most items in one list.
pub const MAX_ITEMS: usize = 100_000;

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        let b = s.as_bytes();
        let n = b.len().min(MAX_STR);
        // Never split a character when truncating.
        let n = (0..=n).rev().find(|&i| s.is_char_boundary(i)).unwrap_or(0);
        self.u32(n as u32);
        self.0.extend_from_slice(&b[..n]);
        self
    }

    pub fn len(&mut self, n: usize) -> &mut Self {
        self.u32(n.min(MAX_ITEMS) as u32)
    }

    pub fn strs(&mut self, v: &[String]) -> &mut Self {
        self.len(v.len());
        for s in v.iter().take(MAX_ITEMS) {
            self.str(s);
        }
        self
    }
}

pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(IpcError::Malformed);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(IpcError::Malformed),
        }
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn str(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        if n > MAX_STR {
            return Err(IpcError::Malformed);
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| IpcError::Malformed)
    }

    pub fn len(&mut self) -> Result<usize> {
        let n = self.u32()? as usize;
        // Every item takes at least one byte, so a count beyond what is left
        // is a lie; refuse it before allocating.
        if n > MAX_ITEMS || n > self.0.len() {
            return Err(IpcError::Malformed);
        }
        Ok(n)
    }

    pub fn strs(&mut self) -> Result<Vec<String>> {
        let n = self.len()?;
        (0..n).map(|_| self.str()).collect()
    }

    pub fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(IpcError::Malformed)
        }
    }
}
