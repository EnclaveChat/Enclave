//! Framing and the connection token.

use crate::{IpcError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame either side accepts.
pub const MAX_FRAME: usize = 16 << 20;
/// Length of the connection token.
pub const TOKEN_LEN: usize = 32;

/// Write one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME {
        return Err(IpcError::TooLarge);
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(IpcError::TooLarge);
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Vault side: present the token as the first bytes of the connection.
pub async fn present_token<W: AsyncWrite + Unpin>(
    w: &mut W,
    token: &[u8; TOKEN_LEN],
) -> Result<()> {
    w.write_all(token).await?;
    w.flush().await?;
    Ok(())
}

/// UI side: read the peer's token and compare it in constant time.
pub async fn check_token<R: AsyncRead + Unpin>(
    r: &mut R,
    expected: &[u8; TOKEN_LEN],
) -> Result<()> {
    let mut got = [0u8; TOKEN_LEN];
    r.read_exact(&mut got).await?;
    let diff = got
        .iter()
        .zip(expected.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff == 0 {
        Ok(())
    } else {
        Err(IpcError::Unauthenticated)
    }
}

/// Hex form of a token (for the environment).
pub fn token_hex(t: &[u8; TOKEN_LEN]) -> String {
    t.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse [`token_hex`].
pub fn token_from_hex(s: &str) -> Option<[u8; TOKEN_LEN]> {
    let s = s.trim();
    if s.len() != 2 * TOKEN_LEN {
        return None;
    }
    let mut t = [0u8; TOKEN_LEN];
    for (i, out) in t.iter_mut().enumerate() {
        *out = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(t)
}
