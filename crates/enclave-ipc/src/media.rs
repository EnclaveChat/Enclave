//! Messages between the vault and `mediad` (`docs/15-client.md` §1.1a).
//!
//! `mediad` holds no keys: the vault hands it the bytes of a picture (one
//! the person is sending, or a decrypted attachment) and gets back a
//! re-encoded file or raw RGBA pixels.

use crate::codec::{MAX_BYTES, Reader, Writer};
use crate::{IpcError, Result};

/// What to do with the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaOp {
    /// Re-encode a picture for sending (metadata stripped, shrunk).
    Sanitize,
    /// Decode and shrink to at most this many pixels on the long side.
    Thumbnail(u16),
    /// Re-encode like `Sanitize`, at most this many pixels on the long
    /// side (stickers).
    Shrink(u16),
    /// A WAV recording to a voice note.
    VoiceNote,
    /// Check a voice note and read its duration and waveform.
    VoiceInfo,
    /// A voice note as a WAV file.
    VoiceWav,
}

/// Vault → mediad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaRequest {
    /// Request number.
    pub id: u32,
    /// Operation.
    pub op: MediaOp,
    /// The picture.
    pub bytes: Vec<u8>,
}

/// A successful result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaOut {
    /// A new file: JPEG (`png` false) or PNG.
    Sanitized {
        /// PNG rather than JPEG.
        png: bool,
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// The file.
        bytes: Vec<u8>,
    },
    /// Audio: a file (voice note or WAV; empty for `VoiceInfo`), its
    /// duration and a 64-point waveform.
    Audio {
        /// Milliseconds.
        duration_ms: u32,
        /// Peak levels, 0 to 255.
        waveform: Vec<u8>,
        /// The file.
        bytes: Vec<u8>,
    },
    /// 8-bit RGBA pixels.
    Rgba {
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// `width × height × 4` bytes.
        pixels: Vec<u8>,
    },
}

/// mediad → vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaReply {
    /// The request it answers.
    pub id: u32,
    /// The result, or why there is none.
    pub result: core::result::Result<MediaOut, String>,
}

impl MediaRequest {
    /// Encode (`bytes` must fit [`MAX_BYTES`]).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.id);
        match self.op {
            MediaOp::Sanitize => w.u8(1),
            MediaOp::Thumbnail(side) => w.u8(2).u32(u32::from(side)),
            MediaOp::Shrink(side) => w.u8(3).u32(u32::from(side)),
            MediaOp::VoiceNote => w.u8(4),
            MediaOp::VoiceInfo => w.u8(5),
            MediaOp::VoiceWav => w.u8(6),
        };
        w.bytes(&self.bytes[..self.bytes.len().min(MAX_BYTES)]);
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let id = r.u32()?;
        let op = match r.u8()? {
            1 => MediaOp::Sanitize,
            2 => MediaOp::Thumbnail(u16::try_from(r.u32()?).map_err(|_| IpcError::Malformed)?),
            3 => MediaOp::Shrink(u16::try_from(r.u32()?).map_err(|_| IpcError::Malformed)?),
            4 => MediaOp::VoiceNote,
            5 => MediaOp::VoiceInfo,
            6 => MediaOp::VoiceWav,
            _ => return Err(IpcError::Malformed),
        };
        let bytes = r.bytes()?;
        r.end()?;
        Ok(Self { id, op, bytes })
    }
}

impl MediaReply {
    /// Encode. A result over [`MAX_BYTES`] becomes an error.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u32(self.id);
        match &self.result {
            Ok(MediaOut::Sanitized {
                png,
                width,
                height,
                bytes,
            }) if bytes.len() <= MAX_BYTES => {
                w.u8(1).bool(*png).u32(*width).u32(*height).bytes(bytes);
            }
            Ok(MediaOut::Rgba {
                width,
                height,
                pixels,
            }) if pixels.len() <= MAX_BYTES => {
                w.u8(2).u32(*width).u32(*height).bytes(pixels);
            }
            Ok(MediaOut::Audio {
                duration_ms,
                waveform,
                bytes,
            }) if bytes.len() <= MAX_BYTES && waveform.len() <= 64 => {
                w.u8(3).u32(*duration_ms).bytes(waveform).bytes(bytes);
            }
            Ok(_) => {
                w.u8(0).str("too large");
            }
            Err(e) => {
                w.u8(0).str(e);
            }
        }
        w.0
    }

    /// Decode. RGBA must be exactly `width × height × 4` bytes.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let id = r.u32()?;
        let result = match r.u8()? {
            0 => Err(r.str()?),
            1 => Ok(MediaOut::Sanitized {
                png: r.bool()?,
                width: r.u32()?,
                height: r.u32()?,
                bytes: r.bytes()?,
            }),
            2 => {
                let (width, height) = (r.u32()?, r.u32()?);
                let pixels = r.bytes()?;
                if crate::rgba_len(width, height) != Some(pixels.len()) {
                    return Err(IpcError::Malformed);
                }
                Ok(MediaOut::Rgba {
                    width,
                    height,
                    pixels,
                })
            }
            3 => {
                let duration_ms = r.u32()?;
                let waveform = r.bytes()?;
                if waveform.len() > 64 {
                    return Err(IpcError::Malformed);
                }
                Ok(MediaOut::Audio {
                    duration_ms,
                    waveform,
                    bytes: r.bytes()?,
                })
            }
            _ => return Err(IpcError::Malformed),
        };
        r.end()?;
        Ok(Self { id, result })
    }
}
