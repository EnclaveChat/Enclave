//! Voice notes (`docs/15-client.md` §5: "Voice notes: Opus").
//!
//! A voice note is Opus in a small fixed-chunk container of our own, so
//! there is no Ogg demuxer to attack:
//!
//! ```text
//! "EVN1" ‖ u32 frames ‖ u16 packet_len ‖ 64 B waveform ‖ frames × packet_len
//! ```
//!
//! Every frame is 20 ms of 48 kHz mono, encoded at a constant 24 kbit/s
//! (`packet_len` = 60), so the size depends only on the duration. The
//! waveform is 64 peak levels (0–255) for the bubble. The sender's audio
//! comes in as a WAV file (any common rate, mono or stereo, 8 or 16 bit),
//! which is resampled and re-encoded: nothing of the original file but its
//! sound leaves the device. Decoding uses `opus-decoder`, which has no
//! unsafe code; the encoder (`opus-rs`) only ever sees our own audio.

use crate::{MediaError, Result};

/// Sample rate of every voice note.
pub const RATE: u32 = 48_000;
/// Samples per frame (20 ms).
pub const FRAME: usize = (RATE as usize) / 50;
/// Encoded bit rate.
pub const BITRATE: i32 = 24_000;
/// Longest voice note: 15 minutes.
pub const MAX_FRAMES: u32 = 15 * 60 * 50;
/// Waveform points.
pub const WAVEFORM: usize = 64;
const MAGIC: &[u8; 4] = b"EVN1";
const HEADER: usize = 4 + 4 + 2 + WAVEFORM;

/// What a voice note's header says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceInfo {
    /// Length in milliseconds.
    pub duration_ms: u32,
    /// 64 peak levels, 0 to 255.
    pub waveform: Vec<u8>,
}

/// Mono 16-bit PCM from a WAV file, at its own rate.
fn read_wav(b: &[u8]) -> Result<(Vec<i16>, u32)> {
    let bad = MediaError::Damaged;
    if b.len() < 12 || &b[..4] != b"RIFF" || &b[8..12] != b"WAVE" {
        return Err(MediaError::NotAnImage);
    }
    let mut at = 12;
    let mut fmt: Option<(u16, u16, u32, u16)> = None;
    while at + 8 <= b.len() {
        let id = &b[at..at + 4];
        let len = u32::from_le_bytes(b[at + 4..at + 8].try_into().map_err(|_| bad)?) as usize;
        let body = b.get(at + 8..at + 8 + len).ok_or(bad)?;
        if id == b"fmt " && len >= 16 {
            let u16le = |o: usize| u16::from_le_bytes([body[o], body[o + 1]]);
            let rate = u32::from_le_bytes(body[4..8].try_into().map_err(|_| bad)?);
            fmt = Some((u16le(0), u16le(2), rate, u16le(14)));
        } else if id == b"data" {
            let (format, channels, rate, bits) = fmt.ok_or(bad)?;
            if format != 1 || !(1..=2).contains(&channels) || !(8_000..=96_000).contains(&rate) {
                return Err(MediaError::Unsupported);
            }
            let ch = usize::from(channels);
            let samples: Vec<i16> = match bits {
                16 => body
                    .chunks_exact(2 * ch)
                    .map(|f| {
                        let sum: i32 = f
                            .chunks_exact(2)
                            .map(|s| i32::from(i16::from_le_bytes([s[0], s[1]])))
                            .sum();
                        (sum / ch as i32) as i16
                    })
                    .collect(),
                8 => body
                    .chunks_exact(ch)
                    .map(|f| {
                        let sum: i32 = f.iter().map(|&s| (i32::from(s) - 128) << 8).sum();
                        (sum / ch as i32) as i16
                    })
                    .collect(),
                _ => return Err(MediaError::Unsupported),
            };
            return Ok((samples, rate));
        }
        at += 8 + len + (len & 1);
    }
    Err(bad)
}

/// Linear resampling to [`RATE`].
fn resample(pcm: &[i16], rate: u32) -> Vec<i16> {
    if rate == RATE || pcm.is_empty() {
        return pcm.to_vec();
    }
    let n = (pcm.len() as u64 * u64::from(RATE) / u64::from(rate)) as usize;
    (0..n)
        .map(|i| {
            let pos = i as f64 * f64::from(rate) / f64::from(RATE);
            let j = pos as usize;
            let t = pos - j as f64;
            let a = f64::from(pcm[j.min(pcm.len() - 1)]);
            let b = f64::from(pcm[(j + 1).min(pcm.len() - 1)]);
            (a + (b - a) * t) as i16
        })
        .collect()
}

fn waveform(pcm: &[i16]) -> Vec<u8> {
    let chunk = pcm.len().div_ceil(WAVEFORM).max(1);
    let mut w: Vec<u8> = pcm
        .chunks(chunk)
        .map(|c| {
            let peak = c
                .iter()
                .map(|s| i32::from(*s).unsigned_abs())
                .max()
                .unwrap_or(0);
            (peak * 255 / 32_768) as u8
        })
        .collect();
    w.resize(WAVEFORM, 0);
    w
}

/// A WAV recording as a voice note.
pub fn voice_note_from_wav(wav: &[u8]) -> Result<Vec<u8>> {
    if wav.len() > crate::MAX_INPUT {
        return Err(MediaError::TooLarge);
    }
    let (pcm, rate) = read_wav(wav)?;
    let pcm = resample(&pcm, rate);
    let frames = pcm.len().div_ceil(FRAME);
    if frames == 0 {
        return Err(MediaError::Damaged);
    }
    if frames > MAX_FRAMES as usize {
        return Err(MediaError::TooLarge);
    }
    let mut enc = opus_rs::OpusEncoder::new(RATE as i32, 1, opus_rs::Application::Voip)
        .map_err(|_| MediaError::Encode)?;
    enc.bitrate_bps = BITRATE;
    enc.use_cbr = true;
    let mut packets = Vec::with_capacity(frames);
    let mut buf = vec![0i16; FRAME];
    for i in 0..frames {
        let part = &pcm[i * FRAME..((i + 1) * FRAME).min(pcm.len())];
        buf.fill(0);
        buf[..part.len()].copy_from_slice(part);
        let mut out = vec![0u8; 400];
        let n = enc
            .encode_i16(&buf, FRAME, &mut out)
            .map_err(|_| MediaError::Encode)?;
        out.truncate(n);
        packets.push(out);
    }
    // Constant bit rate: every packet the same size. If the encoder ever
    // differs, pad to the largest (Opus decoders ignore trailing zeros
    // only in padding frames, so refuse instead).
    let len = packets[0].len();
    if packets.iter().any(|p| p.len() != len) || len == 0 || len > u16::MAX as usize {
        return Err(MediaError::Encode);
    }
    let mut b = Vec::with_capacity(HEADER + frames * len);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&(frames as u32).to_be_bytes());
    b.extend_from_slice(&(len as u16).to_be_bytes());
    b.extend_from_slice(&waveform(&pcm));
    for p in &packets {
        b.extend_from_slice(p);
    }
    Ok(b)
}

/// Check a voice note's container and read its header.
pub fn voice_info(b: &[u8]) -> Result<VoiceInfo> {
    let (frames, _, wave, _) = parse(b)?;
    Ok(VoiceInfo {
        duration_ms: frames * 20,
        waveform: wave.to_vec(),
    })
}

fn parse(b: &[u8]) -> Result<(u32, usize, &[u8], &[u8])> {
    let bad = MediaError::Damaged;
    if b.len() < HEADER || &b[..4] != MAGIC {
        return Err(MediaError::NotAnImage);
    }
    let frames = u32::from_be_bytes(b[4..8].try_into().map_err(|_| bad)?);
    let len = usize::from(u16::from_be_bytes([b[8], b[9]]));
    if frames == 0 || frames > MAX_FRAMES || len == 0 || len > 1275 {
        return Err(bad);
    }
    let body = &b[HEADER..];
    if body.len() != frames as usize * len {
        return Err(bad);
    }
    Ok((frames, len, &b[10..HEADER], body))
}

/// Decode a voice note to 48 kHz mono PCM.
pub fn decode_voice(b: &[u8]) -> Result<Vec<i16>> {
    let (frames, len, _, body) = parse(b)?;
    let mut dec = opus_decoder::OpusDecoder::new(RATE, 1).map_err(|_| MediaError::Damaged)?;
    let mut pcm = Vec::with_capacity(frames as usize * FRAME);
    let mut out = vec![0i16; FRAME * 6];
    for p in body.chunks_exact(len) {
        let n = dec
            .decode(p, &mut out, false)
            .map_err(|_| MediaError::Damaged)?;
        pcm.extend_from_slice(&out[..n.min(out.len())]);
    }
    Ok(pcm)
}

/// A voice note as a 16-bit mono WAV file, to listen to elsewhere.
pub fn voice_to_wav(b: &[u8]) -> Result<Vec<u8>> {
    let pcm = decode_voice(b)?;
    let data = pcm.len() * 2;
    let mut w = Vec::with_capacity(44 + data);
    w.extend_from_slice(b"RIFF");
    w.extend_from_slice(&((36 + data) as u32).to_le_bytes());
    w.extend_from_slice(b"WAVEfmt ");
    w.extend_from_slice(&16u32.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(&RATE.to_le_bytes());
    w.extend_from_slice(&(RATE * 2).to_le_bytes());
    w.extend_from_slice(&2u16.to_le_bytes());
    w.extend_from_slice(&16u16.to_le_bytes());
    w.extend_from_slice(b"data");
    w.extend_from_slice(&(data as u32).to_le_bytes());
    for s in pcm {
        w.extend_from_slice(&s.to_le_bytes());
    }
    Ok(w)
}

/// Whether `b` looks like a WAV file.
pub fn is_wav(b: &[u8]) -> bool {
    b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WAVE"
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn wav(rate: u32, channels: u16, secs: f32) -> Vec<u8> {
        let n = (rate as f32 * secs) as usize;
        let mut pcm = Vec::new();
        for i in 0..n {
            let s = ((i as f32 * 440.0 * 2.0 * std::f32::consts::PI / rate as f32).sin() * 9000.0)
                as i16;
            for _ in 0..channels {
                pcm.extend_from_slice(&s.to_le_bytes());
            }
        }
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&((36 + pcm.len()) as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&channels.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * 2 * u32::from(channels)).to_le_bytes());
        w.extend_from_slice(&(2 * channels).to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        // A metadata chunk the note must not carry.
        w.extend_from_slice(b"LIST");
        w.extend_from_slice(&12u32.to_le_bytes());
        w.extend_from_slice(b"INFOIART\0\0\0\0");
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
        w.extend_from_slice(&pcm);
        w
    }

    #[test]
    fn a_wav_becomes_a_voice_note_and_back() {
        let note = voice_note_from_wav(&wav(44_100, 2, 1.5)).unwrap();
        let info = voice_info(&note).unwrap();
        assert_eq!(info.duration_ms, 1500);
        assert_eq!(info.waveform.len(), WAVEFORM);
        assert!(info.waveform[10] > 50, "a loud tone shows in the waveform");
        assert_eq!(
            note.len(),
            HEADER + 75 * 60,
            "constant bit rate: size from duration"
        );
        assert!(!note.windows(4).any(|w| w == b"IART"), "no WAV metadata");
        let pcm = decode_voice(&note).unwrap();
        assert_eq!(pcm.len(), 75 * FRAME);
        let energy =
            |v: &[i16]| v.iter().map(|&s| f64::from(s).powi(2)).sum::<f64>() / v.len() as f64;
        assert!(energy(&pcm[FRAME * 20..]) > 1e7, "the tone survives");
        let back = voice_to_wav(&note).unwrap();
        assert!(is_wav(&back));
        assert_eq!(read_wav(&back).unwrap().0.len(), pcm.len());
    }

    #[test]
    fn damaged_notes_and_odd_wavs_are_refused() {
        let note = voice_note_from_wav(&wav(16_000, 1, 0.2)).unwrap();
        assert!(voice_info(&note[..note.len() - 1]).is_err(), "truncated");
        let mut huge = note.clone();
        huge[4..8].copy_from_slice(&(MAX_FRAMES + 1).to_be_bytes());
        assert!(voice_info(&huge).is_err());
        let mut fmt = wav(16_000, 1, 0.2);
        fmt[20] = 3; // IEEE float
        assert!(voice_note_from_wav(&fmt).is_err());
        assert!(voice_note_from_wav(b"RIFF\0\0\0\0WAVE").is_err());
        assert!(voice_note_from_wav(b"not a wav").is_err());
    }
}
