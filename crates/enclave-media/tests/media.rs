//! Sender-side sanitising and receiver-side decoding.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_media::{Format, MAX_SIDE, MediaError, decode, detect, sanitize, thumbnail};

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A JPEG of `w × h` (left half red, right half blue) carrying an EXIF block
/// with orientation `o` and a fake GPS marker.
fn jpeg(w: u16, h: u16, o: u16) -> Vec<u8> {
    let mut px = Vec::new();
    for _ in 0..h {
        for x in 0..w {
            px.extend_from_slice(if x < w / 2 {
                &[220, 20, 20]
            } else {
                &[20, 20, 220]
            });
        }
    }
    let mut exif = b"Exif\0\0MM\0\x2a\0\0\0\x08".to_vec();
    exif.extend_from_slice(&1u16.to_be_bytes());
    exif.extend_from_slice(&[0x01, 0x12, 0, 3, 0, 0, 0, 1]);
    exif.extend_from_slice(&o.to_be_bytes());
    exif.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    exif.extend_from_slice(b"GPS 51.5007N 0.1246W");
    let mut out = Vec::new();
    let mut e = jpeg_encoder::Encoder::new(&mut out, 90);
    e.add_app_segment(1, exif).unwrap();
    e.encode(&px, w, h, jpeg_encoder::ColorType::Rgb).unwrap();
    out
}

fn png_rgba(w: u32, h: u32, alpha: u8, text: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(png::ColorType::Rgba);
        e.set_depth(png::BitDepth::Eight);
        if let Some(t) = text {
            e.add_text_chunk("Comment".into(), t.into()).unwrap();
        }
        let mut wr = e.write_header().unwrap();
        wr.write_image_data(&vec![alpha; (w * h * 4) as usize])
            .unwrap();
    }
    out
}

#[test]
fn jpeg_metadata_is_gone_and_orientation_applied() {
    let src = jpeg(64, 32, 6);
    assert!(contains(&src, b"GPS 51.5007N"));
    let s = sanitize(&src).unwrap();
    assert_eq!(s.format, Format::Jpeg);
    assert!(!contains(&s.bytes, b"GPS"), "EXIF survived");
    assert!(!contains(&s.bytes, b"Exif"), "EXIF survived");
    // Rotated upright: 32 × 64, red half on top.
    assert_eq!((s.width, s.height), (32, 64));
    let img = decode(&s.bytes).unwrap();
    assert_eq!((img.width, img.height), (32, 64));
    let top = &img.pixels[(5 * 32 + 16) * 4..][..4];
    let bottom = &img.pixels[(58 * 32 + 16) * 4..][..4];
    assert!(top[0] > 150 && top[2] < 100, "{top:?}");
    assert!(bottom[2] > 150 && bottom[0] < 100, "{bottom:?}");
}

#[test]
fn png_keeps_transparency_and_loses_text() {
    let src = png_rgba(20, 10, 100, Some("taken at home"));
    assert!(contains(&src, b"taken at home"));
    let s = sanitize(&src).unwrap();
    assert_eq!(s.format, Format::Png);
    assert!(!contains(&s.bytes, b"taken at home"));
    assert_eq!(decode(&s.bytes).unwrap().pixels[3], 100);
    // Fully opaque PNGs become JPEGs.
    assert_eq!(
        sanitize(&png_rgba(8, 8, 255, None)).unwrap().format,
        Format::Jpeg
    );
}

#[test]
fn big_pictures_shrink() {
    let s = sanitize(&png_rgba(5000, 100, 255, None)).unwrap();
    assert_eq!((s.width, s.height), (MAX_SIDE, 82));
    let t = thumbnail(&png_rgba(300, 600, 255, None), 120).unwrap();
    assert_eq!((t.width, t.height), (60, 120));
    assert_eq!(t.pixels.len(), 60 * 120 * 4);
}

/// PNG chunk with its CRC.
fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let crc = {
        let mut c = 0xFFFF_FFFFu32;
        for &b in kind.iter().chain(data) {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        !c
    };
    [
        &(data.len() as u32).to_be_bytes()[..],
        kind,
        data,
        &crc.to_be_bytes(),
    ]
    .concat()
}

#[test]
fn forged_sizes_and_garbage_are_refused() {
    // A 100 000 × 100 000 header in a tiny file.
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&100_000u32.to_be_bytes());
    ihdr.extend_from_slice(&100_000u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    let bomb = [
        &b"\x89PNG\r\n\x1a\n"[..],
        &chunk(b"IHDR", &ihdr),
        &chunk(b"IDAT", &[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]),
        &chunk(b"IEND", &[]),
    ]
    .concat();
    assert_eq!(detect(&bomb), Some(Format::Png));
    assert_eq!(decode(&bomb), Err(MediaError::TooLarge));
    assert_eq!(sanitize(b"GIF89a...."), Err(MediaError::NotAnImage));
    assert_eq!(decode(b""), Err(MediaError::NotAnImage));
    // Every truncation of real files fails cleanly.
    for src in [jpeg(24, 16, 1), png_rgba(12, 12, 50, None)] {
        for n in (0..src.len()).step_by(7) {
            let _ = decode(&src[..n]);
        }
        let mut flipped = src.clone();
        for i in (20..flipped.len()).step_by(13) {
            flipped[i] ^= 0x5a;
            let _ = decode(&flipped);
        }
    }
}
