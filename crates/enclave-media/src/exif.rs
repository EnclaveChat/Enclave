//! Just enough EXIF to read the orientation tag, then turn the pixels
//! upright (the tag itself is dropped with the rest of the metadata).

use crate::Rgba;

/// The orientation (1–8) in a JPEG's EXIF block (with or without the
/// leading `Exif\0\0`), if present and sane.
pub fn orientation(exif: &[u8]) -> Option<u16> {
    let tiff = exif.strip_prefix(b"Exif\0\0").unwrap_or(exif);
    let le = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |o: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(o..o + 2)?.try_into().ok()?;
        Some(if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let b: [u8; 4] = tiff.get(o..o + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    if u16_at(2)? != 42 {
        return None;
    }
    let ifd = u32_at(4)? as usize;
    let count = usize::from(u16_at(ifd)?).min(512);
    for i in 0..count {
        let e = ifd + 2 + i * 12;
        if u16_at(e)? == 0x0112 {
            let v = u16_at(e + 8)?;
            return (1..=8).contains(&v).then_some(v);
        }
    }
    None
}

/// Apply EXIF orientation `o` so the result displays upright.
pub fn orient(img: Rgba, o: u16) -> Rgba {
    if !(2..=8).contains(&o) {
        return img;
    }
    let (w, h) = (img.width as usize, img.height as usize);
    // Orientations 5–8 swap the axes.
    let (nw, nh) = if o >= 5 { (h, w) } else { (w, h) };
    let mut out = vec![0u8; img.pixels.len()];
    for y in 0..h {
        for x in 0..w {
            let (nx, ny) = match o {
                2 => (w - 1 - x, y),
                3 => (w - 1 - x, h - 1 - y),
                4 => (x, h - 1 - y),
                5 => (y, x),
                6 => (h - 1 - y, x),
                7 => (h - 1 - y, w - 1 - x),
                _ => (y, w - 1 - x),
            };
            let s = (y * w + x) * 4;
            let d = (ny * nw + nx) * 4;
            out[d..d + 4].copy_from_slice(&img.pixels[s..s + 4]);
        }
    }
    Rgba {
        width: nw as u32,
        height: nh as u32,
        pixels: out,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A big-endian TIFF block with one IFD entry: orientation `o`.
    pub fn block(o: u16) -> Vec<u8> {
        let mut b = b"Exif\0\0MM\0\x2a\0\0\0\x08".to_vec();
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0x01, 0x12, 0, 3, 0, 0, 0, 1]);
        b.extend_from_slice(&o.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        b
    }

    #[test]
    fn reads_orientation_and_rotates() {
        assert_eq!(orientation(&block(6)), Some(6));
        assert_eq!(orientation(&block(9)), None);
        assert_eq!(orientation(b"Exif\0\0junk"), None);
        assert_eq!(orientation(&[]), None);
        // 2×1: red, blue. Orientation 6 (rotate 90° clockwise) → 1×2,
        // red on top.
        let img = Rgba {
            width: 2,
            height: 1,
            pixels: vec![255, 0, 0, 255, 0, 0, 255, 255],
        };
        let r = orient(img.clone(), 6);
        assert_eq!((r.width, r.height), (1, 2));
        assert_eq!(&r.pixels[..4], &[255, 0, 0, 255]);
        let r = orient(img.clone(), 8);
        assert_eq!(&r.pixels[..4], &[0, 0, 255, 255]);
        assert_eq!(orient(img.clone(), 1), img);
        let r = orient(img, 3);
        assert_eq!(&r.pixels[..4], &[0, 0, 255, 255]);
    }
}
