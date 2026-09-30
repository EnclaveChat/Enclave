//! Shrinking by area averaging: every source pixel contributes to the
//! output pixels it overlaps, weighted by the overlap. Never enlarges.

use crate::Rgba;

/// Shrink `img` so its long side is at most `max_side` (aspect kept).
pub fn fit(img: &Rgba, max_side: u32) -> Rgba {
    let long = img.width.max(img.height);
    if long <= max_side {
        return img.clone();
    }
    let scale = f64::from(max_side) / f64::from(long);
    let w = ((f64::from(img.width) * scale).round() as u32).max(1);
    let h = ((f64::from(img.height) * scale).round() as u32).max(1);
    let cols = weights(img.width, w);
    let rows = weights(img.height, h);
    // Horizontal pass into f32 rows, then vertical.
    let sw = img.width as usize;
    let mut tmp = vec![0f32; img.height as usize * w as usize * 4];
    for y in 0..img.height as usize {
        let src = &img.pixels[y * sw * 4..(y + 1) * sw * 4];
        for (x, taps) in cols.iter().enumerate() {
            let mut acc = [0f32; 4];
            for &(sx, wgt) in taps {
                for c in 0..4 {
                    acc[c] += f32::from(src[sx * 4 + c]) * wgt;
                }
            }
            tmp[(y * w as usize + x) * 4..][..4].copy_from_slice(&acc);
        }
    }
    let mut out = vec![0u8; w as usize * h as usize * 4];
    for (y, taps) in rows.iter().enumerate() {
        for x in 0..w as usize {
            let mut acc = [0f32; 4];
            for &(sy, wgt) in taps {
                for c in 0..4 {
                    acc[c] += tmp[(sy * w as usize + x) * 4 + c] * wgt;
                }
            }
            for c in 0..4 {
                out[(y * w as usize + x) * 4 + c] = acc[c].round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    Rgba {
        width: w,
        height: h,
        pixels: out,
    }
}

/// For each of `dst` output positions, the source positions it covers and
/// their weights (summing to 1).
fn weights(src: u32, dst: u32) -> Vec<Vec<(usize, f32)>> {
    let ratio = f64::from(src) / f64::from(dst);
    (0..dst)
        .map(|i| {
            let start = f64::from(i) * ratio;
            let end = start + ratio;
            let mut taps = Vec::new();
            let mut s = start.floor() as u32;
            while f64::from(s) < end && s < src {
                let lo = start.max(f64::from(s));
                let hi = end.min(f64::from(s) + 1.0);
                if hi > lo {
                    taps.push((s as usize, ((hi - lo) / ratio) as f32));
                }
                s += 1;
            }
            taps
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn halves_average_and_keep_aspect() {
        // 4×2 of alternating black and white columns → 2×1 mid grey.
        let px: Vec<u8> = (0..8)
            .flat_map(|i| {
                if i % 2 == 0 {
                    [0, 0, 0, 255]
                } else {
                    [255, 255, 255, 255]
                }
            })
            .collect();
        let img = Rgba {
            width: 4,
            height: 2,
            pixels: px,
        };
        let out = fit(&img, 2);
        assert_eq!((out.width, out.height), (2, 1));
        for p in out.pixels.chunks_exact(4) {
            assert!((126..=129).contains(&p[0]) && p[3] == 255, "{p:?}");
        }
        assert_eq!(fit(&img, 10), img, "never enlarges");
        let odd = fit(&img, 3);
        assert_eq!((odd.width, odd.height), (3, 2));
    }
}
