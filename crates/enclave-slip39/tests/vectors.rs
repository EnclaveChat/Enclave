//! Vectors from the reference implementation (`shamir-mnemonic` 0.3),
//! generated with its random source replaced by the byte stream 0, 1, 2, …
//! (mod 256), continuing across calls. Generating from the same stream here
//! must give the same words; combining a threshold's worth must give the
//! master secret back.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_slip39::{Slip39Error, combine, generate};

fn stream() -> impl FnMut(&mut [u8]) {
    let mut c: usize = 0;
    move |b: &mut [u8]| {
        for x in b.iter_mut() {
            *x = (c % 256) as u8;
            c += 1;
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn reference_vectors() {
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    for case in v.as_array().unwrap() {
        let gt = case["group_threshold"].as_u64().unwrap() as u8;
        let groups: Vec<(u8, u8)> = case["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| (g[0].as_u64().unwrap() as u8, g[1].as_u64().unwrap() as u8))
            .collect();
        let master = hex(case["master"].as_str().unwrap());
        let pass = case["passphrase"].as_str().unwrap().as_bytes();
        let ext = case["extendable"].as_bool().unwrap();
        let e = case["iteration_exponent"].as_u64().unwrap() as u8;
        let want: Vec<Vec<String>> = case["mnemonics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                g.as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_str().unwrap().to_string())
                    .collect()
            })
            .collect();

        let got = generate(gt, &groups, &master, pass, ext, e, &mut stream()).unwrap();
        assert_eq!(got, want, "same words as the reference");

        // A threshold's worth: the first `gt` groups, the last shares of each.
        let mut pick: Vec<&str> = Vec::new();
        for (g, &(mt, _)) in want.iter().zip(&groups).take(gt as usize) {
            pick.extend(g.iter().rev().take(mt as usize).map(String::as_str));
        }
        assert_eq!(*combine(&pick, pass).unwrap(), master);
        if !pass.is_empty() {
            assert_ne!(
                *combine(&pick, b"wrong").unwrap(),
                master,
                "passphrase matters"
            );
        }
    }
}

#[test]
fn bad_share_sets_are_refused() {
    let master = [7u8; 32];
    let g = generate(1, &[(3, 5)], &master, b"", true, 0, &mut stream()).unwrap();
    let s: Vec<&str> = g[0].iter().map(String::as_str).collect();
    assert_eq!(*combine(&s[..3], b"").unwrap(), master);
    assert!(
        matches!(combine(&s[..2], b""), Err(Slip39Error::Shares(_))),
        "too few"
    );
    assert!(
        matches!(combine(&s[..4], b""), Err(Slip39Error::Shares(_))),
        "too many"
    );
    // A typo breaks the checksum.
    let mut typo: Vec<String> = s.iter().map(|x| x.to_string()).collect();
    let mut w: Vec<&str> = typo[0].split(' ').collect();
    w[10] = if w[10] == "academic" {
        "acid"
    } else {
        "academic"
    };
    typo[0] = w.join(" ");
    let t: Vec<&str> = typo.iter().map(String::as_str).collect();
    assert_eq!(combine(&t[..3], b""), Err(Slip39Error::Mnemonic));
    // Shares from two different splits don't mix.
    let other = generate(
        1,
        &[(3, 5)],
        &master,
        b"",
        true,
        0,
        &mut |b: &mut [u8]| b.fill(9),
    )
    .unwrap();
    assert!(combine(&[s[0], s[1], other[0][2].as_str()], b"").is_err());
    // Parameters.
    assert!(generate(1, &[(1, 2)], &master, b"", true, 0, &mut stream()).is_err());
    assert!(generate(2, &[(1, 1)], &master, b"", true, 0, &mut stream()).is_err());
    assert!(generate(1, &[(3, 5)], &[1; 15], b"", true, 0, &mut stream()).is_err());
    assert!(generate(1, &[(3, 17)], &master, b"", true, 0, &mut stream()).is_err());
}
