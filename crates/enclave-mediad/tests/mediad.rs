//! mediad answers picture requests from inside its sandbox.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::media::{MediaOp, MediaOut, MediaReply, MediaRequest};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_enclave-mediad");

fn png(w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut e = png::Encoder::new(&mut out, w, h);
        e.set_color(png::ColorType::Rgba);
        e.set_depth(png::BitDepth::Eight);
        e.add_text_chunk("Comment".into(), "at home".into())
            .unwrap();
        let mut wr = e.write_header().unwrap();
        wr.write_image_data(&vec![255; (w * h * 4) as usize])
            .unwrap();
    }
    out
}

fn send(stdin: &mut impl Write, r: &MediaRequest) {
    let b = r.encode();
    stdin.write_all(&(b.len() as u32).to_be_bytes()).unwrap();
    stdin.write_all(&b).unwrap();
    stdin.flush().unwrap();
}

fn recv(stdout: &mut impl Read) -> MediaReply {
    let mut len = [0u8; 4];
    stdout.read_exact(&mut len).unwrap();
    let mut b = vec![0u8; u32::from_be_bytes(len) as usize];
    stdout.read_exact(&mut b).unwrap();
    MediaReply::decode(&b).unwrap()
}

#[test]
fn sanitizes_thumbnails_and_refuses() {
    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    send(
        &mut stdin,
        &MediaRequest {
            id: 1,
            op: MediaOp::Sanitize,
            bytes: png(40, 20),
        },
    );
    let r = recv(&mut stdout);
    assert_eq!(r.id, 1);
    match r.result.unwrap() {
        MediaOut::Sanitized {
            png,
            width,
            height,
            bytes,
        } => {
            assert!(!png, "opaque pictures become JPEG");
            assert_eq!((width, height), (40, 20));
            assert!(!bytes.windows(7).any(|w| w == b"at home"));
        }
        other => panic!("{other:?}"),
    }
    send(
        &mut stdin,
        &MediaRequest {
            id: 2,
            op: MediaOp::Thumbnail(10),
            bytes: png(40, 20),
        },
    );
    match recv(&mut stdout).result.unwrap() {
        MediaOut::Rgba {
            width,
            height,
            pixels,
        } => {
            assert_eq!((width, height), (10, 5));
            assert_eq!(pixels.len(), 200);
        }
        other => panic!("{other:?}"),
    }
    send(
        &mut stdin,
        &MediaRequest {
            id: 3,
            op: MediaOp::Thumbnail(10),
            bytes: b"not a picture".to_vec(),
        },
    );
    let r = recv(&mut stdout);
    assert_eq!(r.id, 3);
    assert!(r.result.is_err());

    // Garbage ends it.
    stdin.write_all(&[0, 0, 0, 1, 9]).unwrap();
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

/// Like netd, mediad links nothing that holds keys.
#[test]
fn mediad_has_no_key_material() {
    fn deps(dir: &Path, seen: &mut BTreeSet<String>) {
        let toml = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
        let mut in_deps = false;
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_deps = t.ends_with("dependencies]") && !t.contains("dev-");
                continue;
            }
            if let (true, Some(i)) = (in_deps, t.find("path = \"")) {
                let rel = &t[i + 8..];
                let rel = &rel[..rel.find('"').unwrap()];
                if seen.insert(t.split_whitespace().next().unwrap().to_string()) {
                    deps(&dir.join(rel), seen);
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    deps(Path::new(env!("CARGO_MANIFEST_DIR")), &mut seen);
    assert!(seen.contains("enclave-media"));
    for banned in [
        "enclave-store",
        "enclave-core",
        "enclave-proto",
        "enclave-crypto",
        "enclave-net",
        "enclave-vault",
    ] {
        assert!(
            !seen.contains(banned),
            "mediad depends on {banned}: {seen:?}"
        );
    }
}
