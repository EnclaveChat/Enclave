//! Pictures through the engine (demo mode, decoding in-process): what is
//! sent is re-encoded without its metadata, and the UI gets a preview.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::{Cmd, Out, Snapshot};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;

async fn next<T>(rx: &mut UnboundedReceiver<Out>, mut want: impl FnMut(Out) -> Option<T>) -> T {
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Some(t) = want(rx.recv().await.expect("engine running")) {
                return t;
            }
        }
    })
    .await
    .expect("in time")
}

fn snapshot(want: impl Fn(&Snapshot) -> bool) -> impl FnMut(Out) -> Option<Snapshot> {
    move |o| match o {
        Out::Snapshot(s) if want(&s) => Some(*s),
        _ => None,
    }
}

/// A phone photo: EXIF with GPS and orientation 6 (turn right).
fn photo() -> Vec<u8> {
    let (w, h) = (60u16, 40u16);
    let px: Vec<u8> = (0..u32::from(w) * u32::from(h))
        .flat_map(|i| [(i % 251) as u8, 120, 200])
        .collect();
    let mut exif =
        b"Exif\0\0MM\0\x2a\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\x06\0\0\0\0\0\0".to_vec();
    exif.extend_from_slice(b"GPS 48.8584N 2.2945E");
    let mut out = Vec::new();
    let mut e = jpeg_encoder::Encoder::new(&mut out, 90);
    e.add_app_segment(1, exif).unwrap();
    e.encode(&px, w, h, jpeg_encoder::ColorType::Rgb).unwrap();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn sent_pictures_lose_metadata_and_get_previews() {
    let (tx, mut rx) = enclave_vault::spawn(enclave_vault::Mode::Demo);
    tx.send(Cmd::Create("Robin".into(), String::new())).unwrap();
    let s = next(&mut rx, snapshot(|s| !s.requests.is_empty())).await;
    let sam = s.requests[0].id.clone();
    tx.send(Cmd::Accept(sam.clone())).unwrap();
    next(
        &mut rx,
        snapshot(|s| s.contacts.iter().any(|c| c.id == sam && c.state == 2)),
    )
    .await;
    tx.send(Cmd::Select(sam.clone())).unwrap();

    let original = photo();
    assert!(original.windows(3).any(|w| w == b"GPS"));
    tx.send(Cmd::SendFile(
        sam.clone(),
        "IMG_2041.JPG".into(),
        original,
        "Look".into(),
    ))
    .unwrap();
    let s = next(&mut rx, snapshot(|s| s.messages.iter().any(|m| m.image))).await;
    let m = s.messages.iter().find(|m| m.image).unwrap().clone();
    assert_eq!(m.file, "IMG_2041.jpg");
    assert_eq!(
        m.text, "Look",
        "pictures show their caption, not a file line"
    );

    // The preview: turned upright (40 × 60), for this conversation.
    let p = next(&mut rx, |o| match o {
        Out::Preview(p) => Some(p),
        _ => None,
    })
    .await;
    assert_eq!((p.conversation.as_str(), p.seq), (sam.as_str(), m.seq));
    assert_eq!((p.width, p.height), (40, 60));

    // What was sent (and is saved) carries no metadata.
    tx.send(Cmd::SaveFile(sam.clone(), m.seq)).unwrap();
    let (name, bytes) = next(&mut rx, |o| match o {
        Out::File(n, b) => Some((n, b)),
        _ => None,
    })
    .await;
    assert_eq!(name, "IMG_2041.jpg");
    assert!(bytes.starts_with(&[0xFF, 0xD8, 0xFF]));
    assert!(
        !bytes.windows(3).any(|w| w == b"GPS"),
        "GPS left the device"
    );
    assert!(!bytes.windows(4).any(|w| w == b"Exif"));

    // A file that only claims to be a picture is sent as a plain file.
    tx.send(Cmd::SendFile(
        sam.clone(),
        "notes.png".into(),
        b"just text".to_vec(),
        String::new(),
    ))
    .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.messages.iter().any(|m| m.file == "notes.png")),
    )
    .await;
    assert!(
        !s.messages
            .iter()
            .find(|m| m.file == "notes.png")
            .unwrap()
            .image
    );

    // A damaged picture is not sent at all.
    let mut broken = photo();
    broken.truncate(40);
    tx.send(Cmd::SendFile(
        sam.clone(),
        "broken.jpg".into(),
        broken,
        String::new(),
    ))
    .unwrap();
    let s = next(
        &mut rx,
        snapshot(|s| s.status.contains("couldn't read that picture")),
    )
    .await;
    assert!(!s.messages.iter().any(|m| m.file.starts_with("broken")));
}
