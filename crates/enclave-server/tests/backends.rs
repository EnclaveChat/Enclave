//! The storage backends behave the same (`docs/12-servers.md` §6): every
//! operation the server uses, transaction rollback, snapshots to redb and
//! restores from them, on redb and on PostgreSQL (`common::stores`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use enclave_server::db::{Db, ENVELOPES, INBOXES, META, SCHEMA_VERSION, TOKENS};

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-backends-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn operations(db: &Db) {
    db.write(|t| {
        t.put(ENVELOPES, b"aa\x00\x01", b"x")?;
        t.put(ENVELOPES, b"aa\x00\x02", b"y")?;
        t.put(ENVELOPES, b"aa\xff", b"edge")?;
        t.put(ENVELOPES, b"ab\x00\x01", b"z")?;
        t.put(ENVELOPES, b"\xff\xff", b"top")?;
        // Same key in another table is another row.
        t.put(TOKENS, b"aa\x00\x01", b"other")?;
        // Overwrite.
        t.put(ENVELOPES, b"aa\x00\x02", b"y2")
    })
    .unwrap();
    let scan = db.read(|r| r.scan(ENVELOPES, b"aa")).unwrap();
    assert_eq!(
        scan,
        vec![
            (b"aa\x00\x01".to_vec(), b"x".to_vec()),
            (b"aa\x00\x02".to_vec(), b"y2".to_vec()),
            (b"aa\xff".to_vec(), b"edge".to_vec()),
        ],
        "a prefix scan, in key order, through 0xff"
    );
    assert_eq!(db.read(|r| r.scan(ENVELOPES, b"")).unwrap().len(), 5);
    assert_eq!(db.read(|r| r.scan(ENVELOPES, b"\xff")).unwrap().len(), 1);
    assert_eq!(
        db.read(|r| r.next_two(ENVELOPES, b"aa", b"aa\x00\x02"))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        db.read(|r| r.next_two(ENVELOPES, b"aa", b"aa\xff"))
            .unwrap()
            .len(),
        1,
        "stops at the prefix"
    );
    db.write(|t| {
        assert_eq!(t.count(ENVELOPES, b"aa")?, 3);
        assert_eq!(t.count(ENVELOPES, b"")?, 5);
        assert_eq!(
            t.first_from(ENVELOPES, b"ab", b"ab")?,
            Some((b"ab\x00\x01".to_vec(), b"z".to_vec()))
        );
        assert_eq!(t.first_from(ENVELOPES, b"ac", b"ac")?, None);
        assert!(t.has(TOKENS, b"aa\x00\x01")?);
        assert_eq!(t.get(TOKENS, b"aa\x00\x01")?, Some(b"other".to_vec()));
        assert!(t.del(TOKENS, b"aa\x00\x01")?);
        assert!(!t.del(TOKENS, b"aa\x00\x01")?);
        assert_eq!(t.remove_where(ENVELOPES, b"aa", |k, _| k.len() == 4)?, 2);
        Ok(())
    })
    .unwrap();
    assert_eq!(db.read(|r| r.scan(ENVELOPES, b"aa")).unwrap().len(), 1);

    // A transaction that fails leaves nothing behind.
    let r: Result<(), _> = db.write(|t| {
        t.put(INBOXES, b"never", b"1")?;
        t.del(ENVELOPES, b"ab\x00\x01")?;
        Err(enclave_server::db::DbError::new("abort"))
    });
    assert!(r.is_err());
    assert_eq!(db.read(|r| r.get(INBOXES, b"never")).unwrap(), None);
    assert!(
        db.read(|r| r.get(ENVELOPES, b"ab\x00\x01"))
            .unwrap()
            .is_some()
    );

    // The schema version is recorded.
    assert_eq!(
        db.read(|r| r.get(META, b"schema")).unwrap(),
        Some(SCHEMA_VERSION.to_be_bytes().to_vec())
    );
}

#[test]
fn every_backend_does_the_same() {
    let d = dir("ops");
    for store in common::stores("every_backend_does_the_same", &d) {
        eprintln!("on {}", store.name());
        let db = store.open();
        operations(&db);
        // A snapshot is a redb file whatever the backend, and loads back
        // into either.
        let snap = d.join(format!("snap-{}.redb", store.name()));
        let _ = std::fs::remove_file(&snap);
        db.snapshot(&snap).unwrap();
        let copy = Db::open(&snap).unwrap();
        assert_eq!(
            copy.read(|r| r.scan(ENVELOPES, b"")).unwrap(),
            db.read(|r| r.scan(ENVELOPES, b"")).unwrap()
        );
        db.write(|t| t.put(INBOXES, b"after", b"snapshot")).unwrap();
        db.copy_from(&copy).unwrap();
        assert_eq!(db.read(|r| r.get(INBOXES, b"after")).unwrap(), None);
        assert_eq!(db.read(|r| r.scan(ENVELOPES, b"")).unwrap().len(), 3);
        drop(db);
        // Reopening keeps it.
        assert_eq!(
            store.open().read(|r| r.scan(ENVELOPES, b"")).unwrap().len(),
            3
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The server runs inside a multi-thread tokio runtime; PostgreSQL's
/// blocking client must work there.
#[tokio::test(flavor = "multi_thread")]
async fn inside_the_server_runtime() {
    let d = dir("runtime");
    // Like the server binary: set up off the runtime's threads.
    let stores = tokio::task::block_in_place(|| common::stores("inside_the_server_runtime", &d));
    for store in stores {
        let db = tokio::task::block_in_place(|| store.open());
        db.write(|t| t.put(INBOXES, b"k", b"v")).unwrap();
        let got = tokio::spawn(async move { db.read(|r| r.get(INBOXES, b"k")).unwrap() })
            .await
            .unwrap();
        assert_eq!(got, Some(b"v".to_vec()), "{}", store.name());
    }
    let _ = std::fs::remove_dir_all(&d);
}
