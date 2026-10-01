//! The key-transparency log on disk (`docs/12-servers.md` §3.1): akd's own
//! storage test suite passes on `KtStore`, a log reopened after a restart
//! serves the same history under the same keys, and a witness that
//! restarts still refuses a head that doesn't extend what it cosigned.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{COMPOSITE_SEED_LEN, CompositeSigningKey};
use enclave_kt::store::{decode_record, encode_record};
use enclave_kt::{KtError, KtLog, KtService, KtStore, LookupReply, Witness, verify_lookup};
use std::path::PathBuf;

const NOW: u64 = 1_790_000_000;
const SERVER: [u8; 16] = [1; 16];
const VRF: [u8; 32] = [9; 32];

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("enclave-kt-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn akd_storage_suite_passes_on_redb() {
    akd::storage::tests::run_test_cases_for_storage_impl(KtStore::memory().unwrap()).await;
    let d = dir("suite");
    akd::storage::tests::run_test_cases_for_storage_impl(
        KtStore::open(&d.join("kt.redb")).unwrap(),
    )
    .await;
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test(flavor = "multi_thread")]
async fn records_round_trip_and_damage_is_refused() {
    let store = KtStore::memory().unwrap();
    let mut log = KtLog::open(
        store.clone(),
        SERVER,
        CompositeSigningKey::generate(&mut HedgedRng::new().unwrap()).unwrap(),
        VRF,
        NOW,
        &mut HedgedRng::new().unwrap(),
    )
    .await
    .unwrap();
    let mut rng = HedgedRng::new().unwrap();
    for (i, n) in ["alice", "bob", "carol"].iter().enumerate() {
        log.publish(n, vec![i as u8; 80], NOW, &mut rng)
            .await
            .unwrap();
    }
    let d = dir("records");
    store.snapshot(&d.join("copy.redb")).unwrap();
    let copy = KtStore::open(&d.join("copy.redb")).unwrap();
    assert_eq!(copy.heads().unwrap().len(), 3);
    assert_eq!(copy.skeletons().unwrap().len(), 3);
    // Every record type survives encode → decode, and truncation or a
    // trailing byte is refused.
    let azks = akd::storage::types::DbRecord::Azks(akd::Azks {
        latest_epoch: 7,
        num_nodes: 9,
    });
    let b = encode_record(&azks);
    assert_eq!(decode_record(&b).unwrap(), azks);
    assert!(decode_record(&b[..b.len() - 1]).is_err());
    let mut longer = b.clone();
    longer.push(0);
    assert!(decode_record(&longer).is_err());
    assert!(decode_record(&[]).is_err());
    assert!(decode_record(&[3, 0, 0]).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

fn keys() -> ([u8; COMPOSITE_SEED_LEN], [u8; COMPOSITE_SEED_LEN]) {
    let mut rng = HedgedRng::new().unwrap();
    let a = *CompositeSigningKey::generate(&mut rng).unwrap().seed();
    let b = *CompositeSigningKey::generate(&mut rng).unwrap().seed();
    (a, b)
}

fn service(
    store: &KtStore,
    head: &[u8; COMPOSITE_SEED_LEN],
    witness: &[u8; COMPOSITE_SEED_LEN],
    now: u64,
) -> Result<KtService, KtError> {
    let w = Witness::with_store(
        [0xee; 16],
        "other-operator",
        CompositeSigningKey::from_seed(witness).unwrap(),
        store.clone(),
    )?;
    KtService::open(
        store.clone(),
        SERVER,
        "a.example",
        "server-operator",
        CompositeSigningKey::from_seed(head).unwrap(),
        VRF,
        vec![w],
        now,
    )
}

fn check(svc: &KtService, witness: &[u8; COMPOSITE_SEED_LEN], name: &str, now: u64) -> Vec<u8> {
    let reply = LookupReply::decode(&svc.lookup(name, now).unwrap()).unwrap();
    let w = CompositeSigningKey::from_seed(witness).unwrap();
    let policy = enclave_kt::WitnessPolicy {
        witnesses: vec![([0xee; 16], w.public().clone(), "other-operator".into())],
        threshold: 1,
    };
    let info = svc.info();
    verify_lookup(
        &policy,
        &info.head_key,
        "server-operator",
        &info.vrf_public,
        &reply.head,
        name,
        reply.proof,
        now,
    )
    .unwrap()
    .0
}

#[test]
fn a_restarted_log_keeps_its_history_keys_and_witness() {
    let d = dir("restart");
    let path = d.join("kt.redb");
    let (head, witness) = keys();

    let (vrf_public, head_key) = {
        let store = KtStore::open(&path).unwrap();
        let svc = service(&store, &head, &witness, NOW).unwrap();
        assert_eq!(svc.publish("alice", vec![1; 80], NOW).unwrap(), 1);
        assert_eq!(svc.publish("bob", vec![2; 80], NOW + 1).unwrap(), 2);
        assert_eq!(check(&svc, &witness, "alice", NOW + 2), vec![1; 80]);
        (svc.info().vrf_public.clone(), svc.info().head_key.clone())
        // Dropping the service closes the store: as good as a crash.
    };

    let store = KtStore::open(&path).unwrap();
    let svc = service(&store, &head, &witness, NOW + 10).unwrap();
    assert_eq!(svc.info().vrf_public, vrf_public, "VRF pin survives");
    assert_eq!(svc.info().head_key, head_key, "head-key pin survives");
    assert_eq!(check(&svc, &witness, "bob", NOW + 11), vec![2; 80]);
    // The confusable index survived: a look-alike of "alice" is refused.
    assert!(svc.publish("a1ice", vec![3; 80], NOW + 12).is_err());
    // The next head extends the old ones, and the restarted witness, which
    // remembers epoch 2, cosigns it after checking the append-only proof.
    let epoch = svc.publish("carol", vec![4; 80], NOW + 13).unwrap();
    assert_eq!(epoch, 3);
    assert_eq!(check(&svc, &witness, "carol", NOW + 14), vec![4; 80]);
    drop(svc);

    // Opening the log with a different head key is refused, not served.
    let (other, _) = keys();
    assert!(service(&store, &other, &witness, NOW + 20).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_witness_refuses_a_fork() {
    let d = dir("witness");
    let mut rng = HedgedRng::new().unwrap();
    let head = CompositeSigningKey::generate(&mut rng).unwrap();
    let head_seed = *head.seed();
    let wkey = *CompositeSigningKey::generate(&mut rng).unwrap().seed();
    let wstore = KtStore::open(&d.join("witness.redb")).unwrap();

    let mut log = KtLog::new(SERVER, head, VRF).await.unwrap();
    let sh = log
        .publish("alice", vec![1; 80], NOW, &mut rng)
        .await
        .unwrap();
    {
        let mut w = Witness::with_store(
            [0xee; 16],
            "w",
            CompositeSigningKey::from_seed(&wkey).unwrap(),
            wstore.clone(),
        )
        .unwrap();
        w.cosign(log.public_key(), &[sh], None, NOW, &mut rng)
            .await
            .unwrap();
    }

    // A fork under the same key: a different epoch 1, then its epoch 2.
    let mut fork = KtLog::new(
        SERVER,
        CompositeSigningKey::from_seed(&head_seed).unwrap(),
        VRF,
    )
    .await
    .unwrap();
    fork.publish("mallory", vec![6; 80], NOW, &mut rng)
        .await
        .unwrap();
    let f2 = fork
        .publish("alice", vec![7; 80], NOW, &mut rng)
        .await
        .unwrap();
    let proof = fork.audit(1, 2).await.unwrap();

    let mut w = Witness::with_store(
        [0xee; 16],
        "w",
        CompositeSigningKey::from_seed(&wkey).unwrap(),
        wstore,
    )
    .unwrap();
    assert_eq!(w.last_epoch(&SERVER), Some(1), "remembered across restart");
    assert_eq!(
        w.cosign(log.public_key(), &[f2], Some(proof), NOW, &mut rng)
            .await,
        Err(KtError::NotAppendOnly)
    );
    let _ = std::fs::remove_dir_all(&d);
}
