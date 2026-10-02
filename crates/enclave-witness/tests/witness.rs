//! Two witnesses run as services over HTTPS (the Enclave TLS profile); a
//! log reaches them as `HttpWitness`es and their cosignatures meet a
//! threshold of 2 under pins derived from the server list. A fork of the
//! log is refused, and so is a log the list doesn't name.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::{
    FoundationKey, KtKeys, ListedServer, ListedWitness, ServerList, WitnessDescriptor, server_id,
    witness_id,
};
use enclave_kt::{
    KtLog, KtPolicy, KtService, KtStore, LookupReply, Witness, WitnessClient, verify_lookup,
};
use enclave_witness::{HttpWitness, WitnessService};
use std::sync::Arc;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A CA, and a server certificate for 127.0.0.1 signed by it.
fn tls(dir: &std::path::Path) -> (std::path::PathBuf, Arc<rustls::ServerConfig>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    let cfg =
        enclave_witness::service::load_tls(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
    (ca_path, cfg)
}

async fn start_witness(
    dir: &std::path::Path,
    name: &str,
    list: &ServerList,
    tls: Arc<rustls::ServerConfig>,
) -> (String, ListedWitness) {
    let mut rng = HedgedRng::new().unwrap();
    let key = CompositeSigningKey::generate(&mut rng).unwrap();
    let id = witness_id(key.public());
    let d = WitnessDescriptor::sign(
        &key,
        name,
        name,
        "https://w",
        now() - 5,
        now() + 86_400,
        &mut rng,
    )
    .unwrap();
    let store = KtStore::open(&dir.join(format!("{name}.redb"))).unwrap();
    let w = Witness::with_store(id, name, key, store).unwrap();
    let svc = Arc::new(WitnessService::new(w, d.encode()));
    svc.set_logs(list).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(enclave_witness::service::serve(
        listener,
        svc.router(),
        Some(tls),
    ));
    (
        format!("https://{addr}"),
        ListedWitness {
            key: d.key.clone(),
            operator: name.into(),
            family: name.into(),
            url: format!("https://{addr}"),
        },
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn two_remote_witnesses_meet_threshold_two() {
    let dir = std::env::temp_dir().join(format!("enclave-witness-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (ca, tls_cfg) = tls(&dir);
    let mut rng = HedgedRng::new().unwrap();

    // The server's identity and its log keys, listed by the foundation.
    let identity = CompositeSigningKey::generate(&mut rng).unwrap();
    let id = server_id(identity.public());
    let head = CompositeSigningKey::generate(&mut rng).unwrap();
    let head_seed = *head.seed();
    let vrf = [7u8; 32];
    let vrf_public = KtLog::new(id, CompositeSigningKey::from_seed(&head_seed).unwrap(), vrf)
        .await
        .unwrap()
        .vrf_public()
        .to_vec();
    let listed = ListedServer {
        identity: identity.public().clone(),
        domain: "a.test".into(),
        operator: "server-op".into(),
        family: "server-fam".into(),
        nym_address: String::new(),
        weight: 1,
        kt: Some(KtKeys {
            head_key: head.public().clone(),
            vrf_public,
        }),
    };
    let mut list = ServerList {
        seq: 1,
        issued: now(),
        expires: now() + 86_400,
        witness_threshold: 2,
        servers: vec![listed],
        witnesses: Vec::new(),
        relays: Vec::new(),
        push: Vec::new(),
    };
    let (u1, w1) = start_witness(&dir, "witness-one", &list, Arc::clone(&tls_cfg)).await;
    let (u2, w2) = start_witness(&dir, "witness-two", &list, Arc::clone(&tls_cfg)).await;
    list.witnesses = vec![w1, w2];
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let list = ServerList::verify(
        &list.sign(&foundation, &mut rng).unwrap(),
        &foundation.public(),
        now(),
        0,
    )
    .unwrap();
    let pins = KtPolicy::from_server_list(&list);
    assert_eq!(pins.witnesses.threshold, 2);

    // The log, cosigned by both witnesses over HTTPS.
    let mut witnesses: Vec<Box<dyn WitnessClient>> = Vec::new();
    for u in [&u1, &u2] {
        witnesses.push(Box::new(
            HttpWitness::connect(u, Some(&ca), now()).await.unwrap(),
        ));
    }
    let svc = tokio::task::spawn_blocking(move || {
        KtService::open(
            KtStore::memory().unwrap(),
            id,
            "a.test",
            "server-op",
            head,
            vrf,
            witnesses,
            now(),
        )
        .unwrap()
    })
    .await
    .unwrap();
    let svc = Arc::new(svc);
    let s = Arc::clone(&svc);
    tokio::task::spawn_blocking(move || {
        s.publish("ada", vec![1; 80], now()).unwrap();
        s.publish("ben", vec![2; 80], now()).unwrap();
    })
    .await
    .unwrap();
    let s = Arc::clone(&svc);
    let reply = tokio::task::spawn_blocking(move || s.lookup("ben", now()).unwrap())
        .await
        .unwrap();
    let reply = LookupReply::decode(&reply).unwrap();
    assert_eq!(reply.head.cosignatures.len(), 2, "both witnesses cosigned");
    let info = pins.by_server(&id).unwrap();
    let (value, _, _) = verify_lookup(
        &pins.witnesses,
        &info.head_key,
        &info.operator,
        &info.vrf_public,
        &reply.head,
        "ben",
        reply.proof,
        now(),
    )
    .unwrap();
    assert_eq!(value, vec![2; 80]);

    // A fork: the same server key, a different history from epoch 1. Both
    // witnesses have cosigned epoch 2 of the real log and refuse it.
    let mut fork = KtLog::new(id, CompositeSigningKey::from_seed(&head_seed).unwrap(), vrf)
        .await
        .unwrap();
    for (n, v) in [("mallory", 6u8), ("ben", 7), ("carol", 8)] {
        fork.publish(n, vec![v; 80], now(), &mut rng).await.unwrap();
    }
    let heads = fork.heads_after(2, 3);
    let proof = fork.audit(2, 3).await.unwrap();
    let mut w = HttpWitness::connect(&u1, Some(&ca), now()).await.unwrap();
    assert_eq!(w.last_epoch(&id).await, Some(2));
    assert_eq!(
        w.cosign(fork.public_key(), &heads, Some(proof), now())
            .await,
        Err(enclave_kt::KtError::NotAppendOnly)
    );

    // A log the list doesn't name: refused outright.
    let other = CompositeSigningKey::generate(&mut rng).unwrap();
    let mut unlisted = KtLog::new([9; 16], other, vrf).await.unwrap();
    unlisted
        .publish("ada", vec![1; 80], now(), &mut rng)
        .await
        .unwrap();
    let h = unlisted.heads_after(0, 1);
    assert_eq!(
        w.cosign(unlisted.public_key(), &h, None, now()).await,
        Err(enclave_kt::KtError::Signature)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
