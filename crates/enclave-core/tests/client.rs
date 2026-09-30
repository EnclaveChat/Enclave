//! Two real clients, two real servers, one process.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, ContactCard, ContactState, CoreError, Event, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_sim::LocalTransport;
use enclave_store::{FileKeystore, MemoryKeystore};
use std::sync::Arc;

const S1: [u8; 16] = [1; 16];
const S2: [u8; 16] = [2; 16];

fn network() -> LocalTransport {
    let t = LocalTransport::new();
    for id in [S1, S2] {
        t.add_server(enclave_server::Config {
            id,
            effort_request: 4,
            effort_claim: 1,
            effort_blob: 1,
            ..Default::default()
        })
        .unwrap();
    }
    t
}

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn request_accept_chat_refill_and_reopen() {
    let net = network();
    let dir = std::env::temp_dir().join(format!("enclave-core-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bob_opts = || Options {
        path: Some(dir.join("bob.redb")),
        keystore: Arc::new(FileKeystore::new(dir.join("keys")).unwrap()),
        passphrase: Some(zeroize::Zeroizing::new(b"hunter2 hunter2".to_vec())),
        pw_params: PwParams::FLOOR,
    };

    let (mut alice, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    assert_eq!(words.len(), 24);
    assert_eq!(alice.recovery_words().unwrap(), words);
    let (mut bob, _) = Client::create(bob_opts(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();

    // Alice scans Bob's code.
    let card = ContactCard::from_link(&bob.card().to_link()).unwrap();
    assert!(matches!(
        alice.add_contact(&alice.card(), "me").await,
        Err(CoreError::Link(enclave_core::LinkError::OwnCode))
    ));
    alice
        .add_contact(&card, "Hi Bob, it's Alice")
        .await
        .unwrap();
    assert_eq!(
        alice.contact(&bob.root()).unwrap().state,
        ContactState::Pending
    );
    assert!(matches!(
        alice.send_text(&bob.root(), "again?").await,
        Err(CoreError::NotAccepted)
    ));

    // Bob sees a message request, and cannot reply before accepting.
    let ev = bob.sync().await.unwrap();
    assert_eq!(
        ev,
        vec![Event::Request {
            root: alice.root(),
            name: "Alice".into(),
            text: "Hi Bob, it's Alice".into()
        }]
    );
    assert!(matches!(
        bob.send_text(&alice.root(), "hey").await,
        Err(CoreError::NotAccepted)
    ));
    assert!(
        bob.sync().await.unwrap().is_empty(),
        "the request is not processed twice"
    );
    bob.accept(&alice.root()).await.unwrap();

    let ev = alice.sync().await.unwrap();
    assert_eq!(ev, vec![Event::Accepted { root: bob.root() }]);
    assert_eq!(alice.contact(&bob.root()).unwrap().name, "Bob");
    assert_eq!(
        alice.security_code(&bob.root()),
        bob.security_code(&alice.root())
    );

    // Conversation.
    bob.send_text(&alice.root(), "Hi Alice").await.unwrap();
    let ev = alice.sync().await.unwrap();
    assert!(matches!(&ev[..], [Event::Message { message, .. }] if message.text == "Hi Alice"));
    alice.send_text(&bob.root(), "How are you?").await.unwrap();
    bob.sync().await.unwrap();
    bob.send_text(&alice.root(), "Well, thanks").await.unwrap();
    alice.sync().await.unwrap();
    assert!(
        alice.fully_protected(&bob.root()),
        "PQ-authenticated, three KEMs"
    );
    assert!(bob.fully_protected(&alice.root()));

    // A monologue longer than the hello tokens: Bob refills during sync.
    for i in 0..14 {
        alice
            .send_text(&bob.root(), &format!("monologue {i}"))
            .await
            .unwrap();
    }
    let ev = bob.sync().await.unwrap();
    assert_eq!(ev.len(), 14);
    alice.sync().await.unwrap();
    for i in 0..10 {
        alice
            .send_text(&bob.root(), &format!("still talking {i}"))
            .await
            .unwrap();
    }

    // Bob's app restarts: everything comes back from the sealed store.
    let alice_root = alice.root();
    drop(bob);
    let wrong = Options {
        passphrase: Some(zeroize::Zeroizing::new(b"wrong".to_vec())),
        ..bob_opts()
    };
    assert!(Client::open(wrong, Arc::new(net.clone())).is_err());
    let mut bob = Client::open(bob_opts(), Arc::new(net.clone())).unwrap();
    let ev = bob.sync().await.unwrap();
    assert_eq!(ev.len(), 10);
    let history = bob.messages(&alice_root).unwrap();
    assert_eq!(history.len(), 1 + 1 + 1 + 1 + 14 + 10);
    assert!(history.windows(2).all(|w| w[0].seq < w[1].seq));
    assert_eq!(bob.contact(&alice_root).unwrap().unread, 1 + 14 + 10 + 1);
    bob.send_text(&alice_root, "back after a restart")
        .await
        .unwrap();
    let ev = alice.sync().await.unwrap();
    assert!(
        matches!(&ev[..], [Event::Message { message, .. }] if message.text == "back after a restart")
    );

    // Verification and removal.
    bob.set_verified(&alice_root, true).unwrap();
    assert!(bob.contact(&alice_root).unwrap().verified);
    bob.remove_contact(&alice_root).unwrap();
    assert!(bob.contacts().is_empty());
    assert!(bob.messages(&alice_root).unwrap().is_empty());
    bob.erase().unwrap();
    assert!(
        Client::open(bob_opts(), Arc::new(net)).is_err(),
        "crypto-erased"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_adds_become_one_conversation() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "A")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S1, "B")
        .await
        .unwrap();
    a.add_contact(&b.card(), "hi from a").await.unwrap();
    b.add_contact(&a.card(), "hi from b").await.unwrap();
    let ea = a.sync().await.unwrap();
    let eb = b.sync().await.unwrap();
    assert!(ea.contains(&Event::Accepted { root: b.root() }));
    assert!(eb.contains(&Event::Accepted { root: a.root() }));
    a.send_text(&b.root(), "so, both of us").await.unwrap();
    let eb = b.sync().await.unwrap();
    assert!(
        eb.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "so, both of us")
        )
    );
}
