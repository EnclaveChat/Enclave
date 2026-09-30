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
            effort_username: 1,
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

async fn connect(a: &mut Client, b: &mut Client) {
    a.add_contact(&b.card(), "hi").await.unwrap();
    b.sync().await.unwrap();
    b.accept(&a.root()).await.unwrap();
    a.sync().await.unwrap();
}

async fn settle(clients: &mut [&mut Client], rounds: usize) -> Vec<Vec<Event>> {
    let mut all = vec![Vec::new(); clients.len()];
    for _ in 0..rounds {
        for (i, c) in clients.iter_mut().enumerate() {
            all[i].extend(c.sync().await.unwrap());
        }
    }
    all
}

fn group_texts(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::GroupMessage { message, .. } => Some(message.text.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn group_of_three_where_two_are_strangers() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Cy")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    connect(&mut a, &mut c).await;

    let gid = a.create_group("Trip", &[b.root(), c.root()]).await.unwrap();
    let ev = settle(&mut [&mut b, &mut c], 1).await;
    assert!(ev[0].contains(&Event::GroupJoined {
        group_id: gid,
        name: "Trip".into()
    }));
    assert!(ev[1].contains(&Event::GroupJoined {
        group_id: gid,
        name: "Trip".into()
    }));
    // B and C introduce themselves through the group; no message requests.
    let ev = settle(&mut [&mut a, &mut b, &mut c], 3).await;
    assert!(
        ev.iter()
            .flatten()
            .all(|e| !matches!(e, Event::Request { .. }))
    );
    assert!(
        b.contacts().iter().all(|x| x.root != c.root()),
        "group-only contacts stay out of the list"
    );
    assert_eq!(b.groups()[0].members.len(), 2);

    a.send_group_text(&gid, "Train at 9?").await.unwrap();
    b.send_group_text(&gid, "Works for me").await.unwrap();
    c.send_group_text(&gid, "Same").await.unwrap();
    let ev = settle(&mut [&mut a, &mut b, &mut c], 3).await;
    let mut got_a = group_texts(&ev[0]);
    let mut got_b = group_texts(&ev[1]);
    let mut got_c = group_texts(&ev[2]);
    got_a.sort();
    got_b.sort();
    got_c.sort();
    assert_eq!(got_a, vec!["Same", "Works for me"]);
    assert_eq!(got_b, vec!["Same", "Train at 9?"]);
    assert_eq!(got_c, vec!["Train at 9?", "Works for me"]);
    let hist = b.group_messages(&gid).unwrap();
    assert_eq!(hist.len(), 3);
    assert!(
        hist.iter()
            .any(|m| m.from == Some(c.root()) && m.from_name == "Cy")
    );

    // The server holds only fixed-size units.
    net.with_server(&S1, |s| {
        assert!(
            s.stored_lengths()
                .iter()
                .all(|l| *l == enclave_wire::ENVELOPE_LEN)
        )
    });

    // A removes C. B keeps talking with A; C hears nothing more.
    a.remove_group_member(&gid, &c.root()).await.unwrap();
    let ev = settle(&mut [&mut b, &mut c], 2).await;
    assert!(ev[0].contains(&Event::GroupChanged { group_id: gid }));
    assert_eq!(b.groups()[0].members.len(), 1);
    b.send_group_text(&gid, "Just us").await.unwrap();
    let ev = settle(&mut [&mut a, &mut b, &mut c], 2).await;
    assert_eq!(group_texts(&ev[0]), vec!["Just us"]);
    assert!(
        group_texts(&ev[2]).is_empty(),
        "removed member reads nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attachments_reactions_edits_deletes_receipts_and_timers() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    let (ra, rb) = (a.root(), b.root());

    // A 300 KB file travels as a padded 1 MiB bucket and verifies.
    let photo: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let sent = a
        .send_attachment(&rb, "beach.jpg", "image/jpeg", &photo, "Look!")
        .await
        .unwrap();
    let ev = b.sync().await.unwrap();
    let got = ev
        .iter()
        .find_map(|e| match e {
            Event::Message { message, .. } if message.attachment.is_some() => Some(message.clone()),
            _ => None,
        })
        .expect("attachment message");
    assert_eq!(got.text, "Look!");
    assert_eq!(got.attachment.as_ref().unwrap().name, "beach.jpg");
    assert_eq!(b.fetch_attachment(&ra, got.seq).await.unwrap(), photo);
    assert_eq!(
        a.fetch_attachment(&rb, sent.seq).await.unwrap(),
        photo,
        "sender keeps a local copy"
    );
    let chunk_sizes = net
        .with_server(&S1, |s| s.stored_lengths().clone())
        .unwrap();
    assert!(chunk_sizes.iter().all(|l| *l == enclave_wire::ENVELOPE_LEN));

    // Reaction, edit, delete for everyone, read receipt.
    let m = a.send_text(&rb, "See you at 10").await.unwrap();
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.text == "See you at 10")
        .unwrap();
    b.react(&ra, theirs.seq, "👍").await.unwrap();
    b.mark_read(&ra).await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::MessageChanged { .. })));
    let mine = a
        .messages(&rb)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == m.seq)
        .unwrap();
    assert_eq!(
        mine.reactions,
        vec![enclave_core::Reaction {
            from_us: false,
            emoji: "👍".into()
        }]
    );
    assert!(mine.read, "read receipt arrived");
    a.edit_message(&rb, m.seq, "See you at 11").await.unwrap();
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == theirs.seq)
        .unwrap();
    assert_eq!(
        (theirs.text.as_str(), theirs.edited),
        ("See you at 11", true)
    );
    // Ben cannot edit or delete Ada's message.
    assert!(b.edit_message(&ra, theirs.seq, "no").await.is_err());
    assert!(b.delete_for_everyone(&ra, theirs.seq).await.is_err());
    a.delete_for_everyone(&rb, m.seq).await.unwrap();
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == theirs.seq)
        .unwrap();
    assert!(theirs.deleted && theirs.text.is_empty());

    // Disappearing messages: timer set by Ada applies to both sides.
    a.set_timer(&rb, 60).await.unwrap();
    let ev = b.sync().await.unwrap();
    assert!(ev.contains(&Event::TimerChanged { root: ra, secs: 60 }));
    let gone = a.send_text(&rb, "this disappears").await.unwrap();
    assert_eq!(gone.expires_secs, 60);
    assert!(gone.expires_at.is_some());
    b.sync().await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.text == "this disappears")
        .unwrap();
    assert_eq!(theirs.expires_at, None, "their clock starts when read");
    b.mark_read(&ra).await.unwrap();
    let theirs = b
        .messages(&ra)
        .unwrap()
        .into_iter()
        .find(|x| x.seq == theirs.seq)
        .unwrap();
    assert!(theirs.expires_at.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn link_a_second_device() {
    let net = network();
    let (mut a, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    b.send_text(&a.root(), "before the link").await.unwrap();
    a.sync().await.unwrap();

    // The new device shows a code; the general scanner refuses it.
    let mut n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let code = n.code();
    assert_eq!(
        ContactCard::from_link(&code).unwrap_err(),
        enclave_core::LinkError::DeviceLinkCode
    );
    assert_eq!(n.poll().await.unwrap(), enclave_core::LinkProgress::Waiting);

    // A wrong pick links nothing.
    let offer = a.link_prepare(&code).await.unwrap();
    let enclave_core::LinkProgress::Words(words) = n.poll().await.unwrap() else {
        panic!("words")
    };
    let right = offer
        .choices
        .iter()
        .position(|c| *c == words)
        .expect("one choice matches");
    let wrong = (right + 1) % 4;
    assert!(a.link_confirm(offer, wrong).await.is_err());
    assert_eq!(a.devices().len(), 1);

    // Start again and pick the right words.
    let mut n = enclave_core::LinkingDevice::start(memory(), Arc::new(net.clone()), S1)
        .await
        .unwrap();
    let offer = a.link_prepare(&n.code()).await.unwrap();
    let enclave_core::LinkProgress::Words(words) = n.poll().await.unwrap() else {
        panic!("words")
    };
    let right = offer.choices.iter().position(|c| *c == words).unwrap();
    a.link_confirm(offer, right).await.unwrap();
    assert_eq!(n.poll().await.unwrap(), enclave_core::LinkProgress::Ready);
    let mut a2 = n.finish().await.unwrap();
    assert_eq!(a2.root(), a.root());
    assert!(!a2.can_link(), "linked devices hold no root");
    assert_eq!(a.devices().len(), 2);
    assert_eq!(a2.contacts().len(), 1);

    // Ben and Ada's first device learn the new device without any request.
    let ev = b.sync().await.unwrap();
    assert!(ev.iter().all(|e| !matches!(e, Event::Request { .. })));
    let ev = a.sync().await.unwrap();
    assert!(ev.contains(&Event::DevicesChanged));

    // History waits 24 h unless asked for on the first device.
    let new_id = a2.devices().iter().find(|d| d.this_device).unwrap().id;
    assert!(a2.messages(&b.root()).unwrap().is_empty());
    assert!(!a.history_sent(&new_id));
    assert!(
        a2.send_history_now(&new_id).await.is_err(),
        "only the root sends"
    );
    a.send_history_now(&new_id).await.unwrap();
    assert!(a.history_sent(&new_id));
    let ev = a2.sync().await.unwrap();
    assert!(ev.contains(&Event::HistoryImported), "{ev:?}");
    let texts: Vec<String> = a2
        .messages(&b.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    let on_first: Vec<String> = a
        .messages(&b.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(texts, on_first);
    assert!(texts.contains(&"before the link".to_string()));
    // Sending again adds nothing twice.
    a.send_history_now(&new_id).await.unwrap();
    assert!(!a2.sync().await.unwrap().contains(&Event::HistoryImported));
    assert_eq!(a2.messages(&b.root()).unwrap().len(), texts.len());

    // Ben's next message reaches both of Ada's devices.
    b.send_text(&a.root(), "to both of you").await.unwrap();
    for dev in [&mut a, &mut a2] {
        let ev = dev.sync().await.unwrap();
        assert!(ev.iter().any(
            |e| matches!(e, Event::Message { message, .. } if message.text == "to both of you")
        ));
    }
    // What one device sends shows up on the other as sent.
    a2.send_text(&b.root(), "from the new device")
        .await
        .unwrap();
    let ev = b.sync().await.unwrap();
    assert!(ev.iter().any(
        |e| matches!(e, Event::Message { message, .. } if message.text == "from the new device")
    ));
    let ev = a.sync().await.unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Message { message, .. } if message.outgoing && message.text == "from the new device")));
    a.send_text(&b.root(), "and from the first").await.unwrap();
    let ev = a2.sync().await.unwrap();
    assert!(ev.iter().any(|e| matches!(e, Event::Message { message, .. } if message.outgoing && message.text == "and from the first")));

    // Ada removes the new device. Only the primary can; Ben and the removed
    // device find out, and nothing new reaches it.
    let a2_id = a.devices().iter().find(|d| !d.this_device).unwrap().id;
    let a1_id = a.devices().iter().find(|d| d.this_device).unwrap().id;
    assert!(a2.remove_device(&a1_id).await.is_err());
    assert!(a.remove_device(&a1_id).await.is_err(), "not this device");
    a.remove_device(&a2_id).await.unwrap();
    assert_eq!(a.devices().len(), 1);
    b.sync().await.unwrap();
    let ev = a2.sync().await.unwrap();
    assert!(ev.contains(&Event::RemovedFromAccount), "{ev:?}");
    b.send_text(&a.root(), "after the removal").await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(ev.iter().any(
        |e| matches!(e, Event::Message { message, .. } if message.text == "after the removal")
    ));
    let ev = a2.sync().await.unwrap();
    assert!(
        ev.iter().all(|e| !matches!(e, Event::Message { .. })),
        "{ev:?}"
    );
    // Messages the removed device sends are no longer accepted.
    let _ = a2.send_text(&b.root(), "still here?").await;
    let ev = b.sync().await.unwrap();
    assert!(
        ev.iter().all(|e| !matches!(e, Event::Message { .. })),
        "{ev:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_from_backup_on_a_new_device() {
    let net = network();
    let (mut a, words) = Client::create(memory(), Arc::new(net.clone()), S1, "Ada")
        .await
        .unwrap();
    let (mut b, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Ben")
        .await
        .unwrap();
    connect(&mut a, &mut b).await;
    b.send_text(&a.root(), "remember this").await.unwrap();
    a.sync().await.unwrap();
    a.send_text(&b.root(), "I will").await.unwrap();
    b.sync().await.unwrap();
    let archive = a.export_backup().unwrap();
    let root = a.root();
    drop(a); // the phone is lost

    // A wrong phrase fails; the right one restores contacts and history.
    let wrong = RecoverySecretWords::other();
    assert!(
        Client::restore(&wrong, &archive, memory(), Arc::new(net.clone()))
            .await
            .is_err()
    );
    let mut a = Client::restore(&words.join(" "), &archive, memory(), Arc::new(net.clone()))
        .await
        .unwrap();
    assert_eq!(a.root(), root);
    assert_eq!(
        a.devices().len(),
        1,
        "the lost device is gone from the manifest"
    );
    let history: Vec<String> = a
        .messages(&b.root())
        .unwrap()
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert!(
        history.contains(&"remember this".to_string()) && history.contains(&"I will".to_string())
    );

    // Ben's client accepts the new device silently and sends it fresh tokens.
    let ev = b.sync().await.unwrap();
    assert!(ev.iter().all(|e| !matches!(e, Event::Request { .. })));
    a.sync().await.unwrap();
    for i in 0..20 {
        a.send_text(&b.root(), &format!("after restore {i}"))
            .await
            .unwrap();
    }
    let ev = b.sync().await.unwrap();
    assert_eq!(
        ev.iter()
            .filter(|e| matches!(e, Event::Message { .. }))
            .count(),
        20
    );
    b.send_text(&a.root(), "welcome back").await.unwrap();
    let ev = a.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Message { message, .. } if message.text == "welcome back"))
    );
}

struct RecoverySecretWords;
impl RecoverySecretWords {
    fn other() -> String {
        let mut rng = enclave_crypto::rng::HedgedRng::new().unwrap();
        enclave_proto::recovery::RecoverySecret::generate(&mut rng)
            .unwrap()
            .to_words()
            .unwrap()
            .join(" ")
    }
}

/// Usernames across two servers: claim, find, add, message; taken and
/// confusable names; renaming releases the old name but keeps it reserved;
/// a lookup that fails verification is never reported as "not found".
#[tokio::test(flavor = "multi_thread")]
async fn usernames_through_key_transparency() {
    use enclave_core::UsernameError;
    let net = network();
    let mut policy = net.enable_usernames(&S1, "one.test").unwrap();
    policy.merge(net.enable_usernames(&S2, "two.test").unwrap());

    let (mut alice, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Alice")
        .await
        .unwrap();
    let (mut bob, _) = Client::create(memory(), Arc::new(net.clone()), S2, "Bob")
        .await
        .unwrap();
    let (mut carol, _) = Client::create(memory(), Arc::new(net.clone()), S1, "Carol")
        .await
        .unwrap();
    assert!(matches!(
        alice.claim_username("alice").await,
        Err(CoreError::Username(UsernameError::Unavailable))
    ));
    for c in [&mut alice, &mut bob, &mut carol] {
        c.set_kt_policy(policy.clone());
    }

    assert_eq!(
        alice.claim_username("Alice").await.unwrap(),
        "alice@one.test"
    );
    assert_eq!(alice.username().as_deref(), Some("alice@one.test"));
    assert_eq!(bob.claim_username("bob").await.unwrap(), "bob@two.test");
    for (name, err) in [
        ("alice", UsernameError::Taken),
        ("a1ice", UsernameError::Taken),
        ("admin", UsernameError::NotAllowed),
        ("x", UsernameError::NotAllowed),
    ] {
        match carol.claim_username(name).await {
            Err(CoreError::Username(e)) => assert_eq!(e, err, "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }

    // Bob finds Alice on the other server and messages her.
    let card = bob.find_username("@alice@one.test").await.unwrap();
    assert_eq!(card.root, alice.root());
    assert_eq!(card.name, "Alice");
    bob.add_contact(&card, "Hi Alice, found you by name")
        .await
        .unwrap();
    let ev = alice.sync().await.unwrap();
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::Request { root, .. } if *root == bob.root())),
        "{ev:?}"
    );
    // Home-server lookups need no domain.
    assert_eq!(
        carol.find_username("alice").await.unwrap().root,
        alice.root()
    );
    assert!(matches!(
        bob.find_username("nobody@one.test").await,
        Err(CoreError::Username(UsernameError::NotFound))
    ));
    assert!(matches!(
        bob.find_username("alice@elsewhere.test").await,
        Err(CoreError::Username(UsernameError::Unavailable))
    ));

    // Renaming: the old name stops resolving but stays Alice's.
    assert_eq!(
        alice.claim_username("alice_w").await.unwrap(),
        "alice_w@one.test"
    );
    assert!(matches!(
        bob.find_username("alice@one.test").await,
        Err(CoreError::Username(UsernameError::NotFound))
    ));
    assert_eq!(
        bob.find_username("alice_w@one.test").await.unwrap().root,
        alice.root()
    );
    assert!(matches!(
        carol.claim_username("alice").await,
        Err(CoreError::Username(UsernameError::Taken))
    ));

    // A client pinning different witnesses refuses the server's answer.
    let mut strict = policy.clone();
    strict.witnesses.witnesses.truncate(2);
    carol.set_kt_policy(strict);
    assert!(matches!(
        carol.find_username("bob@two.test").await,
        Err(CoreError::Username(UsernameError::Unverified))
    ));
}
