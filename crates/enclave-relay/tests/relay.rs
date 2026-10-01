//! A call through two relays: neither relay sees both callers.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_calls::link::Link;
use enclave_calls::sframe::{Receiver, Sender};
use enclave_calls::shape::{self, Inner, Shaper, Stream};
use enclave_calls::signal::{self, Answer, CALLEE, CALLER, Media, Offer, Route};
use enclave_calls::ticket;
use enclave_crypto::rng::HedgedRng;
use enclave_relay::{P_MEDIA, Relay, client_datagram, client_receive, join_payload, serve};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

const NOW: u64 = 1_790_000_000;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn ticket_for(relay: &mut Relay, now: u64, rng: &mut HedgedRng) -> Link {
    let (req, client) =
        ticket::request(relay.ticket_key(), rng.array("t").unwrap(), 3600, rng).unwrap();
    let reply = relay.issue_ticket(&req, now, |_| true).unwrap();
    // A replayed request (same token) is refused.
    assert!(relay.issue_ticket(&req, now, |_| true).is_err());
    Link::client(client.finish(&reply).unwrap())
}

#[test]
fn two_relays_carry_a_call_without_seeing_both_ends() {
    let mut rng = HedgedRng::new().unwrap();
    let (ra_addr, rb_addr) = (addr("203.0.113.10:4000"), addr("198.51.100.20:4000"));
    let (a_addr, b_addr) = (addr("192.0.2.1:50000"), addr("192.0.2.200:60000"));
    let day = (NOW / 86_400) as u32;
    let mut ra = Relay::new([0xA; 16], "family-a", ra_addr, day).unwrap();
    let mut rb = Relay::new([0xB; 16], "family-b", rb_addr, day).unwrap();
    ra.add_peer(rb.descriptor()).unwrap();
    rb.add_peer(ra.descriptor()).unwrap();

    // Signalling (normally ratchet messages over the mixnet).
    let pending = signal::offer(
        Media::Audio,
        Route::Relay,
        rb_addr.to_string().into_bytes(),
        NOW,
        &mut rng,
    )
    .unwrap();
    let offer = Offer::decode(&pending.offer().encode()).unwrap();
    let (ans, kb) = signal::answer(
        &offer,
        ra_addr.to_string().into_bytes(),
        b"conv",
        NOW,
        &mut rng,
    )
    .unwrap();
    let ka = pending
        .finish(&Answer::decode(&ans.encode()).unwrap(), b"conv", NOW)
        .unwrap();
    assert_eq!(ka.check_words(), kb.check_words());

    let mut la = ticket_for(&mut ra, NOW, &mut rng);
    let mut lb = ticket_for(&mut rb, NOW, &mut rng);
    // Each side joins its own relay, naming the other relay.
    let j = client_datagram(&mut la, NOW, &join_payload(&ka.rendezvous(), rb_addr)).unwrap();
    assert!(ra.handle(a_addr, &j, NOW).is_empty());
    let j = client_datagram(&mut lb, NOW, &join_payload(&kb.rendezvous(), ra_addr)).unwrap();
    assert!(rb.handle(b_addr, &j, NOW).is_empty());

    let mut a_tx = Sender::new(CALLER, &ka.sframe_base(CALLER, 0));
    let mut b_rx = Receiver::new(CALLER, &kb.sframe_base(CALLER, 0));
    let mut b_tx = Sender::new(CALLEE, &kb.sframe_base(CALLEE, 0));
    let mut a_rx = Receiver::new(CALLEE, &ka.sframe_base(CALLEE, 0));
    let mut a_shape = Shaper::new(Stream::Audio);
    let mut b_shape = Shaper::new(Stream::Audio);
    let mut wire_sizes = std::collections::HashSet::new();
    let (mut a_heard, mut b_heard) = (0, 0);

    for i in 0..300u64 {
        let t = NOW + i / 50;
        if i % 2 == 0 {
            a_shape.push_frame(&[1; 80]).unwrap();
        }
        if i % 5 == 0 {
            b_shape.push_frame(&[2; 80]).unwrap();
        }
        // A → RA → RB → B
        let pkt = a_tx
            .protect(i * 20, b"", &a_shape.next_plaintext())
            .unwrap();
        let dg = client_datagram(&mut la, t, &[&[P_MEDIA][..], &pkt].concat()).unwrap();
        wire_sizes.insert(dg.len());
        let hop = ra.handle(a_addr, &dg, t);
        assert_eq!(hop.len(), 1);
        assert_eq!(hop[0].0, rb_addr, "RA only ever sends to the peer relay");
        wire_sizes.insert(hop[0].1.len());
        let out = rb.handle(ra_addr, &hop[0].1, t);
        assert_eq!(out[0].0, b_addr);
        let got = client_receive(&mut lb, t, &out[0].1).unwrap();
        if let Inner::Media(m) =
            shape::decode_plaintext(&b_rx.unprotect(&got, b"").unwrap()).unwrap()
        {
            assert_eq!(m, vec![1; 80]);
            b_heard += 1;
        }
        // B → RB → RA → A
        let pkt = b_tx
            .protect(i * 20, b"", &b_shape.next_plaintext())
            .unwrap();
        let dg = client_datagram(&mut lb, t, &[&[P_MEDIA][..], &pkt].concat()).unwrap();
        let hop = rb.handle(b_addr, &dg, t);
        let out = ra.handle(rb_addr, &hop[0].1, t);
        assert_eq!(out[0].0, a_addr);
        if let Inner::Media(_) = shape::decode_plaintext(
            &a_rx
                .unprotect(&client_receive(&mut la, t, &out[0].1).unwrap(), b"")
                .unwrap(),
        )
        .unwrap()
        {
            a_heard += 1;
        }
    }
    assert_eq!((b_heard, a_heard), (150, 60));
    // Client→relay datagrams and relay→relay datagrams each have one size.
    assert_eq!(wire_sizes.len(), 2, "{wire_sizes:?}");
    assert_eq!(
        ra.client_addrs(),
        vec![a_addr],
        "RA never learns B's address"
    );
    assert_eq!(
        rb.client_addrs(),
        vec![b_addr],
        "RB never learns A's address"
    );

    // A relay-link datagram replayed or from a stranger is dropped.
    let pkt = a_tx.protect(6_000, b"", &a_shape.next_plaintext()).unwrap();
    let dg = client_datagram(&mut la, NOW + 6, &[&[P_MEDIA][..], &pkt].concat()).unwrap();
    let hop = ra.handle(a_addr, &dg, NOW + 6);
    assert_eq!(rb.handle(ra_addr, &hop[0].1, NOW + 6).len(), 1);
    assert!(rb.handle(ra_addr, &hop[0].1, NOW + 6).is_empty(), "replay");
    assert!(
        rb.handle(addr("192.0.2.66:1"), &hop[0].1, NOW + 6)
            .is_empty(),
        "not a peer"
    );
    assert!(ra.handle(a_addr, &dg, NOW + 6).is_empty(), "client replay");
    assert!(rb.stats().dropped >= 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_loopback_call() {
    let mut rng = HedgedRng::new().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let day = (now / 86_400) as u32;
    let sa = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sb = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (ra_addr, rb_addr) = (sa.local_addr().unwrap(), sb.local_addr().unwrap());
    let ra = Arc::new(Mutex::new(
        Relay::new([0xA; 16], "a", ra_addr, day).unwrap(),
    ));
    let rb = Arc::new(Mutex::new(
        Relay::new([0xB; 16], "b", rb_addr, day).unwrap(),
    ));
    {
        let d = rb.lock().await.descriptor().clone();
        ra.lock().await.add_peer(&d).unwrap();
        let d = ra.lock().await.descriptor().clone();
        rb.lock().await.add_peer(&d).unwrap();
    }
    tokio::spawn(serve(Arc::clone(&ra), sa));
    tokio::spawn(serve(Arc::clone(&rb), sb));

    let pending = signal::offer(Media::Audio, Route::Relay, vec![], now, &mut rng).unwrap();
    let (ans, kb) = signal::answer(pending.offer(), vec![], b"c", now, &mut rng).unwrap();
    let ka = pending.finish(&ans, b"c", now).unwrap();
    let mut la = ticket_for(&mut *ra.lock().await, now, &mut rng);
    let mut lb = ticket_for(&mut *rb.lock().await, now, &mut rng);
    let ca = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cb = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    ca.send_to(
        &client_datagram(&mut la, now, &join_payload(&ka.rendezvous(), rb_addr)).unwrap(),
        ra_addr,
    )
    .await
    .unwrap();
    cb.send_to(
        &client_datagram(&mut lb, now, &join_payload(&kb.rendezvous(), ra_addr)).unwrap(),
        rb_addr,
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut tx = Sender::new(CALLER, &ka.sframe_base(CALLER, 0));
    let mut rx = Receiver::new(CALLER, &kb.sframe_base(CALLER, 0));
    let mut buf = vec![0u8; 2048];
    for i in 0..20u64 {
        let pkt = tx.protect(i * 20, b"", &[i as u8; 111]).unwrap();
        ca.send_to(
            &client_datagram(&mut la, now, &[&[P_MEDIA][..], &pkt].concat()).unwrap(),
            ra_addr,
        )
        .await
        .unwrap();
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), cb.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from, rb_addr);
        let got = rx
            .unprotect(&client_receive(&mut lb, now, &buf[..n]).unwrap(), b"")
            .unwrap();
        assert_eq!(got, vec![i as u8; 111]);
    }
}

/// Keys and spent tokens survive a restart; ticket keys roll daily and a
/// request sealed to yesterday's key is still served for a day.
#[test]
fn keys_and_spent_tokens_survive_a_restart() {
    use enclave_calls::ticket;
    use enclave_relay::keys::RelayKeys;
    use enclave_relay::ledger::RedbSpent;
    let dir = std::env::temp_dir().join(format!("enclave-relay-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
    let day = 20_000;
    let now = u64::from(day) * 86_400 + 100;
    let mut rng = HedgedRng::new().unwrap();
    let open = |keys: &RelayKeys| {
        Relay::with_keys(
            keys.id,
            "a",
            addr,
            keys.link_secret(),
            keys.tickets(),
            Box::new(RedbSpent::open(&dir.join("relay.redb")).unwrap()),
        )
        .unwrap()
    };

    let keys = RelayKeys::init(&dir.join("k"), day).unwrap();
    assert!(
        RelayKeys::init(&dir.join("k"), day).is_err(),
        "never overwrites"
    );
    let tomorrow = keys.next_ticket().public().clone();
    let (desc, ticket_key) = {
        let mut relay = open(&keys);
        let (req, _) = ticket::request(relay.ticket_key(), [1; 32], 600, &mut rng).unwrap();
        relay.issue_ticket(&req, now, |_| true).unwrap();
        (relay.descriptor().clone(), relay.ticket_key().clone())
    };

    let mut keys = RelayKeys::load(&dir.join("k")).unwrap();
    let mut relay = open(&keys);
    assert_eq!(relay.descriptor(), &desc, "same id and link key");
    assert!(relay.ticket_key() == &ticket_key, "same ticket key");
    // The token spent before the restart stays spent.
    let (again, _) = ticket::request(relay.ticket_key(), [1; 32], 600, &mut rng).unwrap();
    assert!(relay.issue_ticket(&again, now, |_| true).is_err());

    // Next day: tomorrow's published key is current; yesterday's still works.
    let (late, _) = ticket::request(relay.ticket_key(), [2; 32], 600, &mut rng).unwrap();
    assert!(keys.advance(day + 1).unwrap());
    relay.set_ticket_keys(keys.tickets());
    assert!(relay.ticket_key() == &tomorrow);
    relay.issue_ticket(&late, now + 86_400, |_| true).unwrap();
    // Two days on, the old key is gone.
    let (stale, _) = ticket::request(&ticket_key, [3; 32], 600, &mut rng).unwrap();
    keys.advance(day + 2).unwrap();
    relay.set_ticket_keys(keys.tickets());
    assert!(
        relay
            .issue_ticket(&stale, now + 2 * 86_400, |_| true)
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
