//! Three servers held together by the foundation's list (`docs/12-servers.md`
//! §4): people on different servers find each other by username through
//! pins that come only from the list, add each other and talk; cards carry
//! the home server's domain; the list moves forward from the home server
//! and never back; a list from any other key is refused.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_core::{Client, CoreError, Event, ListUpdate, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_federation::{FedError, FoundationKey, ServerList};
use enclave_sim::LocalTransport;
use enclave_store::MemoryKeystore;
use std::sync::Arc;

fn memory() -> Options {
    Options {
        path: None,
        keystore: Arc::new(MemoryKeystore::default()),
        passphrase: None,
        pw_params: PwParams::FLOOR,
    }
}

fn list(
    seq: u64,
    servers: &[enclave_federation::ListedServer],
    witnesses: &[enclave_federation::ListedWitness],
    now: u64,
) -> ServerList {
    ServerList {
        seq,
        issued: now,
        expires: now + 30 * 86_400,
        witness_threshold: 3,
        servers: servers.to_vec(),
        witnesses: witnesses.to_vec(),
        relays: Vec::new(),
        push: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_servers_one_list() {
    let net = LocalTransport::new();
    let mut servers = Vec::new();
    let mut witnesses = Vec::new();
    for (i, d) in ["a.test", "b.test", "c.test"].iter().enumerate() {
        let (s, w) = net.add_federated_server(d, i as u32 + 1).unwrap();
        servers.push(s);
        witnesses.extend(w);
    }
    let ids: Vec<[u8; 16]> = servers.iter().map(|s| s.id()).collect();
    let now = net.now();
    let mut rng = HedgedRng::new().unwrap();
    let foundation = FoundationKey::generate(&mut rng).unwrap();
    let signed = list(1, &servers, &witnesses, now)
        .sign(&foundation, &mut rng)
        .unwrap();

    let mut people = Vec::new();
    for (i, name) in ["Ada", "Ben", "Cy"].iter().enumerate() {
        let (mut c, _) = Client::create(memory(), Arc::new(net.clone()), ids[i], name)
            .await
            .unwrap();
        c.set_foundation(foundation.public()).unwrap();
        assert_eq!(
            c.offer_server_list(&signed).unwrap(),
            ListUpdate::Updated(1)
        );
        assert_eq!(c.offer_server_list(&signed).unwrap(), ListUpdate::Unchanged);
        people.push(c);
    }
    let [ada, ben, cy] = people.as_mut_slice() else {
        unreachable!()
    };
    // Cards carry the home server's domain, from the list.
    assert_eq!(ada.card().server_domain, "a.test");
    assert_eq!(cy.card().server_domain, "c.test");

    // Usernames on each server, pinned only through the list.
    assert_eq!(ada.claim_username("ada").await.unwrap(), "ada@a.test");
    assert_eq!(ben.claim_username("ben").await.unwrap(), "ben@b.test");
    assert_eq!(cy.claim_username("cyrus").await.unwrap(), "cyrus@c.test");

    // Cy (on C) finds Ada (on A) and Ben (on B) by name, adds both, and
    // each conversation crosses servers.
    let card = cy.find_username("@ada@a.test").await.unwrap();
    assert_eq!(
        (card.root, card.server_domain.as_str()),
        (ada.root(), "a.test")
    );
    cy.add_contact(&card, "Hi Ada, from c.test").await.unwrap();
    let card = cy.find_username("ben@b.test").await.unwrap();
    assert_eq!(card.root, ben.root());
    cy.add_contact(&card, "Hi Ben, from c.test").await.unwrap();
    for (p, text) in [
        (&mut *ada, "Hi Ada, from c.test"),
        (&mut *ben, "Hi Ben, from c.test"),
    ] {
        let ev = p.sync().await.unwrap();
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Request { root, text: t, .. }
                if *root == cy.root() && t == text)),
            "{ev:?}"
        );
    }

    // A newer list, mirrored by A: Ada fetches it from her home server. An
    // older one offered afterwards changes nothing.
    let mut l2 = list(2, &servers, &witnesses, now);
    l2.servers[1].weight = 9;
    let signed2 = l2.sign(&foundation, &mut rng).unwrap();
    net.with_server(&ids[0], |s| s.set_server_list(signed2.clone()))
        .unwrap();
    assert_eq!(
        ada.refresh_server_list().await.unwrap(),
        ListUpdate::Updated(2)
    );
    assert_eq!(ada.server_list().unwrap().servers[1].weight, 9);
    assert_eq!(
        ada.offer_server_list(&signed).unwrap(),
        ListUpdate::Unchanged
    );
    assert_eq!(ada.server_list().unwrap().seq, 2);

    // A list signed by anyone else is refused, however new it claims to be.
    let mallory = FoundationKey::generate(&mut rng).unwrap();
    let forged = list(99, &servers, &witnesses, now)
        .sign(&mallory, &mut rng)
        .unwrap();
    assert!(matches!(
        ben.offer_server_list(&forged),
        Err(CoreError::Federation(FedError::Signature))
    ));
    assert_eq!(ben.server_list().unwrap().seq, 1);

    // The list held is kept: given the key again (as at every start), the
    // client still has it.
    ada.set_foundation(foundation.public()).unwrap();
    assert_eq!(ada.server_list().unwrap().seq, 2);
}
