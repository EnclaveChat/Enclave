//! Round trips, hostile input, framing and the token check.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_ipc::frame::{self, TOKEN_LEN};
use enclave_ipc::{Cmd, Device, Effect, Msg, Out, Pick, Row, Snapshot};

fn snapshot() -> Snapshot {
    let row = Row {
        id: "ab".into(),
        name: "Sam Okafor".into(),
        preview: "See you — tomorrow ☕".into(),
        time: "14:02".into(),
        unread: 2,
        state: 2,
        verified: true,
        met: true,
        tint: 5,
        kind: 0,
        members: 0,
    };
    Snapshot {
        my_name: "Robin".into(),
        my_link: "enclave:add#xyz".into(),
        contacts: vec![row.clone(), Row::default()],
        requests: vec![row.clone()],
        current: Some(row),
        messages: vec![Msg {
            text: "hello".into(),
            outgoing: true,
            time: "14:03".into(),
            status: 1,
            sender: String::new(),
            seq: u64::MAX - 3,
            can_edit: true,
            deleted: false,
            file: "photo.jpg".into(),
        }],
        code_groups: vec!["12345".into(); 12],
        status: "ok".into(),
        recovery_words: vec!["abandon".into(); 24],
        recovery_saved: true,
        add_error: String::new(),
        busy: true,
        pick: vec![Pick {
            id: "cd".into(),
            name: "Priya".into(),
            tint: 1,
            selected: true,
        }],
        devices: vec![Device {
            id: "00ff".into(),
            label: "This device".into(),
            detail: "Added 2 Sep 2026".into(),
            removable: false,
            history_pending: true,
        }],
        link_choices: vec!["a b c".into(); 4],
        link_status: "s".into(),
        can_link: true,
        my_username: "@robin@enclave.example".into(),
        usernames: true,
        username_error: "e".into(),
        can_join: true,
        join_code: "enclave:link#q".into(),
        join_words: "x y z".into(),
        recovery_alert: "3 Oct 14:02".into(),
        meet_code: "enclave:meet#abc".into(),
        meet_words: "harbor ivory kettle".into(),
        meet_name: "Sam".into(),
        meet_error: String::new(),
        meet_done: String::new(),
        timer: 3600,
        search: vec![Row::default()],
        username_problem: "@robin@enclave.example".into(),
        members: vec![Row::default(); 2],
        group_admin: true,
        addable: vec![Pick::default()],
        locked: true,
        unlock_error: "no".into(),
        can_lock: true,
        invites: 2,
    }
}

fn cmds() -> Vec<Cmd> {
    vec![
        Cmd::Create("Robin".into(), "correct horse".into()),
        Cmd::Unlock("correct horse".into()),
        Cmd::Lock,
        Cmd::SetPassphrase(String::new()),
        Cmd::NewInvite(1),
        Cmd::CancelInvites,
        Cmd::Select(String::new()),
        Cmd::Send("id".into(), "text ✓".into()),
        Cmd::Accept("a".into()),
        Cmd::Decline("b".into()),
        Cmd::Add("enclave:add#x".into(), "hi".into()),
        Cmd::Check("c".into()),
        Cmd::Privacy(1),
        Cmd::WordsSaved,
        Cmd::TogglePick("d".into()),
        Cmd::CreateGroup("Book club".into()),
        Cmd::LinkScan("enclave:link#y".into()),
        Cmd::LinkPick(3),
        Cmd::ClaimUsername("robin".into()),
        Cmd::RemoveDevice("00ff".into()),
        Cmd::StartJoin,
        Cmd::CancelJoin,
        Cmd::RevealWords(true),
        Cmd::SendHistory("00ff".into()),
        Cmd::StopRecovery,
        Cmd::ApproveRecovery,
        Cmd::Meet(true),
        Cmd::MeetScan("enclave:meet#x".into()),
        Cmd::MeetConfirm,
        Cmd::React("ab".into(), 3, "👍".into()),
        Cmd::Edit("ab".into(), 4, "fixed".into()),
        Cmd::Delete("ab".into(), 5),
        Cmd::Timer("ab".into(), 86_400),
        Cmd::SendFile("ab".into(), "a.txt".into(), vec![7; 1000], "look".into()),
        Cmd::SaveFile("ab".into(), 6),
        Cmd::Search("café".into()),
        Cmd::AddMembers("g1".into()),
        Cmd::RemoveMember("g1".into(), "ab".into()),
        Cmd::LeaveGroup("g1".into()),
    ]
}

#[test]
fn round_trips() {
    let s = snapshot();
    assert_eq!(Snapshot::decode(&s.encode()).unwrap(), s);
    assert_eq!(
        Snapshot::decode(&Snapshot::default().encode()).unwrap(),
        Snapshot::default()
    );
    for c in cmds() {
        assert_eq!(Cmd::decode(&c.encode()).unwrap(), c);
    }
    for o in [
        Out::Snapshot(Box::new(s)),
        Out::Effect(Effect::ContactAdded),
        Out::Effect(Effect::GroupCreated),
        Out::Effect(Effect::UsernameClaimed),
        Out::Effect(Effect::RemovalDone),
        Out::Effect(Effect::FileSent),
        Out::Effect(Effect::LeftGroup),
        Out::Effect(Effect::PassphraseChanged),
        Out::File("a.txt".into(), vec![1, 2, 3]),
        Out::Invite("enclave:add#AAAA".into()),
    ] {
        assert_eq!(Out::decode(&o.encode()).unwrap(), o);
    }
}

#[test]
fn hostile_input_is_refused_not_panicked_on() {
    let good = Out::Snapshot(Box::new(snapshot())).encode();
    // Every truncation and every trailing byte fails.
    for n in 0..good.len() {
        assert!(Out::decode(&good[..n]).is_err(), "prefix {n}");
    }
    assert!(Out::decode(&[good.clone(), vec![0]].concat()).is_err());
    // Byte flips never panic.
    let mut x = 0x9E37_79B9u32;
    for _ in 0..20_000 {
        let mut b = good.clone();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let i = x as usize % b.len();
        b[i] ^= (x >> 8) as u8 | 1;
        let _ = Out::decode(&b);
    }
    // A huge claimed count is refused before allocating.
    let mut w = vec![1u8];
    w.extend_from_slice(&0u32.to_be_bytes());
    w.extend_from_slice(&0u32.to_be_bytes());
    w.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(Out::decode(&w).is_err());
    for c in cmds() {
        let e = c.encode();
        for n in 0..e.len() {
            assert!(Cmd::decode(&e[..n]).is_err());
        }
    }
    assert!(Cmd::decode(&[99]).is_err());
}

#[tokio::test]
async fn framing_and_token() {
    let token = [7u8; TOKEN_LEN];
    assert_eq!(
        frame::token_from_hex(&frame::token_hex(&token)),
        Some(token)
    );
    assert_eq!(frame::token_from_hex("zz"), None);

    let (mut a, mut b) = tokio::io::duplex(1 << 20);
    frame::present_token(&mut a, &token).await.unwrap();
    frame::check_token(&mut b, &token).await.unwrap();
    frame::present_token(&mut a, &[8; TOKEN_LEN]).await.unwrap();
    assert!(frame::check_token(&mut b, &token).await.is_err());

    let body = Cmd::Send("x".into(), "y".repeat(10_000)).encode();
    frame::write_frame(&mut a, &body).await.unwrap();
    assert_eq!(frame::read_frame(&mut b).await.unwrap(), body);
    // An oversize length prefix is refused without reading the body.
    use tokio::io::AsyncWriteExt;
    a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    assert!(frame::read_frame(&mut b).await.is_err());
}

#[test]
fn net_messages_round_trip_and_refuse_garbage() {
    use enclave_ipc::net::{NetReply, NetRequest};
    for r in [
        NetRequest::Exchange {
            id: 7,
            server: [3; 16],
            bytes: vec![9; 16_384],
        },
        NetRequest::ServerKey {
            id: u32::MAX,
            server: [4; 16],
        },
    ] {
        let e = r.encode();
        assert_eq!(NetRequest::decode(&e).unwrap(), r);
        for n in 0..e.len().min(64) {
            assert!(NetRequest::decode(&e[..n]).is_err());
        }
    }
    for r in [
        NetReply {
            id: 1,
            result: Ok(vec![1; 100]),
        },
        NetReply {
            id: 2,
            result: Err("unreachable".into()),
        },
    ] {
        assert_eq!(NetReply::decode(&r.encode()).unwrap(), r);
    }
    assert!(NetReply::decode(&[0, 0, 0, 1, 9]).is_err());
}
