//! The foundation's workflow end to end with the real binary: a key, a list
//! built from operators' signed descriptors, verification, pins.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::CompositeSigningKey;
use enclave_federation::{
    FoundationPublic, KtKeys, Policy, ServerDescriptor, ServerList, WitnessDescriptor, server_id,
};
use enclave_rpc::ServerSecret;
use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_enclave-admin");
const NOW: u64 = 1_790_000_000;

fn admin(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(BIN)
        .args(args)
        .args(["--now", &NOW.to_string()])
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

fn server_descriptor(domain: &str, rng: &mut HedgedRng) -> (ServerDescriptor, [u8; 16]) {
    let identity = CompositeSigningKey::generate(rng).unwrap();
    let head = CompositeSigningKey::generate(rng).unwrap();
    let day = (NOW / 86_400) as u32;
    let keys = [
        ServerSecret::from_seed(day, &[1; 32]).public().clone(),
        ServerSecret::from_seed(day + 1, &[2; 32]).public().clone(),
    ];
    let d = ServerDescriptor::sign(
        &identity,
        domain,
        &format!("op-{domain}"),
        &format!("fam-{domain}"),
        "",
        "",
        Policy::default(),
        Some(KtKeys {
            head_key: head.public().clone(),
            vrf_public: vec![9; 32],
        }),
        &keys,
        NOW - 10,
        NOW + 86_400,
        rng,
    )
    .unwrap();
    (d, server_id(identity.public()))
}

fn write(dir: &Path, name: &str, b: &[u8]) {
    std::fs::write(dir.join(name), b).unwrap();
}

#[test]
fn build_verify_and_pin_a_server_list() {
    let dir = std::env::temp_dir().join(format!("enclave-admin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).display().to_string();
    let mut rng = HedgedRng::new().unwrap();

    let (ok, _, err) = admin(&[
        "foundation-keygen",
        &p("foundation.key"),
        &p("foundation.pub"),
    ]);
    assert!(ok, "{err}");
    let (again, _, _) = admin(&["foundation-keygen", &p("foundation.key"), &p("x.pub")]);
    assert!(!again, "never overwrites the foundation key");

    let (a, a_id) = server_descriptor("a.example", &mut rng);
    let (b, _) = server_descriptor("b.example", &mut rng);
    write(&dir, "a.bin", &a.encode());
    write(&dir, "b.bin", &b.encode());
    for i in 0..2 {
        let wk = CompositeSigningKey::generate(&mut rng).unwrap();
        let w = WitnessDescriptor::sign(
            &wk,
            &format!("witness-op-{i}"),
            "wf",
            "https://w.example",
            NOW - 10,
            NOW + 86_400,
            &mut rng,
        )
        .unwrap();
        write(&dir, &format!("w{i}.bin"), &w.encode());
    }
    write(&dir, "push.bin", &vec![0u8; 2 * (4 + 56 + 1568)]);
    let spec = |seq: u64, threshold: u8, a_file: &str| {
        format!(
            "seq = {seq}\nvalid_days = 30\nwitness_threshold = {threshold}\n\
             [[server]]\ndescriptor = \"{a_file}\"\nweight = 1\n\
             [[server]]\ndescriptor = \"b.bin\"\nweight = 2\n\
             [[witness]]\ndescriptor = \"w0.bin\"\n[[witness]]\ndescriptor = \"w1.bin\"\n\
             [[push]]\nnym_address = \"push-nym\"\nkeys = \"push.bin\"\n"
        )
    };
    std::fs::write(dir.join("spec.toml"), spec(5, 2, "a.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list.bin"),
    ]);
    assert!(ok, "{err}");

    let (ok, out, err) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
    ]);
    assert!(ok, "{err}");
    assert!(
        out.contains("a.example") && out.contains("b.example"),
        "{out}"
    );
    assert!(out.contains("push-nym  2 keys"), "{out}");

    // Clients holding seq 5 refuse it again; another foundation's key
    // refuses it at all.
    let (stale, _, _) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
        "--held-seq",
        "5",
    ]);
    assert!(!stale);
    let (ok, _, _) = admin(&["foundation-keygen", &p("other.key"), &p("other.pub")]);
    assert!(ok);
    let (wrong, _, _) = admin(&[
        "server-list",
        "verify",
        &p("list.bin"),
        "--foundation",
        &p("other.pub"),
    ]);
    assert!(!wrong);

    // Pins: both servers' logs and both witnesses at threshold 2.
    let (ok, _, err) = admin(&[
        "kt-pins",
        &p("list.bin"),
        "--foundation",
        &p("foundation.pub"),
        "--out",
        &p("pins.bin"),
    ]);
    assert!(ok, "{err}");
    let pins = enclave_kt::KtPolicy::decode(&std::fs::read(dir.join("pins.bin")).unwrap()).unwrap();
    assert_eq!(pins.servers.len(), 2);
    assert_eq!(pins.witnesses.threshold, 2);
    assert_eq!(pins.by_domain("a.example").unwrap().server, a_id);

    // The list itself, read back with the library.
    let public =
        FoundationPublic::decode(&std::fs::read(dir.join("foundation.pub")).unwrap()).unwrap();
    let list = ServerList::verify(
        &std::fs::read(dir.join("list.bin")).unwrap(),
        &public,
        NOW,
        0,
    )
    .unwrap();
    assert_eq!(list.server(&a_id).unwrap().weight, 1);

    // A tampered descriptor, and a threshold above the witness count, stop
    // the build.
    let mut bad = a.encode();
    let n = bad.len();
    bad[n / 2] ^= 1;
    write(&dir, "bad.bin", &bad);
    std::fs::write(dir.join("spec.toml"), spec(6, 2, "bad.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list2.bin"),
    ]);
    assert!(!ok && err.contains("bad.bin"), "{err}");
    std::fs::write(dir.join("spec.toml"), spec(6, 3, "a.bin")).unwrap();
    let (ok, _, err) = admin(&[
        "server-list",
        "build",
        &p("spec.toml"),
        "--key",
        &p("foundation.key"),
        "--out",
        &p("list2.bin"),
    ]);
    assert!(!ok && err.contains("threshold"), "{err}");

    // descriptor verify, with the expected id.
    let hex: String = a_id.iter().map(|b| format!("{b:02x}")).collect();
    let (ok, out, _) = admin(&["descriptor", "verify", "server", &p("a.bin"), "--id", &hex]);
    assert!(ok && out.contains("a.example"), "{out}");
    let (ok, _, _) = admin(&["descriptor", "verify", "server", &p("b.bin"), "--id", &hex]);
    assert!(!ok, "wrong id refused");
    let _ = std::fs::remove_dir_all(&dir);
}
