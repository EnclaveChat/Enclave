//! Process hardening for the vault and netd (`docs/15-client.md` §1.1a).
//!
//! * No core dumps, and (Linux) not dumpable: other processes of the same
//!   user can't attach a debugger or read `/proc/<pid>/mem`, and a crash
//!   leaves no memory image with keys in it.
//! * `no_new_privs`: nothing the process runs can gain privileges.
//! * (Linux) a Landlock sandbox. The vault can only read and write its
//!   profile directory and read the few files the engine needs (pins, time
//!   zone data); with netd running it also may not open or accept any TCP
//!   connection, so the network is only reachable through netd. netd gets no
//!   filesystem access at all.
//!
//! Every step is best effort: the processes keep working on kernels without
//! a feature, and report what they got.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::PathBuf;

/// What hardening took effect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Core dump size limit set to zero.
    pub no_core_dumps: bool,
    /// Marked not dumpable (Linux).
    pub not_dumpable: bool,
    /// `no_new_privs` set.
    pub no_new_privs: bool,
    /// Filesystem sandbox: "full", "partial", "unavailable" or "off".
    pub filesystem: &'static str,
    /// Where the network is: "netd" (a separate process; this one may not
    /// open TCP connections) or "in-process".
    pub network: &'static str,
}

/// Harden the running process. Call first thing.
pub fn process() -> Report {
    let mut r = Report {
        filesystem: "off",
        network: "in-process",
        ..Report::default()
    };
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        r.no_core_dumps = setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .is_ok();
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        r.not_dumpable = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
        r.no_new_privs = rustix::thread::set_no_new_privs(true).is_ok();
    }
    r
}

/// Restrict the filesystem to `read_write` and `read_only` paths, and with
/// `deny_tcp` forbid opening or accepting TCP connections (Linux). Returns
/// how much of the sandbox the kernel enforces.
pub fn filesystem(read_write: &[PathBuf], read_only: &[PathBuf], deny_tcp: bool) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus, path_beneath_rules,
        };
        let abi = ABI::V5;
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| {
                if deny_tcp {
                    // Handled with no rules allowing any port: all denied.
                    r.handle_access(AccessNet::from_all(abi))
                } else {
                    Ok(r)
                }
            })
            .and_then(|r| r.create())
            .and_then(|r| r.add_rules(path_beneath_rules(read_only, AccessFs::from_read(abi))))
            .and_then(|r| r.add_rules(path_beneath_rules(read_write, AccessFs::from_all(abi))))
            .and_then(|r| r.restrict_self());
        match status.map(|s| s.ruleset) {
            Ok(RulesetStatus::FullyEnforced) => "full",
            Ok(RulesetStatus::PartiallyEnforced) => "partial",
            Ok(_) => "unavailable",
            Err(_) => "error",
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (read_write, read_only, deny_tcp);
        "unavailable"
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    /// Landlock confines the calling thread (and threads it starts), so the
    /// sandbox can be tried on a thread of its own.
    #[test]
    fn sandbox_denies_tcp_and_files() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!("enclave-harden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let allowed = dir.join("ok");
        let (status, tcp, outside, inside) = std::thread::spawn({
            let dir = dir.clone();
            move || {
                let status = super::filesystem(&[dir], &[], true);
                let tcp = std::net::TcpStream::connect(addr).is_ok();
                let outside =
                    std::fs::read("/etc/hostname").is_ok() || std::fs::read("/etc/passwd").is_ok();
                let inside = std::fs::write(&allowed, b"x").is_ok();
                (status, tcp, outside, inside)
            }
        })
        .join()
        .unwrap();
        // Before and after, this thread is unaffected.
        assert!(std::net::TcpStream::connect(addr).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
        match status {
            "full" => {
                assert!(!tcp, "TCP connect allowed in the sandbox");
                assert!(!outside, "read outside the sandbox allowed");
                assert!(inside, "profile not writable");
            }
            // Old kernels: nothing (or not everything) is enforced; the
            // vault reports it and keeps working.
            other => eprintln!("landlock: {other}"),
        }
    }
}
