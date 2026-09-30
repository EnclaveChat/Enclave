//! Process hardening for the vault (`docs/15-client.md` §1.1a).
//!
//! * No core dumps, and (Linux) not dumpable: other processes of the same
//!   user can't attach a debugger or read `/proc/<pid>/mem`, and a crash
//!   leaves no memory image with keys in it.
//! * `no_new_privs`: nothing the vault runs can gain privileges.
//! * (Linux) a Landlock filesystem sandbox: after startup the vault can only
//!   read and write its profile directory and read the few files the engine
//!   needs (pins, time zone data). Network access is not restricted here;
//!   that belongs to the netd split.
//!
//! Every step is best effort: the vault keeps working on kernels without a
//! feature, and reports what it got.

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
}

/// Harden the running process. Call first thing.
pub fn process() -> Report {
    let mut r = Report {
        filesystem: "off",
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

/// Restrict the filesystem to `read_write` and `read_only` paths (Linux).
/// Returns how much of the sandbox the kernel enforces.
pub fn filesystem(read_write: &[PathBuf], read_only: &[PathBuf]) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
            path_beneath_rules,
        };
        let abi = ABI::V5;
        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
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
        let _ = (read_write, read_only);
        "unavailable"
    }
}

/// The paths the engine needs for `mode`: (read-write, read-only).
pub fn paths_for(mode: &crate::Mode) -> (Vec<PathBuf>, Vec<PathBuf>) {
    // Local time for message timestamps.
    let mut ro: Vec<PathBuf> = ["/etc/localtime", "/usr/share/zoneinfo"]
        .iter()
        .map(PathBuf::from)
        .collect();
    let mut rw = Vec::new();
    if let crate::Mode::Server {
        profile, kt_pins, ..
    } = mode
    {
        // The engine creates the profile directory if it's missing.
        let _ = std::fs::create_dir_all(profile);
        rw.push(profile.clone());
        if let Some(k) = kt_pins {
            ro.push(k.clone());
        }
    }
    (rw, ro)
}
