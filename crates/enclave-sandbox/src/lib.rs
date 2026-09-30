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
//! * (Linux) a seccomp filter ([`syscalls`]) that answers `EPERM` to
//!   system calls neither process needs once it runs: starting programs,
//!   debugging others, namespaces, kernel modules, `io_uring` (which
//!   seccomp can't see into), and new sockets beyond what the process is
//!   for (the vault opens none; netd only IPv4 and IPv6). Landlock can't
//!   stop UDP or raw sockets; this does.
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
    /// System-call filter: "filtered", "unavailable", "error" or "off".
    pub syscalls: &'static str,
    /// Where pictures are decoded: "mediad" (a separate confined process)
    /// or "in-process".
    pub media: &'static str,
}

/// Which system calls a process keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The vault: no new sockets of any kind (its UI connection and netd's
    /// pipes exist before the filter).
    Vault,
    /// netd: IPv4 and IPv6 sockets only.
    Netd,
}

/// Harden the running process. Call first thing.
pub fn process() -> Report {
    let mut r = Report {
        filesystem: "off",
        network: "in-process",
        syscalls: "off",
        media: "in-process",
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

/// Cap the address space at `bytes` (Unix), so a picture that decodes to
/// more than it claimed fails an allocation instead of exhausting memory.
/// Returns whether the limit took effect.
pub fn memory_limit(bytes: u64) -> bool {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        setrlimit(
            Resource::As,
            Rlimit {
                current: Some(bytes),
                maximum: Some(bytes),
            },
        )
        .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = bytes;
        false
    }
}

/// Install the seccomp filter for `profile` (Linux) on every thread of the
/// process, or with `this_thread_only` on the calling thread (tests). Call
/// after everything that needs the denied calls (spawning netd, connecting
/// to the UI). Returns "filtered", "unavailable" or "error".
pub fn syscalls(profile: Profile, this_thread_only: bool) -> &'static str {
    #[cfg(target_os = "linux")]
    {
        match filter(profile) {
            Some(prog) => {
                let applied = if this_thread_only {
                    seccompiler::apply_filter(&prog)
                } else {
                    seccompiler::apply_filter_all_threads(&prog)
                };
                if applied.is_ok() { "filtered" } else { "error" }
            }
            None => "unavailable",
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, this_thread_only);
        "unavailable"
    }
}

#[cfg(target_os = "linux")]
fn filter(profile: Profile) -> Option<seccompiler::BpfProgram> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond,
        SeccompFilter, SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;
    let arch: TargetArch = std::env::consts::ARCH.try_into().ok()?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let always = |rules: &mut BTreeMap<i64, Vec<SeccompRule>>, nr: libc::c_long| {
        rules.insert(nr, Vec::new());
    };
    for nr in [
        // Starting programs and attaching to others.
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Namespaces and mounts.
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        // The kernel's larger attack surfaces.
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_fanotify_init,
        libc::SYS_personality,
        // The machine itself.
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_syslog,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
    ] {
        always(&mut rules, nr);
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_modify_ldt,
        libc::SYS_uselib,
    ] {
        always(&mut rules, nr);
    }
    // No new user namespaces through clone (clone3 passes its flags by
    // pointer, which seccomp can't read; unshare covers the rest).
    let newuser = libc::CLONE_NEWUSER as u64;
    rules.insert(
        libc::SYS_clone,
        vec![
            SeccompRule::new(vec![
                Cond::new(0, Len::Qword, Op::MaskedEq(newuser), newuser).ok()?,
            ])
            .ok()?,
        ],
    );
    match profile {
        Profile::Vault => always(&mut rules, libc::SYS_socket),
        Profile::Netd => {
            // Anything but IPv4 and IPv6.
            let not = |af: libc::c_int| Cond::new(0, Len::Dword, Op::Ne, af as u64);
            rules.insert(
                libc::SYS_socket,
                vec![
                    SeccompRule::new(vec![not(libc::AF_INET).ok()?, not(libc::AF_INET6).ok()?])
                        .ok()?,
                ],
            );
        }
    }
    let f = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .ok()?;
    f.try_into().ok()
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

#[cfg(all(test, target_os = "linux"))]
mod seccomp_tests {
    #![allow(clippy::unwrap_used)]
    use super::{Profile, syscalls};

    fn in_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::spawn(f).join().unwrap()
    }

    #[test]
    fn vault_profile_denies_sockets_and_programs() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (status, tcp, udp, unix, exec, file) = in_thread(move || {
            let status = syscalls(Profile::Vault, true);
            (
                status,
                std::net::TcpStream::connect(addr).is_ok(),
                std::net::UdpSocket::bind("127.0.0.1:0").is_ok(),
                std::os::unix::net::UnixDatagram::unbound().is_ok(),
                std::process::Command::new("/bin/true").status().is_ok(),
                std::fs::read("/proc/self/status").is_ok(),
            )
        });
        assert_eq!(status, "filtered");
        assert!(!tcp && !udp && !unix, "sockets allowed");
        assert!(!exec, "exec allowed");
        assert!(file, "ordinary calls still work");
        // Other threads are unaffected.
        assert!(std::net::UdpSocket::bind("127.0.0.1:0").is_ok());
    }

    #[test]
    fn netd_profile_keeps_ip_sockets_only() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (status, tcp, unix, exec) = in_thread(move || {
            let status = syscalls(Profile::Netd, true);
            (
                status,
                std::net::TcpStream::connect(addr).is_ok(),
                std::os::unix::net::UnixDatagram::unbound().is_ok(),
                std::process::Command::new("/bin/true").status().is_ok(),
            )
        });
        assert_eq!(status, "filtered");
        assert!(tcp, "netd must reach servers");
        assert!(!unix && !exec);
    }
}
