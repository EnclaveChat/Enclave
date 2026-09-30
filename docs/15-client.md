# Client App and Endpoint Hardening

Status: Draft (M0) · Normative

Source: PLAN.md §14, §22, RT-14. Crates: `enclave-core`, `enclave-ipc`, `enclave-app`, `enclave-sandbox`, `enclave-media`, `enclave-platform`, `enclave-nse`. Platform limits: `15b-platform-constraints.md`. Design: `17-design.md`. Accessibility: `18-a11y-i18n.md`.

## 1. Process split (RT-14)

### 1.1 Desktop: four processes

| Process | Holds | Talks to | Sandbox |
|---|---|---|---|
| `vault` | All long-term keys, ratchet state, the database; runs `enclave-core` (crypto, protocol, storage) | `netd`, `mediad`, UI via IPC | Minimal dependencies; no network sockets; seccomp + Landlock on Linux, App Sandbox on macOS, AppContainer on Windows |
| `netd` | arti and nym-sdk; sees only sealed 16,384 B and 2,048 B objects | `vault` | Network only; no file access beyond its cache |
| `mediad` | Decoders and encoders (images, Opus, AV1), capture | `vault`, UI (decoded RGBA and PCM only) | seccomp + Landlock, the macOS App Sandbox via XPC, or AppContainer; no network |
| UI (Slint) | Rendering, input; never key material | `vault` (typed commands and events), `mediad` (frames) | Standard user process |

IPC is typed `postcard` messages over a Unix domain socket (Linux, macOS) or a named pipe (Windows), defined in `enclave-ipc`. Each message type has a fixed maximum size; parsing is fuzzed. The `vault` process authenticates its peers by OS credentials (peer UID/PID checks) and by a per-launch random 32 B secret passed through inherited handles.

### 1.1a Implemented: UI, vault and netd

Today the desktop app runs as **three** processes: the Slint UI (`enclave`), the vault (`enclave-vault`, crate `enclave-vault`), which runs the client engine and holds every key and the sealed store, and, when connected to a server, `enclave-netd` (crate `enclave-netd`), which holds the network. `mediad` is not split out yet.

- **Messages** (`enclave-ipc`) are exactly three kinds: `Cmd` (UI → vault: what the person did), `Snapshot` (vault → UI: display data only — names, message text, previews, security-code digits) and `Effect` (vault → UI: a few one-off UI resets). They use a strict hand-written codec rather than `postcard` (no serde in the workspace): every field is length-bounded, counts are checked against the bytes left before allocating, trailing bytes are an error, and a hostile-input test flips bytes and truncates at every offset.
- **Files** cross as bytes (at most 15 MiB per message for now): the UI reads a file the person picks and writes a saved attachment into their Downloads folder, so the confined vault never touches the person's files. Saved names keep only their last path component and never overwrite an existing file.
- **Recovery words** are the one secret the UI must display. They are in snapshots only while the recovery sheet is open (`Cmd::RevealWords`), so the UI process holds them only then.
- **Framing**: `u32 BE length ‖ body`, at most 16 MiB.
- **Launch and authentication** (Unix): the UI creates a directory with mode 0700 under the temp dir, listens on `vault.sock` inside it, and starts `enclave-vault --connect <socket> <mode args>` from next to its own executable with a fresh 32-byte token (from the hedged RNG) written to the child's **stdin**. The vault connects and sends the token first; the UI compares it in constant time, then unlinks the socket and the directory, so no other process can connect. A command that does not decode ends the connection. When the UI goes away the vault's engine loop ends and it exits; when the vault dies the UI says so ("Enclave's vault stopped… Restart Enclave.").
- **App lock**: a profile on disk can have a passphrase, chosen when the account is created (`Options::passphrase`, Argon2id with `PwParams::DESKTOP_DEFAULT`, 1 GiB and 4 passes). The vault starts locked when opening fails without it and shows only the unlock screen; **Lock now** drops the client, and with it the keys and the open database, from the vault's memory. It can be set, changed or removed later in Settings (`Store::change_passphrase`): the store's master key never changes, it is wrapped under a key from the device secret and the new passphrase with a fresh salt, in one transaction, so no record is re-encrypted.
- **Fallback**: where the vault binary is missing, on non-Unix platforms (Windows named pipes are not implemented yet), and with `--single-process`, the same engine runs on a thread in the UI process.
- **Peer check**: the UI also asks the kernel who connected (`SO_PEERCRED`, where available) and requires the child's pid.
- **Vault hardening** (`enclave-sandbox`, used by `enclave-vault::harden`): core-dump limit 0; on Linux `PR_SET_DUMPABLE 0` (no same-user debugger attach or `/proc/<pid>/mem`) and `no_new_privs`; and, once connected, a **Landlock** sandbox: read-write only under the profile directory, read-only for the pin file and time-zone data, and (with netd running) **no TCP connect or bind at all** (Landlock ABI 4 network rules, handled with no port allowed). Best effort on older kernels; `--report` prints what took effect (`filesystem`, `network: "netd"`), and a test runs the sandboxed vault against a TCP dev server to prove the profile and the server both still work through netd. A unit test confines one thread and checks that TCP connects and reads outside the allowed directory fail while the allowed directory stays writable.
- **netd** (server mode): the vault starts `enclave-netd --server <id>=<addr>` from next to its own executable *before* it confines itself, and talks to it over the child's stdin and stdout (`enclave-ipc::net`: `NetRequest::{Exchange, ServerKey}` with request ids so several can be in flight, `NetReply` with the bytes or an error; same framing and strict codec). netd only moves sealed requests and sealed replies and fetches servers' public request keys (`key_id ‖ x448 ‖ mlkem`); it holds no keys, hardens itself the same way and takes **no filesystem access**. It links neither `enclave-store`, `enclave-core` nor `enclave-proto` (test `rt14_netd_has_no_key_material` walks its dependencies). If netd is missing or fails to start, the vault uses the network itself and reports `network: "in-process"`. Demo mode needs no network and starts no netd.
- **seccomp** (`enclave_sandbox::syscalls`, Linux): after Landlock, a filter on every thread answers `EPERM` to `execve`/`execveat`, `ptrace` and `process_vm_*`, namespaces and mounts (`unshare`, `setns`, `clone` with `CLONE_NEWUSER`, `mount`, `pivot_root`, `chroot`, handle-based opens), `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_*` (seccomp can't inspect its submissions), the kernel keyring, module loading, `kexec`, reboot, swap, clock setting and similar. It is a deny-list, not an allow-list, so a library that needs an ordinary call keeps working. The **vault** profile also denies `socket()` entirely: its UI connection and netd's pipes exist before the filter, and Landlock alone doesn't cover UDP, raw or Unix sockets. The **netd** profile denies every socket family but IPv4 and IPv6. A vault whose netd didn't start uses the netd profile. `--report` shows `syscalls: "filtered"`; unit tests confine one thread per profile and check TCP, UDP, Unix sockets and `exec`, and the process tests assert the filter in both demo and server mode. Residual: `clone3` passes flags by pointer, so a new user namespace through it is stopped only by `unshare`/`setns` being denied, not at creation.
- **Not yet**: an allow-list seccomp policy, the macOS App Sandbox and Windows AppContainer, restarting a crashed netd (today the vault's requests fail with "netd stopped" until the app restarts), arti and Nym inside netd (it uses the dev TCP transport), and the `mediad` split.

### 1.2 Android

- The network service runs in its own `android:process` (the netd role).
- Decoders run in an `isolatedProcess` service (the mediad role).
- The app process holds the vault role and the Slint UI (the UI never receives key material through the command API).

### 1.3 iOS

- A single app process plus the Notification Service Extension. This is an accepted residual risk (RT-14).
- Image and audio parsers run inside a **WASM isolation sandbox** (wasmi or the Pulley interpreter; no JIT) in `enclave-sandbox`.
- The NSE (`enclave-nse`) decrypts capsules only (`10-push.md` §5.1).

### 1.4 Rules

- `netd` MUST NOT link `enclave-store` or hold any key other than transport session keys (test `rt14_netd_has_no_key_material`).
- `mediad` receives only encrypted-then-decrypted media bytes from `vault`, never keys; it returns only raw RGBA, PCM, or re-encoded outbound media.
- A crash in `netd` or `mediad` is recovered by restarting that process; `vault` state is unaffected.

## 2. UI

- **Slint ≥ 1.18**, one codebase for desktop, Android, and iOS.
- The UI never touches key material. It talks to `enclave-core` through a typed async command/event API (with a UniFFI feature for the fallback shells of §3.3).
- **Skia (C++) is required on Android and iOS** because Slint's mobile backends depend on it. It is fed only Enclave's own paths, text, and decoded RGBA, with its codecs disabled (PLAN §22 exception).
- **Unicode hygiene** for all names (contacts, groups, devices, file names): NFKC normalization; at most 8 combining marks per base character (excess removed); bidi control characters (U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C) removed from names and isolated in message text with first-strong isolation; zero-width characters removed from names.
- Security events are shown inline and persistently, never as toasts (`17-design.md` §8).

## 3. Accessibility gate (M1.5 and M6, hard)

### 3.1 Must pass

- TalkBack and VoiceOver can operate the chat list, composer, and the verification flow (security code, in-person scan, "They match").
- CJK and Indic IME input, RTL layout, color emoji, 200% text, and text selection and copy all work.

### 3.2 Current gap

Slint's Android backend has no AccessKit wiring today. The project will fund or build, and upstream, the `accesskit_android` and `accesskit_ios` integration.

### 3.3 Fallback

If the gate is still blocked **8 weeks after M6**, mobile gets thin SwiftUI and Jetpack Compose shells over the same Rust core via UniFFI, as a declared exception. **Accessibility outranks language purity.** The shells hold no keys and no protocol logic.

## 4. Platform shims

- `enclave-platform` is the only crate (with `enclave-sandbox` and `enclave-nse`) allowed `unsafe`; every `unsafe` block gets two reviews and a tracking comment.
- Android: `jni` and `ndk`, with Kotlin shims of at most 300 lines total and Slint's Java helper.
- Apple: `objc2` for APNs, PushKit, CallKit, Keychain, Secure Enclave, VoiceProcessingIO, and `define_class!` for the NSE principal class.
- Windows: the `windows` crate (CNG, DPAPI, window display affinity).
- Linux: `zbus` (Secret Service, notifications, portals).
- The ARM DIT bit is set around cryptographic operations (`02-cryptography.md` §12).

## 5. Media policy (few formats, few decoders)

| Kind | Sender | Receiver |
|---|---|---|
| Images | Re-encode to JPEG or PNG, at most 4,096 px on the long edge, with EXIF and GPS stripped | Decode in the sandbox (`zune-jpeg`, `png`) to raw RGBA, 25 MP cap. Re-encode only on export. |
| Animated images | Sent as short AV1 clips (no GIF, APNG, or WebP decoders) | AV1 decode in the sandbox |
| Video | AV1 + Opus in Enclave's own fixed-chunk container (no MP4 or WebM demuxer). The sender's own camera files are read with the OS decoder and transcoded. | rav1d and Opus in the sandbox |
| Voice notes | Opus | Opus in the sandbox |
| Files | Sent as-is | **Never previewed.** "Open with…" shows a warning: "Files can contain harmful content. Only open files you expect." |
| From strangers | — | **Nothing auto-downloads.** Message requests show text only. |
| Link previews, GIF search | **Off by default.** When on, generated on the sender side only, fetched through Tor | Shown as a static image and title |

### 5.1 Fixed-chunk container

The container is a sequence of 64 KiB records, each `u8(track) ‖ u32(pts_ms) ‖ u16(frames) ‖ payload`, with a header record listing tracks (AV1 or Opus, with fixed parameters). It has no variable-length boxes, no nesting, and no index; it is fuzzed as a parser (`20-assurance.md` §1).

## 6. Feature parity

The feature matrix is in `16-features.md`.

## Open questions

1. The fixed-chunk container (§5.1) record layout is a proposal; `enclave-media` finalizes it at M9 with fuzzing.
2. Whether the Android vault role should also be split from the UI process (PLAN §14 splits only network and decoders on Android).
3. The Unicode bidi handling in message text (isolation rather than removal) is this spec's choice; PLAN §14 says "bidi controls neutralized in names" only.
