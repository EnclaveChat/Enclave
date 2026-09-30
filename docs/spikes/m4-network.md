# M4 spike: Nym and Tor feasibility

Status: Report (M4) · Informative

This records what the M1.5/M4 network spike could and could not establish in
the development environment on 2026-09-30, and what remains to be measured on
real devices and networks before the M4 gate can close.

## Environment limits

The build sandbox allows outbound HTTPS only, through a proxy. Raw TCP to
arbitrary hosts is blocked, so it cannot reach Tor relays (ORPort) or Nym
gateways (WSS on 9000/443 to gateway IPs). **No live Tor or Nym traffic was
exchanged.** Everything below is build-level evidence plus in-process tests.

## Findings

| Item | Result | Evidence |
|---|---|---|
| `nym-sdk` 1.21.6 (latest) | **Does not resolve** on crates.io: `nym-client-core-gateways-storage` 1.22.0 requires `nym-gateway-client` ^1.22.0, which conflicts with the 1.21.6 set | `cargo generate-lockfile` |
| `nym-sdk` 1.21.5 | Resolves and builds: 5 min 41 s cold build, 3.0 GB target directory | probe build |
| Native code under `nym-sdk` | `aws-lc-sys`, `ring` (several versions), `libsqlite3-sys`, `zstd-sys` | `cargo tree` |
| `arti-client` 0.46 (tokio + rustls + onion-service-client + compression) | Builds in about 1.5 min | probe build and `enclave-net --features tor` |
| Native code under `arti-client` | `zstd-sys`, `libsqlite3-sys` (and `openssl-sys` only with the default `native-tls` feature, which Enclave disables) | `cargo tree` |
| Tor transport code | `TorTransport` implemented against arti (onion-service addressing, same framing as the dev transport); compiles | `crates/enclave-net/src/transport.rs` |
| Nym transport code | Not written yet: needs a working SURB request/reply design on nym-sdk 1.21.5 and live gateways to test | — |
| Cover-traffic scheduler | Implemented; tick timing and poll pattern independent of real traffic (KS test, α = 0.01); real and cover units identical in size and byte distribution | `crates/enclave-net/tests/shape.rs` |

## Consequences for the plan

1. **Pin `nym-sdk` = 1.21.5** until upstream publishes a consistent set, and
   track the regression upstream.
2. **Declared C exceptions grow** (docs/PLAN.md §22): zstd, SQLite, aws-lc and
   ring arrive transitively through arti and nym-sdk. They run in the `netd`
   process, which never holds long-term keys (process split, §14).
3. **Nym over Tor** needs nym-sdk to accept a custom connector for its gateway
   connection. Not verified; if unavailable, the Tor underlay applies only to
   the fallback transport, and the entry gateway sees the client IP. This
   stays the top open risk (Appendix B #1).

## Still to measure (M4 gate)

On a mid-range Android phone, an iPhone and a desktop, with live networks:

- nym-sdk resident memory (≤ 150 MB), cold connect (≤ 5 s), raw throughput;
- zk-nym credential acquisition through the credential proxy, and cost per GB;
- whether disabling Nym's own Poisson stream is a supported configuration;
- Tor exit → Nym gateway reachability on port 443;
- measured data per profile against `docs/math/cover-traffic.md` (±20%);
- foreground battery cost (≤ 5 percentage points per hour above idle).
