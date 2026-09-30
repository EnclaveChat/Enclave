# Releases, Supply Chain, Crash Reports, Versioning

Status: Draft (M0) · Normative

Source: PLAN.md §17, §18 (license, export, regulation), §22, RT-13, RT-14. Crates: `enclave-update`, `enclave-crash`, `xtask`.

## 1. Releases and updates (RT-13)

### 1.1 Signing

- **TUF** via the `tough` crate for update metadata (root, targets, snapshot, timestamp roles).
- Every release target is co-signed by **2 of 3 maintainers**, each signature being **SLH-DSA-SHAKE-256s + Ed448**:
  - SLH-DSA with ctx `enclave/v1/update/release` over the TUF targets metadata hash;
  - Ed448 over `E("enclave/v1/update/release") ‖ targets_hash`.
  - A maintainer signature is valid only if both halves verify.
- Maintainer keys live on offline HSMs held by 3 maintainers in 2 jurisdictions.

### 1.2 Transparency

- Release hashes are logged in **Sigsum** with witnesses (the same witness operators as KT where possible).
- Clients verify a Sigsum inclusion proof (with witness cosignatures) before installing an update, on every platform where Enclave controls installation.

### 1.3 Update fetch

- Update manifests are fetched **through the mixnet**, so they cannot be targeted by IP.
- "Verify this build" (compare the running binary's hash with the reproducible-build log) is available everywhere except iOS.

### 1.4 Channels

| Platform | Channels |
|---|---|
| Android | Play, F-Droid (reproducible), direct APK |
| iOS | App Store |
| macOS | Notarized DMG plus updater |
| Windows | Signed MSIX plus updater |
| Linux | Flathub, Nix, .deb and .rpm |

### 1.5 Update verification algorithm (`enclave-update`)

```
VerifyUpdate(target):
    TUF-verify metadata chain (root → timestamp → snapshot → targets), rejecting rollback and freeze
    require ≥ 2 valid maintainer co-signatures (both halves) on targets, from distinct maintainers
    require a Sigsum inclusion proof for H(target) with ≥ 2 witness cosignatures
    require H(downloaded file) == target hash
    install only if all hold; otherwise keep the current version and log the failure
```

## 2. Supply chain (RT-14)

- `cargo vet` (importing the Mozilla and Google audit sets), `cargo deny` (licenses, advisories, bans, and an allowlist of crates that build C or C++), and `cargo audit` run in CI.
- Pinned lockfile and vendored sources.
- A `build.rs` and proc-macro allowlist; any new build script needs review.
- Hermetic Nix builds with **two independent rebuilders**; release hashes must match across both.
- SLSA v1 provenance for every release artifact.
- **CI hygiene:** third-party actions pinned by commit SHA, least-privilege tokens, no secrets in pull-request jobs.
- `cargo deny` enforces GPLv3-compatible licenses: MIT, Apache-2.0, BSD, ISC, MPL-2.0, and OFL (fonts). **AGPL and GPL-only crates are blocked from iOS builds.**
- `#![forbid(unsafe_code)]` in every crate except `enclave-platform`, `enclave-sandbox`, and `enclave-nse`.
- `cargo vet` must cover 100% of crypto and parser crates (`20-assurance.md`).

## 3. Crash reports without telemetry

- A panic hook and `minidumper` write a **scrubbed local report**: stack only, no heap. Secret types cannot be formatted into it (they implement neither `Debug` nor `Display`).
- The user can view the report and choose to send it through Enclave to "Enclave Support" (end-to-end encrypted, as a normal message) or export it as a file.
- Nothing is sent automatically. There are no analytics.

## 4. Versioning

- Suite and protocol IDs are carried in units and manifests. Capability sets (protocol min/max and feature bits) are signed in the manifest.
- Old peers are refused only for security-critical changes, after a 90-day overlap.
- Critical fixes can force an upgrade: a signed "minimum version" in the TUF metadata makes older clients show "Update Enclave to keep sending messages." and stop sending (receiving continues for 30 days).
- **Database migrations** are versioned, take a snapshot first, and have tested upgrade paths from every released version.
- Retiring a crypto suite requires 12 months of dual support.

## 5. Legal and governance items owned by ops

| Item | Requirement | When |
|---|---|---|
| License | GPLv3 plus §7 additional permissions (app-store conveyance with source available; Slint Royalty-free 2.0 with AboutSlint attribution; platform SDKs) in `legal/ADDITIONAL-PERMISSIONS.md` | M0, before any outside PR |
| DCO | Contributions need a DCO sign-off with an explicit grant of the §7 permissions | M0 |
| Export control | EAR §742.15(b) notification at the first public source release; App Store export answers and the France declaration with counsel | First public release; M11 |
| EU CRA | Vulnerability handling: 24 h early warning, 72 h notification, 14-day final report; the foundation acts as open-source steward | From M0 |
| Security policy | `SECURITY.md` with 90-day disclosure; bug bounty from M10 | M0, M10 |
| Client-side scanning, key escrow | Never shipped; withdraw from a store rather than comply | Always |
| Transparency | Annual report; no warrant canary | Yearly |

## Open questions

1. Whether the maintainers' Ed448 half should sign with the RFC 8032 context parameter instead of a label prefix (`label-registry.md` Open questions).
2. The forced-upgrade grace (receiving continues for 30 days) is not in PLAN.md.
