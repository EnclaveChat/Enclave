# Contributing to Enclave

Thank you for helping. Enclave is a security project, so the bar for changes is
high and the process is explicit.

## Developer Certificate of Origin

Every commit must be signed off:

```
git commit -s
```

This adds `Signed-off-by: Your Name <you@example.com>`. By signing off you
certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
**and** grant the additional permissions in `legal/ADDITIONAL-PERMISSIONS.md`
for your contribution. Commits without a sign-off cannot be merged.

## Before you open a pull request

Run the same checks CI runs:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## Rules for code

* Rust only, unless `docs/PLAN.md` §22 lists an exception. New C, C++ or Go
  dependencies need a written justification and a `deny.toml` entry.
* `#![forbid(unsafe_code)]` in every crate except `enclave-platform`,
  `enclave-sandbox` and `enclave-nse`. Every `unsafe` block there needs two
  reviewers.
* Every KMAC label comes from `docs/label-registry.md`. Never reuse a label.
* Secret types never implement `Debug`, `Display` or `Serialize`, and are
  zeroized on drop.
* No compression before encryption, anywhere.
* Protocol and cryptography changes go through the RFC process in
  `docs/rfcs/` and need review from the crypto working group.

## Reporting security issues

Do not open a public issue. See `SECURITY.md`.
