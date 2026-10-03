# Patched upstream crates

Upstream crates Enclave builds with a change, each a copy of the released
crate with the smallest edit, marked `ENCLAVE PATCH` in the source. Each
change is offered upstream; the copy goes when a release carries it
(`docs/completion-plan.md` X10).

| Crate | Version | Licence | Used by | Change | Why |
|---|---|---|---|---|---|
| `nym-client-core` | 1.21.5 | Apache-2.0 | `nym/` workspace (`[patch.crates-io]`) | `MessageHandler::get_or_create_sender_tag` draws a fresh `AnonymousSenderTag` for every message instead of keeping one per recipient | One tag per recipient lets a server link every request a client sends it; Enclave requests must be unlinkable (`docs/09-transport.md` §1). Enclave sends every reply SURB a reply needs with its request, so no "more SURBs" request ever uses an old tag. |
| `nym-client-core` | 1.21.5 | Apache-2.0 | as above | New module `enclave`: a process-wide count of messages handed to the client and not yet prepared (`note_submitted`, settled by the input listener and the reply controller) plus fragments sent and not yet acknowledged (added in `MessageHandler::insert_pending_acks`, settled in `ActionController::handle_remove`); `outstanding()` reads it | A one-way send returns once the message is queued; a process that exits then loses it. `enclave-nym-sdk`'s `NymDriver::flush` waits for the count to reach 0 before nymd or the ingress exits (`docs/09-transport.md` §6.1). Process-wide because each Enclave process runs one mixnet client. |
| `nym-client-core` | 1.21.5 | Apache-2.0 | as above | `tungstenite`/`tokio-tungstenite` 0.20 → 0.24 in `Cargo.toml` | 0.20 runs the gateway connection on rustls 0.21 and rustls-webpki 0.101 (RUSTSEC-2026-0098, -0099, -0104); 0.24 is on rustls 0.23. No source change was needed. |
| `nym-gateway-client` | 1.21.5 | Apache-2.0 | `nym/` workspace | the same version bump | the same |
| `nym-gateway-requests` | 1.21.5 | Apache-2.0 | `nym/` workspace | the same version bump | the same |

Every other `nym-*` crate is pinned to 1.21.5 in `nym/Cargo.lock`: mixing
1.21.5 with the later-published 1.22.0 helper crates doesn't compile.
