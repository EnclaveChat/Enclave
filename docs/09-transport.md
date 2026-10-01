# Transport and Metadata

Status: Draft (M0, reconciled with the M3–M4 code) · Normative

Source: PLAN.md §9 (D7, D10). Crates: `enclave-rpc` (sealed requests, API payloads), `enclave-net` (transports, scheduler), `enclave-server`, `enclave-tokens`. Layouts: `08-envelope.md`. Rates: `math/cover-traffic.md`. Where this document and the code disagree, the code is normative.

## 1. Path

```
Client → Tor (embedded arti) → Nym entry gateway (WSS, port 443) → 3 mix layers → exit gateway
       → the destination Enclave server's own Nym client
```

- Writes go to the recipient's server. Polls go to your own server. There is no server-to-server relay.
- Every request uses fresh single-use SURBs and a fresh sender tag. Replies return over those SURBs.
- Servers have no clearnet message API.
- Tor always sits in front of Nym. It hides the client IP from the entry gateway and provides pluggable transports.

All transports implement one trait, `enclave_net::transport::Transport`: `exchange(server, request) -> reply` and `server_key(server)`. State of the implementations:

| Transport | Status |
|---|---|
| `TcpTransport` | Implemented. Development only: frames `u32(len) ‖ bytes` over TCP to the `enclave-server` dev binary. A zero-length frame asks for the server's current request key, returned as `u32(key_id) ‖ X448 (56) ‖ ML-KEM ek (1,568)`. |
| `TorTransport` | Implemented behind the `tor` feature (arti 0.46, embedded): same framing to a server's onion service. Compiles; not exercised against the live network. |
| `NymTransport` | Not implemented (placeholder behind the `nym` feature). See `spikes/m4-network.md`. |

## 2. Sealed requests

Every request (wire unit or poll object) is sealed end to end to the destination server's **daily** X448 + ML-KEM-1024 key (`enclave-rpc`). Nym's Sphinx layer is classical, so this seal is what keeps mailbox addresses and tokens post-quantum confidential (RT-27).

### 2.1 Server request keys

- The server generates one key pair per day; `key_id` is the Unix day number (`u32`).
- `Server::rotate(day)` adds the new key and keeps at most two: the new one and the previous one. Older keys are deleted, which gives forward secrecy for request metadata. The previous day's key therefore stays until the next rotation.
- Clients learn the current public key from the server (the dev transport's zero-length frame; server descriptors, `12-servers.md` §4, are not implemented).

### 2.2 Client side

```
seal_request(server_key, header, envelope):                 # envelope is 14,336 B
    (eph_sk, eph_pk) = fresh X448 pair
    (ct, ss_m) = ML-KEM-1024.Encaps(server.mlkem)
    ss = EnclaveCombine(TwoKem,
             secrets = [X448(eph_sk, server.x448), ss_m],
             public  = [eph_pk, ct, server.x448, server.mlkem, u32(key_id)],
             psk = none)
    k_req   = KMAC256(ss, "", 256, "enclave/v1/rpc/request")
    k_reply = KMAC256(ss, "", 256, "enclave/v1/rpc/reply")
    sealed  = seal(k_req, AD = u32(key_id), header (72) ‖ envelope (14,336))       # 14,472 B
    unit    = u16(1) ‖ u16(1) ‖ eph_pk ‖ ct ‖ sealed ‖ random padding (284)        # 16,384 B
    keep k_reply for the reply

seal_poll(server_key, header):                               # same, without the envelope
    sealed = seal(k_req, AD = u32(key_id), header)           # 136 B
    poll   = u16(1) ‖ u16(1) ‖ eph_pk ‖ ct ‖ sealed ‖ random padding (284)          # 2,048 B
```

The key ID is bound into the EnclaveCombine public items and used as the seal's AD, but it is **not on the wire**: one more cleartext field would be one more linkable value.

### 2.3 Server side

```
open_request(held keys, newest first, bytes):
    require len(bytes) in {16,384, 2,048}; version 1; suite 1              else fail
    for each held key:
        ss = EnclaveCombine(…) with the server's secrets; k_req = …
        pt = open(k_req, u32(key_id), sealed)                               else try the next key
        header = RequestHeader::decode(pt[0..72])                           else try the next key
        return (header, envelope = pt[72..] or empty for a poll, exchange keys)
    fail
```

A request that fails to open gets 16,384 random bytes as its reply. An opened request is dispatched (`12-servers.md` §1) and answered with `seal(k_reply, "reply", reply header ‖ reply envelope)` plus random padding (`08-envelope.md` §3).

Not implemented yet: a replay cache of request ciphertexts per key. A replayed request is processed again; ops with single-use tokens fail the second time, but others do not (`12-servers.md` Open questions).

## 3. Inboxes, read credentials, write tokens (D7)

### 3.1 Inbox creation

An inbox is created with `RegisterTokens` and the `CREATE` flag (`08-envelope.md` §2.2):

- `mailbox` is the inbox address, 32 bytes chosen at random by the owner.
- `token` is the **owner secret**, 32 random bytes kept by the owner.
- The server stores `credential_hash(owner_secret)` and `credential_hash(read_credential(owner_secret))`, and refuses to create an address that exists (`Denied`).
- With `REQUEST_INBOX` also set, the inbox is a request inbox (§4).

```
read_credential(owner) = KMAC256(owner, "read", 256, "enclave/v1/rpc/read-credential")[0..24]    # 24 B
credential_hash(x)     = KMAC256(x, "", 256, "enclave/v1/rpc/credential-hash")
```

Not implemented yet: weekly address rotation from an inbox seed, daily address-bound read credentials, and an Equi-X PoW on inbox creation (PLAN §9.3; the reserved labels are in `label-registry.md` §3.3). The address and the read credential are static for the life of the inbox, and the server sees the owner secret whenever the owner creates the inbox or registers tokens.

### 3.2 Reading

- `Poll`: `token = read_credential ‖ u64(cursor)`. The server checks `credential_hash(token[0..24])` and returns the first envelope with a sequence number above the cursor, with `FOUND`, its sequence number in the reply token, and `MORE` if another follows. With nothing to return it replies `Ok` with an empty payload.
- `Ack`: `token = read_credential ‖ u64(watermark)`. The server deletes every envelope with sequence number ≤ watermark.
- A wrong credential gets `Denied`.

### 3.3 Write tokens

```
k_contact = HedgedRng.fill("tokens/contact-key", 32)                  # per contact, kept by the inbox owner
t_i       = KMAC256(k_contact, u64(i), 256, "enclave/v1/tokens/write")   # i = 0, 1, 2, …
h_i       = KMAC256(t_i, "", 256, "enclave/v1/tokens/hash")              # what the server stores
```

**As implemented: a shared pool** (`enclave-core/src/client/tokens.rs`). Registering one contact's tokens as their own batch, as the derivation above suggests, lets the server group writes by sender: every token of a batch that is ever burned belongs to the same person (the dummies never are). The client therefore registers tokens ahead of time in batches that later go to different contacts:

- **Pool.** Tokens are 32 random bytes from the hedged RNG (`core/write-token`). The owner registers 64 at a time (more if one hand-out needs more), shuffled with 16 dummies, and keeps the registered-but-unissued tokens as a per-device pool in the sealed store. The pool is never in a backup, and a restore clears it, so no token is handed out twice.
- **Issue.** A contact who needs tokens gets the oldest ones from the pool, inside the encrypted session; the pool is refilled first if it runs short. The owner keeps the hashes of the last 128 tokens each contact was given, for revocation.
- **Register.** `RegisterTokens` without `CREATE`, `token` = owner secret, payload = the hashes. `registration_batch(real, dummies)` appends `dummies` random 32 B values and shuffles the batch (Fisher-Yates with hedged randomness). The server checks the owner secret, that the payload length is a multiple of 32, and the per-inbox quota of 4,096 unspent hashes (`Quota`). One frame carries at most 447 hashes.

Test `token_batches_mix_contacts` plays a server that logs every batch and every burn, and checks that two contacts' writes used tokens from the same batch. `TokenIssuer` (the per-contact derivation) remains in `enclave-tokens` but the client no longer uses it. Residual: a batch still bounds a time window, and a contact who is the only one given tokens from a batch before it is used up could be grouped by it; the pool's order makes that rare but not impossible for an account with one active contact.
- **Use.** A `Write` carries `t_i` in the header's token field. The server computes `h_i`, accepts the write only if `h_i` is registered, and deletes it (burns it). Reuse gets `Denied` (RT-24). The server cannot tell which contact a token belongs to, and two writes by one contact are unlinkable.
- Hashing is the only cryptography in a token, so nothing here weakens under a quantum computer.

- **Block** (`enclave-core/src/client/blocks.rs`, RT-25). The owner keeps the hashes of the last 128 tokens each contact was given (above). Blocking someone sends `RegisterTokens` with `FLAG_REVOKE` and those hashes (more than anyone holds: 32 outstanding plus a refill in flight), so their writes to the inbox fail with `Denied`; they get no refills, and they are not told. Anything that still arrives from them is dropped without a trace: messages already in the inbox, a new greeting through the request inbox (its prekey is spent and the replay marker kept, but no contact or session is stored), and their messages, reactions and pins in groups we share (their group state updates still apply, so the membership stays consistent). We can't send to them either. Unblocking sends 32 fresh tokens. The app offers **Block** on a message request and in the conversation sheet, and a blocked conversation shows a notice with **Unblock** instead of the composer. Test `block_and_unblock` checks that the server refuses the blocked contact's write.

Not implemented yet: returning the burned token to the owner as a session hint, refill control messages, weekly re-registration under a new address, token hashes bound to the address, and self tokens.

## 4. Request inbox

- Created like an account inbox with `CREATE | REQUEST_INBOX`. Its address is in the account manifest (`request_inbox`, `03-identity.md` §3).
- `WriteRequest` needs an Equi-X proof of work in the header's token field over `"request-inbox" ‖ mailbox ‖ SHA3-512(envelope region)` at the server's request effort (default 64; `12-servers.md` §1). Account inboxes refuse `WriteRequest` and request inboxes refuse `Write` (`Denied`).
- It holds at most `request_quota` pending envelopes (default 100). When full, the oldest is dropped to make room (FIFO).
- The owner reads it with `Poll`/`Ack` and its own read credential.

Not implemented yet: invite capabilities, adaptive effort, and client-side rules for requests (text-only, no auto-download).

## 5. Polling

- **One mailbox per poll request, always.** A poll object names exactly one mailbox.
- The scheduler (`enclave_net::schedule::Scheduler`) keeps a list of mailboxes; index 0 is the account inbox. It counts ticks since the list was last set (`rr`):
  - on **even** ticks it polls the account inbox;
  - on **odd** ticks it polls one of the other mailboxes, chosen by **smooth weighted round robin**: each odd tick, every other mailbox's credit grows by its weight (minimum 1), the mailbox with the highest credit is chosen (the lowest index wins ties), and its credit drops by the sum of the weights;
  - with only the inbox in the list, every tick polls the inbox.
- This alternation is the same in all three profiles.
- Test `inbox_polled_every_other_tick_and_weights_respected`: over 400 ticks with weights 3 and 1, the inbox gets exactly 200 polls and the others 150 and 50.

Not implemented yet: the `MORE` flag steering the next poll to the same mailbox, overlap-week polling, a per-group floor of one poll per 60 s, and decoy re-fetches.

## 6. Cover-traffic scheduler (D10)

Nym's default client sends 50 + 5 packets per second (about 500 MB/h). Enclave disables Nym's Poisson main stream and drives its own tick scheduler.

### 6.1 Tick

`Scheduler::tick` returns, for every tick:

- `after`: the delay since the previous tick;
- `send`: the next queued real request, or `None`, in which case the caller sends a `Cover` unit;
- `poll`: the mailbox to poll (§5).

So each tick sends exactly **1 unit up** (real or cover) and **1 poll up**. The server answers every request with a 16,384 B reply unit, and the transports implemented so far return it, so a tick currently brings back **2 units down**. PLAN §9.4 budgets 1 unit down (writes and cover get no reply over the mixnet); the Nym transport must send writes and cover without reply SURBs to meet the data figures below (`math/cover-traffic.md` §1, §2.1). Real traffic **replaces** cover; it never adds to it. Tick timing depends only on the profile and randomness, never on the queue. Test `crates/enclave-net/tests/shape.rs` checks that delays and poll targets have the same distribution whether or not real traffic is waiting (two-sample Kolmogorov-Smirnov, α = 0.01), and that real and cover units are identical in size.

### 6.2 Send priority

`enqueue` keeps the queue ordered by priority, first in first out within a class:

| Priority | Class |
|---|---|
| 0 | `Peer`: delivery to a contact |
| 1 | `Control`: token registration, acks, prekey refills |
| 2 | `Sync`: own-device sync |
| 3 | `Prefetch`: blobs the user has not opened |

### 6.3 Profiles

There are exactly three profiles, identical in every client, and no per-user or per-network parameters.

| Profile | When | Tick delay (`mean_tick`, `poisson`) | Bulk bursts (`allows_bulk`) | Data (estimate, PLAN's 1-down model; M4 must land within ±20%) | Median text latency (estimate) |
|---|---|---|---|---|---|
| **Foreground** | App visible | fixed 3 s | allowed | ≈60–70 MB/h | ≈5–6 s without other mailboxes; ≈6.5–7.5 s with |
| **Background** | Android foreground service, desktop tray | exponential, mean 120 s | allowed | ≈35–40 MB/day | ≈88 s without other mailboxes; ≈140 s with |
| **Maximum privacy** | Opt-in; Android and desktop always, iOS only while open | fixed 3 s | not allowed | ≈1.5–1.7 GB/day | as Foreground |
| Background (iOS) | Not possible (the OS suspends the app) | none | — | 0 | On open, or on push |

The Background delay is `−ln(U) · 120 s` with `U` uniform in (0, 1], drawn from 53 bits of hedged randomness. Data and latency derivations: `math/cover-traffic.md`.

Not implemented in the scheduler yet: releasing the Sphinx packets of a tick at uniform intervals ("packet-paced"), Nym loop cover (1 per 10 s in Foreground and Maximum, 1 per tick in Background), and Enclave self-loop probes with gateway switching (§6.4 of the M0 draft). The data figures in `math/cover-traffic.md` include loop cover as specified.

### 6.4 Bulk

`Scheduler::bulk(max)` hands out up to `max` queued requests at once for a burst (media, the McEliece key, catch-up), if the profile allows it. In Maximum it returns nothing, so bulk traffic rides the normal ticks one request per tick. The 40 packets/s Bulk rate cap belongs to the transport and is not implemented yet.

### 6.5 Profile transitions

`set_profile` changes the profile only at a foreground/background transition or when the user toggles Maximum privacy (RT-12). The next tick follows the new profile; no extra ticks are added to "catch up".

### 6.6 Maximum privacy

- The 3 s tick runs constantly, including in the background on Android and desktop.
- No bulk bursts: a 1 MiB-bucket photo (74 chunks) takes about 3.7 minutes and a 4 MiB-bucket photo (295 chunks) about 15 minutes. The UI states the time for the actual bucket before sending.
- Not implemented yet: disabling push, forbidding the fallback transport, and waiting for all three KEMs before the first send.

## 7. Nym access, fallback, censorship (not yet implemented)

- zk-nym credentials through a credential proxy gated by Equi-X plus Privacy Pass.
- M4 go/no-go (`roadmap.md`): nym-sdk ≤150 MB RAM on Android and iOS; cold connect ≤5 s; bulk ≥200 KB/s of nym-sdk raw throughput (the Bulk profile itself is capped at 40 packets/s, at most ≈82 KB/s of payload; `00-overview.md` §9, I-12); the credential path works; cost ≤ $1 per user per month; the Tor → gateway path works. The spike report is `spikes/m4-network.md`.
- Fallback transport: Tor onion services (`TorTransport`) with the same scheduler and objects, only with user consent and never in Maximum mode.
- Censorship: obfs4 bridges in process; Snowflake and WebTunnel as declared exceptions, only in censorship mode.
- Nym's post-quantum Sphinx is adopted when nym-sdk exposes it.

## 8. TLS 1.3 (not yet implemented; never on the message path)

A rustls `CryptoProvider` with SecP384r1MLKEM1024 (codepoint 0x11ED) and `TLS_AES_256_GCM_SHA384` only, for server descriptors, witness gossip, update endpoints, the relay control plane and the push relay's front door.

## 9. Blobs

- **Upload:** `BlobPut` with the chunk ID in the mailbox field and an Equi-X proof over `"blob-put" ‖ chunk_id ‖ SHA3-512(chunk)` at the server's blob effort (default 1). The first upload to an ID wins; a second gets `Denied`.
- **Fetch:** `BlobGet` with the chunk ID; no credential. The chunk ID is the capability.
- Blobs expire 30 days after upload.

Not implemented yet: `BLOB_ALLOC` with Privacy Pass quotas, client-side chunk sealing and ID derivation, delayed fetches and decoy fetches (RT-17).

## 10. Errors

| Condition | Client behavior |
|---|---|
| Reply cannot be opened | Treat as failure; retry in a later tick with a new seal |
| `Denied` on a write | The token was spent or never registered; use the next token |
| `Quota` | Inbox full; retry later |
| `Pow` | Solve again at the server's current effort |
| No tokens for a contact | Queue the message until the contact sends more |

## Open questions

1. PLAN §9.3 polls the inbox in slot 1 and rotates groups in slot 2. The implementation alternates strictly in all profiles. In Background this puts the median text latency at about 140 s when other mailboxes are polled, above PLAN's "≤2 min"; the M0 draft proposed using the second slot on only every 4th Background tick (median ≈112 s). The scheduler needs that change, or PLAN's Background latency figure needs to change.
2. PLAN §9.2 asks for a replay cache of request ciphertext hashes per key. It is not implemented.
3. PLAN §9.2 says old daily keys are deleted; the implementation keeps the previous day's key until the next rotation rather than for a short grace window. Deleting it after a grace period needs a timer in the server.
4. Read credentials are static and inbox addresses do not rotate (§3.1). PLAN §9.3 derives weekly addresses and daily credentials from an inbox seed; the implementation intentionally starts simpler. This needs to be implemented before a server can be prevented from linking a device's polls across weeks.
5. Every request, including writes and cover, gets a full reply unit today. Dropping write and cover replies (needed for PLAN's data budget, `math/cover-traffic.md` §2.1) leaves writes without a delivery status; delivery would then be confirmed by receipts only.
