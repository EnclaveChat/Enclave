# Servers, Key Transparency, Discovery, Relays

Status: Draft (M0, reconciled with the M3 code) · Normative

Source: PLAN.md §12.1 to §12.3 and §12.5. Crates: `enclave-server`, `enclave-kt`, `enclave-tokens`, `enclave-rpc`; later `enclave-witness`, `enclave-relay`, `enclave-push-relay`. Moderation and the operator kit are in `13-operators.md`. Where this document and the code disagree, the code is normative.

## 1. `enclave-server`

`enclave_server::Server` is an untrusted mailbox. `Server::handle(request, now)` maps one sealed request (unit or poll) to one sealed reply unit and is transport-agnostic: the dev binary serves it over TCP (`09-transport.md` §1), and a Nym service provider will serve it in production. The server keeps **no accounts, no phone numbers and no IP addresses**; everything it stores is keyed by random addresses, hashes, or public keys. State lives in one redb database file (§1.3); the long-term keys live in a separate key directory (§1.4). Tests, the simulator and the offline demo use the same code over an in-memory database.

### 1.1 Configuration

Operators write `server.toml` (`config.rs`, `FileConfig`). Every key can be overridden from the environment as `ENCLAVE_<SECTION>__<KEY>` (for example `ENCLAVE_SERVER__DOMAIN=a.example`), which is how the compose file sets per-deployment values; integers and `true`/`false` keep their type. Unknown keys are refused, so a typo never silently falls back to a default. `load` also checks that `server.domain` is a domain name, that `policy.ttl_days` and `policy.inbox_quota` are positive and that `kt.epoch_secs` is at least 10.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[server]` | `domain` | `localhost` | Public domain (descriptor, usernames) |
| | `operator`, `family` | empty | Operator name; operator family (servers of one family never count as independent) |
| | `data_dir` | `/var/lib/enclave/server` | Holds `server.redb` |
| | `keys_dir` | `/var/lib/enclave/keys` | Long-term keys (§1.4) |
| | `listen` | `127.0.0.1:7443` | Where the ingress reaches the server |
| | `public_dir` | `/var/lib/enclave/public` | Files the front serves (KT pins, descriptor) |
| `[policy]` | `effort_request`, `effort_claim`, `effort_blob`, `effort_username`, `inbox_quota`, `request_quota`, `token_quota`, `ttl_days` | as `Config` below | Abuse controls |
| `[kt]` | `enabled`, `epoch_secs` | `true`, 600 | Username log |
| `[push]` | `forward` | none | Push egress address for due wakes |
| `[backup]` | `dir`, `interval_hours`, `keep` | none, 24, 7 | Snapshots (§1.5) |

`FileConfig::policy(id)` gives the in-process `Config`:

| Field (`Config`) | Default | Meaning |
|---|---|---|
| `id` | — | 16 B server identifier |
| `effort_request` | 64 | Equi-X effort for `WriteRequest` |
| `effort_claim` | 8 | Equi-X effort for a bundle claim |
| `effort_blob` | 1 | Equi-X effort for `BlobPut` |
| `inbox_quota` | 5,000 | Stored envelopes per account inbox |
| `request_quota` | 100 | Pending envelopes per request inbox |
| `token_quota` | 4,096 | Registered unspent token hashes per inbox |
| `ttl_secs` | 30 days | Lifetime of envelopes and blobs |

Proof-of-work contexts (`enclave_rpc::api`), each passed to `enclave_tokens::verify` (`02-cryptography.md` §10):

| Action | Context | Proof carried in |
|---|---|---|
| Request-inbox write | `"request-inbox" ‖ mailbox (32) ‖ SHA3-512(envelope region)` | header token field |
| Bundle claim | `"claim-bundle" ‖ key (32) ‖ u64(day)`, `day = floor(now / 86,400)` | `DirRequest.proof` |
| Blob upload | `"blob-put" ‖ chunk ID (32) ‖ SHA3-512(chunk)` | header token field |

### 1.2 Operations

| Op | Server behavior |
|---|---|
| `Cover` | Count it; reply `Ok`. |
| `RegisterTokens` + `CREATE` | If the address exists: `Denied`. Otherwise create the inbox with `owner = credential_hash(token)`, `read = credential_hash(read_credential(token))`, request flag from `REQUEST_INBOX`, sequence numbers starting at 1. |
| `RegisterTokens` | Inbox must exist (`NotFound`) and `credential_hash(token)` must equal `owner` (`Denied`). The payload must be a multiple of 32 B (`Malformed`); the unspent total must stay ≤ `token_quota` (`Quota`). Insert the hashes; with `REVOKE` (0x08), remove them instead (cancelled invite links). On a request inbox the hashes are invite capabilities. |
| `Write` | Inbox must exist and not be a request inbox (`Denied`). Burn `token_hash(token)` or reply `Denied`. Store the envelope under the next sequence number, or `Quota` if the inbox holds `inbox_quota` envelopes. |
| `WriteRequest` | Inbox must be a request inbox (`Denied`). With `INVITE` (0x08), burn `token_hash(token)` (an invite capability, `03-identity.md` §9.2) or reply `Denied`; otherwise verify the PoW (`Pow`). Store; when `request_quota` envelopes are pending, drop the oldest first (FIFO). |
| `Poll` | `credential_hash(token[0..24])` must equal `read` (`Denied`). Return the first envelope with sequence number > `u64(token[24..32])`, with `FOUND`, the sequence number in the reply token, and `MORE` if another follows; or `Ok` with no envelope. |
| `Ack` | Same credential check. Delete every envelope with sequence number ≤ `u64(token[24..32])`. |
| `BlobPut` | If the chunk ID exists: `Denied`. Verify the PoW (`Pow`). Store the envelope region under the ID. |
| `BlobGet` | Return the chunk, or `NotFound`. No credential. |
| `Directory` | §2. A payload that does not parse gets `Malformed`. |
| `KeyTransparency` | Not wired to `enclave-kt` yet: `NotFound`. |
| `Report` | The mailbox must be one of this server's request inboxes (`NotFound`). Verify the PoW over `"report" ‖ mailbox ‖ SHA3-512(envelope)` at the request effort (`Pow`); the payload must parse as a `ReportBody` (`Malformed`). Queue it for the operator with the day it arrived; at most 1,000 are kept, oldest dropped first. `Server::take_reports()` hands them to the operator and `Server::disable_request_inbox()` closes a reported account's request inbox. |

A storage failure answers `Unavailable` (status 7) and applies nothing; the client tries again later.

`Server::expire(now)` deletes envelopes and blobs older than `ttl_secs`, bundle claims older than 600 s and unfinished uploads older than 600 s. `Server::install_key(key)` makes a request key from the chain (§1.4) current and keeps one previous (`09-transport.md` §2.1); in-memory servers use `Server::rotate(day)`, which draws a random one. `Server::stats()` returns aggregate counters only (requests, cover, stored, tokens burned, denied). `Server::reports()` lists queued reports without removing them; `Server::take_reports()` removes them.

### 1.3 State the server holds

| Store | Key | Value | Retention |
|---|---|---|---|
| Inbox | 32 B address | owner-secret hash, read-credential hash, request flag, unspent token hashes, envelopes with sequence numbers and receive time | Envelopes: until acknowledged or 30 days |
| Manifest | manifest key (§2.1) | latest version and signed manifest bytes | Until replaced by a higher version |
| Prekey publication | 16 B device ID | publication and the index of the next unserved one-time prekey | Until replaced |
| Claim | 32 B random claim ID | encoded bundle | 600 s |
| Vault object | 32 B locator | owner-secret hash and opaque bytes | Until replaced by the same owner |
| Blob | 32 B chunk ID | 14,336 B chunk | 30 days |
| Upload | (kind, key) | chunks received so far | Until complete |

Nothing in this table is an IP address, a Nym identity or an account identifier. Receive times are stored only to expire envelopes.

**Persistence (`db.rs`).** Everything above except claims and unfinished uploads (both short-lived) is kept in redb tables: inboxes, tokens (keyed `mailbox ‖ hash`), envelopes (keyed `mailbox ‖ seq`), manifests, devices seen, attestations, migrations, moved records, device owners, bundles, vaults, blobs, push registrations, usernames, names by root, reports and a `meta` table holding the schema version (1). Each request runs in one write transaction that commits before its reply is sealed, so a server killed at any point either did all of a request or none of it: a burned token stays burned, and an envelope that was acknowledged as stored survives (`tests/restart.rs`). Key-transparency replies, push wakes and bundle claims are held in memory and expire within minutes; losing them in a restart costs a client one retry.

### 1.4 Identity and daily request keys

`enclave-server init` creates the key directory (mode 0700) with two files (mode 0600, written atomically, never overwritten):

| File | Contents |
|---|---|
| `identity.key` | The server's composite Ed448 + ML-DSA-87 signing key |
| `request-chain.key` | `u32(day) ‖ today's chain seed (32) ‖ 0x00`, or `… ‖ 0x01 ‖ yesterday's chain seed (32)` while yesterday's key is still served |

The **server id** is the first 16 bytes of `SHAKE256("enclave/v1/net/server-id" ‖ identity public key)`: self-certifying, so a descriptor or key certificate signed by the identity proves which id it speaks for.

**Request keys** come from a forward-secure seed chain. Day `d`'s key is derived deterministically: `KMAC256(seed_d, u32(d), "enclave/v1/server/request-key")` gives 120 bytes, the X448 secret (56 B) and the ML-KEM-1024 key-generation seed (64 B). The next seed is `seed_{d+1} = KMAC256(seed_d, "", "enclave/v1/server/request-chain")`. At midnight UTC the server steps the chain, rewrites the file with today's and yesterday's seeds, and drops older ones, so nothing on disk can recompute a request key older than yesterday's (`tests/restart.rs`, `request_keys_roll_forward_and_old_seeds_are_gone`). Because keys are deterministic, a server that restarts serves the same key and clients' cached keys keep working. Today's seed also yields tomorrow's key, which the descriptor publishes in advance.

### 1.5 Running a server

```text
enclave-server init        [--config FILE]   create keys; print the server id
enclave-server run         [--config FILE]   serve (state in redb, keys from disk)
enclave-server show-id     [--config FILE]   print the server id
enclave-server backup DIR  [--config FILE]   snapshot the database (server stopped)
enclave-server healthcheck [--config FILE]   exit 0 if the server answers
enclave-server dev [ADDR] [--domain NAME] [--kt-pins FILE] [--push-relay ADDR]
```

`run` listens on `server.listen` with the length-prefixed frame transport (`09-transport.md` §1); in a deployment only the Nym ingress on the stack's internal network can reach it. Once a minute it steps the request-key chain if the day changed and expires old objects. With `[backup] dir` set it writes `server-<unix time>.redb` snapshots every `interval_hours` and keeps the newest `keep`. On SIGTERM or Ctrl-C it waits for the request in flight (which has already committed) and exits. A restore needs both a snapshot and the key directory; the key directory must be backed up separately, encrypted and off the host. `dev` is the all-in-memory development server: random keys every start, nothing persisted; a bare `enclave-server [ADDR]` runs it.

## 2. Directory

### 2.1 Objects and keys

| Kind | Key | Object | Published by | Fetched by |
|---|---|---|---|---|
| 1 `Manifest` | `SHAKE256("enclave/v1/dir/manifest" ‖ root_pk, 32)` (`manifest_key`) | `SignedManifest` encoding (`03-identity.md` §3) | The account | Anyone with the root public key |
| 2 `Bundle` | `device_id (16) ‖ 0^16` (`device_key`) | `Publication` on put; `Bundle` on claim | The device | Initiators, through claims |
| 3 `Vault` | 32 B random locator | Opaque bytes (the client-sealed vault key) | The account | Holders of the locator and its key (contact card) |
| 4 `Username` | The name's bytes, zero-padded to 32 (`name_key`) on put and on the first get; the reply ID on later gets | `UsernameClaim` on put; `LookupReply` on get (§3.7) | A device of the account | Anyone who knows the name |
| 5 `Attest` | Like the manifest | Device attestations (co-sign or veto, `03-identity.md` §8.1) | A listed device | Contacts and our own devices |
| 6 `Migration` | The **old** root's `manifest_key` | `Migration` record (`03-identity.md` §8.2) | The account, after changing its recovery words | Anyone holding an old code |

Objects travel in `DirRequest`/`DirReply` payloads as chunks of at most 14,000 B (`08-envelope.md` §9.3).

### 2.2 Put

`DirAction::Put` sends one chunk: `total` must be 1 to 200 and `index < total` (`Malformed`). Chunks accumulate per `(kind, key)`; a chunk with a different `total` than the upload in progress discards it (`Malformed`). Until every chunk has arrived the reply is `Ok`. When the last one arrives, the chunks are concatenated in index order and validated:

- **Manifest:** decode the signed manifest and its body (`Malformed`); the key must equal `manifest_key(root)` of the manifest's own root (`Invalid`); the root signature and validity window must verify (`SignedManifest::verify` with the manifest's root, `Invalid`); the version must be higher than the stored one (`Invalid`). Then store it.
- **Bundle:** decode the publication (`Malformed`); the key must equal `device_key` of the signed prekey's device (`Invalid`); some stored manifest must list that device (`NotFound`), and `Publication::verify` must pass with that device's composite key (`Invalid`). Then store it and reset the one-time-prekey pointer to 0.
- **Username:** see §3.7.
- **Migration:** decode the record (`Malformed`); the key must be the old root's `manifest_key` and the old root must have cross-signed it (`Invalid`); the new root's manifest must already be stored (`NotFound`) and the record must verify against it (`Migration::verify`, `Invalid`); only one per key (`Invalid`). From then on a `Manifest` put under the old key is `Denied`, a `Manifest` get under it is `NotFound` (so old codes don't lead to the account), and a username the old root held may be claimed by the new root (§3.5).
- **Vault:** `DirRequest.proof` is the owner secret. If the locator exists with a different owner hash: `Denied`. Otherwise store the bytes with `credential_hash(owner secret)`. The server does not interpret the bytes.

### 2.3 Get and claim

- `Manifest`/`Get` and `Vault`/`Get` return chunk `index` of the stored object with the total chunk count, or `NotFound`.
- `Bundle`/`Claim`: verify the PoW in `proof` (`Pow`); look up the publication of `key[0..16]` (`NotFound`); build a `Bundle` with the signed prekey, the next unserved one-time prekey and its batch header (none if all 100 are served), and the last-resort prekey; advance the pointer; store the encoded bundle under a fresh random 32 B claim ID for 600 s; reply with chunk 0 and the claim ID.
- `Bundle`/`Get` with `key` = claim ID returns further chunks of a claimed bundle.
- `Username`/`Get` with `index` 0 and `key` = `name_key(name)` runs a lookup (§3.7), stores the encoded reply under a fresh random 32 B reply ID for 600 s and returns chunk 0 with that ID; `index` > 0 with `key` = reply ID returns further chunks. A lookup of an unknown name, or on a server without a log, is `NotFound`.
- Any other kind and action combination: `Malformed`.

Each one-time prekey is served once. Manifests and publications are stored in the clear (`01-threat-model.md` §4 note 1).

## 3. Key transparency (`enclave-kt`)

### 3.1 Tree and configuration

- `KtLog` wraps Meta's **akd** 0.13 (NCC-audited 2023) with an in-memory store and a VRF key held in memory. Each `publish` call is one epoch. `heartbeat` starts an epoch with no username change (label `0x00 ‖ "heartbeat"`, which no valid username can equal) so heads stay fresh.
- `KtService` runs the log on its own thread with its own tokio runtime (akd spawns tasks), so the synchronous request handler can call it from any context. After every epoch it asks each attached witness to cosign (§3.3). A lookup against a head older than 1 h first starts a heartbeat epoch.
- `EnclaveKtConfig` replaces every akd hash with domain-separated SHAKE256-256:

```
H(x)                     = SHAKE256("enclave/v1/kt/akd" ‖ x, 32)
i2osp(x)                 = u64(len(x)) ‖ x
empty root / empty node  = 0^32
leaf commitment(v, n)    = H(i2osp(v) ‖ i2osp(n))
leaf with epoch          = H(commitment ‖ u64(epoch))
commitment nonce         = H(commitment_key ‖ u32(label_len) ‖ label_val)
fresh value              = H(i2osp(v) ‖ i2osp(nonce))
label hash input         = H(i2osp(label) ‖ u8(freshness) ‖ u64(version))
parent                   = H(left_value ‖ left_label ‖ right_value ‖ right_label)
root hash                = root value
stale value              = akd EMPTY_DIGEST
empty label              = { value: 0x01 ‖ 0^31, length: 0 }
```

- Label privacy uses akd's classical ECVRF (Ed25519); it only hides usernames from enumeration. Binding is hash-based and post-quantum.
- The leaf value is `root_pk (64) ‖ ContactCard` (`03-identity.md`). A bare `root_pk` is a released name. `KtLog::publish` performs no authorization; the server's `Username` put does (§3.7).

### 3.2 Signed tree heads

```
head       = server (16) ‖ u64(epoch) ‖ root (32) ‖ u64(time)                          # 64 B
server sig = CompositeSign(server_sk, ctx = "enclave/v1/kt/head", head)
cosign msg = head (64) ‖ u64(witness_time)
cosig      = CompositeSign(witness_sk, ctx = "enclave/v1/kt/cosign", cosign msg)
gossip     = SHAKE256("enclave/v1/kt/gossip" ‖ head, 32)                                 # 32 B digest
```

A `Cosignature` is `(witness id (16), witness time, signature)`.

### 3.3 Witnesses

`Witness::cosign(server_key, heads, proof, now)` cosigns the newest of a run of heads:

1. every head's server signature verifies, all heads name the same server, and their epochs are consecutive;
2. if the witness has cosigned this server before, the first head's epoch is the last cosigned epoch + 1, and the akd append-only proof from the last cosigned root through every new root verifies (`NotAppendOnly` otherwise);
3. the first time a witness sees a server, it cosigns without a proof (trust on first use);
4. it signs `newest head ‖ u64(now)` and remembers the newest head.

A witness never cosigns two inconsistent heads for one server, because step 2 requires consecutive epochs and a valid append-only proof from its last head.

### 3.4 Client policy and lookups

`WitnessPolicy { witnesses: [(id, key, operator)], threshold }`. `check(signed_head, server_key, server_operator, now)`:

1. the server signature verifies (`Signature`);
2. each cosignature counts once per witness ID, only if the witness is pinned, only if its operator differs from `server_operator` (operator independence), and only if it verifies;
3. at least `threshold` and at least one cosignature count (`Quorum`);
4. **trusted time** is the median of the counted witness times (`times[len / 2]` after sorting, the upper median for an even count);
5. the head is stale (`Stale`) if `now > head.time + 24 h + 1 h` or `trusted + 24 h < head.time`.

`verify_lookup(policy, server_key, server_operator, vrf_public, signed_head, name, proof, now)` runs `check`, normalizes the name (§3.5), verifies the akd lookup proof against the head's root and epoch, and returns `(value, version, trusted time)`.

PLAN's quorum values (≥3 independent witnesses, ≥2 during beta) are policy inputs; the code takes `threshold` as a parameter.

### 3.5 Usernames

`username::normalize(name)`:

- trim whitespace and lowercase ASCII;
- 3 to 32 bytes;
- only `a`–`z`, `0`–`9` and `_`;
- the first character is a letter;
- its skeleton must not equal the skeleton of a reserved name: `admin`, `enclave`, `support`, `security`, `root`, `help`, `official`, `system`.

`username::skeleton(name)` maps look-alikes to one form: first replace `rn` → `m`, `vv` → `w`, `cl` → `d`, and remove `_`; then map characters `0` → `o`; `1`, `i`, `j` → `l`; `3` → `e`; `4` → `a`; `5` → `s`; `6`, `8` → `b`; `7` → `t`; `9` → `g`; `u`, `y` → `v`. `KtLog::publish` refuses a new name whose skeleton equals that of a different registered name (RT-26).

A name held by a root that has a stored migration (§2.2) moves to the new root when the new root claims it; the old root no longer holds any name.

The username format is `@name@domain`. Unicode names (NFKC and UTS #39 skeletons), operator tombstones and account-deletion tombstones are not implemented.

### 3.6 Not implemented yet

The device-clock warning based on trusted time; C2SP cosignature interoperability; witness descriptors and remote witnesses (the dev server runs three in-process witnesses); a persistent KT store; non-existence proofs for "nobody has this name" (a server can falsely claim a name is unused, but cannot bind it to the wrong key).

### 3.7 Claims and lookups

**Pins.** A client pins `KtPolicy { servers: [KtInfo], witnesses: WitnessPolicy }`, shipped with the app's server list; nothing about a log is learned from the log at lookup time. `KtInfo` is `server (16) ‖ domain ‖ operator ‖ head key ‖ VRF public key` (each variable field `u32 length ‖ bytes`).

**Claim** (`Username`/`Put`, `key` = `name_key(name)`, `proof` = Equi-X over `"claim-username" ‖ key ‖ u64(day)` at `effort_username`, default 64):

```
UsernameClaim = u32 len ‖ name ‖ u32 len ‖ value ‖ u32 len ‖ signature ‖ device (16) ‖ u64(time)
value         = root_pk (64) ‖ ContactCard
signature     = CompositeSign(device_sk, ctx = "enclave/v1/kt/claim",
                  server (16) ‖ u32(len) ‖ name ‖ u32(len) ‖ value ‖ u64(time))
```

The server checks, in order: the PoW (`Pow`); the claim decodes (`Malformed`); the name is valid, already normalized and equal to the key's name, and `time` is within 1 h of the server clock (`Invalid`); the server holds a manifest for the value's root (`NotFound`); a device in that manifest with the claim's device ID verifies the signature (`Invalid`); the name is unowned or owned by the same root (`Denied`) and `time` is later than the owner's last accepted claim (`Invalid`, stops replays). One name per account: if the root owns a different name, that name is republished as the bare root (released, but still reserved for this root). Then the name is published; a confusable skeleton of another root's name is `Denied`.

**Lookup reply** = `u32 len ‖ SignedHead ‖ u32 len ‖ akd LookupProof (akd's protobuf encoding)`, with `SignedHead = head (64) ‖ u32 len ‖ server sig ‖ u8 n ‖ n × (witness (16) ‖ u64(time) ‖ u32 len ‖ sig)`.

**Self-audit** (`Client::audit_username`, run from `sync` once every 24 h): a client that has a username looks itself up exactly as anyone else would. If the verified answer names another account or server, says the name is free, or fails verification, the client raises `Event::UsernameProblem` and the app shows a persistent notice. Network errors retry at the next sync. The operator can't target a lie at one person without the witnesses signing it for everyone, and the owner is one of those everyones.

**Client** (`Client::find_username`): parse `@name@domain` (a bare name means the home server), pick the pinned log by domain (`Unavailable`), normalize (`NotAllowed`), fetch, then `verify_lookup` with the pinned head key, operator, VRF key and witness policy. Any decoding or verification failure is `Unverified`, never "not found", and the UI refuses to add anyone. A bare root is `NotFound`. The card's root must equal the value's root and its server the log's server (`Unverified`). The result is only a contact card: the usual message request and security-code check follow.


### 3.8 Gossip (RT-04, `client/gossip.rs`)

A server whose witnesses collude can show different people different logs, each properly signed and cosigned. Contacts compare notes:

- Every head a client verifies (lookups, claims, the daily self-audit) is kept (the newest 64).
- Every direct message carries, when the content leaves room, up to three `(server (16) ‖ u64 epoch ‖ gossip digest (32))` items for the newest heads held. The payload becomes `0xFE ‖ u32 len ‖ content ‖ u8 n ‖ items` (content kinds are small numbers, so a bare content never starts with `0xFE`); this uses space the envelope pads anyway and never costs a unit.
- A received item for an epoch the receiver also holds, with a different digest, means one of them saw a fork. The receiver sends its signed head (≈19 KB with cosignatures, so as a sealed blob with a `Content::KtHead` reference, kind 16) to that contact, once per contact and epoch. An item for an epoch not held yet is remembered and compared when that epoch is verified.
- A received head is checked against the pinned server key and the witness quorum (signatures only, not freshness). If it verifies and its root differs from the held head of the same epoch, the server has **provably equivocated**: both heads are stored as proof, `Event::KtSplitView { server, epoch }` is raised, and the receiver sends its own head back so the other side holds the proof too. A verified head for an epoch not held is kept like any other.
- The app shows a persistent notice ("A username server showed people different lists … check security codes, ideally in person").
- Test `rt04_split_view_detected_by_gossip`: twin logs under one server key and one set of (colluding) witnesses (`KtService::start_dev_twins`, server test hooks `enable_kt_fork`, `kt_fork_force`, `kt_serve_fork`); Ada sees the real binding of a name, Ben the forked one, each view verifies alone, and one message from Ada to Ben leaves both holding the proof. Honest views raise nothing.
- Limits: gossip only compares heads of logs the client pins, the fork is found only if two people who talk saw different heads for the same epoch, and group messages carry no gossip yet. Publishing proofs to the witnesses or a public place is not built.
## 4. Discovery and migration (not yet implemented)

- **Server list.** The foundation publishes a signed list of vetted servers, relays, witnesses and push relays, shipped in the app and updated through TUF, with an SLH-DSA signature under ctx `enclave/v1/update/server-list`.
- **Server descriptors** at `https://<domain>/.well-known/enclave`, self-signed (`enclave/v1/net/server-descriptor`), pinned on first use and logged in KT: the server composite key, `server_id`, operator family, Nym address, current and next daily request keys, PoW efforts, quotas, and the KT head-signing key. Today a client learns a server's request key from the dev transport.
- **Moving an account:** a root-signed `Moved` record (ctx `enclave/v1/proto/moved`).

## 5. Relays (not yet implemented)

`enclave-relay`: GotaTun WireGuard endpoints, the relay-ticket service, a Rosenpass daemon for relay↔relay links, and the SFU for group calls; relay descriptors declare the operator family (`enclave/v1/calls/relay-descriptor`). `enclave-push-relay` is in `10-push.md`. `enclave-witness` will package §3.3 as a service.

## 6. Deployment

- The dev binary (`enclave-server`, `main.rs`) listens on TCP (default `127.0.0.1:7443`) and is **not for production**; production servers are reachable only through Nym.
- Planned: Docker and Nix with reproducible builds; redb storage (Postgres for large operators, M11); KT database backups; local aggregate metrics only.

## 7. Scale estimate (100k accounts)

Assumptions: 1.5 devices per account (150,000 devices), 5% of devices in Foreground or Maximum at any moment (7,500), the rest in Background (142,500); PLAN's model of one 16,384 B reply unit per tick.

| Quantity | Computation | Result |
|---|---|---|
| Reply egress, Foreground | 7,500 × 16,384 B × 8 / 3 s | 327.7 Mbit/s |
| Reply egress, Background | 142,500 × 16,384 B × 8 / 120 s | 155.6 Mbit/s |
| Total reply egress (Enclave layer) | | ≈483 Mbit/s (PLAN: 400 to 500) |
| Sealed requests per second | 7,500 × 2 / 3 + 142,500 × 2 / 120 | ≈7,375 /s |
| Decapsulation cost | ≈0.3 ms per request (X448 + ML-KEM-1024 decaps + EnclaveCombine + one open) | ≈2.2 cores (PLAN: 2 to 3) |

As implemented, every request (including writes and cover) gets a reply unit, which doubles reply egress (`math/cover-traffic.md` §2.1). A server that holds two daily keys may try both on a request, so the decapsulation cost is up to twice as high around rotation.

## 8. Errors

| Condition | Server reply |
|---|---|
| Wrong size, unsupported version or suite, no key opens it, bad header | 16,384 random bytes |
| Token not registered or already used; wrong credential; wrong inbox type; inbox exists | `Denied` |
| Inbox, object, chunk or claim missing | `NotFound` |
| Inbox or token quota exceeded | `Quota` |
| Malformed payload or chunking | `Malformed` |
| Proof of work invalid | `Pow` |
| Directory object fails validation | `Invalid` |

## Open questions

1. **Proofs of work are not single-use.** The server keeps no replay set of solutions. A bundle-claim proof is bound only to the device key and the day, so one solution can claim every one-time prekey of a device for a whole day (RT-06). A request-inbox proof is bound to the envelope hash, so one solution lets the same envelope be written repeatedly, which can push every legitimate pending request out of the 100-entry FIFO. PLAN §9.3 and §12.1 need a per-solution replay set, or a claim context that includes a per-claim nonce.
2. **Directory uploads are unauthenticated until complete.** Anyone can send chunks for any `(kind, key)`: a chunk with a different `total` discards an upload in progress, and partial uploads are kept in memory without expiry.
3. **Bundle publication is authorized by device ID alone.** The server accepts a publication signed by the key of any stored manifest that lists the device ID. A second account whose manifest reuses another account's device ID could replace that device's publication; initiators then reject the bundle (they verify it against the right manifest), so the effect is denial of first contact. Binding the bundle key to the root (as for manifests) would close this.
4. **Inbox creation has no cost.** PLAN §9.3 and the M0 draft require an Equi-X proof for a new inbox address; `RegisterTokens` with `CREATE` needs none.
5. PLAN §12.1 says "hourly epochs" and §12.2 "10-minute to 1-hour epochs". The implementation makes one epoch per publish; a batching interval is open.
6. PLAN §12.2 describes witness cosignatures as C2SP format "with an added ML-DSA-87 cosignature". The implementation uses a composite cosignature over the 64 B head and the witness time, not the C2SP text format.
7. Whether the KT value should carry the vault-key locator, given that the KT operator is usually the same server as the directory and could then link vault-key fetches to usernames.
8. The KT skeleton map (§3.5) is ASCII-only and small; for example `vv` is replaced before `u` → `v`, so `uu` and `w` do not collide. A reviewed confusables table is needed before Unicode names.
