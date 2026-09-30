# Identity, Devices, and Recovery

Status: Draft (M0) · Normative

Source: PLAN.md §3 (D3, D4, D12). Crate: `enclave-proto` (manifest, linking), `enclave-core` (flows), `enclave-store` (root wrap). Derivations: `02b-key-schedule.md` §2 to §5, §11.

## 1. Account creation

1. The client generates the recovery secret `rs = HedgedRng.fill("recovery", 32)` and derives the root key pair (`02b-key-schedule.md` §2.1).
2. It generates the device keys (§3.2), the account IK, the vault key and `vbs`, the inbox seed, the request-inbox address, and the first prekey batch.
3. While the user types a display name, it solves an Equi-X proof-of-work for account creation (target 20 to 30 s on a median phone, `02-cryptography.md` §10) against the chosen server's daily seed. The UI shows one line: "Setting up your private address…". The PoW is presented with the first directory publish.
4. The server is chosen automatically, weighted by capacity from the foundation's signed server list (`12-servers.md` §4). The user can change it.
5. The client builds manifest version 1 (§3), root-signs it, and publishes the manifest, the account bundle object (`04-eqxdh.md` §2), the vault-key blob, and the OPK batch to the directory. It registers the inbox (first week's address, read-credential hashes for the next 14 days) and the request inbox.
6. The recovery words are not shown yet. They are shown as a persistent card after the first conversation or after 24 hours, whichever comes first (`17-design.md` §6.1). The words MUST be saved (the 3-word check passed) before the user can link a device or claim a username.

Account creation MUST NOT require a phone number, email, or any other identifier.

## 2. Recovery secret and root key

- `rs` is 256 bits, shown as 24 English BIP-39 words with the BIP-39 checksum (`recovery::RecoverySecret`). Import ignores case and extra whitespace and MUST reject a failed checksum with "These words don't match. Check each word and try again." Other BIP-39 languages are not implemented.
- The root is derived as `SLH-DSA.KeyGen(KMAC256(rs, "", 768, "enclave/v1/root/keygen"))` (`02b-key-schedule.md` §2.1). `AccountKeys::create` derives it, generates the X448 identity key, and generates the McEliece vault key (a few seconds; run in the background).
- **Not implemented yet:** storing `rs` wrapped on the primary device under `k_root = KMAC256(hw_root_secret, Argon2id(PIN), 256, "enclave/v1/store/root-wrap")` (`14-storage.md` §1.3), where both the hardware key and the PIN are needed and biometrics MUST NOT unlock root operations.
- Root operations unwrap `rs`, derive the root secret key, sign, and zeroize both within one call in the vault process. Linked devices without the "may add devices" role hold no root key (`AccountKeys.root` is `None`).

## 3. Account manifest

The manifest (`manifest.rs`) is the only object the root signs day to day (D3). It is hash-chained, versioned, and valid for at most 13 months (395 days, `MAX_VALIDITY_SECS`).

### 3.1 Contents

- version (starting at 1) and the SHA3-512 hash of the previous signed manifest (zero for version 1);
- issue and expiry times;
- the root public key;
- the account X448 identity key (the only X448 identity key; `00-overview.md` §9, I-8);
- `vault_hash = SHA3-512(vault_pk)`;
- the request-inbox locator (opaque bytes, at most 256 B);
- the bundle epoch (1 in the genesis manifest);
- 1 to 5 device entries (1 primary plus up to 4 linked), each with: device ID, role, time added, capability bits, composite signing public key, and ML-KEM-1024 auth key.

The account inbox address, its owner secret and read credential are **never** in the manifest or in KT. Contacts receive the inbox address and tokens inside the encrypted session.

### 3.2 Encoding (manifest format 1)

The canonical encoding (`Manifest::encode`) is variable-length; all integers are big-endian:

| Field | Length |
|---|---|
| format | `u16` = 1 |
| `version` | `u64` |
| `prev_hash` | 64 |
| `issued_at` | `u64` |
| `expires_at` | `u64` |
| root public key | 64 |
| account X448 identity key | 56 |
| `vault_hash` | 64 |
| request-inbox locator | `u32` length ‖ bytes (≤ 256) |
| `bundle_epoch` | `u64` |
| device count `n` | `u8` (1 to 5) |
| `n` device entries | 4,250 each |

Device entry (4,250 B): device ID 16 ‖ role `u8` (1 primary, 2 linked, 3 linked and may add devices) ‖ `added_at` `u64` ‖ capability bits `u64` ‖ composite public key 2,649 ‖ ML-KEM-1024 auth key 1,568. 16 + 1 + 8 + 8 + 2,649 + 1,568 = 4,250.

The body is 287 + `L` + 4,250·`n` bytes for an `L`-byte locator (`math/envelope-budget.md` §8.2).

The signed form (`SignedManifest`) is

```
signed = u32(len(body)) ‖ body ‖ SLH-DSA-SHAKE-256s signature (29,792 B)
signature = RootSign(root_sk, ctx = "enclave/v1/ctx/manifest", body)
hash(signed) = SHA3-512(signed)                     # the next manifest's prev_hash
```

34,365 B for one device and a 32 B locator; 51,365 B for five devices (PLAN: "about 52 KB").

### 3.3 Manifest update cosignatures

Every manifest update the primary makes (linking, removing a device) is co-signed by the primary's device key, which the previous manifest lists; an update without such a co-signature is held for 72 h (§8.1). Implemented as `enclave_proto::attest` (§8.1, "Implementation").

### 3.4 Validation

`Manifest::decode` rejects, in addition to malformed encodings and trailing bytes: format ≠ 1; version 0; `expires_at ≤ issued_at`; a validity longer than 395 days (`Expired`); zero or more than 5 devices (`Limit`); duplicate device IDs; anything other than exactly one primary device; a locator over 256 B; an unknown role; an invalid Ed448 point in a composite key.

`SignedManifest::verify(expected_root, now)`:

1. decode the body (above);
2. the manifest's root equals `expected_root`, the root the caller already trusts (from a QR code, an invite link, or a KT lookup) (`BadSignature`);
3. the SLH-DSA signature verifies with ctx `enclave/v1/ctx/manifest` (`BadSignature`);
4. `now + 48 h ≥ issued_at` and `now ≤ expires_at + 48 h` (`SKEW_SECS`; `Expired`).

`SignedManifest::verify_successor(previous, expected_root, now)` additionally requires `version > previous.version` and, when `version = previous.version + 1`, `prev_hash = hash(previous)` (`Rollback`). A jump of more than one version is accepted without checking the intermediate chain.

`now` is trusted time where available (the median witness time, `12-servers.md` §3.4). ML-KEM auth keys are validated when used, not at decode.

## 4. Device linking (RT-09)

### 4.1 Link QR code

The new device shows a link QR code. Its URI uses a distinct scheme, `enclave-link:`, followed by base32 (RFC 4648, no padding) of:

| Field | Length |
|---|---|
| version 0x01 | 1 |
| ephemeral X448 public key | 56 |
| ephemeral ML-KEM-1024 ek | 1,568 |
| `link_secret` | 16 |
| rendezvous server ID | 32 |
| rendezvous mailbox address | 32 |

1,705 B in total (QR version 32 or larger at error-correction level L; the new device's screen shows it large).

### 4.2 Where it can be scanned

- The link QR MUST be accepted only by the scanner opened from **Settings → Your devices → Link a new device** on a device whose role is primary or "may add devices".
- The general scanner, the contact-add scanner, deep links, and pasted text MUST refuse `enclave-link:` URIs and show: "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one." (`17-design.md` §6.6).
- Contact QR codes (`enclave:` scheme, §9.1) MUST be refused by the link scanner with an explanation.

### 4.3 Link protocol

The rendezvous mailbox accepts writes and reads authorized by `link_cap` (`02b-key-schedule.md` §11). It expires after 30 minutes.

1. **P (primary) scans** the QR. P generates an ephemeral X448 key and encapsulates ML-KEM to the QR's ek. It computes `ss_link` with Combine2 using `psk = link_psk`, `psk_flag = 0x03`, and derives `k_p2n`, `k_n2p`.
2. **P → N:** P's ephemeral X448 public key, the ML-KEM ciphertext, and `Seal(k_p2n, E("enclave/v1/wire/ad-link") ‖ u8(1), {root_pk, P.device_id})`.
3. **Phrase check.** Both devices compute the 3-word phrase (`02b-key-schedule.md` §11). N shows the phrase. P shows 4 phrases (the real one plus 3 random decoys, in random order) and asks "Which words does your new device show?". A wrong pick aborts the link, deletes all link state, and shows "The words didn't match, so nothing was linked." After 1 wrong pick the QR is void; N must show a new one.
4. **N → P:** N's device ID, composite public key, auth ek, capabilities, and a user-visible device name (from the OS model name, editable), sealed with `k_n2p`.
5. **P asks for the PIN**, builds the next manifest with N as role 2, root-signs it, cosigns it with P's composite key (§8.1), and publishes it.
6. **P → N** (bulk mode, sealed with `k_p2n` in chunks): the vault key pair and `vbs`, the IK, the inbox seed, the request-inbox address, contacts (root pins, manifests cache, security-code states, bond PSKs), group states, notification key chains, and settings. It does **not** send ratchet state; N establishes its own pairwise sessions.
7. Every existing device of the account and N establish intra-account pairwise sessions (EQXDH between own devices, `06-multidevice.md` §5).
8. **History transfer** begins 24 hours after step 5, unless both devices confirm "Transfer now" sooner. History moves over the LAN when both devices are on it (mDNS discovery, a TCP connection carrying EnclaveSeal chunks under a key derived from the intra-account session), and otherwise as bulk blobs.

### 4.4 After linking

- Every device of the account shows a persistent in-app banner for 7 days: "New device linked: *Pixel 9*, 30 Sep 14:02. Not you? Remove it". "Remove it" starts revocation (§5.1) and requires the PIN on the primary.
- A linked device that has not sent any intra-account sync message for 30 days is treated as inactive: the account's other devices stop wrapping keys for it immediately, and the primary publishes a manifest without it the next time the root is unlocked. The UI asks for the PIN at the next app open when such a removal is pending.
- The device cap is 5 (1 primary plus 4 linked). Linking a sixth device MUST be refused with "You can link up to 4 devices. Remove one first."

### 4.x Implementation status (M5 follow-up)

`crates/enclave-core/src/client/link.rs`, test `link_a_second_device`. Where this differs from §4.1–4.3 above, the code is normative:

- **Code.** `enclave:link#` + base64url of `version ‖ server 16 ‖ mailbox 32 ‖ owner 32 ‖ X448 56 ‖ link_secret 32 ‖ commit 32` (201 B), not base32 with the ML-KEM key inline. The new device writes its ML-KEM ek and device keys (composite signing key, ML-KEM auth key) to the rendezvous mailbox first; `commit` is the first 32 bytes of SHA3-512 of that record, so the QR code stays small and the primary can check it read the right record. The general scanner refuses the code (`ContactCard::from_link` → `DeviceLinkCode`).
- **Key.** `EnclaveCombine(TwoKem, [X448, ML-KEM-1024], [X_new, ek, X_primary, ct, transcript], psk = link_secret)` with transcript `"enclave/v1/proto/link-transcript" ‖ commit ‖ mailbox`. Both screens derive three BIP-39 words (`link-phrase`); the primary shows four choices and links only on the right one.
- **Handover.** The primary signs and publishes manifest `version + 1` (with `prev_hash`), then uploads the account as a sealed blob: profile, shared account keys, the signed manifest, and every accepted contact's card, name, checked state, timer, inbox and **half of its write tokens** (tokens are single use, so each device needs its own). The blob reference travels sealed under `link-keys`.
- **After linking.** The new device publishes its prekeys and opens sessions with every contact's devices (contacts accept them silently: the device is in the root-signed manifest) and with the account's other devices. Every message sent from one device is copied to the others (`Content::SelfCopy`) through the shared account inbox.
- **History transfer** (`client/history.rs`): not part of the link. The device holding the root sends history to a linked device 24 h after it was added (checked on every `sync`), or at once when the person taps "Send history now" on that device. History is one sealed file in our server's blob store (`files::seal_file`, bucket-padded chunks) whose reference goes to our devices as `Content::History` (kind 14). It holds every 1:1 conversation's messages except disappearing and deleted ones: `u8(1) ‖ u32(n) ‖ n × (root (64) ‖ u32(m) ‖ m × bytes(message record))`. A receiver merges it into conversations with contacts it knows, skipping message ids it already has, and renumbers each conversation by time. Sending is recorded per device, so it happens once; a repeat adds nothing. Group history is not sent.
- **Not implemented:** the "both devices confirm" shortcut (only the root device can skip the delay), the 7-day "new device" banner, automatic removal of inactive devices, group membership for the new device, and contacts without a card (from before cards were exchanged) are not handed over.

## 5. Revocation and "Secure my account"

### 5.1 Revocation

Revocation publishes a new manifest without the device (PIN required on the primary). Contacts learn of it through a ratchet control message and the manifest refresh. Other devices delete their pairwise sessions with the revoked device. If the revoked device was possibly compromised, the UI offers "Secure my account" next.

**Implementation (`client/devices.rs`).** `Client::remove_device(id)` runs only on the device holding the root and never on itself:

1. sign and publish manifest version `v + 1` without the device (`publish_manifest`);
2. send `Content::Devices(v + 1)` (kind 13, `u64` version) to our other devices, the removed one included so it can tell its user, then drop our sessions with the removed device;
3. send the same notice to every accepted contact.

A receiver records `(root, version)` and, at the end of the same `sync`, fetches the account's manifest from its server, verifies the root signature, ignores it if its version is lower than announced or not newer than the one held, then adopts it and deletes its sessions with devices it no longer lists. A device that finds itself missing from its own account's manifest reports `Event::RemovedFromAccount`. The removed device is then shut out both ways: nothing new is encrypted to it, and its new initial messages name an old manifest version, which fails the rollback check. Not yet done: the PIN gate, and rotating the inbox and vault key (so the removed device can still see that envelopes arrive and could delete them) — those belong to §5.2.

### 5.2 "Secure my account"

A single action, PIN-gated, that:

1. rotates the vault key (new `vault_pk`, `vbs`, and blob), the account IK, the inbox seed (new addresses, new read credentials), and all signed prekeys, and publishes a new manifest;
2. re-issues write tokens to every contact (new token generation `g`, so all outstanding tokens die when the old address expires);
3. forces a PQ ratchet step with every contact by sending a control message that carries a fresh ek (`05-ratchet.md` §12);
4. rekeys every group (new sender chain and MAC keys; if the user is an admin and a device was removed, a new group epoch);
5. rotates the notification key chains and the request-inbox address.

The security code does not change (D4). Contacts see no warning.

## 6. Security code (D4)

### 6.1 Computation

For each side, `fp = SHAKE256^5200(root_pk)` as specified in `02b-key-schedule.md` §4.1, giving 64 B, 30 digits, and 5 words.

### 6.2 Display

- Order: the two fingerprints are sorted lexicographically by their 64 B values; call them `fp_lo` and `fp_hi`. Both phones show the same order.
- Digits: `digits(fp_lo) ‖ digits(fp_hi)`, 60 digits in 12 groups of 5, in Atkinson Hyperlegible Mono (`17-design.md`).
- Words: `words(fp_lo) ‖ words(fp_hi)`, 10 BIP-39 words in the user's language (110 bits).
- QR: the contact QR (§9.1) carries the full `root_pk`, from which the scanner computes the full 64 B digest.
- Screen readers read one group of 5 digits at a time.

### 6.3 Changes

The code covers root keys only and changes only after a root migration (§8.2). Yearly key rotation, relinking, and "Secure my account" never change it. A changed code produces the in-conversation card of `17-design.md` §6.4.

### 6.4 States

Each contact has a verification state: `unchecked` (default), `checked_remote` (the user tapped "They match"), `checked_in_person` (mutual scan, §7), `changed` (root migrated since last check). The first send after a change to `changed` needs a tap-through. If "Only send to checked contacts" is on, sending to `unchecked` or `changed` contacts is blocked.

## 7. In-person PSK (D12)

### 7.1 Mutual scan

Both users open "Scan a code" and point their phones at each other. Each contact QR shown for scanning carries a fresh 32 B secret `s` (regenerated every time the QR is shown). After both scans, each phone has both payloads `Q_A`, `Q_B` and both secrets. Both compute `psk_bond` (`02b-key-schedule.md` §4.2).

- If the two are not yet contacts, the side with the lexicographically lower `root_hash` initiates EQXDH with `psk = psk_bond`, `psk_flag = 0x01`. If both initiate, the session initiated by the lower `root_hash` is kept.
- If they are contacts, both re-root existing sessions (§7.4).
- The contact becomes `checked_in_person`, which also verifies the security code.

### 7.2 Seal check

Both screens show three Seal words from `psk_bond` (`02b-key-schedule.md` §4.2) and the Seal animation (`17-design.md` §6.2). The copy asks the users to confirm the words match. A mismatch means one phone scanned a different code; the flow shows "The words don't match. Scan again." and discards `psk_bond`.

### 7.3 One-way fallback

Invite QR codes and invite links carry a 256-bit `invite_secret` in the fragment. It becomes a one-way PSK (`psk_flag = 0x02`). It is weaker than the bond PSK because the link may have been copied.

### 7.4 Meeting again

A new mutual scan with an existing contact produces a new `psk_bond`. Each device pair session mixes it into its root key at the next DH ratchet step after both sides have processed the "re-root" control message: `RK = KMAC256(RK, psk_bond_new, 256, "enclave/v1/proto/bond-reroot")`. This heals the session through a physical channel even if every KEM has been broken.

### 7.4a Implementation (`client/meet.rs`)

- The code is `enclave:meet#` + base64url(`u8(1) ‖ bytes(ContactCard) ‖ s (32)`), made fresh each time the Meet sheet opens; the secret lives in memory only and is dropped when the sheet closes. The general "Add" field and invite parser refuse it.
- After scanning, both phones compute `psk_bond = eqxdh::bond_psk(s_A, s_B, Q_A, Q_B)` (ordered by payload) and show `seal_words(psk_bond)`. Nothing is stored until the person taps **They match**; then the bond is kept per contact root and the contact is marked checked.
- **Re-rooting differs from §7.4**: instead of mixing the PSK into the running ratchet, the side with the lower root key drops its sessions with the other account and starts new EQXDH sessions with `psk = psk_bond` to each of their devices (a greeting with fresh tokens), which the other side takes in place of the old ones. Strangers who meet become contacts this way; the receiving side accepts a bonded greeting without a message request.
- A greeting with the PSK flag is tried against each stored bond (the responder can't know the sender before opening it). A failed try burns nothing: one-time prekeys are removed only after a handshake succeeds.
- The header shows "Met in person" for bonded contacts. Not done: the invite-link one-way PSK (§7.3), the Seal animation and haptics, and camera scanning on desktop (the code is pasted).

### 7.5 Formal model and copy

A Tamarin lemma covers the case "all KEMs broken, the optical exchange not recorded" (`20-assurance.md` §2). Product copy MUST NOT claim this makes messages "unbreakable" or similar.

## 8. Recovery, migration, deletion

### 8.1 Pending root actions (RT-22)

A device decision is a composite signature by a device listed in the current manifest:

```
device_decision = CompositeSign(device_sk, "enclave/v1/proto/veto", u8(decision) ‖ manifest_hash)
decision        = 0x01 approve | 0x02 veto
```

A manifest update is **cosigned** if its update envelope (§3.3) carries a valid `device_decision` with `decision = 0x01` from a device listed in the previous manifest with an unexpired key.

Rules:

- A cosigned update takes effect immediately.
- An update without a valid cosignature (for example, recovery on a new phone after losing every device) is published as a **pending** record: `Pending = {manifest_hash, not_before = trusted_now + 72 h}`, root-signed with ctx `enclave/v1/proto/pending-root`, and posted to the directory and to KT.
- Any device in the current manifest MAY veto the pending update with a `device_decision` with `decision = 0x02`, posted to the directory and KT. A vetoed pending update is dead; the UI on the recovering device says "One of your other devices stopped this change."
- Contacts' clients MUST NOT accept a pending manifest before `not_before`, and MUST NOT accept it at all if a valid veto exists. Contacts' clients check for a veto when they fetch the manifest after `not_before`.
- Every device of the account shows a persistent alert while a pending action exists: "Someone is setting up your account on a new device. If this isn't you, tap Stop."
- After a successful recovery, contacts see "Sam set up a new device". The security code does not change.

**Implementation** (`enclave_proto::attest`, `client/guard.rs`; differs from the draft above where noted):

- An **attestation** is `u8(verdict) ‖ u64(version) ‖ manifest_hash (64) ‖ device (16) ‖ u32 len ‖ signature`, where `verdict` is 1 co-sign or 2 veto and the signature is `CompositeSign(device_sk, ctx, root_pk (64) ‖ u64(version) ‖ manifest_hash)` with ctx `enclave/v1/ctx/manifest-cosign` or `enclave/v1/ctx/manifest-veto`. It counts only if the device is listed in the manifest the judge currently holds for that account.
- Attestations live in the directory (`DirKind::Attest`, keyed like the manifest). The server keeps at most 16 per account and stores one only if its signature verifies against a device that some manifest of the account has listed, so strangers can't fill the slot. The primary uploads its co-signature **before** the manifest, so no contact ever sees the update unsigned.
- **The wait is counted from when each contact first saw the update**, not from a `not_before` in a root-signed record: whoever signs with the root chooses every time in the manifest, and there is no trusted (witnessed) time yet. The first sighting is stored per account (`version ‖ hash ‖ first_seen`).
- A contact that receives a greeting whose sender's manifest is held keeps the envelope and re-runs it every 10 minutes and when the wait ends; if the update is vetoed, the greeting is dropped. The `refresh` after a `Devices` notice applies the same rule.
- Our own devices fetch our manifest every 10 minutes. A newer version that no listed device co-signed raises `Event::RecoveryPending { until }` and a persistent card ("Someone is setting up your account on another device… Stop it / It's me"). **Stop it** signs a veto, publishes it, and also sends it as `Content::Veto` (kind 15) to every contact and our devices, so a server that withholds it doesn't win. **It's me** signs a co-signature, and contacts accept the update on their next look.
- Not implemented: posting pending records and vetoes to KT, the recovering device's own "One of your other devices stopped this change" notice, and refusing to send from a device whose update is still held (its messages are lost until contacts accept it).

### 8.2 Migration (recovery words compromised)

1. The user creates a new recovery secret and new root on a current device.
2. The new root signs `Migration{old_root_pk, new_root_pk, new_manifest_hash, time}` with ctx `enclave/v1/proto/migration`. If the old root is still available (the old words are known), the old root cross-signs the same payload with the same ctx.
3. The migration is delivered to every contact inside existing sessions and published to KT.
4. Contacts with a valid cross-signature see: "Sam reset their account. Check the security code again." Their state becomes `changed`.
5. Without the old root's cross-signature, the UI says: "Sam's account was replaced. Enclave can't tell whether Sam did this or someone else did. Check the security code in person before sharing anything private."
6. Migration always changes the security code.

### 8.3 Social recovery (M9, optional)

- `rs` is split with SLIP-0039 into 3-of-5 shares, each sent inside an existing session to a chosen contact.
- A holder releases a share only after an in-person mutual scan (§7.1) with the recovering person and an explicit confirmation ("Sam asked for your recovery share. Only continue if you're with Sam right now.").
- The reconstructed `rs` leads to a pending root action (§8.1): 72 h wait, all devices notified, veto possible.

### 8.4 Lost words and all devices, no social recovery

The account cannot be recovered. The user creates a new identity. Onboarding says so plainly: "If you lose your recovery words and all your devices, you'll need to start a new account."

### 8.5 Account deletion (App Store rule 5.1.1(v))

Deletion, PIN-gated, performs in order:

1. sends a "closed" control message to every contact and group;
2. writes a KT tombstone: `Tombstone{root_hash, time}` root-signed with ctx `enclave/v1/proto/tombstone`;
3. deletes the inbox, request inbox, directory objects, and every blob the account uploaded (each delete op authenticated by the corresponding credential);
4. crypto-shreds local data (`14-storage.md` §3) on every device (each device receives a deletion control message; devices offline for 30 days are covered by inbox deletion and manifest expiry).

## 9. Adding contacts

### 9.1 Contact QR ("Show my code")

URI scheme `enclave:` followed by `c/` and base32 of:

| Field | Length |
|---|---|
| version 0x01 | 1 |
| `root_pk` | 64 |
| home `server_id` | 32 |
| `manifest_version` hint | 8 |
| `vbs` (vault-key blob secret) | 32 |
| `invite_secret` | 32 |
| `s` (in-person secret, fresh per display) | 32 |

201 B. Scanning resolves the contact by fetching the manifest (by `root_hash` at `server_id`), bundles, and the vault-key blob in bulk mode while the UI shows "Adding Sam…".

### 9.2 Invite links

`https://<invite-host>/i#<base32 payload>`, where the payload is the §9.1 fields without `s`. The secret part is only in the URL fragment, which browsers do not send to servers. Invite links:

- are limited-use (default 1 use for contacts) and expire (default 7 days);
- can be revoked from Settings → Invite links, which deletes the `cap_hash` registration at the request inbox;
- deliver the first message to the recipient's request inbox, authorized by `invite_cap`, where it waits as a message request.

### 9.3 Usernames

- Format `@name@server`. One username per account. Registration needs an Equi-X PoW (≈30 s) and is checked for UTS #39 confusable-skeleton uniqueness per server (`12-servers.md` §3.3).
- KT maps the name to `{root_hash, manifest_hash, manifest_version, locator}` where the locator contains the request-inbox server and address and `vbs` (`12-servers.md` §3).
- Username contacts land in Message requests until accepted, like any stranger.
- The UI says: "A username is public, like an email address."

## 10. Errors

| Condition | Behavior | User-facing copy |
|---|---|---|
| Manifest signature invalid | Reject, keep cached | "Couldn't check Sam's account. We'll try again." |
| Manifest expired and no newer one | Stop sending new sessions; existing sessions continue for 7 days | "Sam's account needs to update. Messages may not arrive." |
| Pending root without veto after 72 h | Accept | "Sam set up a new device" |
| Pending root with veto | Reject | none to contacts |
| Link phrase mismatch | Abort link | "The words didn't match, so nothing was linked." |
| Sixth device | Refuse | "You can link up to 4 devices. Remove one first." |
| Link QR in general scanner | Refuse | §4.2 text |
| BIP-39 checksum failure | Refuse | "These words don't match. Check each word and try again." |

## Open questions

1. The invite-link host (`<invite-host>`) is not fixed by PLAN.md. It must be a static page that never sees the fragment and offers store links. Candidate: a foundation-run domain, decided at M6.
2. The rendezvous mailbox for linking is hosted on the new device's chosen default server. Whether the primary should instead choose it (so the new device's first network activity is not tied to a server choice) is open.
3. Whether the 30-day inactivity removal should be performed by any device with role 3 as well as the primary, to avoid a PIN prompt on the primary.
4. The manifest carries `expires` per device key (1 year). PLAN.md does not say whether an expired device key blocks that device from sending until relinking or whether the primary can extend it in place with a new manifest. This spec allows in-place extension by the primary.
