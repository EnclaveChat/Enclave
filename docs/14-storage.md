# Local Storage

Status: Draft (M0, reconciled with the M5 code) · Normative

Source: PLAN.md §13 (D11), RT-08, RT-21. Crates: `enclave-store`; later `enclave-platform` (keystore adapters). Derivations: `02b-key-schedule.md` §13. Where this document and the code disagree, the code is normative.

## 1. Keys

### 1.1 Device secret and keystore

Each profile has one random 32 B **device secret**, created with the store (`HedgedRng.fill("store/device-secret", 32)`) and kept in a platform keystore under the name `enclave-profile-secret`. The `Keystore` trait has three operations: `create(name, secret)`, `load(name)`, `destroy(name)`.

| Adapter | Status | Use |
|---|---|---|
| `MemoryKeystore` | Implemented | Tests |
| `FileKeystore` | Implemented | One file per secret; overwritten with zeros before removal. Development, and Linux desktops without a Secret Service on full-disk-encrypted machines only (flash wear levelling makes overwriting unreliable). |
| Secure Enclave + Keychain (Apple), StrongBox/Keystore (Android), CNG/TPM (Windows), Secret Service (Linux) | Not implemented (`enclave-platform`) | Production |

The intended platform sources of the device secret (PLAN §13) are: on Apple platforms a Keychain secret (`WhenUnlockedThisDeviceOnly`) additionally wrapped by a Secure Enclave P-256 key agreement, so the Secure Enclave is never the only wrap; on Android a StrongBox (or TEE Keystore) AES-256-GCM key that unwraps a stored secret; on Windows CNG with DPAPI and TPM-sealed keys where available; on Linux Secret Service, or a mandatory passphrase.

### 1.2 Master key

```
salt   = HedgedRng.fill("store/salt", 32)                                  # stored in the database
pw     = Argon2id(passphrase, salt, params)       # 32 B, only if the user set a passphrase (02-cryptography.md §9)
master = KMAC256(device_secret, frame(pw or ""), 256, "enclave/v1/store/master")
index  = KMAC256(master, "", 256, "enclave/v1/store/index")
```

This is PLAN §13's `KMAC256(hw_secret‖Argon2id(passphrase)?)` with the device secret as the KMAC key and the passphrase output framed.

The `meta` table holds `salt`, the Argon2id parameters (`u32(memory_kib) ‖ u32(iterations) ‖ u32(parallelism)`, or empty without a passphrase), and a **verifier** `seal(master, "verifier", "enclave")`. `Store::open` recomputes the master key and opens the verifier; a wrong passphrase, a missing passphrase where one is set (or the reverse), or a wrong device secret fails with `StoreError::Crypto`.

### 1.3 Root wrap (not yet implemented)

On the primary device the recovery secret is to be wrapped under `KMAC256(hw_root_secret, Argon2id(PIN), 256, "enclave/v1/store/root-wrap")`, where `hw_root_secret` is a separate hardware-wrapped secret that requires device unlock and that biometrics cannot unlock. The label is reserved.

## 2. Database

### 2.1 Engine and tables

One redb database per profile (a file, or in memory for tests) with two tables: `records` (bytes → bytes) and `meta` (string → bytes).

### 2.2 Blinded keys

Every record is addressed by a `(namespace, key)` pair. The stored key is a 40 B **blinded key**:

```
ns_tag(ns)       = KMAC256(index, ns, 256, "enclave/v1/store/namespace")[0..8]                 # 8 B
blind(ns, key)   = ns_tag(ns) ‖ KMAC256(index, frame(ns) ‖ frame(key), 256, "enclave/v1/store/blind")   # 8 + 32 B
```

The file reveals no namespace or key names. Because every blinded key starts with its namespace tag, `Store::scan(ns)` is one range query over `[ns_tag ‖ 0^32, ns_tag ‖ 0xff^32]`. An observer of the file can count records per (unnamed) namespace.

### 2.3 Sealed records

```
record_key = KMAC256(master, frame(salt) ‖ frame(blinded_key), 256, "enclave/v1/store/record")
plaintext  = u32(len(key)) ‖ key ‖ value            # the plain key is kept inside the seal so scans can return it
stored     = seal_chunked(record_key, blinded_key, plaintext)
```

**Chunked sealing** (`seal_chunked`, `open_chunked`) handles data of any size:

```
seal_chunked(K, AD, P):
    segments = P split into 60,000 B pieces (one empty segment if P is empty)
    for i, seg in segments:
        last  = u8(1) if seg is the final segment else u8(0)
        out  ‖= u32(len(s_i)) ‖ s_i   where s_i = seal(K, AD ‖ u64(i) ‖ last, seg)
open_chunked(K, AD, S):
    read segments in order; a segment is "last" exactly when it ends at the end of S;
    open each with AD ‖ u64(i) ‖ last; any failure is StoreError::Crypto
```

The segment index and the last flag are in each segment's AD, so reordering, dropping a final segment (the new final segment was sealed with `last = 0`), and appending all fail. The blinded key is the AD of every record, so records cannot be swapped.

### 2.4 Not implemented yet

Blinded full-text search tokens (labels `enclave/v1/store/search-key`, `enclave/v1/store/search-token` reserved); excluding the data directory from OS backups (`NSURLIsExcludedFromBackupKey`, `allowBackup="false"`); versioned migrations. As PLAN §13 says, there is no monotonic rollback counter on mobile; hedged nonces keep a rolled-back state from reusing a keystream (RT-08).

## 3. Crypto-shredding

Disappearing messages and deletions are sealed under **per-conversation, per-day shred keys** kept in a keyring (`shred::Shredder`).

- A shred key is 32 random bytes (`HedgedRng.fill("store/shred-key", 32)`), created on first use for a `(conversation, day)` pair.
- A message body is sealed with `seal(shred_key, conversation, body)`; `open_msg` fails with `NotFound` once its key is gone.
- The keyring plaintext is a sequence of entries `u32(len(conversation)) ‖ conversation ‖ u64(day) ‖ key (32)`.
- The keyring is sealed with `seal_chunked(wrap_key, "keyring", keyring)` and stored as the record `("__shred", "keyring")`, so it is also sealed under its record key. The current generation `g` is the record `("__shred", "generation")` (`u64`).
- `wrap_key` is a random 32 B secret (`HedgedRng.fill("store/shred-wrap", 32)`) held in the keystore under the name `enclave-shred-{g}`.

**Rewrap** runs whenever a shred key is created and on every shred event:

```
Rewrap():
    g' = g + 1
    wrap' = fresh random 32 B; keystore.create("enclave-shred-{g'}", wrap')
    store ("__shred", "keyring") = seal_chunked(wrap', "keyring", keyring)
    store ("__shred", "generation") = u64(g')
    keystore.destroy("enclave-shred-{g}")
    g = g'

Shred(conversation, before_day):
    remove every key of conversation with day < before_day
    if any was removed: Rewrap()
```

After a shred, any earlier copy of the keyring (for example in a disk image or in unreclaimed database pages) is sealed under a wrap key the keystore has destroyed. Deleted data is therefore unrecoverable from a forensic image taken **after** the shred, as long as the keystore really deleted the old key. With `FileKeystore` that depends on the file system.

Opening a store with no shred generation starts at generation 0 with an empty keyring and rewraps once (generation 1).

## 4. Backups

- `backup_key = KMAC256(rs, "", 256, "enclave/v1/backup/key")`, where `rs` is the 256-bit recovery secret (PLAN: `KMAC(recovery, "backup")`).
- `backup::export(store, namespaces, rs)` walks the requested namespaces, skips the excluded ones, and encodes every record as `u32(len(ns)) ‖ ns ‖ u32(len(key)) ‖ key ‖ u32(len(value)) ‖ value`. The concatenation is sealed with `seal_chunked(backup_key, "enclave-backup-v1", …)`. No compression.
- **Excluded namespaces** (`backup::EXCLUDED`): `sessions`, `sender-keys`, `__shred`, `prekeys`. Ratchet sessions, sender keys, the shred keyring and prekey secrets therefore never enter a backup, so a restored backup cannot cause key reuse.
- `backup::import(store, archive, rs)` opens the archive, skips any excluded namespace it finds, writes every other record into the store, and returns the count.
- **Restoring creates a new device that re-establishes sessions.** Restore needs the recovery words.

Not implemented yet: an archive header (magic, version, sequence number), server-stored backups with blob IDs (`enclave/v1/store/backup-blob-id` reserved), media selection, and the "Check my backup" restore test.

## 5. Device protections

`Store::crypto_erase` destroys the device secret in the keystore, which makes the database file unreadable. It is the primitive for the emergency PIN and panic wipe. The rest of the table below is specified for M5–M6 and not implemented:

| Protection | Specification |
|---|---|
| App lock | PIN or biometrics; locks after a user-chosen timeout (default 5 minutes); never unlocks root operations |
| Emergency PIN | A second PIN that crypto-erases the profile (`crypto_erase`), deletes the wrapped root secret, and opens an empty profile. The UI states the caveat: "A copy of your phone made before you used the emergency PIN isn't affected." |
| Panic wipe | Settings action (and optional OS shortcut) that performs the erase without opening a decoy profile |
| Screen security | Android `FLAG_SECURE`; Windows `WDA_EXCLUDEFROMCAPTURE`; macOS `NSWindow.sharingType = .none` (best effort); iOS cannot block screenshots, so the app blurs its snapshot and hides content while the screen is captured |
| Input and clipboard | Android `IME_FLAG_NO_PERSONALIZED_LEARNING`; optional "Block third-party keyboards" on iOS; clipboard cleared 60 s after copying codes or recovery words |
| Lock screen | Shows "New message" by default |

## 6. Errors

`enclave_store::StoreError`:

| Error | Cause | Behavior |
|---|---|---|
| `Crypto` | Wrong passphrase or device secret; a record, segment or keyring fails to open | Refuse to open; skip a corrupt record and log locally |
| `Keystore` | Keystore unavailable or failing | Refuse to open the profile |
| `NotFound` | Missing keystore secret; shredded message key | Treat as deleted |
| `Malformed` | Bad metadata, keyring or backup encoding | Refuse the object |
| `Db` | redb error | Retry; report |

## Open questions

1. PLAN §13 describes the Apple master key as a Keychain secret "combined with" a Secure Enclave P-256 unwrap. This spec reads "combined" as two nested wraps of the device secret (both must be removed). An alternative is to feed two independent secrets into the master-key KMAC.
2. The PIN attempt limit and wipe behavior for the wrapped root secret are not in PLAN.md.
3. A shred rewrap writes the keyring and the generation in two separate database transactions after creating the new keystore entry, and destroys the old entry last. A crash between the two writes leaves a keyring sealed under generation `g + 1` while the stored generation is still `g`, so the keyring cannot be opened. The two writes should be one transaction.
4. The reference backup format has no header or version. PLAN's "Enclave Backup v1" needs one before backups leave the device.
