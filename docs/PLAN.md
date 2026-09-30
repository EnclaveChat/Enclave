# Enclave: Master Plan (rev. 2, combined from six independent drafts)

> **How this revision was made.** Six agents each rewrote the plan under a different strategy: Minimalist, Maximalist, First-principles, Prior-art, Adversarial, and Wildcard. Each draft included a fact-check pass (verifying every claim) and a design pass (a real visual direction). A seventh agent judged and ranked the drafts. This plan uses the **Adversarial** draft (ranked 1st, 25/30) as its skeleton and adds the strongest part of each of the others. Appendix C records which part came from which draft.

## Context

The repository `EnclaveChat/Enclave` (`/home/user/Enclave`) is empty apart from a GPLv3 `LICENSE` and a one-line `README.md`. We are building **Enclave**, an open-source messenger with Signal's features, usable by non-technical people.

**Signal is already post-quantum** (PQXDH plus the SPQR Triple Ratchet, Oct 2025). Enclave's advantage therefore has to come from other things:
1. Category-5 hybrid cryptography with **three independent KEM families**, plus post-quantum *authentication*.
2. A **full post-quantum ratchet step on every turn**. Signal's steps are sparse.
3. **Hiding metadata**: sender, recipient, size, timing, device count, and group membership are hidden from servers and from a global observer. This uses a mixnet, constant-size units, and cover traffic.
4. **No phone number, and no trusted server.** This includes key-transparency servers, which are checked by witnesses.
5. Hardware-bound storage that can be crypto-shredded, plus a hardened endpoint that separates components into different processes.

### Fixed user decisions
| Topic | Decision |
|---|---|
| Platforms | Android, iOS, and desktop (Linux, macOS, Windows). Desktop is not an always-on node. No web client. |
| Topology | Federated **untrusted** servers that anyone can run, reached through **Nym over Tor**. There is no server-to-server message relay: clients write directly to the recipient's server through the mixnet. |
| Identity | Key-based accounts, with optional `@name@server` usernames backed by key transparency (KT). Contacts are added by QR code, invite link, or username. No phone numbers. |
| Calls | Chosen per call. **Private relays** by default. **Direct** P2P is opt-in and shows an IP warning. |
| Cover traffic | Adaptive: constant rate in the foreground, a trickle in the background, and a Paranoid toggle (called "Maximum privacy" in the UI). |
| Deniability | Set per conversation. **"Off the record"** (deniable) is the default. **"On the record"** signs every message. |
| Multi-device | Linked devices, each with its own keys, certified by the root. |
| Groups | Up to 100 members, built on pairwise sessions. No MLS. |
| Language | **Rust for everything possible, including the UI.** Non-Rust code is allowed only where unavoidable, isolated, and justified (§22). |
| Scope | The full roadmap, built across sessions. This session covers **M0 (the spec) and M1 (the crypto core)**. |
| Crypto stack | As the user requested: SLH-DSA-SHAKE-256s root; Ed448+ML-DSA-87; X448+ML-KEM-1024+Classic McEliece-8192128 (HQC-256 later); KMAC256 and SHA3; a Double-Ratchet-family ratchet with an ML-KEM-1024 post-quantum ratchet; an XChaCha20→AES-256 cascade with a KMAC256 256-bit tag; constant-size padding; TLS 1.3 SecP384r1MLKEM1024 + TLS_AES_256_GCM_SHA384; WireGuard+Rosenpass; Nym over Tor; LUKS2 and Argon2id at rest. |

### Decisions made in this revision
| # | Decision | Why |
|---|---|---|
| D1 | **Each message is a 16,384 B wire unit.** It carries a sealed request header and a **14,336 B stored envelope**. | "Every object is exactly 16 KiB" cannot be true once requests are sealed. |
| D2 | **McEliece is used by the initiator only, and from the first message.** Alice encapsulates to Bob's account "vault" key. Bob's reply authenticates Alice post-quantum via her per-device **ML-KEM auth key**. If the 1.36 MB key hasn't arrived yet, the session starts and McEliece is braided in afterwards. | This keeps all three KEMs from message 1 without a 1.36 MB fetch in each direction. |
| D3 | **One root-signed account manifest.** No intermediate signing key. | Every binding stays on the hash-based root. |
| D4 | **Safety code covers root keys only.** | Yearly key rotation must never cause "code changed" warnings that train users to ignore them. |
| D5 | **Multi-device uses a wrap table.** The body is encrypted once and slots are padded to the 5-device cap. A self-copy is always sent. | Cuts up to 11 units per message to 2, and hides how many devices you have. |
| D6 | **Groups:** each message is authenticated with a MAC vector; rekeying uses a DCGKA-style exporter-key broadcast. | Deniable and post-quantum, and 3.1 KB smaller per message. A rekey costs about 3 units, not about 500. |
| D7 | **One account inbox.** Writes need hash-registered single-use tokens. Each poll request touches exactly one mailbox. | Per-contact mailboxes forced joint polling, which linked them together. |
| D8 | **Rosenpass runs only between relays.** Client↔relay WireGuard gets its PSK from Enclave's Category-5 sealed relay ticket. | Rosenpass needs about 524 KB of pre-shared static keys per peer. On phones that would link calls to each other and add C code. |
| D9 | **No DTLS-SRTP and no SCTP.** Calls use WireGuard+SFrame in both modes. RingRTC is dropped. | Less parser surface. RingRTC is AGPL and C++, which conflicts with the App Store plan. |
| D10 | **Exactly three global cover profiles.** There are no per-user or per-network rates. Nym per-hop delays stay at Nym's defaults. | Any per-user parameter becomes a fingerprint. |
| D11 | **Hedged nonces and hedged RNG.** Backups never contain ratchet state. | A state rollback must never produce a two-time pad. |
| D12 | **Optional in-person PSK.** Scanning each other's QR codes mixes an optical secret into the handshake. | An independent physical assumption at almost no cost. |
| D13 | **GPLv3 §7 additional permissions and a DCO at M0.** App Store builds use Slint under its Royalty-free 2.0 license. | Plain GPLv3 is unsafe on the App Store. There is a single copyright holder today, so this is the time to do it. |

### On "inventing a new form of encryption"
We invent **no primitives**. Every broken "unbreakable" cipher was someone's invention. Enclave's novelty is in **composition**, and each composition is secure if any one component holds:

- **EnclaveCombine** is the triple-KEM combiner. It takes an optional in-person PSK. It binds every public key, every ciphertext, and a PSK flag.
- **EnclaveSeal** is a two-cipher cascade with a KMAC256 tag, hedged nonces, and key commitment.
- **The Lockstep Ratchet** is a Triple Ratchet with a full ML-KEM-1024 step every round trip.
- **MAC-vector group authentication.**

Each has a written argument, a symbolic proof (Tamarin/ProVerif), and a computational proof for the combiners (CryptoVerif/EasyCrypt). Two independent audits happen before 1.0. Proofs **add to** differential testing; they never replace it. A 2026 paper found bugs inside formally verified PQ code.

### Honest limits (in `docs/00-overview.md` and in the app's help)
1. **The endpoint is the real attack surface.** Spyware on the device defeats everything here.
2. **Using Enclave is visible. Who you talk to is what we hide.**
3. **Anonymity is not yet post-quantum.** Nym's Sphinx packets and Tor use classical crypto, so recorded traffic could later reveal routes. Content stays post-quantum safe. Sealed requests keep mailbox IDs and tokens hidden even then.
4. **The mixnet adds latency.** Text takes about 5–6 s. Calls take 3–10 s to start ringing.
5. **Metadata protection costs data.** Roughly 60–70 MB per hour open, 35–40 MB per day in the background, and about 1.5 GB per day in Maximum privacy mode. The UI shows these numbers.
6. **iOS cannot run cover traffic in the background.** Apple sees push-wake timing. iPhone is the weakest platform for metadata.
7. **Calls hide IP addresses, but not call timing,** from a global observer.
8. **Most PQ Rust crates are not audited yet.** Audits are budgeted in M1–M2 and M10.
9. **Metadata protection depends on Nym's credential economics and capacity.** M4 is a go/no-go gate, and a fallback is specified.

---

## 1. Threat model (`docs/01-threat-model.md`, `docs/redteam-matrix.md`)

### 1.1 Adversary NATION-2035
- **Global passive observer.** Sees every link and records everything.
- **Active network attacker.** Can inject, drop, delay, replay, and tag traffic, and can block Nym or Tor.
- **Infrastructure control.** Runs or coerces 50% or more of Nym nodes and Enclave servers, relays, and witnesses.
- **Legal reach.** Can subpoena Apple, Google, and operators, and can compel operators to start logging.
- **Quantum.** A cryptographically relevant quantum computer (CRQC) arrives in 2035 and is used on everything recorded before then.
- **Temporary device compromise.** A border search or a transient exploit.
- **Supply chain.** Can attack crates, CI, stores, and update mirrors.
- **Social engineering.** Link phishing, lookalike usernames, malicious admins, and spam at scale.

### 1.2 Goals
- Confidentiality, integrity, and authenticity, all post-quantum at Category 5.
- Forward secrecy and post-compromise security. 1:1 conversations heal in one round trip. Groups heal within one epoch.
- Deniability, as configured per conversation.
- Sender and recipient unlinkability against servers and the network.
- Hiding of size, timing, contact graph, device count, and group membership, within the limits in §1.3.
- No stable identifier visible to servers.
- Recovery from a temporary device compromise without creating a new account.

### 1.3 Metadata leakage matrix
| Observer | Learns | Does not learn |
|---|---|---|
| Your ISP | That you use Enclave (unless you use a pluggable transport). When you are online. Traffic volume, which is fixed per profile. On iOS, when the app is open. | Your contacts, recipients, or message timing (on Android/desktop in the foreground or in Maximum mode) |
| Tor guard | The same as your ISP | Which Nym gateway you use |
| Nym entry gateway | The Tor exit's IP, your rotating Nym identity, and Poisson-smoothed timing | Your real IP, content, or destination server |
| Mix nodes | Nothing linkable, as long as one layer is honest | |
| Your home server | Pseudonymous inbox write counts, poll timing (smoothed), and object counts at fixed sizes | Who writes to you, your contacts, content, your IP, or your device count |
| Push relay | The push token and wake timing, quantized into 60 s windows | Your inbox, your server, or any content |
| Apple / Google | Wake timing for each device. Capsule ciphertext if previews are on. | Content |
| Call relay | Its own caller's IP, stream timing, and the IP of the peer relay | The other caller's IP, or content |
| Peer in a direct call | Your IP, which you opted into | |

### 1.4 Red-team matrix
Every row maps to a spec section and a test in §21.

| ID | Attack | Fix | Accepted residual |
|---|---|---|---|
| RT-01 | Long-term intersection attack: correlating when you are online with writes to an inbox | Always-on background profile on Android and desktop. Fixed send slots. Unlinkable tokens. Push quantized into windows. Maximum privacy mode. | iOS app-open times remain visible. A pair who talk often can be narrowed down over months. |
| RT-02 | n-1 attack or flooding by a malicious gateway or mix | Nym loop cover at 1 per 10 s, plus Enclave self-loop probes. If loss exceeds 10% or latency exceeds 5× the median, the client switches gateway and logs it. | A single message can be targeted this way |
| RT-03 | Active tagging of Sphinx packets | A tagged envelope fails the EnclaveSeal check and is dropped. Tor hides the client IP from the gateway. | A colluding gateway and server can learn "this Tor circuit talks to server S" |
| RT-04 | Key-transparency split view (showing different users different keys) | Tree heads need ≥3 independent witness cosignatures. Head digests are gossiped inside message padding. Clients audit their own entries anonymously. Safety codes remain available. | A colluding witness quorum against a target who has checked no contacts |
| RT-05 | Malicious prekey server (withholding or replaying prekeys) | Signed prekeys expire after 14 days. Replay cache of initial-message hashes. The bundle epoch is committed in the manifest. | Withholding the one-time prekey means forward secrecy for the first message rests only on the signed prekey |
| RT-06 | Draining one-time prekeys | Equi-X proof-of-work to claim one. Last-resort PQ prekey that rotates weekly. | Can force use of the last-resort key |
| RT-07 | Downgrade: stripping the PQ or McEliece parts, or switching modes | No negotiation in v1. Suite ID, H(McE_pk), and mode are bound into the manifest, transcript, and associated data. Mode changes are visible in-band. The fallback transport requires user consent. | An attacker can *delay* the McEliece braid (the session still has X448+ML-KEM-1024) |
| RT-08 | Rolling back state from a snapshot or backup | Hedged nonces. Backups exclude ratchet state. The database is excluded from OS backups. | Old messages could be accepted again, but confidentiality is never lost |
| RT-09 | Device-link phishing (used against Signal in 2025) | Linking starts only from Settings. A separate URI type that the general scanner refuses. Pick-1-of-4 word check. History transfer delayed 24 h. A banner on every device for 7 days. Inactive devices auto-expire after 30 days. | A user who is socially engineered through every one of these steps |
| RT-10 | Invite links leaking | The secret lives in the URL fragment. Links are limited-use, expire, and can be revoked. Requests land in quarantine. | Spam requests until the link is revoked |
| RT-11 | Malicious admin forking group state | Group state is a hash chain. Every message carries the state hash and a causal frontier. Membership changes are always shown in the chat. | Admins can legitimately add people, and everyone sees it |
| RT-12 | Fingerprinting the cover-traffic implementation | Three global profiles. Packet-paced traffic. Nym default delays. Profile changes only at foreground/background transitions. | "Is an Enclave user" and "screen is on" remain visible |
| RT-13 | Targeted malicious update | Reproducible builds. TUF with 2-of-3 SLH-DSA+Ed448 signatures. Sigsum log. Update manifests fetched over the mixnet. | App stores can serve a targeted binary. This is detectable but not preventable. |
| RT-14 | Crate supply chain | `cargo vet`, `cargo deny`, vendoring, a build.rs allowlist, hermetic Nix builds, and **a process split** | iOS runs as a single process |
| RT-15 | Side channels in the crypto | `subtle`. Tests with dudect and ctgrind/secret-poisoning. The ARM DIT bit. Hardware AES or bitsliced fallback. `mlock`. Core dumps disabled. | Physical, power, and EM side channels |
| RT-16 | iOS push timing | 60 s windows. Jitter. Dummy wakes only with Apple's filtering entitlement. Fixed-size capsule. "Notifications off" option. | Apple learns which windows had at least one message |
| RT-17 | Correlating blob uploads and fetches | Size buckets. Random blob IDs. Delayed fetches with 1–3 decoy fetches. McEliece keys fetched as encrypted blobs. | Approximate fan-out count |
| RT-18 | Colluding call relays plus a global observer | Each side picks a relay from a different operator family. PQ PSK obtained anonymously. Maximum mode keeps a constant audio-shaped tunnel open. | Call start and stop times without Maximum mode |
| RT-19 | Traffic analysis of CBR media | Opus in CBR mode with DTX off. The RFC 6464 audio-level extension is forbidden. Fixed packet size and rate. Padding while muted or with the camera off. Quality can only step down. | Audio-only vs. video tier is visible |
| RT-20 | Deanonymizing push tokens | Tokens are sealed to the relay and re-randomized each time they are registered. The relay is reached over Nym. The Android default avoids FCM. | On iOS, activity windows can be tied to a device |
| RT-21 | Temporary device compromise | 1:1 heals in one round trip. Groups heal on the next rekey. **"Secure my account"** rotates everything. The root is gated by a PIN. | Message history already on the device is exposed |
| RT-22 | Theft of the recovery words | Root actions without a co-signature from an existing device wait 72 h and can be vetoed by any device. Contacts enforce the delay. | Recovery is slow if every device is lost |
| RT-23 | Clock manipulation | Trusted time is the median of witness timestamps. Skew warnings. Disappearing timers run on local monotonic time after receipt. | A device that is offline and has had its clock tampered with |
| RT-24 | Server replays or delays messages | Counters, skipped-key cache, and single-use tokens. "Delivered late" indicator. Gap notice. | A server can still drop messages. Probes detect it. |
| RT-25 | Spam and Sybil accounts with no identity | Invite capability or Equi-X PoW. Text-only requests. Quotas. Local blocking. | Well-funded PoW spam can still reach the requests folder |
| RT-26 | Lookalike usernames and man-in-the-middle at first contact | Confusable-skeleton uniqueness (UTS #39). Key-derived contact art. In-person QR scan. | Trust on first use until the contact is checked |
| RT-27 | Quantum computer used on recorded transport metadata | Sealed requests (X448+ML-KEM-1024) | Recorded traffic reveals routing, but not mailbox IDs or content |
| RT-28 | Operators legally compelled to log | Nothing identifying to log. Reproducible server builds. | Pseudonymous inbox activity from that point on |

**Out of scope:** a persistently compromised endpoint; physical side channels; hiding the fact that someone uses Enclave; screenshots taken by the recipient; a user who hands over their recovery words.

---

## 2. Cryptography (`crates/enclave-crypto`, `docs/02-cryptography.md`, `docs/label-registry.md`)

### 2.1 Primitives
Sizes are verified against the FIPS/RFC documents; see Appendix A.

| Role | Primitive | Sizes (B) | Use |
|---|---|---|---|
| Account root | **SLH-DSA-SHAKE-256s** (FIPS 205) | pk 64, sig 29,792 | Signs only the manifest (the device list and key bindings), migration and recovery records, and releases. It relies only on SHAKE256. |
| Device signature | **Ed448 + ML-DSA-87 composite**, `id-MLDSA87-Ed448-SHAKE256` (draft-ietf-lamps-pq-composite-sigs-19, pinned until it becomes an RFC). **Both signatures must verify.** | pk 57+2,592; sig ≈4,741 | Signed prekeys, On-the-record messages, key-transparency heads, witness cosignatures |
| Handshake KEM | **X448 + ML-KEM-1024 + Classic McEliece-8192128** (ISO/IEC 18033-2 Amd 2:2026) | X448 56; ML-KEM ek/ct 1,568; McE pk 1,357,824, sk 14,120, ct 208 | EQXDH (§4). McEliece is the account **vault key**. |
| Device auth KEM | ML-KEM-1024 static key per device | ek 1,568 | Post-quantum authentication of the initiator in Bob's reply |
| Ratchet / request / call KEM | X448 + ML-KEM-1024 | | §5, §9, §11 |
| KDF / PRF / MAC | **KMAC256 only.** SP 800-56C one-step KDF to combine, SP 800-108r1 KMAC mode to expand. | | Every call has a unique label from `label-registry.md`. CI rejects duplicate labels. HKDF-SHA3 is **dropped** because it relies on the same Keccak assumption. |
| AEAD | **EnclaveSeal-v1** (§2.3) | overhead 72 (32-byte nonce + 32-byte tag + 8 bytes of framing) | Everything: messages, storage, SFrame, sealed requests, blobs |
| Hash | SHA3-512 for transcripts and fingerprints; SHAKE256 for IDs | | |
| Password KDF | Argon2id (RFC 9106) | | Desktop default 1 GiB (range 1–4 GiB), t=4. Mobile calibrated to ~1.5 s: 256 MiB by default, 512 MiB–1 GiB only on devices with ≥6 GB RAM. |
| Anti-spam | **Equi-X** (the Tor onion-service PoW, from arti's `equix` crate) | | Request inboxes, prekey claims, username registration, account creation |
| Cross-operator quota | Privacy Pass (RFC 9578, blind RSA-2048, token type 0x0002) | about 354 B/token | Relay tickets, blob quotas, the zk-nym faucet. Only its unforgeability is classical, and breaking that yields free quota, not deanonymization. |
| KT privacy VRF | ECVRF-EDWARDS25519-SHA512-TAI (as used by akd) | | Hides usernames from enumeration only. Classical, and documented as such. KT *binding* is hash-based. |
| Agility | HQC-256 suite ID reserved | ct ≈14.4–14.5 KB (unresolved) | Ships after FIPS 207 is final and an audited implementation exists. Its ciphertext exceeds one envelope, so the handshake would need two units. |
| Not used | AEGIS-256 | | A single AES-family construction. The cascade is fast enough. |

### 2.2 Libraries
All shipped crypto is pure Rust.

| Primitive | Crate | Assurance | Test-only oracle |
|---|---|---|---|
| ML-KEM-1024 | `libcrux-ml-kem` | Formally verified with hax/F\* | RustCrypto `ml-kem`, OpenSSL 3.5 |
| ML-DSA-87 | `libcrux-ml-dsa` 0.0.x | Only arithmetic, NTT, and serialization are verified. Pinned exactly. | RustCrypto `ml-dsa`, OpenSSL 3.5 |
| SLH-DSA-SHAKE-256s | RustCrypto `slh-dsa` | **Never audited** | `fips205`, OpenSSL 3.5 |
| Ed448 / X448 | `ed448-goldilocks`, `x448` | **Not audited** | OpenSSL 3.5 |
| McEliece-8192128 | `classic-mceliece-rust` (round 4, safe Rust) | **No audit found.** Uses a large stack, so it runs on a dedicated thread with an 8 MiB stack. | liboqs / libmceliece |
| XChaCha20 / AES-256 / SHA3 | RustCrypto `chacha20`, `aes` (fixslice constant-time fallback), `sha3` | Mature | OpenSSL |
| KMAC256 | **Written in-house** (~150 lines) on `sha3` cSHAKE256 | Tested against SP 800-185 vectors | `libcrux-kmac`, OpenSSL KMAC |
| Argon2id, P-384 | RustCrypto `argon2`, `p384` | | RFC 9106 vectors, Wycheproof |
| Key hygiene | `zeroize`, `secrecy`, `subtle` | | |

- **Differential tests** run on every primitive, across two or three backends.
- **Funded audit (M1–M2):** `slh-dsa`, `ed448-goldilocks`, `classic-mceliece-rust`, and EnclaveSeal.
- **If a Rust crate fails review:** the release is **blocked**. A C backend can ship only as a written §22 exception, running inside the vault process. Nothing is swapped in silently.

### 2.3 Constructions
- **EnclaveCombine**, the KEM combiner:
  - `prk = KMAC256(suite_label, ss_x448‖ss_mlkem‖ss_mce‖psk_or_zero, 512, "enclave/v1/kem-extract")`
  - `ss = KMAC256(prk, SHA3-512(all pks‖all cts‖transcript‖psk_flag‖suite), 512, "enclave/v1/kem")`

  It follows the GHP18 / KitchenSink argument (draft-irtf-cfrg-hybrid-kems): the output is IND-CCA if any one component is. Binding every public key and ciphertext is the lesson from PQXDH's re-encapsulation flaw. The two-KEM variant (used before the McEliece braid) has its own label. `psk_flag` prevents downgrading a PSK session to a non-PSK one.
- **EnclaveSeal-v1** takes a key K, associated data AD, and plaintext P:
  - **Hedged nonce:** `N = KMAC256(k_n, rand32‖AD‖SHA3-512(P), 256, "seal/nonce")`
  - **Subkeys:** `k_c‖k_a‖k_m = KMAC256(K, N, 768, "seal/keys")`
  - **Encrypt:** `c = AES-256-CTR(k_a, iv=0) ⊕ ChaCha20(k_c, nonce=0) ⊕ P`
  - **Tag:** `T = KMAC256(k_m, len(AD)‖AD‖N‖c, 256, "seal/tag")`
  - **Output:** `N‖c‖T`. The tag is checked in constant time **before** any keystream is generated.
  - **Properties:** IND-CCA if either cipher is secure and KMAC is a PRF. Key-committing (no "invisible salamanders"). A reused key never reuses a keystream unless P, AD, and the randomness all repeat.
  - **Storage:** each record gets its own `mk_rec = KMAC(master, salt‖record_id)`.
  - **Size cap:** at most 64 KiB per seal. Larger data is chunked.
- **Hedged RNG** for all key generation and encapsulation: `KMAC256(os_rng(64)‖device_hedge_secret‖counter, label)`. This survives a weak OS RNG and VM snapshots.
- **No compression before encryption, anywhere**, backups included. This is the lesson from Threema.

### 2.4 Key inventory (`docs/02b-key-schedule.md`)
| Key | Scope | Lifetime | Rotation |
|---|---|---|---|
| Root (SLH-DSA) | Account | Permanent | Migration only (§3.7) |
| Vault KEM (McEliece) | Account; shared with its devices | 1 year, 30-day overlap | On schedule, "Secure my account", or revocation after compromise |
| X448 IK | Account | 1 year | Same |
| Device signing composite and ML-KEM auth ek | Device | 1 year | Relink or revocation |
| Signed prekey (X448 + ML-KEM) | Device | 14 days | On schedule |
| One-time prekeys | Device | Single use. Batches of 100, refilled when below 20. | Consumed |
| Last-resort PQ prekey | Device | 7 days | On schedule |
| Inbox seed | Account | Until a block, revocation, or "Secure my account" | The address rotates weekly |
| Write tokens | Per contact | Single use, 32 outstanding | Continuous |
| Group sender chains | Per member device | 24 h or 200 messages (lazy), and on any membership change | §7 |
| Notification keys | Per contact | 1 day | On schedule |
| Server request KEM | Server | **1 day**; the old key is deleted | On schedule |
| Local master / shred keys | Profile | Rewrapped on every shred event | §13 |

---

## 3. Identity, devices, recovery (`docs/03-identity.md`)

### 3.1 Account creation
- A **256-bit recovery secret** is generated with the hedged RNG and shown as **24 BIP-39 words**. Any BIP-39 wordlist language is accepted.
- The root is derived from it: `SLH-DSA.KeyGen(KMAC256(recovery, "enclave/v1/root", 768))`.
- The root secret is stored on the primary device, wrapped by the hardware keystore **and** by Argon2id(app PIN). **Biometrics cannot unlock root operations.**
- Creating an account requires an Equi-X proof-of-work (about 20–30 s, run while the user types their name).

### 3.2 Account manifest
The manifest is the only object the root signs day to day. It is hash-chained, versioned, and expires after at most 13 months.

It contains:
- `devices[≤5]`, each with a device ID, the composite signature pk, the X448 IK, the ML-KEM-1024 auth ek, capabilities (protocol versions and features), a role (primary, linked, or may-add-devices), and when it was added;
- the account X448 IK;
- **SHA3-512 of the McEliece vault pk**;
- the request-inbox descriptor;
- the suite ID;
- the bundle epoch.

Size is about 52 KB with 5 devices. It is always fetched in bulk and cached per contact. The **account inbox is never in the manifest or in key transparency**; contacts receive it inside the encrypted session.

### 3.3 Linking (hardened against RT-09)
1. The new device shows a link QR code containing an ephemeral X448 key, an ML-KEM ek, a 128-bit link secret, and a rendezvous mailbox.
2. It can be scanned **only from Settings → Your devices** on the primary. The QR uses a distinct URI type that the general scanner and deep links refuse, showing an explanation instead.
3. The two devices run EnclaveCombine with the link secret as PSK. The user then picks the matching phrase out of 4 options.
4. The primary signs a new manifest and sends the vault key, the inbox seed, and contacts. **History transfer starts after 24 h** unless both devices confirm sooner. History goes over the LAN if both devices are on it, otherwise as bulk blobs.
5. Every device shows "New device linked: *Pixel 9*, 30 Sep 14:02. Not you? Remove it" for 7 days.
6. Linked devices that are inactive for 30 days are removed automatically. The cap is 5 devices: 1 primary plus 4 linked.

### 3.4 Revocation and "Secure my account"
- **Revocation** publishes a new manifest without the device.
- **"Secure my account"** does the following:
  - rotates the vault key, the X448 IK, the inbox seed, and all signed prekeys;
  - re-issues tokens;
  - forces a PQ ratchet step with every contact;
  - rekeys every group.

### 3.5 Safety code (D4)
- Per side: `fp = SHAKE256^5200(root_pk)`, truncated to 30 digits. The pair is shown as **60 digits** in 12 groups of 5, using a monospace font, plus a QR code of the full digests.
- The spoken form is **10 BIP-39 words** (≥100 bits).
- Scanning each other's QR codes in person is both **verification** and the **in-person PSK** (§3.6).
- The code changes only after a root migration.

### 3.6 In-person PSK (D12)
- **Mutual scan:** each QR carries 32 fresh random bytes, `s_A` and `s_B`. They are combined as `psk = KMAC256(s_A‖s_B (ordered), "enclave/v1/bond", SHA3-512(QR_A‖QR_B))`.
- **Seal check:** both screens show three "Seal" words so users can confirm they scanned the right phone.
- **One-way fallback:** invite QR codes and links carry a 256-bit secret, used as a weaker PSK.
- **Meeting again** re-roots every session with that contact, which heals through a physical channel.
- **Formal model:** a Tamarin lemma covers the case where "all KEMs are broken but the optical exchange was not recorded".
- **Product copy never claims** this makes messages "unbreakable".

### 3.7 Recovery, migration, deletion
- **Recovery or root actions without an existing device (RT-22).** The action is published as *pending* with `not_before = now + 72 h`. Any current device can veto it, and contacts' clients enforce the waiting period. After recovery, contacts see "Sam set up a new device". The safety code does not change.
- **Migration, when the recovery words are compromised:**
  - A new root signs `Migration{old, new}`. The old root cross-signs it if still available.
  - Contacts are told "Sam reset their account. Check the security code again."
  - Without the old root's cross-signature, the UI says plainly that it cannot tell a reset from an impostor.
- **Social recovery (M9, optional):**
  - SLIP-0039 3-of-5 shares go to chosen contacts.
  - A share is released only after an in-person scan plus the holder's confirmation.
  - Recovery then waits 72 h, and every device is notified.
- **Lost words and all devices, with no social recovery:** you get a new identity. Onboarding says so plainly.
- **Account deletion** (App Store rule 5.1.1(v)) does all of the following:
  - writes a key-transparency tombstone;
  - deletes the inbox and blobs;
  - sends a "closed" notice to contacts;
  - crypto-shreds local data.

---

## 4. Session establishment: EQXDH v1 (`docs/04-eqxdh.md`)

### Bob's bundle
Per device:
- a signed prekey (X448 SPK + ML-KEM PQSPK, 14-day expiry) with a composite signature;
- **100 one-time prekeys** (X448 + ML-KEM PQOPK) under **one composite signature over a Merkle root**, each with a 224 B path. This saves about 470 KB of signatures per batch.
- a **last-resort PQ prekey** for when the one-time prekeys run out.

The McEliece vault pk is a **blob encrypted under a key found only in Bob's QR code, link, or KT record**, so the directory can't tell whose key is being fetched. Claiming a one-time prekey needs an Equi-X proof-of-work.

### Contact-add fetch
When a QR code, link, or username resolves, the client fetches in bulk mode over SURBs, while the screen shows "Adding Sam…":
- the manifest (about 52 KB);
- the bundles (about 8 KB per device);
- the McEliece blob, 1.36 MB, which is fetched **once per contact per year** and pinned.

### Alice's side
1. **Stage 1 (hides the initiator).**
   - Alice computes `DH3 = X448(EK_A, SPK_B)` and, if a one-time prekey is available, `DH4 = X448(EK_A, OPK_B)`.
   - She encapsulates ML-KEM to PQOPK_B (or to PQSPK / the last-resort key) and McEliece to Bob's vault pk.
   - From these she derives `k_id`, which **seals Alice's identity** (root hash, manifest version, device ID). Bob's server never learns who is initiating.
2. **Stage 2.**
   - Add `DH1 = X448(IK_A, SPK_B)` and `DH2 = X448(EK_A, IK_B)`.
   - Encapsulate ML-KEM to **Bob's device auth ek**, which is PQ authentication of Bob.
   - Compute `SK = EnclaveCombine(DH1..4, KEMs, psk?, transcript)`.
   - The transcript covers: both root hashes, both manifest hashes, the capability sets (against downgrade), the suite, the bundle epoch, all public keys and ciphertexts, the mode, and `psk_flag`.
3. **Bob's first reply.**
   - Bob encapsulates to **Alice's device ML-KEM auth ek** and mixes the result into the root key. This is implicit, deniable PQ authentication of Alice.
   - He adds key confirmation: `KMAC(SK', "confirm")`.
   - Until that round trip completes, Alice is authenticated classically plus by the PSK if one exists. Unknown senders stay in "Message requests" regardless.

### Braid fallback (D2)
If the McEliece blob hasn't arrived yet:
- Alice sends under the **two-KEM label**. `H(McE_pk_B)` is already committed in Bob's root-signed manifest, so stripping McEliece is a detectable downgrade (RT-07).
- McEliece is then braided in during the session: Alice encapsulates and sends the 208 B ciphertext in the next PQ slot, and it is mixed into the root key.
- Contact info shows "Extra protection: finishing…".
- **Maximum privacy mode waits** for all three KEMs before the first send.

### Group-only peers
For people you share only a group with, sessions start on two KEMs. They must upgrade to three within 7 days, on an unmetered network. Maximum mode forces the upgrade before the first send.

### Other rules
- **On the record mode:** both first messages carry a composite signature over the transcript.
- **Replay:** one-time prekeys are burned on fetch. Bob keeps an initial-message hash cache for the signed prekey's lifetime plus 7 days.

---

## 5. Lockstep Ratchet (`docs/05-ratchet.md`)

### Structure
The Lockstep Ratchet has the **same shape as Signal's Triple Ratchet**:
- a Double Ratchet over X448 **with header encryption**;
- **in parallel**, an ML-KEM-1024 post-quantum ratchet;
- per-message keys derived as `mk = KMAC256(mk_DR‖mk_PQ, "enclave/v1/msg")`.

We adapt Signal's published SPQR/Triple Ratchet ProVerif models. **We do not link Signal's AGPL SPQR code.**

### Unchunked PQ step
Padding is already paid for, so every unit carries a full **PQ slot** (sealed, about 3.26 KB):
- the sender's current ek (1,568 B), repeated until acknowledged;
- the ciphertext answering the peer's latest ek (1,568 B, or zero-filled with a flag);
- counters.

A new ek is generated only after the peer's ciphertext for the old one arrives, which bounds how many decapsulation keys must be stored. **PQ healing takes one round trip**, versus about a dozen chunked messages in SPQR.

### Symmetric chains and lookup
- Chains use KMAC256.
- Skipped message keys are capped at 1,000 and expire after 7 days.
- Each device slot carries a 128-bit **lookup tag**, `KMAC(hk, "tag"‖N)`. The receiver keeps the next 8 tags per chain, so lookup is O(1) with no trial decryption.

### Modes
- The mode is bound into the ratchet init and into each header's associated data. A mode switch is an authenticated in-band event that both sides' UIs show.
- **On the record:** each message carries a composite signature over `("enclave/v1/signed-msg", conv_id, sender_device, recipient_account, counter, mode, SHA3-512(plaintext))`. All context fields are included to prevent cross-context replay.

### Gaps and monologues
- **Gap detection:** counters reveal missing messages. After 60 s the UI shows "A message from Sam may not have arrived".
- **Monologues:** if one side keeps sending without replies, only the symmetric chain advances. Post-compromise security needs a round trip, which is inherent to KEM ratchets and documented.

---

## 6. Multi-device fan-out (`docs/06-multidevice.md`)

- **Wrap table (D5).** The body is encrypted **once** under a fresh `mk`. The envelope carries **5 device slots of 160 B each**, **always 5**, with unused slots filled with random bytes. Each slot holds:
  - a 16 B lookup tag;
  - a sealed record with the DR header, counters, and the wrapped `mk`;
  - a tag and padding.
- **One PQ slot per unit**, rotated round-robin across the device pairs that are due. With single devices, every message takes a PQ step. With 5 pairs, each pair steps every 5 messages.
- **Each message is exactly 2 units:** one to the recipient's account inbox, and one **self-copy** to the sender's own inbox. The self-copy is sent even when you have only one device and is then discarded, so device count never shows.
- **Deletion watermark.** Envelopes stay in the inbox until a device advances the watermark after intra-account sync confirms that every device has them (hard limit 30 days). Re-fetching is normal and reveals nothing.
- **Device-list changes** reach contacts through ratchet control messages and are verified against the root-signed manifest.

---

## 7. Groups, up to 100 members (`docs/07-groups.md`)

### Message authentication (MAC vectors)
- **Sender chains.** Each member device has a KMAC256 sender chain (sender keys).
- **MAC vector.** Every message carries one 16 B tag per other member account, **always padded to 99 entries (1,584 B)**. The tags are keyed with per-(sender device → recipient account) MAC keys that were delivered with the sender key.
  - Insiders cannot forge each other's messages, and there is no signature to prove authorship to outsiders. That makes it deniable and post-quantum.
  - On-the-record groups additionally carry a composite device signature on each message.

### Delivery
- One unit per message goes to the **group mailbox** on the creator's home server. Its address is `KMAC(epoch_secret, "gmbox"‖day)`.
- Writes use epoch MAC tokens. Hosting can be moved by admin vote.

### Rekey (DCGKA-style)
- A rotating member posts one broadcast to the group mailbox. It contains the new chain seed and MAC keys, **wrapped for each recipient device under a pairwise exporter key**: `K_exp = KMAC(PQ_epoch_secret‖DR_root, "grp-export"‖group_id‖epoch)`, about 72 B per device.
- The broadcast is **bucketed by a members-only hash of the recipient**, so each device fetches only its own bucket. Cost is about **3 units per rotation** for 100 × 5 devices.
- **Before a rekey,** the sender forces a pairwise PQ round trip with any device whose PQ epoch is older than the last group epoch. That makes the rekey post-compromise secure.

### Cadence
- **Membership or device-list change:** the remover rotates immediately. Everyone else rotates before their next send.
- **Otherwise:** each sender rotates lazily on its first send after 24 h or after 200 messages.
- **Group post-compromise security is one epoch** (documented).

### Group state
- Group state (members, admins, name, avatar, timer, join policy, "admins only can send") is a hash chain.
- Admin updates are authenticated with an **admin MAC vector**, or with a composite signature in On-the-record groups.
- **Every message carries the state hash and a causal frontier:** the last-seen message ID per member (8 B each, capped at 100).
  - A persistent mismatch shows: "Some people in this group may be seeing different messages."
  - Poll closes carry a tally hash signed by the poll's creator.
  - Forks resolve by lowest hash wins; the loser re-applies.
- If the last admin leaves, the longest-standing member is promoted.

### Joining
- Invite links carry a capability in the URL fragment. They are limited-use (default 1 use for contacts, 7 days) and can be revoked. **Admin approval is on by default.**
- New members cannot read history from before they joined.
- Joining costs about 99 × 60 KB ≈ 6 MB of manifests and bundles in bulk mode, with a progress bar.

---

## 8. Wire units and envelopes (`docs/08-envelope.md`)

### Wire unit (every request and every reply): exactly 16,384 B (D1)
| Part | Bytes |
|---|---|
| Version + suite | 4 |
| Server seal: X448 ephemeral 56 + ML-KEM-1024 ct 1,568 | 1,624 |
| EnclaveSeal overhead | 72 |
| Sealed request header: op, mailbox ID 32, single-use token 32, flags | 64 |
| **Stored envelope / blob chunk** | **14,336** |
| Random padding | 284 |

Poll requests are a separate fixed-size small object (1–2 Sphinx packets carrying fixed-size SURBs). Replies are always a full unit, filled with cover if there is nothing real. On the Nym transport a unit is **k ≈ 9–11 Sphinx packets** (2,413 B each on the wire, 2,048 B payload). **k and the usable bytes per packet are measured in M4.**

### 1:1 stored envelope: 14,336 B, fixed offsets, no plaintext lengths
| Field | Bytes |
|---|---|
| Version, kind, flags | 16 |
| Device-slot table (5 × 160) | 800 |
| PQ slot (sealed) | 3,264 |
| Notification capsule (**random** unless used) | 1,024 |
| Body seal overhead | 72 |
| **Content: Off the record** | **9,160** |
| Content: On the record (minus 4,741) | ≈4,419 |

### Group stored envelope
| Field | Bytes |
|---|---|
| Header (version, sender index, chain, counter, epoch) | 88 |
| State hash | 32 |
| Causal frontier | 800 |
| MAC vector | 1,584 |
| Capsule | 1,024 |
| Seal overhead | 72 |
| **Content** | **≈10,736** (≈6,000 in an On-the-record group) |

### Content rules
- Inner content is Protobuf (`prost`) with strict limits: depth 16, unknown fields rejected in security messages.
- Content up to 64 KB spills into continuation units.
- Receipts, reactions, typing indicators, and KT-head gossip (up to 3 × 40 B) ride inside the content and padding.

### Attachments
- Sealed in 14,336 B chunks at **random 256-bit blob IDs** (not content hashes).
- Total size is padded to buckets: 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB, 64 MiB, 128 MiB. The per-attachment maximum is 100 MiB.

---

## 9. Transport and metadata (`crates/enclave-net`, `docs/09-transport.md`)

### 9.1 Path
Client → **Tor (embedded arti)** → Nym entry gateway (WSS on port 443) → 3 mix layers → exit gateway → the **destination Enclave server's own Nym client**.

- Writes go to the recipient's server and polls go to your own. Every request gets **fresh single-use SURBs and a fresh sender tag**.
- Servers have **no clearnet message API**.
- **Tor always sits in front of Nym**, as the user requested. It hides your IP from an entry gateway that anyone can run and that sees your Nym identity and timing. It also provides pluggable transports.
- The M4 spike measures Tor exit → gateway reachability and latency. The load estimate uses **Tor *exit* capacity**, and the project will coordinate with the Tor Project before launch.

### 9.2 Sealed requests
- Every request is sealed to the server's X448 + ML-KEM-1024 key, which **rotates daily**; old keys are deleted.
- Nym's Sphinx layer is classical, so this is what keeps mailbox IDs and tokens post-quantum (RT-27).
- A replay cache of request ciphertext hashes is kept for each key's lifetime.

### 9.3 Inboxes, tokens, polling (D7)
- **Account inbox.**
  - Address: `KMAC(inbox_seed, "inbox"‖week)`, with a 7-day overlap.
  - Read credential: `KMAC(read_key, day)`, stored at the server only as a hash.
- **Write tokens.**
  - Each contact holds 32 single-use tokens `t_i = KMAC(k_contact, i)`.
  - The owner registers `H(t_i)` in **shuffled batches padded with dummies**. The server burns each token on use and cannot group writes by sender.
  - The token also serves as the recipient's session hint.
  - Refills ride inside messages (16 × 32 B).
  - Blocking a contact means that contact gets no new tokens.
- **Request inbox.** Listed in the manifest. A write needs an invite capability or an adaptive Equi-X PoW (about 2 s median on a phone, up to 60 s during floods). It holds at most 100 pending requests, oldest dropped first. Requests are text-only, with no media, links, or receipts.
- **One mailbox per poll request, always.**
  - Slot 1 polls the inbox.
  - Slot 2 rotates across groups, weighted by activity, with a floor of one poll per 60 s in the foreground.
  - A reply flag "more pending" prioritizes the next slot.
  - **Residual:** anti-correlated poll rates across group mailboxes are a weak, documented signal.

### 9.4 Cover-traffic scheduler (D10)
Nym's default client sends 50 + 5 packets/s, about 500 MB/h. Enclave **disables Nym's Poisson main stream** and drives its own tick scheduler; M4 confirms this is a supported configuration and not a debug-only one. Nym loop cover stays at 1 per 10 s for n-1 detection.

Each tick is:
- **1 unit up**: a real write, or cover sent to a random directory server, which drops it;
- **1 fixed poll up**;
- **1 unit down**.

Real traffic *replaces* cover. The sending priority is: peer delivery, then control messages, then own-device sync, then prefetch.

| Profile (identical in every client) | When | Tick | Data (incl. est. Sphinx/Tor overhead; M4 must land within ±20%) | Median text latency |
|---|---|---|---|---|
| **Foreground** | App visible | 3 s, packet-paced | ≈60–70 MB/h | ≈5–6 s |
| **Background** | Android (foreground service) and desktop tray | Poisson, mean 120 s | ≈35–40 MB/day | ≤2 min, or on push |
| **Background (iOS)** | Not possible (the OS suspends the app) | none | 0 | On open, or on push |
| **Maximum privacy** | Opt-in; Android and desktop always, iOS only while open | 3 s always | ≈1.5–1.7 GB/day, shown before enabling | ≈5–6 s |
| **Bulk** | Media, McEliece keys, joins, history, catch-up | Up to 40 packets/s, sizes padded to buckets | "Sending a large file uses a burst of data" | Photo ~16 s |

In Maximum mode, bulk transfers are throttled to the constant rate: a 1 MiB photo takes about 15 minutes, and the UI says so.

### 9.5 Nym access, fallback, censorship
- **Credentials.** zk-nym credentials are required at entry gateways. Enclave runs a **credential proxy** that hands clients unlinkable, re-randomized ticketbooks. It is gated by Equi-X plus Privacy Pass and funded by operators or a foundation.
- **M4 go/no-go**, all required:
  - nym-sdk on Android and iOS uses ≤150 MB RAM;
  - cold connect in ≤5 s;
  - bulk transfer ≥200 KB/s;
  - the credential path works end to end;
  - Standard-mode cost is ≤ $1 per user per month;
  - the Tor → gateway path works.
- **Fallback transport:** Tor onion services with the *same* scheduler and envelopes. It is used **only with user consent and never in Maximum mode**, and labelled "Backup route: slower to hide who you talk to". Katzenpost (post-quantum Sphinx) is tracked behind the `Transport` trait.
- **Censorship:** Tor bridges using obfs4 via the Rust `ptrs` crate in-process. Snowflake and WebTunnel are Go exceptions (a subprocess, or IPtProxy on iOS), enabled only in censorship mode. The app detects blocking and offers "Try a bridge?".
- **Post-quantum mixnet:** we adopt Nym's post-quantum Sphinx / Outfox or Lewes links as soon as nym-sdk exposes them.

### 9.6 TLS 1.3 (never on the message path)
- **Key exchange:** our own rustls `CryptoProvider` implementing **SecP384r1MLKEM1024** (RFC 10024, codepoint 0x11ED). It is built from RustCrypto `p384` and libcrux ML-KEM-1024, and interop-tested against OpenSSL 3.5. No stock rustls provider ships this group; the upstream PR #3293 targets aws-lc-rs, which is C.
- **Cipher suite:** `TLS_AES_256_GCM_SHA384` via RustCrypto.
- **Used for:**
  - server descriptors at `https://<domain>/.well-known/enclave`, fetched via Tor, pinned on first use, and checked against witnessed KT checkpoints;
  - KT witness gossip;
  - update endpoints;
  - the relay control plane;
  - the push relay's front door.
- Certificates are classical ECDSA-P384. Everything carried over TLS is **also** PQ-signed at the application layer.
- The push relay → APNs/FCM hop uses whatever TLS Apple and Google negotiate.

---

## 10. Push and notifications (`docs/10-push.md`)

The push relay is **run by the project**, because APNs and FCM accept only the publisher's credentials.

- **Reaching the relay.** Servers reach it **through Nym**, so it cannot tell which server is waking which device.
- **Token sealing.** Push tokens are sealed to the relay and **re-randomized on every registration**. The server never sees the plain token, and a device's mailboxes cannot be linked through it.
- **Rate shaping.** 60 s windows, at most one wake per device per window, and 0–30 s of jitter.
- **Maximum privacy disables push entirely.**

| Platform | Default | Opt-in |
|---|---|---|
| Android (F-Droid) | The always-on Background profile in a foreground service. No FCM. | UnifiedPush (self-hostable) |
| Android (Play) | Same, if Play policy accepts the `specialUse`/`remoteMessaging` foreground-service type (**checked in the M1.5 spike**). Otherwise FCM content-free wakes plus Poisson dummy wakes (about 1/h). | "Battery saver delivery" (FCM) |
| iOS | APNs **generic alert** ("New message"). Content is fetched when the app opens. | **Show previews**: the sender adds a **1 KB capsule** (sender name plus about 600 B of preview) sealed under a per-contact notification key that rotates daily. The Rust NSE decrypts it with symmetric crypto only, well within **24 MB / ~30 s**, and never runs arti or Nym. The capsule field is random bytes when unused. |
| iOS dummy wakes | Only if Apple grants `com.apple.developer.usernotifications.filtering` (requested at M6). Otherwise jitter only. | |
| iOS calls | PushKit VoIP → CallKit (mandatory and disclosed). CallKit is unavailable in China, so the app falls back to a notification there (unverified). | Maximum: calls ring only while the app is open |
| Desktop | Background profile while running | |

---

## 11. Voice and video calls (`crates/enclave-calls`, `docs/11-calls.md`)

- **Signalling** travels as ratchet messages. Each call does a fresh X448 + ML-KEM-1024 exchange, and **call keys are independent of chat keys**.
- **Media E2EE:** SFrame (RFC 9605) with a **private-use EnclaveSeal suite** (256-bit tag; about 12.8 kbps of overhead on 20 ms Opus, which we accept).
  - Per-sender base keys ratchet every 5 s.
  - A participant leaving triggers a rekey. Joiners receive ratcheted-forward keys, so they cannot read earlier frames.
- **Relay mode (default).** Each person picks a relay whose **operator family** differs from both their home server's and the peer relay's.
  - **Client↔relay:** WireGuard via **GotaTun** in userspace, so no VPN permission is needed. WireGuard keys are fresh per call. The **PSK comes from a sealed X448 + ML-KEM-1024 relay ticket** obtained over the mixnet and paid with Privacy Pass, and it is re-keyed every 2 minutes.
  - **Relay↔relay:** WireGuard + **upstream Rosenpass**, running as a server daemon.
  - No ICE is used, so no host candidates leak. No single relay sees both IP addresses.
- **Direct mode.** Opt-in per call.
  - Checked contacts get one confirmation. Unchecked contacts get a second, stronger warning.
  - ICE comes from the webrtc-rs sans-IO `rtc` crates; str0m is evaluated in M8. STUN goes only through Enclave relays, and host candidates use mDNS.
  - The tunnel is WireGuard with the call PSK. **There is no DTLS-SRTP.**
- **Traffic shaping (RT-19).**
  - Opus in CBR at 32 kbps, 20 ms frames, DTX off, in-band FEC on.
  - Video tiers of 300, 800, and 1,500 kbps, with fixed 1,200 B packets at a fixed rate, chosen at call start. Quality can only step down, at most once per 30 s.
  - Padding keeps the same rate when muted or when the camera is off.
  - A header-extension allowlist; the RFC 6464 audio-level extension is forbidden.
- **Maximum privacy calls.** A constant 32 kbps audio-shaped tunnel runs to your relay while the app is in the foreground, which hides call start and stop.
- **Media engine.**
  - **Opus:**
    - Decoding uses the **pure-Rust `opus-decoder`** once it passes the RFC 8251 vectors plus fuzzing.
    - Encoding uses libopus (C) in the media sandbox, which only ever processes your own microphone, until `opus-rs` matches its quality.
    - Symphonia is never used for Opus; it cannot decode it.
  - **Echo cancellation:**
    - On mobile, the OS voice-processing path (VoiceProcessingIO; Android `VOICE_COMMUNICATION` with its AEC).
    - On desktop, pure-Rust `sonora` if it passes quality tests, otherwise `webrtc-audio-processing` in the sandbox.
  - **Video:**
    - AV1, encoded with rav1e at speed 10, or with an OS hardware AV1 encoder.
    - Decoded with **rav1d, in software, inside the sandbox**. Incoming video never touches hardware decoders.
    - **M8 gate:** 360p at 30 fps on the reference low-end phone. If that fails, fall back to OS hardware H.264 encode as a declared exception.
  - **Capture:** `cpal` for audio. For cameras, platform shims (CameraX via `jni`, AVFoundation via `objc2`) plus `nokhwa` on desktop.
- **Group calls.**
  - An SFU in the host's relay forwards only SFrame frames and simulcast layers in fixed-rate slots.
  - Audio is forward-all at CBR, with no dominant-speaker detection.
  - Each receiver has a fixed 2.5 Mbps downlink budget.
  - **Limits:** 32 video tiles or 64 audio participants.
  - Extras: call links (capability URL, optional lobby), raise hand, reactions, picture-in-picture.
  - Screen share on desktop in M8, on mobile post-1.0.
- **Call check.** An optional 2-word code derived from the call key, as in ZRTP.
- **RingRTC is not used (D9).**

---

## 12. Servers and operations (`crates/enclave-server`, `-relay`, `-push-relay`, `-witness`; `docs/12-servers.md`, `docs/13-operators.md`)

### 12.1 `enclave-server`
A single Rust binary (tokio) that runs as a Nym service provider. It keeps **no accounts, no phone numbers, no IP addresses, and no plaintext metadata**.

| Component | Function | Abuse control |
|---|---|---|
| Inbox store | Token-authorized writes, credentialed cursor reads, watermark deletion, 30-day TTL | Single-use tokens; 256 MiB per inbox |
| Request inbox | First contact from strangers | Adaptive Equi-X; max 100 pending |
| Directory | Manifests, bundles, encrypted McEliece blobs | PoW on one-time-prekey claims; publishing requires a root-certified device |
| Blob store | Random-ID chunks. TTL 30 days (backups 90 days, refreshable). | Privacy Pass quota |
| Key transparency | `enclave-kt` on **akd** (Meta; NCC-audited 2023; MIT/Apache). Maps `@name` → {root hash, manifest hash and version, request-inbox locator}. Hourly epochs. | One username per account; Equi-X; reserved names; UTS #39 confusable skeletons |
| Token issuer | Privacy Pass for relays, blobs, and the credential faucet | Per inbox per day |
| Push forwarder | Wakes go to the push relay through Nym | |

### 12.2 Key transparency
- **Tree heads** are composite-signed, with 10-minute to 1-hour epochs.
- **Witness cosignatures:** tree heads are valid only with **≥3 cosignatures from independent witnesses** on the client's pinned list (≥2 during beta, at least one from another operator). The format follows C2SP tlog-cosignature, with an added ML-DSA-87 cosignature.
- **Gossip:** clients gossip the 32 B head digest in message padding. A mismatch triggers a proof exchange and a clear alert.
- **Self-audit:** clients audit their own entry anonymously on every launch.
- **Trusted time:** the median of the witnesses' timestamps. Heads older than 24 h are rejected.
- akd's hash-width and SHA3 configurability are checked in M3; a fork is used if needed.

### 12.3 Discovery and migration
- The foundation publishes a signed list of vetted public servers, relays, and witnesses, chosen for jurisdiction diversity. It is shipped in the app and updated via TUF.
- Onboarding picks a server automatically, weighted by capacity. Advanced users can paste a server link.
- Server descriptors are self-signed, pinned on first use, and logged in KT.
- **Moving an account to another server:** the root signs a `Moved` record, which contacts receive in their own inboxes. The username must be re-claimed on the new server.
- If a server disappears, contacts' clients show "Sam's server is unreachable. We'll keep trying."

### 12.4 Moderation (operators cannot see content)
- **What operators can do:** rate-limit; delete a reported blob ID; disable a reported inbox or mailbox address; tombstone a username that breaks policy (visible in KT); refuse registrations.
- **User reports** voluntarily include the reported plaintext.
  - In Off-the-record chats, a report is an unverifiable claim, and the UI says so.
  - In On-the-record chats, the signatures make reports verifiable.
- **Operator kit:**
  - terms-of-service and acceptable-use templates;
  - a transparency-report template;
  - a law-enforcement guide listing what can and cannot be provided;
  - a GDPR note;
  - a data-processing record.

### 12.5 Relays and deployment
- **`enclave-relay`:** GotaTun endpoints, a relay-ticket service, a Rosenpass daemon for relay↔relay links, and the SFU. Relay descriptors declare the operator family.
- **Deployment:**
  - Docker and Nix, with reproducible server builds.
  - Storage: redb by default; a pure-Rust Postgres backend for large operators (M11).
  - **The KT database must be backed up.**
  - Metrics are local aggregates only.
- **Scale estimate** for 100k accounts: about 400–500 Mbit/s of reply egress, and about 2–3 cores for sealed-request decapsulation. Measured in M4.

---

## 13. Local storage (`crates/enclave-store`, `docs/14-storage.md`)

### Keys and database
- **Master key** = `KMAC256(hw_secret‖Argon2id(passphrase)?)`, where `hw_secret` comes from the platform:
  - **iOS/macOS:** a random secret in the Keychain (`WhenUnlockedThisDeviceOnly`, symmetric and UID-rooted), **combined with** a Secure Enclave P-256 unwrap. The Secure Enclave supports only P-256, so it is never the only wrap.
  - **Android:** a StrongBox or Keystore AES-256-GCM key.
  - **Windows:** CNG/DPAPI, with TPM-sealed keys through CNG where available.
  - **Linux:** Secret Service, or a passphrase if Secret Service is unavailable.
- **Database: redb.** Every key is blinded with KMAC, and every value is sealed with its own per-record subkey. The full-text search index uses blinded tokens.
- **Excluded from OS backups:** `NSURLIsExcludedFromBackupKey` on Apple platforms, `allowBackup=false` on Android.
- **No claim of a monotonic rollback counter on mobile.** Hedged nonces plus session reset give the actual protection (RT-08).

### Crypto-shredding
- Disappearing messages and deletions use per-conversation, per-day shred keys held in a small keyring.
- The keyring is **re-wrapped under a fresh hardware key on every shred event**, and the old hardware key is deleted.
- Deleted data is therefore unrecoverable even from a forensic image taken *after* the shred.

### Backups
- An Enclave Backup v1 archive holds contacts, history (media optional), and settings, **never ratchet or sender-key state**.
- It is keyed by `KMAC(recovery, "backup")`.
- It can be saved to a local file, through the OS file picker (iCloud Drive or Google Drive only ever see ciphertext), or to a server blob.
- **Restoring creates a new device and re-establishes sessions.** The app offers a restore test.

### Device protections
- **App lock:** PIN or biometrics.
- **Emergency PIN:** crypto-erases the hardware-wrapped key and opens an empty profile. The UI states the caveat that a forensic image taken beforehand is unaffected.
- **Panic wipe.**
- **Screen security:**
  - Android: `FLAG_SECURE`.
  - Windows: `WDA_EXCLUDEFROMCAPTURE`.
  - macOS: best effort.
  - **iOS cannot block screenshots.** The app blurs in the app switcher and hides content while `isCaptured` is true.
- **Input and clipboard:**
  - Android IME no-personalized-learning flag.
  - Optional "Block third-party keyboards" on iOS.
  - The clipboard is cleared automatically after 60 s for codes and recovery words.
- **Lock screen** shows "New message" by default.
- **Desktop documentation** recommends LUKS2 AES-256-XTS with Argon2id for full-disk encryption. The app does not depend on it.

---

## 14. Client app and endpoint hardening (`docs/15-client.md`, `docs/15b-platform-constraints.md`)

### Process split (RT-14)
- **Desktop:** four processes that talk over typed `postcard` IPC through a UDS or named pipe:
  - `vault`: crypto, protocol, and storage. The only process that holds long-term keys. Minimal dependencies.
  - `netd`: arti and Nym. Sees only sealed wire objects.
  - `mediad`: decoders, inside the OS sandbox (seccomp + Landlock, the macOS App Sandbox via XPC, or AppContainer).
  - The Slint UI.
- **Android:** the network service runs in its own `android:process`, and decoders run in an `isolatedProcess` service.
- **iOS:** a single process plus the NSE (an accepted residual risk). Image and audio parsers run inside a **WASM isolation sandbox** (wasmi or the Pulley interpreter; no JIT).

### UI
- **Slint ≥ 1.18**, one codebase.
  - The UI never touches key material. It talks to `enclave-core` through a typed async command/event API.
  - **Skia (C++) is required on Android and iOS** (Slint's mobile backends depend on it). It is fed only our own paths, text, and decoded RGBA, with its codecs disabled.
- **Unicode hygiene:** at most 8 combining marks per base character, bidi controls neutralized in names, and NFKC normalization for names.

### M1.5 and M6 accessibility gate (hard)
- **Must pass:**
  - TalkBack and VoiceOver can operate the chat list, composer, and verification flow;
  - CJK and Indic IME input, RTL layout, color emoji, 200% text, and text selection and copy all work.
- **Current gap:** Slint's Android backend has no AccessKit wiring today. We will fund or build and upstream the `accesskit_android` and `accesskit_ios` integration.
- **If it's still blocked 8 weeks after M6:** mobile gets thin SwiftUI and Jetpack Compose shells over the same Rust core via UniFFI, as a declared exception. **Accessibility outranks language purity.**

### Platform shims
- The `enclave-platform` crate is the only crate allowed `unsafe`, and every `unsafe` block gets two reviews.
- Android: `jni` and `ndk`. Apple: `objc2` (APNs, PushKit, CallKit, Keychain, Secure Enclave, VoiceProcessingIO, and `define_class!` for the NSE). Windows: the `windows` crate. Linux: `zbus`.
- The ARM DIT bit is set around cryptographic operations.

### Media policy (few formats, few decoders)
- **Images:** the sender re-encodes to JPEG or PNG, at most 4096 px, with EXIF and GPS stripped. The receiver decodes in the sandbox (`zune-jpeg`, `png`) to raw RGBA with a 25 MP cap. Images are re-encoded only on export.
- **Animated images:** sent as short AV1 clips.
- **Video:** AV1 + Opus in **our own fixed-chunk container**, so there is no MP4 or WebM demuxer. The sender's own camera files are read with the OS decoder and then transcoded.
- **Voice notes:** Opus.
- **Files:** never previewed. "Open with…" shows a warning.
- **Nothing auto-downloads from strangers.** Message requests show text only.
- **Link previews and GIF search:** off by default, generated on the sender side only, fetched through Tor.

### Feature parity (`docs/16-features.md`)
| Feature | Milestone |
|---|---|
| 1:1 text, formatting (bold/italic/strike/mono/spoiler), emoji (Noto Color Emoji), reactions | M6 |
| Replies, forwarding (labelled), mentions | M6/M7 |
| Disappearing messages (timer starts on read, per device), view-once | M6/M9 |
| Images, voice notes | M6 |
| Video, files (100 MiB) | M9 |
| Typing indicators (**off by default**), read receipts (optional, batched) | M6 |
| Encrypted profile (name, photo, about), usernames, QR codes/links | M6 |
| Note to self, archive, pin, mute, chat folders, block, message requests, spam reports | M6/M9 |
| Security codes, change alerts, linked devices, backups | M5/M6 |
| Groups: admins, announcement-only, invite links, approval | M7 |
| 1:1 and group voice/video, call links, raise hand, desktop screen share | M8 |
| Edit (24 h, advisory), delete for everyone (advisory), polls, pins, stickers (encrypted packs), GIFs (opt-in via Tor), contact sharing, location (coordinates only), search, media gallery, device transfer, social recovery | M9 |
| Stories (24 h), mobile screen share, on-device voice transcription (optional download) | M11 |
| Payments, public group directory | Not planned |

---

## 15. Design system: "Paper & Seal" (`docs/17-design.md`, `design/tokens.toml` → generated `tokens.slint`)

**Point of view:** *Enclave feels like private correspondence done well: warm paper, deep pine ink, and one saffron seal that appears only when something has really been confirmed.*

### 15.1 Typefaces
Two families, both SIL OFL 1.1, bundled unmodified with `OFL.txt` in `LICENSES/`.

| Face | Job |
|---|---|
| **Atkinson Hyperlegible Next** (400 and 600 only) | Everything people read: messages, UI, headings. Built for low-vision legibility. |
| **Atkinson Hyperlegible Mono** | Only things people must **compare or copy exactly**: security codes, recovery words, link and invite codes. Its 0/O and 1/l/I glyphs are clearly different. |

- **Content fonts, not design choices:** Noto Color Emoji for emoji, and Noto Sans (bundled per shipped locale) for scripts Atkinson doesn't cover.
- **Type scale (sp/pt):** 13 caption, 15 secondary, **17 body and messages**, 20 title, 24 screen title, 32 onboarding only.
  - Line height 1.4. Mono codes at 22 with 0.04 em tracking.
  - OS text scaling up to 200%, with no truncation of message text.

### 15.2 Palette
One dominant color, one accent, and neutrals. Ratios follow WCAG 2.x and are checked in CI by `cargo xtask tokens-check`.

| Token | Light | Dark | Role / contrast |
|---|---|---|---|
| Background | Paper `#F6F3EC` | Night `#111412` | |
| Surface | `#FFFFFF` | `#1A1E1B` | Sheets |
| Incoming bubble | `#ECE7DC` | `#242A26` | |
| Outgoing bubble | `#DCEBE6` | `#2A6B58` | Ink on it 13.51; Chalk on it 5.23 |
| Text | Ink `#1C1F1D` | Chalk `#EEEAE1` | 15.0 / 15.44 |
| Muted text and input borders | `#585E59` | `#A7ADA6` | 6.0 (5.39 on incoming) / ≥3:1 for borders |
| **Pine (dominant)** | `#1D5646` | `#7CC4A8` | Primary buttons, links, focus. Paper on Pine 7.67; Pine-light on Night 9.11 |
| **Saffron (accent)** | `#F2B230`, **fill only in light mode** | `#F5BE45` | **Fixed meaning: "confirmed by you".** Ink on Saffron 8.86. Saffron on Paper is only 1.69, so the Seal glyph always has a Pine or Ink stroke to reach 3:1. |
| Brick / Ember (danger only) | `#A8321E` | `#F08A73` | 6.04 / 7.58. Always paired with an icon and text. |
| Hairline | `#CFC8BA` | `#3A423D` | Decorative only |

Proportions: about 85% neutrals, 12% Pine, under 3% Saffron. **No gradients.** Color is never the only way state is shown.

### 15.3 Spacing, grid, shape, motion
- **Spacing:** 4-pt base, with steps of 4, 8, 12, 16, 24, 32, 48, 64.
- **Grid:**
  - Phone: 4 columns, 16 margin, 8 gutter.
  - Tablet: 8 / 24 / 16.
  - Desktop: 320 conversation list, a fluid conversation with a 680 max text width, and a 360 details pane.
- **Touch targets:** at least 48 × 48 dp.
- **Radii:** 8 for controls, 12 for bubbles (4 on the tail corner), 20 for sheets.
- **Elevation:** two levels only.
- **Motion:** 150–200 ms ease-out. Reduce-motion turns everything into cross-fades.
- **Haptics:** a light tick on send, and a pattern when the Seal closes.
- **Icons:** a custom 24 px set with 1.75 px stroke, derived from Lucide (ISC). No locks, shields, or keyholes.
- **App icon:** a Pine square with a paper-colored Seal (a circle with a folded notch).

### 15.4 Signature moments
1. **Onboarding, no phone number, under 60 s:**
   - "Talk privately. No phone number. No email." **[Get started]**
   - "What should people call you?" (name, optional photo): "Only people you talk to can see this." While the user types, keys are generated and the proof-of-work runs behind a single line: "Setting up your private address…"
   - A server is picked automatically: "Your messages wait here, locked, until your devices collect them. **Change**"
   - The home screen shows three equal actions: **Show my code**, **Scan a code**, **Share an invite link**. Usernames come later, with one honest line: "A username is public, like an email address."
   - **Recovery words** are deferred until after the first conversation or 24 hours.
     - They appear as a persistent card: 24 numbered words in Mono, a check of 3 words, "Save as file" on desktop, and screenshot blocking on Android.
     - The words must be saved before linking a device or claiming a username.
     - Completing this earns the Saffron seal on Settings → Account.
2. **Meeting in person is verification.**
   - Two people scan each other's codes. The **Seal closes**: two halves meet in 240 ms (instant under reduce-motion) with a haptic pulse.
   - Three matching Seal words appear on both phones.
   - "You and Sam are checked in person. If anything changes, we'll tell you before you send anything."
   - The contact header gains a small Saffron seal and the date.
3. **Checking remotely:** "Check it's really Sam."
   - Twelve groups of 5 digits in Mono, or 10 words to read aloud on a call.
   - Screen readers read one group at a time.
   - The user taps **They match**.
4. **Security code changed:** an in-conversation card with a Saffron left rule and no red.
   > Sam's security code changed. This usually means a new phone or a reinstall. Check again before sharing anything private.

   Buttons: **Check now** and **Later**. The first send after a change needs a tap-through. If "Only send to checked contacts" is on, sending is blocked.
5. **Security state without jargon.** "Private" is the default and is never labelled; only exceptions show.
   - The contact state has three shapes plus words: a filled Seal for "Checked in person", an outline for "Not checked yet", and a notched Seal for "Code changed".
   - The mode chip reads **"Off the record"**: "Nobody can prove to others who wrote these messages." Or **"On the record"**: "Your messages carry your signature. Anyone who gets a copy can prove you wrote them."
   - Delivery shapes: hollow dot "Sending privately…", half dot "On its way", full dot "Delivered", ring "Read". The first time only: "Private delivery takes a few seconds. That pause is part of what hides who you talk to."
   - The pre-call sheet offers **"Private route (hides where you are)"** or **"Direct (clearer, but Sam can see your internet address)"**.
   - Settings → Privacy: "Standard" or "Maximum (hides even when you're using Enclave; uses about 1.5 GB a day)". On iPhone it adds: "iPhone pauses apps in the background, so Maximum only works while Enclave is open."
   - "Extra protection: finishing…" (the McEliece braid) and "Backup route" appear only on the contact-info and settings screens.
6. **Wrong-place link code:** "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one."

### 15.5 Copy voice
- A calm, exact friend who has done this before.
- Second person, sentence case, one idea per sentence.
- Say what happened, what it means, and what to do.
- Use concrete numbers ("about 60 MB an hour"). Never fear, never brag, never blame.
- Aim for grade 6–8 reading level.
- **Glossary:** security code (not "safety number" or "fingerprint"); recovery words; checked; private route; off/on the record; linked devices; message request.
- **Keys and algorithms appear only in an "Advanced details" sheet.**
- Example error: "Couldn't send yet. Your phone is offline. We'll send it when you're back."

### 15.6 Banned
**Visuals:**
- purple-to-blue gradients, or any gradients;
- glassmorphism or frosted blur;
- emoji used as UI decoration;
- identical icon-card grids;
- **padlocks, shields, keyholes, vault doors, hooded hackers, binary rain, terminal green, or skeuomorphic wax seals with shadows**;
- confetti, stock photos of people, 3D blobs;
- more than two elevation levels;
- red or green as the only signal;
- toasts for security events (they must be inline and persistent);
- spinners over 2 s without text;
- fake progress.

**Copy:** "unlock", "seamless", "elevate", "empower", "supercharge", "military-grade", "bank-level", "unbreakable", "bulletproof", "hacker-proof", "100% secure", "anonymous" as a promise, "Oops", and exclamation marks in system copy.

**Behaviour:** dark patterns in privacy or data settings.

---

## 16. Accessibility and localization (`docs/18-a11y-i18n.md`)

**Accessibility (WCAG 2.2 AA):**
- token contrast checked in CI;
- a 2 px focus ring (Pine in light mode, Saffron in dark), ≥3:1;
- full keyboard navigation on desktop;
- labels on every control, including bubble metadata ("Sent, read");
- 200% text;
- no information conveyed by color alone;
- reduce-motion honored;
- 48 dp targets;
- captions and transcripts for voice notes (optional, on-device, M11);
- errors identified in text.

The **screen-reader gate** is §14.

**Localization:**
- Slint `@tr()` with gettext catalogs, translated on Weblate. String freeze 3 weeks before each release.
- Pseudo-localization with +40% text expansion and RTL.
- **Tier-1 locales at 1.0:** en, es, pt-BR, fr, de, ru, uk, fa, ar, tr, zh-Hans, zh-Hant, hi, id, ja.
- RTL and bidi rendering are a release gate for ar, fa, and he. Slint's support is unverified, so it is tested in M6 and patched upstream if needed.
- Dates, plurals, and numbers use ICU4X. Recovery words use the BIP-39 list for each language.

---

## 17. Supply chain, releases, crash reports, versioning (`docs/19-ops.md`)

### Releases and updates
- **Signing:** TUF (the `tough` crate) plus a **2-of-3 maintainer co-signature, each SLH-DSA-SHAKE-256s + Ed448**, on offline HSMs held by 3 maintainers in 2 jurisdictions.
- **Transparency:** release hashes are logged in **Sigsum** with witnesses.
- **Update fetch:** update manifests are fetched through the mixnet, so they cannot be targeted by IP.
- **"Verify this build":** available everywhere except iOS.
- **Channels:**

  | Platform | Channels |
  |---|---|
  | Android | Play, F-Droid (reproducible), direct APK |
  | iOS | App Store |
  | macOS | Notarized DMG plus updater |
  | Windows | Signed MSIX plus updater |
  | Linux | Flathub, Nix, .deb/.rpm |

### Supply chain
- `cargo vet` (importing the Mozilla and Google audit sets), `cargo deny` (licenses, advisories, allowlist of crates that build C or C++), `cargo audit`.
- Pinned lockfile and vendored sources.
- A build.rs and proc-macro allowlist.
- Hermetic Nix builds, with **two independent rebuilders**.
- SLSA v1 provenance.
- **CI hygiene:** actions pinned by SHA, least-privilege tokens, no secrets in PR jobs.

### Crash reports without telemetry
- A panic hook and `minidumper` write a **scrubbed local report**: the stack only, no heap. Secret types can't be formatted into it.
- The user can view the report and choose to send it through Enclave to "Enclave Support" (end-to-end encrypted) or export it.
- Nothing is sent automatically, and there are no analytics.

### Versioning
- Suite and protocol IDs are carried in units and manifests. Capability sets are signed.
- Old peers are refused only for security-critical changes, after a 90-day overlap.
- Critical fixes can force an upgrade.
- **Database migrations** are versioned, take a snapshot first, and have tested upgrade paths from every release.
- Retiring a crypto suite requires 12 months of dual support.

---

## 18. Legal, licensing, governance (`legal/`, `GOVERNANCE.md`)

### License
- GPLv3, plus **§7 additional permissions added at M0, while there is still one copyright holder**:
  1. conveyance through app stores whose terms conflict with GPLv3, provided the same source is available under GPLv3;
  2. linking with **Slint under its Royalty-free License 2.0**, with the AboutSlint attribution in About;
  3. platform SDKs.
- Contributions require a **DCO** sign-off with an explicit grant of these permissions.
- `cargo deny` enforces GPLv3-compatible licenses: MIT, Apache-2.0, BSD, ISC, MPL-2.0, and OFL for fonts. **AGPL and GPL-only crates are blocked from iOS builds.**

### Export control
- File the **EAR §742.15(b)** notification at the first public source release. Enclave uses non-standard compositions, so we take the conservative reading.
- App Store export-compliance answers and the France declaration are handled with counsel.

### Regulation
- **EU CRA:** a vulnerability-handling process (24 h / 72 h / 14 days) is in place from M0. The foundation acts as an open-source steward.
- CSAR, the UK Online Safety Act, and similar laws are tracked.
- **Policy: never ship client-side scanning or key escrow.** If a jurisdiction requires either, we withdraw from that store.

### Governance
- A non-profit foundation (Switzerland or the Netherlands, chosen with counsel).
- Protocol and crypto changes go through an **RFC process**: 30 days of comments and review by the crypto working group.
- `SECURITY.md` sets 90-day disclosure. The bug bounty starts at M10.
- A code of conduct.
- A trademark policy: forks must rename.
- An operator program: vetting, a code of practice, and jurisdiction diversity.
- An annual transparency report.
- No warrant canary.

---

## 19. Repository layout

```
LICENSE (GPLv3)  legal/ADDITIONAL-PERMISSIONS.md  README.md  SECURITY.md  CONTRIBUTING.md (DCO)
GOVERNANCE.md  CODE_OF_CONDUCT.md  LICENSES/ (OFL etc.)
docs/   00-overview 01-threat-model redteam-matrix 02-cryptography 02b-key-schedule 03-identity
        04-eqxdh 05-ratchet 06-multidevice 07-groups 08-envelope 09-transport 10-push 11-calls
        12-servers 13-operators 14-storage 15-client 15b-platform-constraints 16-features
        17-design 18-a11y-i18n 19-ops 20-assurance label-registry.md math/ roadmap.md rfcs/
design/ tokens.toml  fonts/  icons/  copy-glossary.md
crates/
  enclave-crypto     KMAC256, EnclaveSeal, EnclaveCombine, composite sigs, hedged RNG, CryptoProvider (+test-only C)
  enclave-wire       fixed-layout unit/envelope/poll codecs, padding, buckets
  enclave-proto      manifest, EQXDH, Lockstep ratchet, wrap table, groups (MAC vectors, exporter rekey, frontier)
  enclave-tokens     write tokens, Privacy Pass, Equi-X
  enclave-kt         akd config, witness cosign verify, gossip, trusted time
  enclave-tls        rustls CryptoProvider (0x11ED + AES-256-GCM-SHA384)
  enclave-net        Transport trait; arti + nym-sdk; sealed requests; tick scheduler; bulk; fallback; PTs
  enclave-store      redb sealing, keystore adapters, crypto-shred keyring, backups
  enclave-media      sanitize/re-encode, chunk container, voice notes
  enclave-sandbox    WASM isolation host + OS sandbox launchers
  enclave-calls      signalling, SFrame-EnclaveSeal, GotaTun + PSK tickets, ICE/RTP (rtc), shaping, codecs
  enclave-ipc        typed postcard IPC (vault/netd/mediad/ui)
  enclave-core       client state machine (vault process), command/event API (+UniFFI feature for fallback shells)
  enclave-platform   jni/objc2/windows/linux shims — the only crate allowing `unsafe`
  enclave-design     tokens → Slint globals, contrast checker
  enclave-app        Slint UI (desktop/Android/iOS entry points)
  enclave-nse        iOS Notification Service Extension (capsule decrypt only)
  enclave-update     TUF + co-signature + Sigsum verification
  enclave-crash      scrubbed local crash reports
  enclave-server     inbox/request/directory/blobs/KT/issuer/push-forwarder
  enclave-push-relay APNs/FCM/UnifiedPush relay (mixnet ingress)
  enclave-relay      GotaTun endpoints, tickets, Rosenpass (relay↔relay), SFU
  enclave-witness    KT + binary-transparency witness
  enclave-sim        deterministic network/mixnet/adversary simulator
apps/   android/ (Gradle, manifest, ≤300-line Kotlin shims)  ios/ (Xcode, entitlements)  desktop/ (packaging)
formal/ tamarin/ proverif/ (SPQR-derived) easycrypt/ cryptoverif/
fuzz/  tests/  supply-chain/ (cargo-vet, deny.toml)  ops/ (docker, nix, operator-kit)  xtask/
```
**CI:**
- `fmt`, `clippy -D warnings`, `cargo deny`, `cargo vet`, `cargo audit`;
- tests; KAT/ACVP, Wycheproof, SP 800-185, RFC 9578, and RFC 9605 vectors;
- a fuzz smoke run; Tamarin/ProVerif;
- dudect and ctgrind;
- a reproducible-build diff;
- **token contrast check**, **label-registry uniqueness**, **traffic-shape test**, and **size-invariant test**.

---

## 20. Roadmap (every milestone has an exit gate)

| M | Deliverable | Exit gate |
|---|---|---|
| **M0** | All `docs/` (threat model, red-team matrix, label registry, byte layouts, `math/`, design spec, platform constraints). **LICENSE §7 permissions, DCO**, SECURITY/GOVERNANCE. Workspace scaffold, CI (fmt, clippy, deny, vet, audit), design tokens, README. | Spec review checklist done. §7 merged before any outside PR. |
| **M1** | `enclave-crypto` + `enclave-wire`: providers, KMAC256, EnclaveSeal (hedged), EnclaveCombine (2/3 KEM + PSK), composite signatures, hedged RNG, padding and size invariants, Argon2id calibration. KATs/ACVP, Wycheproof, SP 800-185, differential tests, dudect/ctgrind, ARM + x86 benchmarks. **Send the audit RFP.** | All vectors pass. Zero differential mismatches in 10⁷ fuzz iterations. EnclaveSeal ≥50 MB/s on the reference phone. SLH-DSA signing ≤10 s on the phone. McEliece keygen time and memory measured. |
| **M1.5** (in parallel) | Time-boxed spikes: **(a)** nym-sdk over arti on Android, iOS, and desktop (credentials, cost, the cover-stream flags, k and u, Tor→gateway reachability); **(b)** Slint Android/iOS with TalkBack/VoiceOver, IME, RTL, emoji, 200% text; **(c)** a Rust iOS NSE decrypting a capsule in under 24 MB; **(d)** Play policy for the `specialUse`/`remoteMessaging` foreground service. | Written go/no-go for each spike |
| **M2** | `enclave-proto`: manifest, EQXDH (sealed initiator, vault KEM, auth ek, braid, PSK), Lockstep, wrap table, modes, replay caches. Loss, reorder, and replay simulation. Tamarin/ProVerif models, including the PSK "all KEMs broken" lemma. | Lemmas pass: secrecy, authentication, forward secrecy, post-compromise security, deniability, downgrade. Every unit is exactly 16,384 B. |
| **M3** | `enclave-server`, `enclave-kt` (akd), `enclave-witness`, `enclave-tokens`, `enclave-sim`, dev transport | E2E simulation with 3 clients × 2 devices: the server stores only opaque 14,336 B objects and burned tokens, and sees no device count. KT split view detected. |
| **M4** | **Hard gate.** `enclave-net`: arti + Nym, sealed requests, tick scheduler with three profiles, loop probes, bulk mode, the credential proxy, push relay, fallback transport | The §9.5 go/no-go numbers. Measured data within ±20% of §9.4. Battery ≤5 percentage points per hour above idle in the foreground on the reference device (otherwise lengthen the tick). |
| **M5** | `enclave-store`, `enclave-core`, `enclave-ipc`: process split, contacts, hardened linking, the 72 h veto, backups, crypto-shred, emergency PIN | Restore from words works. Forensic test shows shredded data cannot be recovered. |
| **M6** | Slint MVP (desktop, then Android, then iOS): design system, onboarding, all three add paths plus the in-person Seal, 1:1 chat, emoji, reactions, images, voice notes, disappearing messages, the §10 push matrix, app lock, message requests. Upstream AccessKit and RTL work. Apply for the filtering entitlement. | **WCAG AA audit plus TalkBack/VoiceOver scripts pass.** 5 moderated sessions with non-technical users: ≥4 of 5 add a contact and check them without help. |
| **M7** | Groups: MAC vectors, exporter rekey, state chain, causal frontier, invites. Group formal model. | 100-member simulation: a rotation costs ≤ ~3 units per sender. Equivocation is detected. |
| **M8** | Calls: relay tickets, GotaTun, Rosenpass relay↔relay, SFrame, shaping, direct mode, SFU, call links. Codec gates. | Audio MOS ≥4.0 on the reference network. 360p30 AV1 gate decided. Constant rate verified by packet capture. |
| **M9** | Parity: video and files, stickers, GIFs, edits and deletes, polls, pins, previews, search, device transfer, social recovery, location, contact sharing, WebTunnel. | Parity rows up to M9 complete |
| **M10** | Assurance: full fuzz campaign (apply to OSS-Fuzz), CryptoVerif/EasyCrypt proofs of the combiners and EnclaveSeal, reproducible builds, TUF + Sigsum, **two external audits** (crypto crates plus protocol, and app plus infrastructure), public beta, bug bounty, McEliece literature re-review | All critical and high findings closed |
| **M11** | Launch: store submissions, export filings, operator program (≥5 operators, ≥3 jurisdictions, ≥5 witnesses), Postgres backend, stories, mobile screen share, transcription | 1.0 |
| **M12+** | HQC-256 suite after FIPS 207; Nym post-quantum Sphinx once it is available; libopus replaced by pure-Rust Opus; envelope v2 evaluated | |

**This session:** M0 plus M1. Write the specs, add the license permissions, scaffold the workspace, and implement and test `enclave-crypto` and `enclave-wire`. Commit and push to `claude/kind-goodall-44koll`. Later milestones go on this branch or new ones, as directed.

---

## 21. Verification

- **Crypto:**
  - NIST ACVP/KAT vectors for ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256s, and McEliece-8192128;
  - Wycheproof for X448, Ed448, P-384, AES, and ChaCha20;
  - SP 800-185 vectors for KMAC;
  - composite-signature vectors from the draft;
  - RFC 9106, RFC 9578, and RFC 9605 vectors;
  - Rust-vs-C differential tests on every primitive.
- **EnclaveSeal:**
  - round-trip tests;
  - every flipped bit is rejected;
  - the tag is rejected before any keystream is generated;
  - key commitment: two keys over one ciphertext, at most one verifies;
  - **nonce hedging**: the same key and a different plaintext always produce a different keystream, including after a simulated state rollback.
- **EnclaveCombine:** a downgrade test for `psk_flag` and the 2-KEM vs. 3-KEM labels. Stripping H(McE) is rejected.
- **Invariants:**
  - every wire unit is 16,384 B and every stored object is 14,336 B;
  - the byte budgets in §8 are asserted at compile time;
  - label-registry uniqueness;
  - no secret type implements `Debug`.
- **Adversary simulation (`enclave-sim`, one test per row of the RT-matrix):**
  - KT split view detected (RT-04);
  - stripped McEliece rejected (RT-07);
  - rollback produces no keystream reuse (RT-08);
  - a link QR scanned from the wrong place is refused (RT-09);
  - group fork and equivocation detected (RT-11);
  - replayed initial message rejected (RT-05, RT-24);
  - pending-root veto honored (RT-22);
  - clock-skew warning shown (RT-23);
  - the server sees no device count and no repeated tokens.
  - The server never sees a plaintext initiator identity.
  - Every poll request contains at most one mailbox.
- **Traffic shape (`cargo xtask shape`):**
  - capture traffic for scripted workloads (idle, heavy chat, media, call setup) in each profile;
  - a two-sample KS test shows **inter-packet times do not depend on real traffic** (p > 0.01);
  - byte rates are within budget;
  - real and cover units can't be told apart with χ² or an ML classifier;
  - call packets are a constant size and rate.
- **Timing:** dudect and ctgrind on MAC compare, ML-KEM and McEliece decapsulation, token verification, and Ed448. The DIT bit is confirmed set.
- **Fuzzing:** unit, envelope, poll, manifest, bundle, KT proof, protobuf, SFrame, the chunk container, and every media decoder inside the sandbox.
- **Formal:**
  - Tamarin/ProVerif for EQXDH (including deniability, the braid, and the PSK lemma), Lockstep (adapted from Signal's SPQR models), wrap tables, groups (bounded), linking, the pending-root window, and tokens;
  - CryptoVerif/EasyCrypt for EnclaveCombine and EnclaveSeal;
  - hax extraction for `enclave-crypto` and the ratchet core where the backend supports it (experimental);
  - each proof's boundary is documented.
- **E2E:** servers, a relay, and 3 clients × 2 devices. Covers 1:1, groups, revocation, migration, a vanished server, dropped messages (the gap notice fires), offline delivery, emergency PIN, and shredding.
- **Budgets:** data and battery per profile on a low-end Android, a mid-range Android, and the oldest supported iPhone. Measured at M4 and every release.
- **Clients:**
  - `slint::testing` headless tests;
  - the contrast check;
  - emulator smoke runs via `cargo xtask`;
  - TalkBack and VoiceOver scripts;
  - pseudo-locale and RTL screenshots;
  - moderated usability sessions (M6 and M9) measuring onboarding success and whether users correctly understand security states.
- **Calls:** a relay and direct test matrix; SFrame vectors; MOS under netem loss of 1%, 5%, and 10%.
- **Supply chain:** two independent rebuilders produce identical hashes; `cargo vet` covers 100% of crypto and parser crates.

---

## 22. Rust-everywhere policy and declared exceptions

`#![forbid(unsafe_code)]` applies to every Enclave crate except `enclave-platform`, `enclave-sandbox`, and `enclave-nse`, where each `unsafe` block gets two reviews. `cargo deny` allowlists crates that build C, C++, or assembly. Every exception has a tracking issue.

| Exception | Where | Why unavoidable | Containment | Exit |
|---|---|---|---|---|
| **Skia (C++)** via Slint | Android, iOS | Slint's mobile backends require it | Only local paths, text, and RGBA; codecs off; Unicode sanitizing | Slint FemtoVG or wgpu on mobile |
| libopus encoder (C) | All | No Rust encoder of equal quality | Media sandbox; own microphone only | `opus-rs` after M8 |
| webrtc-audio-processing (C++) | Desktop, only if `sonora` fails | Echo-cancellation quality | Sandbox | `sonora` or `aec3` |
| dav1d assembly inside rav1d and rav1e | Video | SIMD performance | Sandbox; software decoding | rav1d safe-SIMD work |
| OS hardware H.264 encode | Only if the M8 AV1 gate fails | Encoding speed on phones | OS media service | Hardware AV1 or faster rav1e |
| Rosenpass (+ liboqs, libsodium) | **Relay servers only** | The user-requested relay↔relay layer | A separate daemon | A Rust Rosenpass backend |
| Snowflake / WebTunnel (Go) | Censorship mode only | No Rust implementation | Subprocess, or IPtProxy on iOS | Rust ports |
| C code pulled in transitively by arti or nym-sdk (confirmed in M1.5) | netd | Upstream | The netd process | Upstream patches |
| Kotlin shims (≤300 lines), Slint's Java helper | Android | The OS requires JVM entry points | No logic, no keys | none |
| *(conditional)* SwiftUI and Compose shells | Mobile UI | Only if the accessibility gate fails | Over UniFFI; no keys | When Slint's mobile accessibility is ready |
| Gradle and Xcode manifests, Info.plist | Build | OS-mandated | | none |
| OpenSSL, liboqs, libmceliece, PQClean | **Tests only** | Differential oracles | Never shipped | none |

---

## Appendix A: Verification ledger

Status key:
- **V** = verified during this pass.
- **V\*** = standard value taken from memory, not re-fetched.
- **C** = the previous plan was wrong.
- **U** = unresolved. Each U item has an M0, M1.5, or M4 check assigned.

| Claim | Status | Note / source |
|---|---|---|
| SLH-DSA-SHAKE-256s pk 64 B, sig 29,792 B | V\* | FIPS 205 |
| ML-KEM-1024 ek/ct 1,568; ML-DSA-87 pk 2,592, sig 4,627; X448 56; Ed448 57/114 | V\* | FIPS 203/204, RFC 7748/8032 |
| McEliece-8192128 pk 1,357,824, sk 14,120, ct 208; McEliece-460896 pk 524,160 | V | OQS algorithm docs |
| Classic McEliece is ISO/IEC 18033-2:2006/Amd 2:2026 | V | ISO; multiple secondary sources |
| 2026 McEliece distinguisher (~2^124, not key recovery) | U (one source) | Re-review at M10 |
| Composite `id-MLDSA87-Ed448-SHAKE256`, draft -19 | V | IETF datatracker. The 4,741 vs 4,748 B encoding difference is pinned at M0. |
| SecP384r1MLKEM1024 = RFC 10024, 0x11ED | V | RFC Editor |
| rustls ships 0x11ED | **C**: no stock provider; PR #3293 is aws-lc-rs only | Build our own provider |
| HQC: selected March 2025; FIPS 207 still a draft; final expected 2027 | V | NIST |
| HQC-256 ct 14,421–14,485 B (varies by spec revision) | U | Resolve against the FIPS 207 draft |
| AEGIS-256 is RFC 10032 | U (probably true) | Not used by Enclave |
| libcrux-ml-dsa is 0.0.x; only arithmetic, NTT, and serialization are verified | V / **C** | "Formally verified" was an overclaim |
| Bugs found inside formally verified PQ code | V | ePrint 2026/192 |
| RustCrypto `slh-dsa` and `ed448-goldilocks` are unaudited; no audit found for `classic-mceliece-rust` | V / **C** | crate documentation |
| KMAC crates exist (libcrux-kmac, sha3-kmac, tiny-keccak feature) | V | We implement our own anyway |
| Slint iOS has been a tech preview since 1.12. Current version is ≥1.18. The mobile backends need Skia. There is no AccessKit on Android. | V / **C** | Slint blog, source code, changelog |
| Slint Royalty-free 2.0 license covers mobile and requires attribution | V | Slint LICENSES |
| AccessKit has Android (0.9) and iOS (0.2.x) adapters | V | AccessKit releases |
| nym-sdk 1.21.x is on crates.io; its libraries are Apache/MIT | V | docs.rs, Nym licensing page |
| Nym entry gateways require zk-nym credentials | V (treated as required) | Nym documentation |
| Nym Sphinx packet is 2,413 B with a 2,048 B payload; default client is 50+5 pkt/s | V | Nym documentation |
| Disabling Nym's Poisson stream is supported in production | U | M1.5 |
| Nym Sphinx is post-quantum | **C**: it is classical. Whether Lewes links cover the SDK's mixnet is U. | Nym PQ roadmap |
| Rosenpass uses McEliece-460896 static + **Kyber-512** ephemeral, and depends on liboqs and libsodium | V / **C** | rosenpass.eu, lib.rs |
| GotaTun is Mullvad's Rust fork of boringtun and runs on mobile. License MPL-2.0 vs BSD-3 is unclear. | V / U (both GPL-compatible) | Mullvad |
| webrtc-rs 0.20.x stable on the sans-IO `rtc` 0.3 | V | webrtc.rs blog |
| rav1d is complete, about 5% slower than dav1d, and shares dav1d's assembly | V | memorysafety.org |
| rav1e runs real-time on phones | U | M8 gate |
| Pure-Rust Opus crates exist (opus-decoder, opus-rs, opus-pure); `sonora` and `aec3` exist | V (existence) / U (quality) | M8 |
| Symphonia decodes Opus | **C**: it does not | |
| SFrame is RFC 9605 and defines only AES suites | V | RFC 9605 |
| Signal SPQR uses ML-KEM-768 with chunking; the ProVerif models are public | V | signal.org/blog/spqr |
| Signal key transparency launched Aug 2026 | V | Signal blog |
| akd: MIT/Apache, NCC-audited 2023, in production at WhatsApp and Messenger | V | GitHub, NCC report |
| akd hash width and SHA3 configurability | U | M3 |
| iOS NSE limits: 24 MB / ~30 s | V | Apple forums |
| The iOS notification-filtering entitlement exists and needs Apple approval | V | Apple docs |
| PushKit VoIP pushes must be reported to CallKit | V | Apple forums |
| CallKit is unavailable in China | U | M6 |
| Android 15 caps `dataSync` foreground services at 6 h per 24 h | V | Android docs |
| Play policy accepts `specialUse` or `remoteMessaging` for this app | U | M1.5 |
| Device-link QR phishing was used against Signal in 2025 | V | Google TI |
| Privacy Pass token type 0x0002 is blind RSA-2048, about 354 B | V\* / **C** (one draft said RSA-4096 / 578 B) | RFC 9578 |
| Equi-X is available in Rust via arti | U (high confidence) | M1 |
| Atkinson Hyperlegible Next and Mono are OFL 1.1 | V | Braille Institute; googlefonts |
| Palette contrast ratios | V (computed with the WCAG formula) | §15.2 |
| CRA reporting dates; EAR §742.15(b) | V | EC; eCFR |
| Data-rate and latency figures | Computed; Nym and Tor overhead U | M4 |
| Tor load estimate | Must use **exit** capacity | M4 |

## Appendix B: Open risks (ranked)

1. **Nym viability.** Credential cost, capacity, SDK weight, Tor→gateway reachability, and whether the cover-stream flags are supported. *Mitigation:* the M1.5/M4 gates, the credential proxy, and the consented onion fallback.
2. **Long-term intersection attacks (RT-01), especially on iOS.** Inherent to messaging. *Mitigation:* always-on background profiles, push windows, Maximum mode, honest copy.
3. **Small anonymity set at launch.** Early users are the most exposed. Disclosed during beta.
4. **Slint mobile maturity:** screen readers, IME, RTL, and the Skia C++ dependency. *Mitigation:* upstream work, a hard gate, and the native-shell fallback.
5. **Unaudited Rust PQ and Curve448 crates, plus bugs inside verified code.** *Mitigation:* the M1–M2 audit, differential tests, blocking releases on failure, and hybrids everywhere.
6. **Novel compositions:** the vault KEM plus auth-ek authentication, the braid, the PSK, MAC-vector groups, and the exporter rekey. *Mitigation:* formal models, CryptoVerif, the RFC process, external audit.
7. **Data and battery cost** leading users to turn features off, which shrinks the anonymity set. *Mitigation:* measured budgets and global tuning, never per user.
8. **Call metadata versus a global observer, and call quality** (no DTLS or WebRTC stack, AV1 on phones). *Mitigation:* the Maximum tunnel, the M8 gates, the H.264 fallback.
9. **Supply chain:** hundreds of crates across arti, Nym, and Slint. *Mitigation:* the process split, `cargo vet`, hermetic builds.
10. **Targeted updates through app stores.** Detectable but not preventable.
11. **Store and platform policy:** Play foreground-service review, Apple's filtering entitlement, CallKit in China, export controls.
12. **Too few independent operators and witnesses** at launch.
13. **Licensing:** §7 depends on DCO grants, and transitive GPL crates may block iOS.
14. **McEliece cryptanalysis trend and HQC's size.** *Mitigation:* the agility slot and the M10 re-review.
15. **Spam and Sybil** attacks from well-funded actors.
16. **Account loss** when recovery words are lost and no social recovery was set up.
17. **Regulation** (CSAR, the UK Online Safety Act) aimed at operators.
18. **Formal-methods reach:** hax's ProVerif backend is experimental, so hand-written models can drift from the code.
19. **The KT VRF is classical**, so usernames could be enumerated after a quantum break.

## Appendix C: The 67 process and where each part came from

**Leaderboard, scored by the judge (agent 7) out of 30:**

| Rank | Draft | Score |
|---|---|---|
| 1 | Adversarial | 25 |
| 2 | Maximalist | 24 |
| 3 | Prior art | 24 |
| 4 | First principles | 23 |
| 5 | Wildcard | 23 |
| 6 | Minimalist | 21 |

| Taken from | Parts used |
|---|---|
| **Adversarial** (skeleton) | NATION-2035 adversary and RT-01…28 matrix; hedged nonces; three global profiles; Nym default delays; hardened device linking; 72 h root veto; vault/netd/mediad/UI process split; call traffic shaping (DTX off, no RFC 6464); constant tunnel in Maximum mode; trusted time from witnesses; the McEliece braid and its commitment; server seal counted inside the unit's byte budget |
| **Maximalist** | Initiator-only McEliece vault key plus ML-KEM auth keys; two-KEM start for group-only peers; invite PSK; §7 + Slint RF + DCO; TUF + Sigsum + 2-of-3 signing; hedged RNG; DIT bit; crypto-shredding; WASM parsers on iOS; metadata-leakage matrix; moderation and operator kit; legal/CRA/EAR; accessibility and localization gates; feature matrix; RingRTC dropped |
| **First principles** | Quantified model of what is hidden from whom; MAC-vector groups; lookup tags; padded device slots with a self-copy and watermark; Merkle-batched one-time prekeys; Keychain + Secure Enclave dual wrap; one mailbox per poll; KS traffic-shape test; the "Paper & Seal" palette |
| **Prior art** | Triple Ratchet shape and SPQR models; DCGKA exporter rekey; causal frontier and poll-close hashes; last-resort PQ prekey; no compression before encryption; the principle that formal proofs never replace differential tests; akd plus C2SP witnesses; UniFFI fallback shells |
| **Wildcard** | In-person PSK with Seal words and re-rooting; the wrap table; re-randomized push tokens; M4 go/no-go numbers; the "all KEMs broken" Tamarin lemma; WireGuard in every call mode |
| **Minimalist** | 16,384 B unit vs 14,336 B stored-envelope split; sealed initiator identity; KMAC-only KDF; daily sealed-request key rotation; "meeting in person *is* verification"; server descriptor from `.well-known` pinned to KT; typing indicators off by default; honest iOS limits (no screenshot blocking, no helper processes) |

**Rejected by the judge** (none of these are in this plan):
- removing Tor or making it Paranoid-only;
- running Rosenpass on phones, or a home-made Rosenpass variant;
- a 9,088 B envelope treated as settled;
- a 200 ms per-hop delay;
- user-selectable or per-network cover rates;
- attachments bypassing Nym;
- a 3 KB APNs capsule, or a zero-filled capsule;
- batched group polls;
- a safety code covering rotating keys;
- a 55-bit spoken check;
- a mobile monotonic counter;
- Symphonia for Opus;
- RingRTC, or linking Signal's AGPL SPQR code;
- McEliece-sealed server requests.
