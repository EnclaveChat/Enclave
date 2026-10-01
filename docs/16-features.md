# Feature-Parity Matrix

Status: Draft (M0) · Normative

Source: PLAN.md §14 (feature parity), §20 (milestones). This matrix fixes which features ship in which milestone and the privacy rule each must follow. A feature marked for a milestone is part of that milestone's exit gate (M9: "parity rows up to M9 complete").

## 1. Matrix

| Feature | Milestone | Privacy rule | Spec |
|---|---|---|---|
| 1:1 text | M6 | Constant-size units | `05-ratchet.md`, `08-envelope.md` |
| Formatting: bold, italic, strike, mono, spoiler | M6 | Inside content only | `08-envelope.md` §5.6 |
| Emoji (Noto Color Emoji), reactions | M6 | Reactions ride in `Piggyback` | `08-envelope.md` §5.6 |
| Replies, forwarding (labelled "Forwarded"), mentions | M6 / M7 | Message IDs are local-only hashes | `02b-key-schedule.md` §7 |
| Disappearing messages (timer starts on read, per device) | M6 | Crypto-shred; monotonic timers | `14-storage.md` §3 |
| View-once | M9 | Shredded after view; screenshots still possible (copy says so) | `14-storage.md` §3 |
| Images | M6 | Re-encoded, EXIF/GPS stripped, sandboxed decode | `15-client.md` §5 |
| Voice notes | M6 | Opus, sandboxed decode | `15-client.md` §5 |
| Video | M9 | AV1 + Opus, own container | `15-client.md` §5 |
| Files (up to 100 MiB) | M9 | Never previewed; bucketed | `08-envelope.md` §9 |
| Typing indicators (**off by default**) | M6 | Only in a tick slot that would otherwise carry cover; never adds a unit (§7) | `09-transport.md` §6.7 |
| Read receipts (optional, batched) | M6 | Batched in `Piggyback` | `05-ratchet.md` §12 |
| Encrypted profile (name, photo, about) | M6 | Shared only inside sessions | `05-ratchet.md` §12 |
| Usernames | M6 | Optional; KT-backed; "public, like an email address" | `12-servers.md` §3.3 |
| QR codes and invite links | M6 | Secret in fragment; limited use | `03-identity.md` §9 |
| Note to self | M6 | Uses self-copy path | `06-multidevice.md` §4 |
| Archive, pin, mute, chat folders | M6 / M9 | Local and synced between own devices | `06-multidevice.md` §5 |
| Block | M6 | No new tokens for the contact | `09-transport.md` §3.2 |
| Message requests | M6 | Text only; no auto-download | `09-transport.md` §4 |
| Spam reports | M9 | Voluntary plaintext | `13-operators.md` §2 |
| Security codes, change alerts | M5 / M6 | Root-only code | `03-identity.md` §6 |
| Linked devices | M5 / M6 | Hardened linking | `03-identity.md` §4 |
| Backups | M5 / M6 | No ratchet state | `14-storage.md` §4 |
| Groups: admins, announcement-only, invite links, approval | M7 | MAC vectors; approval on by default | `07-groups.md` |
| 1:1 voice and video calls | M8 | Relay by default; CBR shaping | `11-calls.md` |
| Group voice and video calls | M8 | SFU forwards SFrame only | `11-calls.md` §8 |
| Call links, raise hand | M8 | Capability URL | `11-calls.md` §8 |
| Desktop screen share | M8 | Inside SFrame | `11-calls.md` §8 |
| Edit (24 h, advisory) | M9 | Recipient may keep the original; UI says "Edited" | — |
| Delete for everyone (advisory) | M9 | Recipient's client deletes if it cooperates; UI says so | — |
| Polls | M9 | Tally hash authenticated by creator | `07-groups.md` §7.5 |
| Pinned messages | M9 | Group state or local | `07-groups.md` §7 |
| Stickers (encrypted packs) | M9 | Packs are blobs keyed by pack secret | `08-envelope.md` §9 |
| GIFs (opt-in, via Tor) | M9 | Sender-side fetch through Tor only | `15-client.md` §5 |
| Contact sharing | M9 | Shares root pin and QR fields | `03-identity.md` §9 |
| Location (coordinates only) | M9 | No map tiles fetched automatically | — |
| Search | M9 | Blinded local index | `14-storage.md` §2 |
| Media gallery | M9 | Local | — |
| Device transfer | M9 | LAN or bulk blobs; no ratchet state | `03-identity.md` §4.3 |
| Social recovery | M9 | SLIP-0039 3-of-5, in-person release, 72 h | `03-identity.md` §8.3 |
| Stories (24 h) | M11 | Same delivery as group messages to a per-user audience | — |
| Mobile screen share | M11 | Inside SFrame | `11-calls.md` |
| On-device voice transcription (optional download) | M11 | Local model only; nothing leaves the device | `18-a11y-i18n.md` |
| Payments | Not planned | — | — |
| Public group directory | Not planned | — | — |

## 2. Features explicitly excluded

| Feature | Reason |
|---|---|
| Phone-number or email discovery | No phone numbers (fixed decision) |
| Cloud message history on servers | Servers keep ciphertext for at most 30 days |
| Server-side link previews | Would reveal links to a server |
| Web client | Fixed decision |
| Automatic contact import | Would require identifiers |
| Analytics or telemetry | `19-ops.md` §3 |

## 3. As implemented: locations

`enclave-core/src/client/location.rs`. A location is `i32 lat ‖ i32 lon` in millionths of a degree (about 11 cm) and a label of at most 200 B, sent as `Content::Location { id, location, expires }` (content kind 20) with the conversation's disappearing timer. Receivers reject coordinates off the Earth. The place is stored inside the message record (`Message::location`), so it is sealed with the message and crypto-shredded with it when the timer runs out; deleting for everyone removes it too. Nothing is looked up on either side: no map tiles, geocoding or place names, and no network request at all. The app takes typed or pasted coordinates (desktop has no location sensor here) from the attach sheet and shows the label, the coordinates in the monospace face, and **Copy coordinates**. Test `share_a_location`. Not done: reading the platform location on phones, and handing the coordinates to a maps app the person chooses.

## 4. As implemented: media gallery

Local only, in the app (`enclave-app/ui/app.slint`, sheet `gallery`): the conversation sheet offers **Photos and files (n)**, a list of every attachment in the open conversation that hasn't been deleted, with the decoded preview for pictures (from `mediad`, as in the conversation) and **Save**. It is built from the messages the vault already sends the UI, so it adds no protocol, storage or IPC. Groups have the same list (07 §7.6). Not done: a grid across all conversations.

## 5. As implemented: stickers

`enclave-core/src/client/stickers.rs`. A pack is a title (at most 64 B) and 1 to 40 pictures, encoded `"ESP1" ‖ bytes(title) ‖ u8 n ‖ n × bytes(picture)` (at most 512 KiB each, 8 MiB in all), and sealed like any file (`08-envelope.md` §9): chunks padded to a size bucket at random IDs on its creator's server, under a key only holders of the reference have. That reference is the "pack secret". The app redraws each picture in `mediad` first (`MediaOp::Shrink`: at most 512 px a side, metadata gone). Sending a sticker sends the reference and an index: `Content::Sticker` (content kind 22, with the conversation's timer) or, in a group, `FLAG_RICH` kind 9. The server sees an ordinary unit. A recipient downloads the whole pack once (every chunk of its bucket, hash-checked), decodes the one picture in `mediad`, and can **Add pack**; added packs are listed per device. The app's sticker button opens a picker of added packs (thumbnails decoded in `mediad`) and **Make a pack** from picture files. Tests `sticker_packs` and `sticker_pack_through_the_engine`. Not done: animated stickers (they would be short AV1 clips), removing a pack from the app, and a pack's own preview before adding it.

## 7. As implemented: typing indicators

`enclave-core/src/client/typing.rs`; 1:1 conversations only.

- **Off by default, and both ways**: Settings → Typing indicators. With them off we send none and show none.
- **Wire**: `Content::Typing { on }` (content kind 23), sealed like any message. The spec said typing would ride in `Piggyback`, inside a real message's padding, but you type *before* there is a message to ride on, so that can't work. Instead each indicator is its own unit sent with `Transport::exchange_droppable`: it may take only a slot of the next two ticks that would otherwise carry cover, and is dropped if none is free. The pattern on the wire is the same with typing indicators on or off, which is what "never its own unit" was protecting.
- **What a dropped one costs**: the write token it spent (the contact's server never sees it), and one skipped message key on the receiving side, which the ratchet already handles as a lost message. It carries **no PQ slot**, so a dropped unit never loses a PQ step, and **no self-copy**, so our other devices don't learn we were typing.
- **Tokens**: none is sent while the contact has given us `TYPING_RESERVE` (8) write tokens or fewer, so real messages always have tokens left.
- **Timing**: the app sends "typing" when the draft becomes non-empty and repeats it at most every 5 s while the person types, and sends "stopped" when the draft is cleared. A message itself ends the indicator. The receiving app shows "typing…" under the name for `TYPING_SHOW_SECS` (10 s) after the last one, since a "stopped" may never arrive. The sending is detached from the vault's command loop, so waiting for a slot never delays anything else.
- **Not built**: typing indicators in groups.

Test `typing_indicators` (`crates/enclave-core/tests/client.rs`): off by default, both ways; on and off arrive in order; with a transport that drops every droppable request, the conversation continues normally afterwards; blocked contacts get none. Screenshots 47–48.

## Open questions

1. Stories (M11) need an audience model (all contacts, a list, or a group). The delivery design is not in PLAN.md.
2. "Edit" and "Delete for everyone" are advisory; the exact UI copy for the advisory nature is to be written with `17-design.md` §7.
