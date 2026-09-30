//! The client state machine.

use crate::card::{ContactCard, LinkError, MAX_NAME};
use crate::content::{Content, MAX_TEXT, Token};
use crate::persist::{
    self, NS_CONTACTS, NS_ISSUERS, NS_PROFILE, NS_REPLAY, NS_SECRETS, NS_SESSIONS, NS_SETTINGS,
    Profile,
};
use crate::rpc::Rpc;
use crate::{CoreError, Result, unix_now};
use enclave_crypto::hash::{security_code, sha3_512};
use enclave_crypto::kem::McEliecePublic;
use enclave_crypto::pwhash::PwParams;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::SealKey;
use enclave_crypto::sig::RootPublic;
use enclave_net::transport::{ServerId, Transport};
use enclave_proto::bundle::{Bundle, PrekeyStore};
use enclave_proto::envelope;
use enclave_proto::eqxdh::{self, InitiatorIdentity, Local, ManifestResolver, Mode, Peer};
use enclave_proto::identity::{AccountKeys, DeviceKeys};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_proto::ratchet::Session;
use enclave_proto::recovery::RecoverySecret;
use enclave_proto::{ProtoError, manifest::MAX_DEVICES};
use enclave_rpc::api::{
    self, DirAction, DirKind, FLAG_CREATE, FLAG_REQUEST_INBOX, device_key, manifest_key,
};
use enclave_store::{Keystore, Store};
use enclave_tokens::TokenIssuer;
use enclave_wire::{Op, RequestHeader};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Tokens handed to a contact in each hello.
const HELLO_TOKENS: usize = 16;
/// Refill once the contact has used this many tokens.
const REFILL_AFTER: u32 = 8;
/// Most tokens kept for one contact's inbox.
const MAX_HELD_TOKENS: usize = 64;
/// Keep expired prekeys this long for late initial messages.
const PREKEY_GRACE: u64 = 7 * 86_400;
/// Republish prekeys when fewer one-time prekeys than this remain.
const OPK_LOW_WATER: usize = 20;

/// Where a contact stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContactState {
    /// We sent a request; they have not answered.
    Pending,
    /// They sent us a request; we have not accepted it.
    Request,
    /// Both sides can write.
    Accepted,
}

/// A contact as the UI sees it.
#[derive(Clone)]
pub struct Contact {
    /// Root public key.
    pub root: [u8; 64],
    /// Display name (theirs, or the one on their card).
    pub name: String,
    /// State.
    pub state: ContactState,
    /// Checked in person or by comparing security codes.
    pub verified: bool,
    /// Home server.
    pub server: [u8; 16],
    /// Request inbox.
    pub request_inbox: [u8; 32],
    pub(crate) inbox: Option<[u8; 32]>,
    pub(crate) tokens: Vec<Token>,
    pub(crate) manifest: Manifest,
    pub(crate) next_seq: u64,
    pub(crate) received_since_refill: u32,
    /// Unread incoming messages.
    pub unread: u32,
    /// When the contact was added.
    pub added_at: u64,
}

impl Contact {
    /// Number of linked devices the contact has.
    pub fn device_count(&self) -> usize {
        self.manifest.devices.len()
    }
}

/// A stored message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Position in the conversation.
    pub seq: u64,
    /// Sent by us.
    pub outgoing: bool,
    /// Accepted by the recipient's server (outgoing only).
    pub delivered: bool,
    /// Unix time (local clock) when sent or received.
    pub at: u64,
    /// Text.
    pub text: String,
}

/// Something the UI should show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A stranger sent a message request.
    Request {
        /// Their root.
        root: [u8; 64],
        /// The name they gave.
        name: String,
        /// Their first message.
        text: String,
    },
    /// Someone accepted our request.
    Accepted {
        /// Their root.
        root: [u8; 64],
    },
    /// A new message.
    Message {
        /// From whom.
        root: [u8; 64],
        /// The message.
        message: Message,
    },
}

/// Where and how to keep the profile.
pub struct Options {
    /// Database file; `None` keeps everything in memory (tests).
    pub path: Option<PathBuf>,
    /// Platform keystore holding the device secret.
    pub keystore: Arc<dyn Keystore>,
    /// Optional app passphrase.
    pub passphrase: Option<Zeroizing<Vec<u8>>>,
    /// Argon2id parameters for the passphrase.
    pub pw_params: PwParams,
}

/// The client engine for one profile on one device.
pub struct Client {
    store: Store,
    rng: HedgedRng,
    rpc: Rpc,
    account: AccountKeys,
    device: DeviceKeys,
    prekeys: PrekeyStore,
    manifest: Manifest,
    profile: Profile,
    sessions: HashMap<([u8; 64], [u8; 16]), Session>,
    contacts: BTreeMap<[u8; 64], Contact>,
    issuers: HashMap<[u8; 64], TokenIssuer>,
}

/// A session is identified by the peer root and the peer device.
type SessionKey = ([u8; 64], [u8; 16]);

fn session_key(root: &[u8; 64], dev: &[u8; 16]) -> Vec<u8> {
    [&root[..], &dev[..]].concat()
}

/// Resolves the initiator's manifest from contacts or a freshly fetched copy,
/// recording what was asked for when it has neither.
struct Resolver<'a> {
    contacts: &'a BTreeMap<[u8; 64], Contact>,
    fetched: Option<Manifest>,
    wanted: Option<([u8; 64], u64, Vec<u8>)>,
}

impl ManifestResolver for Resolver<'_> {
    fn resolve(&mut self, id: &InitiatorIdentity) -> enclave_proto::Result<Manifest> {
        if let Some(m) = &self.fetched
            && m.root.0 == id.root
            && m.version == id.manifest_version
        {
            return Ok(m.clone());
        }
        if let Some(c) = self.contacts.get(&id.root)
            && c.manifest.version == id.manifest_version
        {
            return Ok(c.manifest.clone());
        }
        self.wanted = Some((id.root, id.manifest_version, id.locator.clone()));
        Err(ProtoError::Missing)
    }
}

impl Client {
    // ------------------------------------------------------------------
    // Profile lifecycle
    // ------------------------------------------------------------------

    /// Create a new account on `server` and publish it. Returns the client and
    /// the 24 recovery words (show them later, per the onboarding design).
    ///
    /// Slow: generates a Classic McEliece key and signs with SLH-DSA. Run it
    /// off the UI thread while the person types their name.
    pub async fn create(
        opts: Options,
        transport: Arc<dyn Transport>,
        server: ServerId,
        name: &str,
    ) -> Result<(Self, Vec<String>)> {
        if name.len() > MAX_NAME {
            return Err(CoreError::TooLong);
        }
        let mut rng = HedgedRng::new()?;
        let now = unix_now();
        let recovery = RecoverySecret::generate(&mut rng)?;
        let words = recovery.to_words()?;
        let account = AccountKeys::create(&recovery, &mut rng)?;
        let device = DeviceKeys::generate(&mut rng)?;
        let mut prekeys = PrekeyStore::default();
        let publication = prekeys.publish(&device, now, &mut rng)?;
        let profile = Profile {
            server,
            inbox: rng.array("core/inbox")?,
            inbox_owner: rng.array("core/inbox-owner")?,
            request_inbox: rng.array("core/request-inbox")?,
            request_owner: rng.array("core/request-owner")?,
            vault_locator: rng.array("core/vault-locator")?,
            vault_key: rng.array("core/vault-key")?,
            name: name.to_string(),
            cursor: 0,
            request_cursor: 0,
            created_at: now,
        };
        let manifest = Manifest::genesis(&account, &device, now, profile.request_inbox.to_vec());
        let signed = manifest.sign(&account, &mut rng)?;

        let mut rpc = Rpc::new(transport);
        for (addr, owner, flags) in [
            (profile.inbox, profile.inbox_owner, FLAG_CREATE),
            (
                profile.request_inbox,
                profile.request_owner,
                FLAG_CREATE | FLAG_REQUEST_INBOX,
            ),
        ] {
            let h = RequestHeader {
                op: Op::RegisterTokens,
                flags,
                mailbox: addr,
                token: owner,
            };
            let env = api::frame(&[], &mut rng)?;
            rpc.call_ok(&server, h, &env, now, &mut rng).await?;
        }
        let mk = manifest_key(&account.root_public.0);
        rpc.dir_put(
            &server,
            DirKind::Manifest,
            mk,
            [0; 32],
            &signed.to_bytes(),
            now,
            &mut rng,
        )
        .await?;
        rpc.dir_put(
            &server,
            DirKind::Bundle,
            device_key(&device.id),
            [0; 32],
            &publication.encode(),
            now,
            &mut rng,
        )
        .await?;
        let vault_owner: [u8; 32] = rng.array("core/vault-owner")?;
        let blob = persist::seal_large(
            &SealKey::from_bytes(profile.vault_key),
            &account.vault_public.0[..],
            &mut rng,
        )?;
        rpc.dir_put(
            &server,
            DirKind::Vault,
            profile.vault_locator,
            vault_owner,
            &blob,
            now,
            &mut rng,
        )
        .await?;

        let pw = opts
            .passphrase
            .as_ref()
            .map(|p| (p.as_slice(), opts.pw_params));
        let store = Store::create(opts.path.as_deref(), opts.keystore, pw, &mut rng)?;
        store.put(NS_SECRETS, b"recovery", recovery.as_bytes(), &mut rng)?;
        store.put(NS_SECRETS, b"account", &account.export_shared(), &mut rng)?;
        store.put(NS_SECRETS, b"device", &device.export(), &mut rng)?;
        store.put(NS_SECRETS, b"prekeys", &prekeys.export(), &mut rng)?;
        store.put(NS_PROFILE, b"profile", &profile.encode(), &mut rng)?;
        store.put(NS_PROFILE, b"manifest", &manifest.encode()?, &mut rng)?;

        let client = Self {
            store,
            rng,
            rpc,
            account,
            device,
            prekeys,
            manifest,
            profile,
            sessions: HashMap::new(),
            contacts: BTreeMap::new(),
            issuers: HashMap::new(),
        };
        Ok((client, words))
    }

    /// Open an existing profile.
    pub fn open(opts: Options, transport: Arc<dyn Transport>) -> Result<Self> {
        let path = opts.path.as_deref().ok_or(CoreError::NotFound)?;
        let store = Store::open(
            path,
            opts.keystore,
            opts.passphrase.as_ref().map(|p| p.as_slice()),
        )?;
        let get = |ns: &str, k: &[u8]| -> Result<Vec<u8>> {
            store.get(ns, k)?.ok_or(CoreError::NotFound)
        };
        let recovery_bytes: [u8; 32] = get(NS_SECRETS, b"recovery")?
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::NotFound)?;
        let recovery = RecoverySecret::from_bytes(recovery_bytes);
        let account = AccountKeys::import_shared(
            &Zeroizing::new(get(NS_SECRETS, b"account")?),
            Some(&recovery),
        )?;
        let device = DeviceKeys::import(&Zeroizing::new(get(NS_SECRETS, b"device")?))?;
        let prekeys = PrekeyStore::import(&Zeroizing::new(get(NS_SECRETS, b"prekeys")?))?;
        let profile = Profile::decode(&get(NS_PROFILE, b"profile")?)?;
        let manifest = Manifest::decode(&get(NS_PROFILE, b"manifest")?)?;
        let mut sessions = HashMap::new();
        for (k, v) in store.scan(NS_SESSIONS)? {
            if k.len() != 80 {
                continue;
            }
            let mut root = [0u8; 64];
            let mut dev = [0u8; 16];
            root.copy_from_slice(&k[..64]);
            dev.copy_from_slice(&k[64..]);
            sessions.insert((root, dev), Session::import(&Zeroizing::new(v))?);
        }
        let mut contacts = BTreeMap::new();
        for (_, v) in store.scan(NS_CONTACTS)? {
            let c = persist::decode_contact(&v)?;
            contacts.insert(c.root, c);
        }
        let mut issuers = HashMap::new();
        for (k, v) in store.scan(NS_ISSUERS)? {
            let root: [u8; 64] = k.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
            let b: [u8; 40] = v.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
            issuers.insert(root, TokenIssuer::from_bytes(&b));
        }
        Ok(Self {
            store,
            rng: HedgedRng::new()?,
            rpc: Rpc::new(transport),
            account,
            device,
            prekeys,
            manifest,
            profile,
            sessions,
            contacts,
            issuers,
        })
    }

    /// Crypto-erase this profile (emergency PIN, panic wipe, account deletion).
    pub fn erase(self) -> Result<()> {
        Ok(self.store.crypto_erase()?)
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Our display name.
    pub fn name(&self) -> &str {
        &self.profile.name
    }

    /// Our root public key.
    pub fn root(&self) -> [u8; 64] {
        self.account.root_public.0
    }

    /// Our contact card (for the QR code and invite link).
    pub fn card(&self) -> ContactCard {
        ContactCard {
            root: self.account.root_public.0,
            server: self.profile.server,
            request_inbox: self.profile.request_inbox,
            vault_locator: self.profile.vault_locator,
            vault_key: self.profile.vault_key,
            name: self.profile.name.clone(),
        }
    }

    /// The 24 recovery words (for the deferred "save your recovery words" card).
    pub fn recovery_words(&self) -> Result<Vec<String>> {
        let b = Zeroizing::new(
            self.store
                .get(NS_SECRETS, b"recovery")?
                .ok_or(CoreError::NotFound)?,
        );
        let arr: [u8; 32] = b.as_slice().try_into().map_err(|_| CoreError::NotFound)?;
        Ok(RecoverySecret::from_bytes(arr).to_words()?)
    }

    /// All contacts.
    pub fn contacts(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }

    /// One contact.
    pub fn contact(&self, root: &[u8; 64]) -> Option<&Contact> {
        self.contacts.get(root)
    }

    /// The 60-digit security code shared with `root`.
    pub fn security_code(&self, root: &[u8; 64]) -> String {
        security_code(&self.account.root_public.0, root)
    }

    /// Messages with `root`, oldest first.
    pub fn messages(&self, root: &[u8; 64]) -> Result<Vec<Message>> {
        let mut v: Vec<Message> = self
            .store
            .scan(&persist::msg_ns(root))?
            .into_iter()
            .filter_map(|(_, b)| persist::decode_message(&b).ok())
            .collect();
        v.sort_by_key(|m| m.seq);
        Ok(v)
    }

    /// Whether every session with `root` has completed the post-quantum
    /// authentication round trip and uses all three KEMs.
    pub fn fully_protected(&self, root: &[u8; 64]) -> bool {
        let mut any = false;
        for ((r, _), s) in &self.sessions {
            if r == root {
                any = true;
                if !(s.three_kem() && s.pq_authenticated()) {
                    return false;
                }
            }
        }
        any
    }

    // ------------------------------------------------------------------
    // Commands
    // ------------------------------------------------------------------

    /// Store an app setting (sealed like everything else).
    pub fn set_setting(&mut self, key: &str, value: &[u8]) -> Result<()> {
        Ok(self
            .store
            .put(NS_SETTINGS, key.as_bytes(), value, &mut self.rng)?)
    }

    /// Read an app setting.
    pub fn setting(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(NS_SETTINGS, key.as_bytes())?)
    }

    /// Mark a contact as checked (or not).
    pub fn set_verified(&mut self, root: &[u8; 64], verified: bool) -> Result<()> {
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.verified = verified;
        let c = c.clone();
        self.save_contact(&c)
    }

    /// Mark a conversation as read.
    pub fn mark_read(&mut self, root: &[u8; 64]) -> Result<()> {
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.unread = 0;
        let c = c.clone();
        self.save_contact(&c)
    }

    /// Add someone from their card and send a first message. Fetches and
    /// verifies their manifest, McEliece vault key and a bundle per device.
    pub async fn add_contact(&mut self, card: &ContactCard, text: &str) -> Result<()> {
        if card.root == self.account.root_public.0 {
            return Err(LinkError::OwnCode.into());
        }
        if text.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        if self.contacts.contains_key(&card.root) {
            return Ok(());
        }
        let now = unix_now();
        let server = card.server;
        let mb = self
            .rpc
            .dir_get(
                &server,
                DirKind::Manifest,
                DirAction::Get,
                manifest_key(&card.root),
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        let peer_manifest = SignedManifest::from_bytes(&mb)?.verify(&RootPublic(card.root), now)?;
        let vb = self
            .rpc
            .dir_get(
                &server,
                DirKind::Vault,
                DirAction::Get,
                card.vault_locator,
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        let vault = McEliecePublic::from_slice(&persist::open_large(
            &SealKey::from_bytes(card.vault_key),
            &vb,
        )?)?;
        if sha3_512(&vault.0[..]) != peer_manifest.vault_hash {
            return Err(ProtoError::BadSignature.into());
        }

        let tokens = self.issue_tokens(&card.root, HELLO_TOKENS, now).await?;
        let hello = Content::Hello {
            server: self.profile.server,
            inbox: self.profile.inbox,
            tokens,
            name: self.profile.name.clone(),
            text: text.to_string(),
        }
        .encode()?;

        let contact = Contact {
            root: card.root,
            name: card.name.clone(),
            state: ContactState::Pending,
            verified: false,
            server,
            request_inbox: card.request_inbox,
            inbox: None,
            tokens: Vec::new(),
            manifest: peer_manifest.clone(),
            next_seq: 0,
            received_since_refill: 0,
            unread: 0,
            added_at: now,
        };
        self.contacts.insert(card.root, contact.clone());
        self.save_contact(&contact)?;
        if !text.is_empty() {
            self.store_message(&card.root, true, text, now)?;
        }

        for dev in peer_manifest.devices.iter().take(MAX_DEVICES) {
            let bb = self
                .rpc
                .claim_bundle(&server, device_key(&dev.id), now, &mut self.rng)
                .await?;
            let bundle = Bundle::decode(&bb)?;
            bundle.verify(&dev.signing, now)?;
            let (session, env) = {
                let local = Local {
                    account: &self.account,
                    device: &self.device,
                    manifest: &self.manifest,
                    locator: &self.profile.server,
                };
                let peer = Peer {
                    manifest: &peer_manifest,
                    device: dev,
                    bundle: &bundle,
                    vault: Some(&vault),
                };
                let init = eqxdh::initiate(&local, &peer, Mode::OffTheRecord, None, &mut self.rng)?;
                let mut session = init.session;
                let env =
                    envelope::seal_request(&init.message, &mut session, &hello, &mut self.rng)?;
                (session, env)
            };
            // Persist before the envelope leaves.
            self.save_session(&card.root, &dev.id, &session)?;
            self.sessions.insert((card.root, dev.id), session);
            self.rpc
                .write_request(&server, card.request_inbox, &env, now, &mut self.rng)
                .await?;
        }
        Ok(())
    }

    /// Accept a message request: give them our inbox and write tokens.
    pub async fn accept(&mut self, root: &[u8; 64]) -> Result<()> {
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Request {
            return Ok(());
        }
        let now = unix_now();
        let tokens = self.issue_tokens(root, HELLO_TOKENS, now).await?;
        let hello = Content::Hello {
            server: self.profile.server,
            inbox: self.profile.inbox,
            tokens,
            name: self.profile.name.clone(),
            text: String::new(),
        };
        self.send_content(root, &hello, now).await?;
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        c.state = ContactState::Accepted;
        let c = c.clone();
        self.save_contact(&c)
    }

    /// Delete a contact (declining a request, blocking). Their sessions and
    /// history are removed; they get no new tokens.
    pub fn remove_contact(&mut self, root: &[u8; 64]) -> Result<()> {
        self.contacts.remove(root);
        self.issuers.remove(root);
        self.store.delete(NS_CONTACTS, root)?;
        self.store.delete(NS_ISSUERS, root)?;
        let devs: Vec<[u8; 16]> = self
            .sessions
            .keys()
            .filter(|(r, _)| r == root)
            .map(|(_, d)| *d)
            .collect();
        for d in devs {
            self.sessions.remove(&(*root, d));
            self.store.delete(NS_SESSIONS, &session_key(root, &d))?;
        }
        let ns = persist::msg_ns(root);
        for (k, _) in self.store.scan(&ns)? {
            self.store.delete(&ns, &k)?;
        }
        Ok(())
    }

    /// Send a text message.
    pub async fn send_text(&mut self, root: &[u8; 64], text: &str) -> Result<Message> {
        if text.len() > MAX_TEXT {
            return Err(CoreError::TooLong);
        }
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state != ContactState::Accepted {
            return Err(CoreError::NotAccepted);
        }
        let now = unix_now();
        let tokens = if c.received_since_refill >= REFILL_AFTER {
            let n = refill_size(c.received_since_refill);
            self.issue_tokens(root, n, now).await?
        } else {
            Vec::new()
        };
        let refilled = !tokens.is_empty();
        let mut msg = self.store_message(root, true, text, now)?;
        self.send_content(
            root,
            &Content::Text {
                tokens,
                text: text.to_string(),
            },
            now,
        )
        .await?;
        if refilled && let Some(c) = self.contacts.get_mut(root) {
            c.received_since_refill = 0;
            let c = c.clone();
            self.save_contact(&c)?;
        }
        msg.delivered = true;
        self.store.put(
            &persist::msg_ns(root),
            &msg.seq.to_be_bytes(),
            &persist::encode_message(&msg),
            &mut self.rng,
        )?;
        Ok(msg)
    }

    /// Fetch and process everything waiting in our inboxes, refill tokens and
    /// maintain prekeys. Returns what the UI should show.
    pub async fn sync(&mut self) -> Result<Vec<Event>> {
        let now = unix_now();
        let mut events = Vec::new();

        let server = self.profile.server;
        let reqs = self
            .rpc
            .poll(
                &server,
                self.profile.request_inbox,
                &self.profile.request_owner,
                self.profile.request_cursor,
                now,
                &mut self.rng,
            )
            .await?;
        for (env, cursor) in reqs {
            match self.handle_request(&env, now).await {
                Ok(Some(e)) => events.push(e),
                Ok(None) => {}
                // Network trouble: stop here and retry this envelope next time.
                Err(e @ CoreError::Net(_)) => {
                    self.save_profile()?;
                    return Err(e);
                }
                // Anything else is a bad or foreign envelope: skip it.
                Err(_) => {}
            }
            self.profile.request_cursor = cursor;
            self.save_profile()?;
        }

        let msgs = self
            .rpc
            .poll(
                &server,
                self.profile.inbox,
                &self.profile.inbox_owner,
                self.profile.cursor,
                now,
                &mut self.rng,
            )
            .await?;
        for (env, cursor) in msgs {
            if let Ok(mut e) = self.handle_direct(&env, now) {
                events.append(&mut e);
            }
            self.profile.cursor = cursor;
            self.save_profile()?;
        }

        // Token refills for contacts who have been writing without replies.
        let due: Vec<([u8; 64], usize)> = self
            .contacts
            .values()
            .filter(|c| {
                c.state == ContactState::Accepted && c.received_since_refill >= REFILL_AFTER + 4
            })
            .map(|c| (c.root, refill_size(c.received_since_refill)))
            .collect();
        for (root, n) in due {
            let tokens = self.issue_tokens(&root, n, now).await?;
            self.send_content(&root, &Content::Tokens(tokens), now)
                .await?;
            if let Some(c) = self.contacts.get_mut(&root) {
                c.received_since_refill = 0;
                let c = c.clone();
                self.save_contact(&c)?;
            }
        }

        self.maintain_prekeys(now).await?;
        Ok(events)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    async fn handle_request(&mut self, env: &[u8], now: u64) -> Result<Option<Event>> {
        let msg = envelope::request_initial(env)?;
        if !self.prekeys.signed.contains_key(&msg.spk_id) {
            return Ok(None);
        }
        let rid = msg.replay_id();
        if self.store.get(NS_REPLAY, &rid)?.is_some() {
            return Ok(None);
        }
        let mut fetched: Option<Manifest> = None;
        let resp = loop {
            let (result, wanted) = {
                let local = Local {
                    account: &self.account,
                    device: &self.device,
                    manifest: &self.manifest,
                    locator: &self.profile.server,
                };
                let mut resolver = Resolver {
                    contacts: &self.contacts,
                    fetched: fetched.clone(),
                    wanted: None,
                };
                let r = eqxdh::respond(
                    &local,
                    &mut self.prekeys,
                    &msg,
                    None,
                    &mut resolver,
                    &mut self.rng,
                );
                (r, resolver.wanted)
            };
            match (result, wanted) {
                (Ok(r), _) => break r,
                (Err(ProtoError::Missing), Some((root, version, locator))) if fetched.is_none() => {
                    let server: ServerId = locator
                        .as_slice()
                        .try_into()
                        .map_err(|_| ProtoError::Decode)?;
                    let mb = self
                        .rpc
                        .dir_get(
                            &server,
                            DirKind::Manifest,
                            DirAction::Get,
                            manifest_key(&root),
                            [0; 32],
                            now,
                            &mut self.rng,
                        )
                        .await?;
                    let m = SignedManifest::from_bytes(&mb)?.verify(&RootPublic(root), now)?;
                    if m.version != version {
                        return Err(ProtoError::Rollback.into());
                    }
                    if let Some(c) = self.contacts.get(&root)
                        && c.manifest.version > m.version
                    {
                        return Err(ProtoError::Rollback.into());
                    }
                    fetched = Some(m);
                }
                (Err(e), _) => return Err(e.into()),
            }
        };
        let mut session = resp.session;
        let content = Content::decode(&envelope::open_request(&mut session, env, &mut self.rng)?)?;
        let Content::Hello {
            server,
            inbox,
            tokens,
            name,
            text,
        } = content
        else {
            return Err(ProtoError::Decode.into());
        };
        let root = resp.identity.root;
        if root == self.account.root_public.0 {
            return Ok(None);
        }
        // Commit: replay marker, consumed prekey, session. If both sides
        // started a session with each other at once, both keep the one the
        // lower root initiated, so they end up with the same pair.
        self.store
            .put(NS_REPLAY, &rid, &now.to_be_bytes(), &mut self.rng)?;
        self.save_prekeys()?;
        let sk = (root, resp.identity.device);
        let keep_ours = self.account.root_public.0 < root
            && self
                .sessions
                .get(&sk)
                .is_some_and(|s| s.role() == enclave_proto::ratchet::Role::Initiator);
        if !keep_ours {
            self.save_session(&root, &resp.identity.device, &session)?;
            self.sessions.insert(sk, session);
        }

        let name = sanitize_name(&name);
        let (event, contact) = match self.contacts.get(&root).cloned() {
            Some(mut c) => {
                // A known contact: a new device of theirs, or both sides added
                // each other at once.
                if resp.manifest.version > c.manifest.version {
                    c.manifest = resp.manifest.clone();
                }
                c.server = server;
                c.inbox = Some(inbox);
                add_tokens(&mut c.tokens, tokens);
                let ev = if c.state == ContactState::Pending {
                    c.state = ContactState::Accepted;
                    Some(Event::Accepted { root })
                } else {
                    None
                };
                (ev, c)
            }
            None => {
                let c = Contact {
                    root,
                    name: name.clone(),
                    state: ContactState::Request,
                    verified: false,
                    server,
                    request_inbox: request_inbox_of(&resp.manifest),
                    inbox: Some(inbox),
                    tokens: tokens.into_iter().take(MAX_HELD_TOKENS).collect(),
                    manifest: resp.manifest.clone(),
                    next_seq: 0,
                    received_since_refill: 0,
                    unread: 0,
                    added_at: now,
                };
                (
                    Some(Event::Request {
                        root,
                        name,
                        text: text.clone(),
                    }),
                    c,
                )
            }
        };
        let mut contact = contact;
        if !text.is_empty() {
            contact.unread = contact.unread.saturating_add(1);
        }
        self.contacts.insert(root, contact.clone());
        self.save_contact(&contact)?;
        if !text.is_empty() {
            let m = self.store_message(&root, false, &text, now)?;
            if event.is_none() {
                return Ok(Some(Event::Message { root, message: m }));
            }
        }
        Ok(event)
    }

    fn handle_direct(&mut self, env: &[u8], now: u64) -> Result<Vec<Event>> {
        let (key, content) = {
            let (keys, mut refs): (Vec<SessionKey>, Vec<&mut Session>) =
                self.sessions.iter_mut().map(|(k, s)| (*k, s)).unzip();
            let opened =
                envelope::open_direct(&mut refs, env, Some(&self.account.vault), &mut self.rng)?;
            (keys[opened.session_index], opened.content)
        };
        let (root, dev) = key;
        if let Some(s) = self.sessions.get(&key) {
            let s = s.clone();
            self.save_session(&root, &dev, &s)?;
        }
        let mut c = self
            .contacts
            .get(&root)
            .cloned()
            .ok_or(CoreError::NotFound)?;
        let mut events = Vec::new();
        let text = match Content::decode(&content)? {
            Content::Hello {
                server,
                inbox,
                tokens,
                name,
                text,
            } => {
                c.server = server;
                c.inbox = Some(inbox);
                c.name = sanitize_name(&name);
                add_tokens(&mut c.tokens, tokens);
                if c.state == ContactState::Pending {
                    c.state = ContactState::Accepted;
                    events.push(Event::Accepted { root });
                }
                text
            }
            Content::Text { tokens, text } => {
                add_tokens(&mut c.tokens, tokens);
                c.received_since_refill = c.received_since_refill.saturating_add(1);
                text
            }
            Content::Tokens(tokens) => {
                add_tokens(&mut c.tokens, tokens);
                c.received_since_refill = c.received_since_refill.saturating_add(1);
                String::new()
            }
        };
        if !text.is_empty() {
            c.unread = c.unread.saturating_add(1);
        }
        self.contacts.insert(root, c.clone());
        self.save_contact(&c)?;
        if !text.is_empty() {
            let m = self.store_message(&root, false, &text, now)?;
            events.push(Event::Message { root, message: m });
        }
        Ok(events)
    }

    async fn send_content(&mut self, root: &[u8; 64], content: &Content, now: u64) -> Result<()> {
        let bytes = content.encode()?;
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        let inbox = c.inbox.ok_or(CoreError::NotAccepted)?;
        let server = c.server;
        let token = c.tokens.pop().ok_or(CoreError::OutOfTokens)?;
        let c = c.clone();
        // The token is spent whatever happens next.
        self.save_contact(&c)?;

        let env = {
            let (keys, mut refs): (Vec<SessionKey>, Vec<&mut Session>) = self
                .sessions
                .iter_mut()
                .filter(|((r, _), s)| r == root && s.can_send())
                .take(MAX_DEVICES)
                .map(|(k, s)| (*k, s))
                .unzip();
            if refs.is_empty() {
                return Err(CoreError::NotAccepted);
            }
            let carrier = refs.iter().position(|s| s.wants_pq_slot());
            let env = envelope::seal_direct(&mut refs, &bytes, carrier, &mut self.rng)?;
            drop(refs);
            for k in keys {
                if let Some(s) = self.sessions.get(&k) {
                    let s = s.clone();
                    self.save_session(&k.0, &k.1, &s)?;
                }
            }
            env
        };
        let h = RequestHeader {
            op: Op::Write,
            flags: 0,
            mailbox: inbox,
            token,
        };
        self.rpc
            .call_ok(&server, h, &env, now, &mut self.rng)
            .await?;
        Ok(())
    }

    async fn issue_tokens(&mut self, root: &[u8; 64], n: usize, now: u64) -> Result<Vec<Token>> {
        if !self.issuers.contains_key(root) {
            let issuer = TokenIssuer::new(&mut self.rng)?;
            self.issuers.insert(*root, issuer);
        }
        let issuer = self.issuers.get_mut(root).ok_or(CoreError::NotFound)?;
        let (toks, hashes) = issuer.issue(n);
        let bytes = issuer.to_bytes();
        self.store.put(NS_ISSUERS, root, &bytes, &mut self.rng)?;
        let batch = enclave_tokens::registration_batch(&hashes, n / 2, &mut self.rng)?;
        let payload = api::frame(&batch.concat(), &mut self.rng)?;
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: 0,
            mailbox: self.profile.inbox,
            token: self.profile.inbox_owner,
        };
        self.rpc
            .call_ok(&self.profile.server, h, &payload, now, &mut self.rng)
            .await?;
        Ok(toks)
    }

    async fn maintain_prekeys(&mut self, now: u64) -> Result<()> {
        self.prekeys.expire(now, PREKEY_GRACE);
        let latest = self
            .prekeys
            .signed
            .values()
            .map(|(_, exp)| *exp)
            .max()
            .unwrap_or(0);
        if self.prekeys.one_time.len() >= OPK_LOW_WATER && latest > now + 2 * 86_400 {
            return Ok(());
        }
        let publication = self.prekeys.publish(&self.device, now, &mut self.rng)?;
        self.save_prekeys()?;
        let server = self.profile.server;
        self.rpc
            .dir_put(
                &server,
                DirKind::Bundle,
                device_key(&self.device.id),
                [0; 32],
                &publication.encode(),
                now,
                &mut self.rng,
            )
            .await
    }

    fn store_message(
        &mut self,
        root: &[u8; 64],
        outgoing: bool,
        text: &str,
        now: u64,
    ) -> Result<Message> {
        let c = self.contacts.get_mut(root).ok_or(CoreError::NotFound)?;
        let seq = c.next_seq;
        c.next_seq += 1;
        let c = c.clone();
        self.save_contact(&c)?;
        let m = Message {
            seq,
            outgoing,
            delivered: false,
            at: now,
            text: text.to_string(),
        };
        self.store.put(
            &persist::msg_ns(root),
            &seq.to_be_bytes(),
            &persist::encode_message(&m),
            &mut self.rng,
        )?;
        Ok(m)
    }

    fn save_contact(&mut self, c: &Contact) -> Result<()> {
        Ok(self.store.put(
            NS_CONTACTS,
            &c.root,
            &persist::encode_contact(c)?,
            &mut self.rng,
        )?)
    }

    fn save_session(&mut self, root: &[u8; 64], dev: &[u8; 16], s: &Session) -> Result<()> {
        Ok(self.store.put(
            NS_SESSIONS,
            &session_key(root, dev),
            &s.export(),
            &mut self.rng,
        )?)
    }

    fn save_prekeys(&mut self) -> Result<()> {
        Ok(self.store.put(
            NS_SECRETS,
            b"prekeys",
            &self.prekeys.export(),
            &mut self.rng,
        )?)
    }

    fn save_profile(&mut self) -> Result<()> {
        Ok(self.store.put(
            NS_PROFILE,
            b"profile",
            &self.profile.encode(),
            &mut self.rng,
        )?)
    }
}

fn add_tokens(held: &mut Vec<Token>, new: Vec<Token>) {
    held.extend(new);
    if held.len() > MAX_HELD_TOKENS {
        let excess = held.len() - MAX_HELD_TOKENS;
        held.drain(..excess);
    }
}

/// A refill replaces every token the contact used since the last one.
fn refill_size(used: u32) -> usize {
    (used as usize).clamp(1, crate::content::MAX_TOKENS)
}

fn request_inbox_of(m: &Manifest) -> [u8; 32] {
    let mut out = [0u8; 32];
    if m.request_inbox.len() == 32 {
        out.copy_from_slice(&m.request_inbox);
    }
    out
}

/// Names from other people: strip control and bidi-override characters and
/// cap combining marks, so a name cannot spoof layout (`docs/15-client.md`).
fn sanitize_name(name: &str) -> String {
    let mut out = String::new();
    let mut combining = 0;
    for ch in name.chars() {
        let c = ch as u32;
        let bidi = matches!(c, 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x061C);
        if ch.is_control() || bidi {
            continue;
        }
        let is_combining = matches!(c, 0x0300..=0x036F | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F);
        if is_combining {
            combining += 1;
            if combining > 8 {
                continue;
            }
        } else {
            combining = 0;
        }
        out.push(ch);
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        "Unnamed".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name("Sam\u{202E}evil"), "Samevil");
        assert_eq!(sanitize_name("  \u{0007} "), "Unnamed");
        let zalgo: String = std::iter::once('a')
            .chain(std::iter::repeat_n('\u{0301}', 30))
            .collect();
        assert_eq!(sanitize_name(&zalgo).chars().count(), 9);
    }

    #[test]
    fn held_tokens_are_capped() {
        let mut held = vec![[1u8; 32]; MAX_HELD_TOKENS];
        add_tokens(&mut held, vec![[2u8; 32]; 3]);
        assert_eq!(held.len(), MAX_HELD_TOKENS);
        assert_eq!(held.pop().map(|t| t[0]), Some(2));
    }
}
