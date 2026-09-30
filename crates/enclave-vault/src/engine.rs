//! The engine: owns the `Client`, runs the foreground tick and turns UI
//! commands into protocol actions. Its only outputs are display snapshots and
//! UI resets ([`Out`]); nothing secret crosses to the UI.

use enclave_core::{Client, ContactCard, ContactState, CoreError, Event, LinkError, Options};
use enclave_crypto::pwhash::PwParams;
use enclave_ipc::{Cmd, Device, Effect, Msg, Out, Pick, Row, Snapshot, tint_for};
use enclave_net::transport::{ServerId, TcpTransport, Transport};
use enclave_sim::LocalTransport;
use enclave_store::{FileKeystore, MemoryKeystore};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Foreground tick (docs/09-transport.md §9.4).
const TICK: Duration = Duration::from_secs(3);

/// Where the account lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Everything in memory with a local server and a demo contact.
    Demo,
    /// A profile on disk talking to a dev server over TCP.
    Server {
        /// Profile directory.
        profile: PathBuf,
        /// Server address.
        addr: SocketAddr,
        /// Key-transparency pins for usernames (written by the dev server).
        kt_pins: Option<PathBuf>,
    },
}

impl Mode {
    /// Parse `--server HOST:PORT --profile DIR [--kt-pins FILE]`; anything
    /// else is the demo.
    pub fn from_args(args: &[String]) -> Self {
        let arg = |k: &str| {
            args.iter()
                .position(|a| a == k)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        match (
            arg("--server").and_then(|s| s.parse().ok()),
            arg("--profile"),
        ) {
            (Some(addr), Some(p)) => Mode::Server {
                profile: p.into(),
                addr,
                kt_pins: arg("--kt-pins").map(Into::into),
            },
            _ => Mode::Demo,
        }
    }

    /// Inverse of [`Mode::from_args`].
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Mode::Demo => vec!["--demo".into()],
            Mode::Server {
                profile,
                addr,
                kt_pins,
            } => {
                let mut v = vec![
                    "--server".into(),
                    addr.to_string(),
                    "--profile".into(),
                    profile.display().to_string(),
                ];
                if let Some(k) = kt_pins {
                    v.push("--kt-pins".into());
                    v.push(k.display().to_string());
                }
                v
            }
        }
    }
}

const DEMO_SERVER: ServerId = [0x5e; 16];

const SAM_HELLO: &str = "Hi, I'm Sam. I'm a demo contact running on this computer, so you can try Enclave before inviting anyone. Accept to start talking.";
const SAM_REPLIES: [&str; 5] = [
    "Every message travels as a sealed unit of exactly the same size, so a server can't tell a short hello from a long letter.",
    "Try the \"Check code\" button above. With a real person you'd compare those numbers face to face or on a call.",
    "In demo mode nothing you type leaves this computer.",
    "When you're ready, share your invite link with someone you trust.",
    "People can also find you by username, if you choose one in Settings. Mine is @sam@demo.enclave.",
];

const DEMO_DOMAIN: &str = "demo.enclave";

struct Demo {
    sam: Client,
    replies: usize,
}

/// Processes the vault hands work to (`docs/15-client.md` §1.1a).
#[derive(Default)]
pub struct Helpers {
    /// netd, for the network in server mode.
    pub net: Option<Arc<dyn Transport>>,
    /// mediad, for pictures (in-process decoding when absent).
    pub media: Option<crate::media::Media>,
}

/// Longest side of a preview sent to the UI.
const PREVIEW_SIDE: u16 = 560;
/// Largest attachment downloaded on its own for a preview.
const PREVIEW_MAX_BYTES: u64 = 16 << 20;

struct Engine {
    mode: Mode,
    media: crate::media::Media,
    /// Previews already sent to the UI (conversation, message position).
    previews: std::collections::HashSet<(String, u64)>,
    transport: Arc<dyn Transport>,
    server: ServerId,
    client: Option<Client>,
    demo: Option<Demo>,
    selected: Option<[u8; 64]>,
    selected_group: Option<[u8; 32]>,
    picked: BTreeSet<[u8; 64]>,
    link_offer: Option<enclave_core::LinkOffer>,
    link_status: String,
    status: String,
    add_error: String,
    username_error: String,
    kt: Option<enclave_core::KtPolicy>,
    /// This device, while it is being linked to an existing account.
    joining: Option<enclave_core::LinkingDevice>,
    join_code: String,
    join_words: String,
    busy: bool,
    /// The recovery sheet is open: only then do the words leave the vault.
    reveal_words: bool,
    /// The profile on disk needs its passphrase to open.
    locked: bool,
    unlock_error: String,
    /// The open profile has a passphrase (so "Lock now" makes sense).
    passphrase_set: bool,
    search: String,
    username_problem: String,
    meet_code: String,
    meet_words: String,
    meet_name: String,
    meet_error: String,
    meet_done: String,
    out: mpsc::UnboundedSender<Out>,
}

/// Run the engine on a thread of this process (where a separate vault
/// process is not available). Returns the command sender and output receiver.
pub fn spawn(mode: Mode) -> (mpsc::UnboundedSender<Cmd>, mpsc::UnboundedReceiver<Out>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("enclave-engine".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(run(mode, rx, out_tx));
        })
        .ok();
    (tx, out_rx)
}

fn hex_id(root: &[u8; 64]) -> String {
    root[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn group_id_str(gid: &[u8; 32]) -> String {
    let h: String = gid[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("g{h}")
}

fn clock(at: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(at as i64, 0)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_default()
}

/// Media type from a file name (what the sender says; receivers never open
/// files by it).
fn mime_for(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Edits are allowed for 24 hours (`docs/16-features.md`).
const EDIT_WINDOW: u64 = 24 * 3600;

/// How a stored message reads in the conversation.
fn display(m: &enclave_core::Message, now: u64) -> Msg {
    let mut text = if m.deleted {
        "This message was deleted.".to_string()
    } else if m.attachment.as_ref().is_some_and(is_picture) {
        // The UI shows the picture (or its name until it arrives).
        m.text.clone()
    } else if let Some(a) = &m.attachment {
        let kind = if a.mime.starts_with("image/") {
            "Photo"
        } else {
            "File"
        };
        if m.text.is_empty() {
            format!("{kind}: {}", a.name)
        } else {
            format!("{kind}: {}\n{}", a.name, m.text)
        }
    } else {
        m.text.clone()
    };
    if m.edited && !m.deleted {
        text.push_str(" (edited)");
    }
    for r in &m.reactions {
        text.push_str(&format!("  {}", r.emoji));
    }
    // 0 sending privately, 1 on its way (accepted by their server), 2 read.
    let status = if !m.outgoing || m.read {
        2
    } else if m.delivered {
        1
    } else {
        0
    };
    let mut time = clock(m.at);
    if m.expires_secs > 0 {
        time.push_str(" · disappears");
    }
    Msg {
        text,
        outgoing: m.outgoing,
        time,
        status,
        sender: String::new(),
        seq: m.seq,
        can_edit: m.outgoing
            && !m.deleted
            && m.attachment.is_none()
            && now.saturating_sub(m.at) < EDIT_WINDOW,
        deleted: m.deleted,
        file: m
            .attachment
            .as_ref()
            .filter(|_| !m.deleted)
            .map(|a| a.name.clone())
            .unwrap_or_default(),
        image: m
            .attachment
            .as_ref()
            .is_some_and(|a| !m.deleted && is_picture(a)),
    }
}

/// An attachment we'd preview: a JPEG or PNG (by its stated type; the bytes
/// are checked again before decoding) of a size worth fetching on its own.
fn is_picture(a: &enclave_core::files::Attachment) -> bool {
    matches!(a.mime.as_str(), "image/jpeg" | "image/png") && a.size <= PREVIEW_MAX_BYTES
}

/// `name` with its extension replaced by `ext`.
fn with_extension(name: &str, ext: &str) -> String {
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    let stem = if stem.is_empty() { "picture" } else { stem };
    format!("{stem}.{ext}")
}

fn link_error(e: &CoreError) -> String {
    use enclave_core::UsernameError as U;
    match e {
        CoreError::Username(U::Unavailable) => "Usernames aren't available on that server. Ask them for their invite link instead.".into(),
        CoreError::Username(U::NotAllowed) => "That isn't a valid username. Usernames are 3 to 32 letters, numbers or _, and start with a letter.".into(),
        CoreError::Username(U::NotFound | U::Taken) => "Nobody has that username. Check the spelling, or ask them for their invite link.".into(),
        CoreError::Username(U::Unverified) => "Enclave couldn't confirm that this username is genuine, so it didn't add anyone. Ask them for their invite link instead.".into(),
        CoreError::Link(LinkError::DeviceLinkCode) => "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.".into(),
        CoreError::Link(LinkError::MeetCode) => "That's an in-person code. It only works in Meet in person, with them next to you.".into(),
        CoreError::Link(LinkError::NotEnclave) => "That isn't an Enclave invite link.".into(),
        CoreError::Link(LinkError::Malformed) => "This link is damaged. Ask them to send it again.".into(),
        CoreError::Link(LinkError::OwnCode) => "That's your own invite link.".into(),
        CoreError::Link(LinkError::InviteUsed) => "This invite link was already used, has expired or was cancelled. Ask them for a new one.".into(),
        CoreError::Net(_) => "Couldn't reach their server. Check your connection and try again.".into(),
        _ => "Couldn't add them with this link. Ask them to send a new one.".into(),
    }
}

fn username_error(e: &CoreError) -> String {
    use enclave_core::UsernameError as U;
    match e {
        CoreError::Username(U::Unavailable) => {
            "Usernames aren't available on your server yet.".into()
        }
        CoreError::Username(U::NotAllowed) => {
            "Use 3 to 32 letters, numbers or _, starting with a letter.".into()
        }
        CoreError::Username(U::Taken) => {
            "That name is taken, or looks too much like one that is. Try another.".into()
        }
        CoreError::Net(_) => {
            "Couldn't reach your server. Check your connection and try again.".into()
        }
        _ => "Couldn't claim that name. Try again in a moment.".into(),
    }
}

/// Run the engine until the command channel closes.
pub async fn run(mode: Mode, rx: mpsc::UnboundedReceiver<Cmd>, out: mpsc::UnboundedSender<Out>) {
    run_with(mode, Helpers::default(), rx, out).await;
}

/// [`run`], reaching the server in server mode through `net` (netd) instead
/// of opening connections from this process.
pub async fn run_with(
    mode: Mode,
    helpers: Helpers,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    out: mpsc::UnboundedSender<Out>,
) {
    let (transport, server, kt): (Arc<dyn Transport>, ServerId, _) = match &mode {
        Mode::Demo => {
            let t = LocalTransport::new();
            let _ = t.add_server(enclave_server::Config {
                id: DEMO_SERVER,
                effort_request: 4,
                effort_claim: 1,
                effort_blob: 1,
                effort_username: 4,
                ..Default::default()
            });
            let kt = t.enable_usernames(&DEMO_SERVER, DEMO_DOMAIN);
            (Arc::new(t), DEMO_SERVER, kt)
        }
        Mode::Server { addr, kt_pins, .. } => {
            let id = enclave_server::Config::default().id;
            let kt = kt_pins
                .as_ref()
                .and_then(|p| std::fs::read(p).ok())
                .and_then(|b| enclave_core::KtPolicy::decode(&b).ok());
            let t: Arc<dyn Transport> = match helpers.net {
                Some(t) => t,
                None => Arc::new(TcpTransport::new(HashMap::from([(id, *addr)]))),
            };
            (t, id, kt)
        }
    };
    let mut e = Engine {
        mode,
        media: helpers
            .media
            .unwrap_or_else(crate::media::Media::in_process),
        previews: std::collections::HashSet::new(),
        transport,
        server,
        client: None,
        demo: None,
        selected: None,
        selected_group: None,
        picked: BTreeSet::new(),
        link_offer: None,
        link_status: String::new(),
        status: String::new(),
        add_error: String::new(),
        username_error: String::new(),
        kt,
        joining: None,
        join_code: String::new(),
        join_words: String::new(),
        busy: false,
        reveal_words: false,
        locked: false,
        unlock_error: String::new(),
        passphrase_set: false,
        search: String::new(),
        username_problem: String::new(),
        meet_code: String::new(),
        meet_words: String::new(),
        meet_name: String::new(),
        meet_error: String::new(),
        meet_done: String::new(),
        out,
    };
    // Reopen an existing profile.
    if let Mode::Server { profile, .. } = &e.mode
        && profile.join("profile.redb").exists()
    {
        match Client::open(e.options(None), Arc::clone(&e.transport)) {
            Ok(mut c) => {
                if let Some(p) = e.kt.clone() {
                    c.set_kt_policy(p);
                }
                e.client = Some(c);
            }
            // Protected by a passphrase: ask for it.
            Err(CoreError::Store(enclave_store::StoreError::Crypto)) => e.locked = true,
            Err(err) => e.status = format!("Couldn't open your profile: {err}"),
        }
        e.push();
    }
    let mut tick = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return };
                e.handle(cmd).await;
                e.push();
                e.load_previews().await;
            }
            _ = tick.tick() => {
                if e.client.is_some() {
                    e.sync().await;
                    e.push();
                    e.load_previews().await;
                } else if e.joining.is_some() {
                    e.poll_join().await;
                    e.push();
                }
            }
        }
    }
}

impl Engine {
    /// Storage options; `passphrase` applies to profiles on disk (the demo
    /// lives in memory).
    fn options(&self, passphrase: Option<&str>) -> Options {
        let passphrase = passphrase
            .filter(|p| !p.is_empty())
            .map(|p| zeroize::Zeroizing::new(p.as_bytes().to_vec()));
        match &self.mode {
            Mode::Demo => Options {
                path: None,
                keystore: Arc::new(MemoryKeystore::default()),
                passphrase: None,
                pw_params: PwParams::FLOOR,
            },
            Mode::Server { profile, .. } => {
                let _ = std::fs::create_dir_all(profile);
                let keystore: Arc<dyn enclave_store::Keystore> =
                    match FileKeystore::new(profile.join("keys")) {
                        Ok(k) => Arc::new(k),
                        Err(_) => Arc::new(MemoryKeystore::default()),
                    };
                Options {
                    path: Some(profile.join("profile.redb")),
                    keystore,
                    passphrase,
                    // Argon2id, 1 GiB and 4 passes: seconds to unlock, slow
                    // to guess.
                    pw_params: PwParams::DESKTOP_DEFAULT,
                }
            }
        }
    }

    fn group_of(&self, id: &str) -> Option<[u8; 32]> {
        self.client
            .as_ref()?
            .groups()
            .into_iter()
            .map(|g| g.id)
            .find(|g| group_id_str(g) == id)
    }

    fn root_of(&self, id: &str) -> Option<[u8; 64]> {
        self.client
            .as_ref()?
            .contacts()
            .into_iter()
            .map(|c| c.root)
            .find(|r| hex_id(r) == id)
    }

    /// Send the UI previews of pictures in the open conversation: fetched
    /// (people we accepted only, never message requests), decoded by
    /// mediad, a few per pass.
    async fn load_previews(&mut self) {
        let (Some(root), Some(c)) = (self.selected, self.client.as_mut()) else {
            return;
        };
        if c.contact(&root).map(|ct| ct.state) != Some(enclave_core::ContactState::Accepted) {
            return;
        }
        let id = hex_id(&root);
        let Ok(msgs) = c.messages(&root) else {
            return;
        };
        let want: Vec<u64> = msgs
            .iter()
            .rev()
            .filter(|m| !m.deleted && m.attachment.as_ref().is_some_and(is_picture))
            .map(|m| m.seq)
            .filter(|s| !self.previews.contains(&(id.clone(), *s)))
            .take(4)
            .collect();
        for seq in want {
            // A download that fails is tried again next time; a picture
            // that doesn't decode is not.
            let Ok(bytes) = c.fetch_attachment(&root, seq).await else {
                continue;
            };
            self.previews.insert((id.clone(), seq));
            if enclave_media::detect(&bytes).is_none() {
                continue;
            }
            if let Ok(t) = self.media.thumbnail(bytes, PREVIEW_SIDE).await {
                let _ = self.out.send(Out::Preview(enclave_ipc::Preview {
                    conversation: id.clone(),
                    seq,
                    width: t.width,
                    height: t.height,
                    pixels: t.pixels,
                }));
            }
        }
    }

    async fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Create(name, passphrase) => {
                let name = name.trim().to_string();
                let protect = !passphrase.is_empty() && matches!(self.mode, Mode::Server { .. });
                match Client::create(
                    self.options(Some(&passphrase)),
                    Arc::clone(&self.transport),
                    self.server,
                    &name,
                )
                .await
                {
                    Ok((mut c, _words)) => {
                        if let Some(p) = self.kt.clone() {
                            c.set_kt_policy(p);
                        }
                        self.client = Some(c);
                        self.passphrase_set = protect;
                        if matches!(self.mode, Mode::Demo) {
                            self.start_demo().await;
                        }
                    }
                    Err(err) => self.status = format!("Couldn't set up your address: {err}"),
                }
            }
            Cmd::Select(id) => {
                self.selected = self.root_of(&id);
                self.selected_group = self.group_of(&id);
                if let (Some(c), Some(r)) = (self.client.as_mut(), self.selected) {
                    let _ = c.mark_read(&r).await;
                }
                if let (Some(c), Some(g)) = (self.client.as_mut(), self.selected_group) {
                    let _ = c.mark_group_read(&g);
                }
            }
            Cmd::Send(id, text) if id.starts_with('g') => {
                let Some(gid) = self.group_of(&id) else {
                    return;
                };
                self.push();
                if let Some(c) = self.client.as_mut()
                    && c.send_group_text(&gid, &text).await.is_err()
                {
                    self.status = "Couldn't send to the group yet. We'll keep trying.".into();
                }
            }
            Cmd::Send(id, text) => {
                let Some(root) = self.root_of(&id) else {
                    return;
                };
                // Show it as "sending privately" right away.
                self.push();
                if let Some(c) = self.client.as_mut()
                    && let Err(err) = c.send_text(&root, &text).await
                {
                    self.status = match err {
                        CoreError::OutOfTokens => {
                            "Waiting for them to come online before sending more.".into()
                        }
                        _ => "Couldn't send yet. We'll try again when you're back online.".into(),
                    };
                }
            }
            Cmd::Accept(id) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut())
                    && c.accept(&root).await.is_err()
                {
                    self.status = "Couldn't accept yet. Check your connection.".into();
                }
            }
            Cmd::Decline(id) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    let _ = c.remove_contact(&root);
                    self.selected = None;
                }
            }
            Cmd::Add(link, text) => {
                self.add_error.clear();
                let link = link.trim();
                self.busy = true;
                self.push();
                // An invite link, or a username to look up.
                let card = if link.starts_with("enclave:") || link.contains('#') {
                    ContactCard::from_link(link).map_err(CoreError::Link)
                } else if let Some(c) = self.client.as_mut() {
                    c.find_username(link).await
                } else {
                    Err(CoreError::NotFound)
                };
                let card = match card {
                    Ok(card) => card,
                    Err(err) => {
                        self.add_error = link_error(&err);
                        self.busy = false;
                        return;
                    }
                };
                if let Some(c) = self.client.as_mut() {
                    match c.add_contact(&card, text.trim()).await {
                        Ok(()) => {
                            self.selected = Some(card.root);
                            self.effect(Effect::ContactAdded);
                        }
                        Err(err) => self.add_error = link_error(&err),
                    }
                }
                self.busy = false;
            }
            Cmd::ClaimUsername(name) => {
                self.username_error.clear();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.claim_username(name.trim()).await {
                        Ok(_) => {
                            // A new name replaces one that stopped leading to us.
                            self.username_problem.clear();
                            self.effect(Effect::UsernameClaimed);
                        }
                        Err(err) => self.username_error = username_error(&err),
                    }
                }
                self.busy = false;
            }
            Cmd::React(id, seq, emoji) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut())
                    && c.react(&root, seq, &emoji).await.is_err()
                {
                    self.status = "Couldn't send the reaction. Check your connection.".into();
                }
            }
            Cmd::Edit(id, seq, text) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut())
                    && c.edit_message(&root, seq, text.trim()).await.is_err()
                {
                    self.status = "Couldn't edit that message. Edits work for 24 hours.".into();
                }
            }
            Cmd::Delete(id, seq) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut())
                    && c.delete_for_everyone(&root, seq).await.is_err()
                {
                    self.status = "Couldn't delete that message. Check your connection.".into();
                }
            }
            Cmd::Timer(id, secs) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut())
                    && c.set_timer(&root, secs).await.is_err()
                {
                    self.status = "Couldn't change the timer. Check your connection.".into();
                }
            }
            Cmd::SendFile(id, name, bytes, caption) => {
                self.busy = true;
                self.push();
                // Pictures are re-encoded first: what leaves is new pixels
                // only, never the original file's metadata (GPS, camera).
                let (name, mime, bytes) = if enclave_media::detect(&bytes).is_some() {
                    match self.media.sanitize(bytes).await {
                        Ok(s) => (
                            with_extension(&name, s.format.extension()),
                            s.format.mime(),
                            s.bytes,
                        ),
                        Err(_) => {
                            self.status = "Enclave couldn't read that picture, so it wasn't sent. Try another file.".into();
                            self.busy = false;
                            return;
                        }
                    }
                } else {
                    // Not a JPEG or PNG, whatever its name says.
                    let mime = match mime_for(&name) {
                        "image/jpeg" | "image/png" => "application/octet-stream",
                        m => m,
                    };
                    (name, mime, bytes)
                };
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    match c
                        .send_attachment(&root, &name, mime, &bytes, caption.trim())
                        .await
                    {
                        Ok(_) => self.effect(Effect::FileSent),
                        Err(CoreError::TooLong) => {
                            self.status = "That file is too large to send.".into();
                        }
                        Err(_) => {
                            self.status = "Couldn't send the file. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::SaveFile(id, seq) => {
                self.busy = true;
                self.push();
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    let name = c
                        .messages(&root)
                        .ok()
                        .and_then(|ms| ms.into_iter().find(|m| m.seq == seq))
                        .and_then(|m| m.attachment)
                        .map(|a| a.name)
                        .unwrap_or_else(|| "file".into());
                    match c.fetch_attachment(&root, seq).await {
                        Ok(bytes) if bytes.len() <= 15 * 1024 * 1024 => {
                            let _ = self.out.send(Out::File(name, bytes));
                        }
                        Ok(_) => {
                            self.status = "That file is too large to save from here yet.".into()
                        }
                        Err(_) => {
                            self.status =
                                "Couldn't download the file. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::StopRecovery | Cmd::ApproveRecovery => {
                let stop = cmd == Cmd::StopRecovery;
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let r = if stop {
                        c.stop_recovery().await
                    } else {
                        c.approve_recovery().await
                    };
                    self.status = match (r, stop) {
                        (Ok(()), true) => "Stopped. Your contacts won't accept that device. Choose new recovery words soon: whoever used them still has them.".into(),
                        (Ok(()), false) => "Approved. Your contacts will accept your new device now.".into(),
                        (Err(CoreError::Net(_)), _) => "Couldn't reach your server. Try again now — this matters.".into(),
                        (Err(_), _) => "Couldn't do that. Try again.".into(),
                    };
                }
                self.busy = false;
            }
            Cmd::SendHistory(hex) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let id =
                        c.devices().into_iter().map(|d| d.id).find(|d| {
                            d.iter().map(|b| format!("{b:02x}")).collect::<String>() == hex
                        });
                    if let Some(id) = id {
                        self.link_status = match c.send_history_now(&id).await {
                            Ok(()) => "Message history sent. It appears on the other device when it next connects.".into(),
                            Err(CoreError::Net(_)) => "Couldn't reach your server. Try again in a moment.".into(),
                            Err(_) => "Couldn't send message history.".into(),
                        };
                    }
                }
                self.busy = false;
            }
            Cmd::RemoveDevice(hex) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let id =
                        c.devices().into_iter().map(|d| d.id).find(|d| {
                            d.iter().map(|b| format!("{b:02x}")).collect::<String>() == hex
                        });
                    self.link_status = match id {
                        Some(id) => match c.remove_device(&id).await {
                            Ok(()) => "Removed. Your contacts will stop sending to it.".into(),
                            Err(CoreError::Net(_)) => {
                                "Couldn't reach your server. Try again in a moment.".into()
                            }
                            Err(_) => "Couldn't remove that device.".into(),
                        },
                        None => String::new(),
                    };
                }
                self.effect(Effect::RemovalDone);
                self.busy = false;
            }
            Cmd::StartJoin => {
                self.status.clear();
                match enclave_core::LinkingDevice::start(
                    self.options(None),
                    Arc::clone(&self.transport),
                    self.server,
                )
                .await
                {
                    Ok(l) => {
                        self.join_code = l.code();
                        self.joining = Some(l);
                        self.status = "Waiting for your other device…".into();
                    }
                    Err(CoreError::Net(_)) => {
                        self.status =
                            "Couldn't reach the server. Check your connection and try again."
                                .into();
                    }
                    Err(_) => self.status = "Couldn't start linking. Try again.".into(),
                }
            }
            Cmd::RevealWords(on) => self.reveal_words = on,
            Cmd::Unlock(passphrase) => {
                self.unlock_error.clear();
                self.busy = true;
                self.push();
                match Client::open(self.options(Some(&passphrase)), Arc::clone(&self.transport)) {
                    Ok(mut c) => {
                        if let Some(p) = self.kt.clone() {
                            c.set_kt_policy(p);
                        }
                        self.client = Some(c);
                        self.locked = false;
                        self.passphrase_set = true;
                    }
                    Err(CoreError::Store(enclave_store::StoreError::Crypto)) => {
                        self.unlock_error = "That passphrase doesn't open this profile.".into();
                    }
                    Err(err) => self.unlock_error = format!("Couldn't open your profile: {err}"),
                }
                self.busy = false;
            }
            Cmd::Lock if self.passphrase_set => {
                // Dropping the client drops its keys and the open database.
                self.client = None;
                self.locked = true;
                self.selected = None;
                self.selected_group = None;
                self.reveal_words = false;
                self.search.clear();
            }
            Cmd::Lock => {}
            Cmd::SetPassphrase(p) if matches!(self.mode, Mode::Server { .. }) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    let new = (!p.is_empty()).then_some(p.as_bytes());
                    match c.change_passphrase(new, PwParams::DESKTOP_DEFAULT) {
                        Ok(()) => {
                            self.passphrase_set = new.is_some();
                            self.status = if new.is_some() {
                                "Passphrase set. You'll type it each time Enclave starts.".into()
                            } else {
                                "Passphrase removed. Anyone using this computer account can open Enclave.".into()
                            };
                            self.effect(Effect::PassphraseChanged);
                        }
                        Err(err) => self.status = format!("Couldn't change the passphrase: {err}"),
                    }
                }
                self.busy = false;
            }
            Cmd::SetPassphrase(_) => {}
            Cmd::NewInvite(uses) => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.create_invite(uses).await {
                        Ok(link) => {
                            let _ = self.out.send(Out::Invite(link));
                        }
                        Err(_) => {
                            self.status =
                                "Couldn't make an invite link. Check your connection and try again."
                                    .into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::CancelInvites => {
                if let Some(c) = self.client.as_mut() {
                    self.status = match c.cancel_invites().await {
                        Ok(()) => "Your unused invite links no longer work.".into(),
                        Err(_) => "Couldn't cancel your invite links. Check your connection and try again.".into(),
                    };
                }
            }
            Cmd::Search(q) => self.search = q,
            Cmd::AddMembers(id) => {
                let members: Vec<[u8; 64]> = self.picked.iter().copied().collect();
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    match c.add_group_members(&gid, &members).await {
                        Ok(()) => self.picked.clear(),
                        Err(_) => {
                            self.status = "Couldn't add them. Check your connection.".into();
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::RemoveMember(id, member) => {
                self.busy = true;
                self.push();
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    let root = c
                        .groups()
                        .into_iter()
                        .find(|g| g.id == gid)
                        .and_then(|g| g.members.into_iter().find(|(r, _)| hex_id(r) == member))
                        .map(|(r, _)| r);
                    if let Some(root) = root
                        && c.remove_group_member(&gid, &root).await.is_err()
                    {
                        self.status = "Couldn't remove them. Check your connection.".into();
                    }
                }
                self.busy = false;
            }
            Cmd::LeaveGroup(id) => {
                if let (Some(gid), Some(c)) = (self.group_of(&id), self.client.as_mut()) {
                    if c.leave_group(&gid).await.is_ok() {
                        self.selected_group = None;
                        self.effect(Effect::LeftGroup);
                    } else {
                        self.status = "Couldn't leave the group. Check your connection.".into();
                    }
                }
            }
            Cmd::Meet(open) => {
                self.meet_words.clear();
                self.meet_name.clear();
                self.meet_error.clear();
                self.meet_done.clear();
                self.meet_code.clear();
                if let Some(c) = self.client.as_mut() {
                    c.meet_cancel();
                    if open && let Ok(code) = c.meet_code() {
                        self.meet_code = code;
                    }
                }
            }
            Cmd::MeetScan(code) => {
                self.meet_error.clear();
                if let Some(c) = self.client.as_mut() {
                    match c.meet_scan(&code) {
                        Ok(m) => {
                            self.meet_words = m.words.join(" ");
                            self.meet_name = m.name;
                        }
                        Err(CoreError::Link(LinkError::OwnCode)) => {
                            self.meet_error =
                                "That's your own code. Scan the other person's.".into();
                        }
                        Err(_) => {
                            self.meet_error = "That isn't an in-person code. Ask them to open Meet in person and show theirs.".into();
                        }
                    }
                }
            }
            Cmd::MeetConfirm => {
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.meet_confirm().await {
                        Ok(root) => {
                            self.meet_done = std::mem::take(&mut self.meet_name);
                            self.meet_words.clear();
                            self.meet_code.clear();
                            self.selected = Some(root);
                            self.selected_group = None;
                        }
                        Err(CoreError::Net(_)) => {
                            self.meet_error = "Checked, but couldn't reach the server to update your conversation. It will finish when you're back online.".into();
                        }
                        Err(_) => {
                            self.meet_error =
                                "Something went wrong. Scan each other's codes again.".into()
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::CancelJoin => {
                self.joining = None;
                self.join_code.clear();
                self.join_words.clear();
                self.status.clear();
            }
            Cmd::Check(id) => {
                if let (Some(root), Some(c)) = (self.root_of(&id), self.client.as_mut()) {
                    let _ = c.set_verified(&root, true);
                }
            }
            Cmd::Privacy(p) => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_setting("privacy", &[p as u8]);
                }
            }
            Cmd::WordsSaved => {
                if let Some(c) = self.client.as_mut() {
                    let _ = c.set_setting("recovery-saved", &[1]);
                }
            }
            Cmd::TogglePick(id) => {
                if let Some(r) = self.root_of(&id)
                    && !self.picked.remove(&r)
                {
                    self.picked.insert(r);
                }
            }
            Cmd::CreateGroup(name) => {
                let members: Vec<[u8; 64]> = self.picked.iter().copied().collect();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.create_group(name.trim(), &members).await {
                        Ok(gid) => {
                            self.picked.clear();
                            self.selected = None;
                            self.selected_group = Some(gid);
                            self.effect(Effect::GroupCreated);
                        }
                        Err(_) => {
                            self.status = "Couldn't create the group. Check your connection.".into()
                        }
                    }
                }
                self.busy = false;
            }
            Cmd::LinkScan(code) => {
                self.link_status.clear();
                self.busy = true;
                self.push();
                if let Some(c) = self.client.as_mut() {
                    match c.link_prepare(code.trim()).await {
                        Ok(offer) => self.link_offer = Some(offer),
                        Err(CoreError::TooLong) => {
                            self.link_status =
                                "You can link up to 4 devices. Remove one first.".into()
                        }
                        Err(_) => self.link_status =
                            "That code didn't work. Check that the new device is still showing it."
                                .into(),
                    }
                }
                self.busy = false;
            }
            Cmd::LinkPick(i) => {
                if let (Some(offer), Some(c)) = (self.link_offer.take(), self.client.as_mut()) {
                    self.busy = true;
                    self.link_status = match c.link_confirm(offer, i.max(0) as usize).await {
                        Ok(()) => "Linked. Your new device will finish setting up in a moment.".into(),
                        Err(CoreError::Crypto) => {
                            "Those words don't match, so nothing was linked. If you didn't start this, someone may be trying to get into your account.".into()
                        }
                        Err(_) => "Linking didn't finish. Try again from the new device.".into(),
                    };
                    self.busy = false;
                }
            }
        }
    }

    /// Advance linking this device: words to show, then the account.
    async fn poll_join(&mut self) {
        let Some(l) = self.joining.as_mut() else {
            return;
        };
        match l.poll().await {
            Ok(enclave_core::LinkProgress::Waiting) => {}
            Ok(enclave_core::LinkProgress::Words(w)) => {
                self.join_words = w.join(" ");
                self.status = "Waiting for you to pick them there…".into();
            }
            Ok(enclave_core::LinkProgress::Ready) => {
                let Some(l) = self.joining.take() else {
                    return;
                };
                self.status = "Bringing over your contacts…".into();
                match l.finish().await {
                    Ok(mut c) => {
                        if let Some(p) = self.kt.clone() {
                            c.set_kt_policy(p);
                        }
                        self.client = Some(c);
                        self.join_code.clear();
                        self.join_words.clear();
                        self.status.clear();
                    }
                    Err(_) => {
                        self.join_code.clear();
                        self.join_words.clear();
                        self.status = "Linking didn't finish. Start again on both devices.".into();
                    }
                }
            }
            Err(CoreError::Net(_)) => {
                self.status = "Couldn't reach the server. Still trying…".into();
            }
            Err(_) => {}
        }
    }

    async fn start_demo(&mut self) {
        let Some(me) = self.client.as_ref() else {
            return;
        };
        let card = me.card();
        let opts = Options {
            path: None,
            keystore: Arc::new(MemoryKeystore::default()),
            passphrase: None,
            pw_params: PwParams::FLOOR,
        };
        if let Ok((mut sam, _)) =
            Client::create(opts, Arc::clone(&self.transport), self.server, "Sam (demo)").await
            && sam.add_contact(&card, SAM_HELLO).await.is_ok()
        {
            if let Some(p) = self.kt.clone() {
                sam.set_kt_policy(p);
                let _ = sam.claim_username("sam").await;
            }
            self.demo = Some(Demo { sam, replies: 0 });
        }
    }

    async fn sync(&mut self) {
        if let Some(c) = self.client.as_mut() {
            match c.sync().await {
                Ok(events) => {
                    if !events.is_empty() {
                        self.status.clear();
                    }
                    if let Some(Event::UsernameProblem { address }) = events
                        .iter()
                        .find(|e| matches!(e, Event::UsernameProblem { .. }))
                    {
                        self.username_problem = format!("@{address}");
                    }
                    if events.contains(&Event::RemovedFromAccount) {
                        self.status = "This device was removed from your account on another device. It can't get new messages.".into();
                    }
                    if let Some(sel) = self.selected
                        && events
                            .iter()
                            .any(|e| matches!(e, Event::Message { root, .. } if *root == sel))
                    {
                        let _ = c.mark_read(&sel).await;
                    }
                    if let Some(g) = self.selected_group
                        && events.iter().any(
                            |e| matches!(e, Event::GroupMessage { group_id, .. } if *group_id == g),
                        )
                    {
                        let _ = c.mark_group_read(&g);
                    }
                }
                Err(_) => self.status = "Offline. Messages will send when you're back.".into(),
            }
        }
        if let Some(d) = self.demo.as_mut()
            && let Ok(events) = d.sam.sync().await
        {
            for ev in events {
                let (Event::Message { root, .. } | Event::Accepted { root }) = ev else {
                    continue;
                };
                let reply = SAM_REPLIES[d.replies % SAM_REPLIES.len()];
                d.replies += 1;
                let _ = d.sam.send_text(&root, reply).await;
            }
        }
    }

    fn push(&self) {
        let _ = self.out.send(Out::Snapshot(Box::new(self.snapshot())));
    }

    fn effect(&self, e: Effect) {
        let _ = self.out.send(Out::Effect(e));
    }

    fn snapshot(&self) -> Snapshot {
        let mut s = Snapshot {
            locked: self.locked,
            unlock_error: self.unlock_error.clone(),
            can_lock: self.passphrase_set && self.client.is_some(),
            status: self.status.clone(),
            add_error: self.add_error.clone(),
            username_error: self.username_error.clone(),
            username_problem: self.username_problem.clone(),
            usernames: self.kt.is_some(),
            can_join: matches!(self.mode, Mode::Server { .. }),
            join_code: self.join_code.clone(),
            join_words: self.join_words.clone(),
            meet_code: self.meet_code.clone(),
            meet_words: self.meet_words.clone(),
            meet_name: self.meet_name.clone(),
            meet_error: self.meet_error.clone(),
            meet_done: self.meet_done.clone(),
            busy: self.busy,
            ..Default::default()
        };
        let Some(c) = self.client.as_ref() else {
            return s;
        };
        let now = c.now();
        s.my_name = c.name().to_string();
        if !self.search.trim().is_empty() {
            s.search = c
                .search(&self.search, 50)
                .unwrap_or_default()
                .into_iter()
                .map(|h| {
                    let (id, kind, tint) = match h.place {
                        enclave_core::Place::Contact(r) => (hex_id(&r), 0, tint_for(&r)),
                        enclave_core::Place::Group(g) => (group_id_str(&g), 1, tint_for(&g)),
                    };
                    Row {
                        id,
                        name: h.name,
                        preview: if h.outgoing {
                            format!("You: {}", h.snippet)
                        } else {
                            h.snippet
                        },
                        time: clock(h.at),
                        state: 2,
                        tint,
                        kind,
                        ..Default::default()
                    }
                })
                .collect();
        }
        s.my_link = c.card().to_link();
        s.invites = c.invites().map(|v| v.len() as u32).unwrap_or(0);
        s.my_username = c.username().map(|u| format!("@{u}")).unwrap_or_default();
        s.recovery_alert = c
            .recovery_alert()
            .map(|a| {
                use chrono::TimeZone;
                chrono::Local
                    .timestamp_opt(a.until as i64, 0)
                    .single()
                    .map(|t| t.format("%-d %b %H:%M").to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        if self.reveal_words {
            s.recovery_words = c.recovery_words().unwrap_or_default();
        }
        s.recovery_saved = matches!(c.setting("recovery-saved"), Ok(Some(v)) if v == [1]);
        let mut rows: Vec<(u64, Row)> = Vec::new();
        for ct in c.contacts() {
            let msgs = c.messages(&ct.root).unwrap_or_default();
            let last = msgs.last();
            let row = Row {
                id: hex_id(&ct.root),
                name: ct.name.clone(),
                preview: last
                    .map(|m| {
                        let t = display(m, now).text;
                        if m.outgoing { format!("You: {t}") } else { t }
                    })
                    .unwrap_or_default(),
                time: last.map(|m| clock(m.at)).unwrap_or_default(),
                unread: ct.unread as i32,
                state: match ct.state {
                    ContactState::Pending => 0,
                    ContactState::Request => 1,
                    ContactState::Accepted => 2,
                },
                verified: ct.verified,
                met: c.met_in_person(&ct.root),
                tint: tint_for(&ct.root),
                kind: 0,
                members: 0,
            };
            if self.selected == Some(ct.root) {
                s.current = Some(row.clone());
                s.timer = ct.timer;
                s.messages = msgs.iter().map(|m| display(m, now)).collect();
                let digits: String = c
                    .security_code(&ct.root)
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect();
                s.code_groups = digits
                    .as_bytes()
                    .chunks(5)
                    .map(|g| String::from_utf8_lossy(g).into_owned())
                    .collect();
            }
            rows.push((last.map(|m| m.at).unwrap_or(ct.added_at), row));
        }
        for g in c.groups().into_iter().filter(|g| !g.left) {
            let msgs = c.group_messages(&g.id).unwrap_or_default();
            let last = msgs.last();
            let row = Row {
                id: group_id_str(&g.id),
                name: g.name.clone(),
                preview: last
                    .map(|m| {
                        if m.from.is_none() {
                            format!("You: {}", m.text)
                        } else {
                            format!("{}: {}", m.from_name, m.text)
                        }
                    })
                    .unwrap_or_else(|| "New group".into()),
                time: last.map(|m| clock(m.at)).unwrap_or_default(),
                unread: g.unread as i32,
                state: 2,
                verified: false,
                met: false,
                tint: tint_for(&g.id),
                kind: 1,
                members: g.members.len() as i32 + 1,
            };
            if self.selected_group == Some(g.id) {
                s.current = Some(row.clone());
                s.group_admin = g.admin;
                s.members = g
                    .members
                    .iter()
                    .map(|(r, name)| Row {
                        id: hex_id(r),
                        name: name.clone(),
                        state: 2,
                        verified: c.contact(r).is_some_and(|ct| ct.verified),
                        met: c.met_in_person(r),
                        tint: tint_for(r),
                        ..Default::default()
                    })
                    .collect();
                if g.admin {
                    s.addable = c
                        .contacts()
                        .into_iter()
                        .filter(|ct| {
                            ct.state == ContactState::Accepted
                                && !g.members.iter().any(|(r, _)| *r == ct.root)
                        })
                        .map(|ct| Pick {
                            id: hex_id(&ct.root),
                            name: ct.name.clone(),
                            tint: tint_for(&ct.root),
                            selected: self.picked.contains(&ct.root),
                        })
                        .collect();
                }
                s.messages = msgs
                    .iter()
                    .map(|m| Msg {
                        text: m.text.clone(),
                        outgoing: m.from.is_none(),
                        time: clock(m.at),
                        status: if m.delivered { 1 } else { 0 },
                        sender: m.from_name.clone(),
                        ..Default::default()
                    })
                    .collect();
            }
            rows.push((last.map(|m| m.at).unwrap_or(0), row));
        }
        rows.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, r) in rows {
            if r.state == 1 {
                s.requests.push(r)
            } else {
                s.contacts.push(r)
            }
        }
        s.pick = c
            .contacts()
            .into_iter()
            .filter(|ct| ct.state == ContactState::Accepted)
            .map(|ct| Pick {
                id: hex_id(&ct.root),
                name: ct.name.clone(),
                tint: tint_for(&ct.root),
                selected: self.picked.contains(&ct.root),
            })
            .collect();
        let can_link = c.can_link();
        s.devices = c
            .devices()
            .into_iter()
            .map(|d| {
                let label = if d.this_device {
                    "This device"
                } else if d.primary {
                    "First device"
                } else {
                    "Linked device"
                };
                let day = chrono::DateTime::from_timestamp(d.added_at as i64, 0)
                    .map(|t| t.format("%-d %b %Y").to_string())
                    .unwrap_or_default();
                let history_pending = can_link && !d.this_device && !c.history_sent(&d.id);
                Device {
                    id: d.id.iter().map(|b| format!("{b:02x}")).collect(),
                    label: label.to_string(),
                    detail: if history_pending {
                        format!("Added {day} · Message history follows 24 hours after linking")
                    } else {
                        format!("Added {day}")
                    },
                    removable: can_link && !d.this_device,
                    history_pending,
                }
            })
            .collect();
        s.link_choices = self
            .link_offer
            .as_ref()
            .map(|o| o.choices.iter().map(|c| c.join(" ")).collect())
            .unwrap_or_default();
        s.link_status = self.link_status.clone();
        s.can_link = c.can_link();
        s
    }
}
