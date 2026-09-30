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

struct Engine {
    mode: Mode,
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

/// How a stored message reads in the conversation.
fn display(m: &enclave_core::Message) -> Msg {
    let mut text = if m.deleted {
        "This message was deleted.".to_string()
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
    }
}

fn link_error(e: &CoreError) -> String {
    use enclave_core::UsernameError as U;
    match e {
        CoreError::Username(U::Unavailable) => "Usernames aren't available on that server. Ask them for their invite link instead.".into(),
        CoreError::Username(U::NotAllowed) => "That isn't a valid username. Usernames are 3 to 32 letters, numbers or _, and start with a letter.".into(),
        CoreError::Username(U::NotFound | U::Taken) => "Nobody has that username. Check the spelling, or ask them for their invite link.".into(),
        CoreError::Username(U::Unverified) => "Enclave couldn't confirm that this username is genuine, so it didn't add anyone. Ask them for their invite link instead.".into(),
        CoreError::Link(LinkError::DeviceLinkCode) => "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.".into(),
        CoreError::Link(LinkError::NotEnclave) => "That isn't an Enclave invite link.".into(),
        CoreError::Link(LinkError::Malformed) => "This link is damaged. Ask them to send it again.".into(),
        CoreError::Link(LinkError::OwnCode) => "That's your own invite link.".into(),
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
pub async fn run(
    mode: Mode,
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
            (
                Arc::new(TcpTransport::new(HashMap::from([(id, *addr)]))),
                id,
                kt,
            )
        }
    };
    let mut e = Engine {
        mode,
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
        out,
    };
    // Reopen an existing profile.
    if let Mode::Server { profile, .. } = &e.mode
        && profile.join("profile.redb").exists()
    {
        match Client::open(e.options(), Arc::clone(&e.transport)) {
            Ok(mut c) => {
                if let Some(p) = e.kt.clone() {
                    c.set_kt_policy(p);
                }
                e.client = Some(c);
            }
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
            }
            _ = tick.tick() => {
                if e.client.is_some() {
                    e.sync().await;
                    e.push();
                } else if e.joining.is_some() {
                    e.poll_join().await;
                    e.push();
                }
            }
        }
    }
}

impl Engine {
    fn options(&self) -> Options {
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
                    passphrase: None,
                    pw_params: PwParams::FLOOR,
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

    async fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Create(name) => {
                let name = name.trim().to_string();
                match Client::create(
                    self.options(),
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
                            self.effect(Effect::UsernameClaimed);
                        }
                        Err(err) => self.username_error = username_error(&err),
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
                    self.options(),
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
            status: self.status.clone(),
            add_error: self.add_error.clone(),
            username_error: self.username_error.clone(),
            usernames: self.kt.is_some(),
            can_join: matches!(self.mode, Mode::Server { .. }),
            join_code: self.join_code.clone(),
            join_words: self.join_words.clone(),
            busy: self.busy,
            ..Default::default()
        };
        let Some(c) = self.client.as_ref() else {
            return s;
        };
        s.my_name = c.name().to_string();
        s.my_link = c.card().to_link();
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
                        let t = display(m).text;
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
                tint: tint_for(&ct.root),
                kind: 0,
                members: 0,
            };
            if self.selected == Some(ct.root) {
                s.current = Some(row.clone());
                s.messages = msgs.iter().map(display).collect();
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
                tint: tint_for(&g.id),
                kind: 1,
                members: g.members.len() as i32 + 1,
            };
            if self.selected_group == Some(g.id) {
                s.current = Some(row.clone());
                s.messages = msgs
                    .iter()
                    .map(|m| Msg {
                        text: m.text.clone(),
                        outgoing: m.from.is_none(),
                        time: clock(m.at),
                        status: if m.delivered { 1 } else { 0 },
                        sender: m.from_name.clone(),
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
