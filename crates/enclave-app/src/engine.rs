//! The engine thread: owns the `Client`, runs the foreground tick and turns
//! UI commands into protocol actions. Nothing secret crosses to the UI.

use crate::AppWindow;
use crate::view::{Msg, Row, Snapshot};
use enclave_core::{Client, ContactCard, ContactState, CoreError, Event, LinkError, Options};
use enclave_crypto::pwhash::PwParams;
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

/// UI → engine.
#[derive(Debug)]
pub enum Cmd {
    /// Create the account with this name.
    Create(String),
    /// Open a conversation (empty id closes it).
    Select(String),
    /// Send text to a contact.
    Send(String, String),
    /// Accept a message request.
    Accept(String),
    /// Delete a request or contact.
    Decline(String),
    /// Add from an invite link, with an optional first message.
    Add(String, String),
    /// "They match".
    Check(String),
    /// Privacy profile: 0 standard, 1 maximum.
    Privacy(i32),
    /// Recovery words written down.
    WordsSaved,
    /// Toggle a contact in the new-group picker.
    TogglePick(String),
    /// Create a group from the picked contacts.
    CreateGroup(String),
    /// A link code was pasted on the devices screen.
    LinkScan(String),
    /// The person picked link words (index).
    LinkPick(i32),
}

/// Where the account lives.
pub enum Mode {
    /// Everything in memory with a local server and a demo contact.
    Demo,
    /// A profile on disk talking to a dev server over TCP.
    Server {
        /// Profile directory.
        profile: PathBuf,
        /// Server address.
        addr: SocketAddr,
    },
}

const DEMO_SERVER: ServerId = [0x5e; 16];

const SAM_HELLO: &str = "Hi, I'm Sam. I'm a demo contact running on this computer, so you can try Enclave before inviting anyone. Accept to start talking.";
const SAM_REPLIES: [&str; 4] = [
    "Every message travels as a sealed unit of exactly the same size, so a server can't tell a short hello from a long letter.",
    "Try the \"Check code\" button above. With a real person you'd compare those numbers face to face or on a call.",
    "In demo mode nothing you type leaves this computer.",
    "When you're ready, share your invite link with someone you trust.",
];

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
    busy: bool,
}

/// Start the engine thread.
pub fn spawn(ui: slint::Weak<AppWindow>, mode: Mode) -> mpsc::UnboundedSender<Cmd> {
    let (tx, rx) = mpsc::unbounded_channel();
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
            rt.block_on(run(ui, mode, rx));
        })
        .ok();
    tx
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
    match e {
        CoreError::Link(LinkError::DeviceLinkCode) => "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.".into(),
        CoreError::Link(LinkError::NotEnclave) => "That isn't an Enclave invite link.".into(),
        CoreError::Link(LinkError::Malformed) => "This link is damaged. Ask them to send it again.".into(),
        CoreError::Link(LinkError::OwnCode) => "That's your own invite link.".into(),
        CoreError::Net(_) => "Couldn't reach their server. Check your connection and try again.".into(),
        _ => "Couldn't add them with this link. Ask them to send a new one.".into(),
    }
}

async fn run(ui: slint::Weak<AppWindow>, mode: Mode, mut rx: mpsc::UnboundedReceiver<Cmd>) {
    let (transport, server): (Arc<dyn Transport>, ServerId) = match &mode {
        Mode::Demo => {
            let t = LocalTransport::new();
            let _ = t.add_server(enclave_server::Config {
                id: DEMO_SERVER,
                effort_request: 4,
                effort_claim: 1,
                effort_blob: 1,
                ..Default::default()
            });
            (Arc::new(t), DEMO_SERVER)
        }
        Mode::Server { addr, .. } => {
            let id = enclave_server::Config::default().id;
            (
                Arc::new(TcpTransport::new(HashMap::from([(id, *addr)]))),
                id,
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
        busy: false,
    };
    // Reopen an existing profile.
    if let Mode::Server { profile, .. } = &e.mode
        && profile.join("profile.redb").exists()
    {
        match Client::open(e.options(), Arc::clone(&e.transport)) {
            Ok(c) => e.client = Some(c),
            Err(err) => e.status = format!("Couldn't open your profile: {err}"),
        }
        e.push(&ui);
    }
    let mut tick = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return };
                e.handle(cmd, &ui).await;
                e.push(&ui);
            }
            _ = tick.tick() => {
                if e.client.is_some() {
                    e.sync().await;
                    e.push(&ui);
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

    async fn handle(&mut self, cmd: Cmd, ui: &slint::Weak<AppWindow>) {
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
                    Ok((c, _words)) => {
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
                self.push(ui);
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
                self.push(ui);
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
                let card = match ContactCard::from_link(&link) {
                    Ok(card) => card,
                    Err(err) => {
                        self.add_error = link_error(&CoreError::Link(err));
                        return;
                    }
                };
                self.busy = true;
                self.push(ui);
                if let Some(c) = self.client.as_mut() {
                    match c.add_contact(&card, text.trim()).await {
                        Ok(()) => {
                            self.selected = Some(card.root);
                            ui.upgrade_in_event_loop(|ui| {
                                ui.set_sheet(crate::Sheet::None);
                                ui.set_add_link("".into());
                                ui.set_add_text("".into());
                            })
                            .ok();
                        }
                        Err(err) => self.add_error = link_error(&err),
                    }
                }
                self.busy = false;
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
                self.push(ui);
                if let Some(c) = self.client.as_mut() {
                    match c.create_group(name.trim(), &members).await {
                        Ok(gid) => {
                            self.picked.clear();
                            self.selected = None;
                            self.selected_group = Some(gid);
                            ui.upgrade_in_event_loop(|ui| {
                                ui.set_sheet(crate::Sheet::None);
                                ui.set_group_name("".into());
                            })
                            .ok();
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
                self.push(ui);
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

    fn push(&self, ui: &slint::Weak<AppWindow>) {
        let snap = self.snapshot();
        ui.upgrade_in_event_loop(move |ui| crate::view::apply(&ui, &snap))
            .ok();
    }

    fn snapshot(&self) -> Snapshot {
        let mut s = Snapshot {
            status: self.status.clone(),
            add_error: self.add_error.clone(),
            busy: self.busy,
            ..Default::default()
        };
        let Some(c) = self.client.as_ref() else {
            return s;
        };
        s.my_name = c.name().to_string();
        s.my_link = c.card().to_link();
        s.recovery_words = c.recovery_words().unwrap_or_default();
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
                tint: crate::view::tint_for(&ct.root),
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
                tint: crate::view::tint_for(&g.id),
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
            .map(|ct| crate::view::Pick {
                id: hex_id(&ct.root),
                name: ct.name.clone(),
                tint: crate::view::tint_for(&ct.root),
                selected: self.picked.contains(&ct.root),
            })
            .collect();
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
                (label.to_string(), format!("Added {day}"))
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
