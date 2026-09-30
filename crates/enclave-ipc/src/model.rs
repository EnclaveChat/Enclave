//! The messages and their encodings.

use crate::codec::{Reader, Writer};
use crate::{IpcError, Result};

/// Number of contact-art tints the UI has.
pub const TINT_COUNT: usize = 6;

/// Tint index derived from key bytes (the same key always gets the same art).
pub fn tint_for(key: &[u8]) -> usize {
    key.first().map(|b| *b as usize % TINT_COUNT).unwrap_or(0)
}

/// A conversation in the list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// Opaque id (a root or group id prefix).
    pub id: String,
    /// Name.
    pub name: String,
    /// Last message.
    pub preview: String,
    /// Time of the last message.
    pub time: String,
    /// Unread count.
    pub unread: i32,
    /// 0 waiting, 1 request, 2 talking.
    pub state: i32,
    /// Checked.
    pub verified: bool,
    /// Checked in person (bonded).
    pub met: bool,
    /// Tint index (below [`TINT_COUNT`]).
    pub tint: usize,
    /// 0 person, 1 group.
    pub kind: i32,
    /// Members (groups).
    pub members: i32,
}

/// A contact that can be picked for a new group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pick {
    /// Id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Tint.
    pub tint: usize,
    /// Picked.
    pub selected: bool,
}

/// A device of the account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Device {
    /// Hex id.
    pub id: String,
    /// "This device", "First device", "Linked device".
    pub label: String,
    /// When it was added.
    pub detail: String,
    /// This device may remove it.
    pub removable: bool,
    /// Message history hasn't been sent to it yet (and this device can send it).
    pub history_pending: bool,
}

/// A message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Msg {
    /// Text.
    pub text: String,
    /// Ours.
    pub outgoing: bool,
    /// "14:02".
    pub time: String,
    /// 0 sending, 1 on its way, 2 delivered.
    pub status: i32,
    /// Sender name (incoming group messages).
    pub sender: String,
}

/// Everything the window shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Our name.
    pub my_name: String,
    /// Invite link.
    pub my_link: String,
    /// Conversations.
    pub contacts: Vec<Row>,
    /// Message requests.
    pub requests: Vec<Row>,
    /// Selected conversation.
    pub current: Option<Row>,
    /// Its messages.
    pub messages: Vec<Msg>,
    /// Security code in groups of five digits.
    pub code_groups: Vec<String>,
    /// Status line.
    pub status: String,
    /// Recovery words: empty unless the UI asked with `RevealWords(true)`.
    pub recovery_words: Vec<String>,
    /// Recovery words saved.
    pub recovery_saved: bool,
    /// Error for the add sheet.
    pub add_error: String,
    /// A request is in flight.
    pub busy: bool,
    /// Contacts to pick for a new group.
    pub pick: Vec<Pick>,
    /// Devices.
    pub devices: Vec<Device>,
    /// Link word choices (when a link code was scanned).
    pub link_choices: Vec<String>,
    /// Link status line.
    pub link_status: String,
    /// This device can link others.
    pub can_link: bool,
    /// Our username as `@name@domain`, or empty.
    pub my_username: String,
    /// Usernames work on this server.
    pub usernames: bool,
    /// Error for the username field.
    pub username_error: String,
    /// This device can be linked to an existing account.
    pub can_join: bool,
    /// Link code this device shows while it is being linked.
    pub join_code: String,
    /// Words to pick on the other device.
    pub join_words: String,
    /// When someone else's change to this account takes effect unless it is
    /// stopped ("3 Oct 14:02"), or empty.
    pub recovery_alert: String,
    /// Our in-person code while the meet sheet is open.
    pub meet_code: String,
    /// Seal words after scanning their code.
    pub meet_words: String,
    /// Who we scanned.
    pub meet_name: String,
    /// Why their code didn't work.
    pub meet_error: String,
    /// Name of the person we just met (confirmed), or empty.
    pub meet_done: String,
}

/// UI → vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// Create the account with this name.
    Create(String),
    /// Open a conversation (empty id closes it).
    Select(String),
    /// Send text to a conversation.
    Send(String, String),
    /// Accept a message request.
    Accept(String),
    /// Delete a request or contact.
    Decline(String),
    /// Add from an invite link or username, with an optional first message.
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
    /// Claim a username.
    ClaimUsername(String),
    /// Remove a linked device (hex id).
    RemoveDevice(String),
    /// Link this device to an existing account.
    StartJoin,
    /// Stop linking this device.
    CancelJoin,
    /// Send message history to a linked device now (hex id).
    SendHistory(String),
    /// "This wasn't me": veto the pending change to this account.
    StopRecovery,
    /// "It's me": approve the pending change to this account.
    ApproveRecovery,
    /// The meet sheet opened (make a code) or closed (forget it).
    Meet(bool),
    /// Their in-person code.
    MeetScan(String),
    /// The Seal words match.
    MeetConfirm,
    /// Include the recovery words in snapshots (only while the recovery
    /// sheet is open), or stop.
    RevealWords(bool),
}

/// One-off UI resets after a request succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Close the open sheet and clear the add fields.
    ContactAdded,
    /// Close the open sheet and clear the group name.
    GroupCreated,
    /// Clear the username field.
    UsernameClaimed,
    /// Close the device-removal confirmation.
    RemovalDone,
}

/// Vault → UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// New display state.
    Snapshot(Box<Snapshot>),
    /// A one-off reset.
    Effect(Effect),
}

fn put_row(w: &mut Writer, r: &Row) {
    w.str(&r.id)
        .str(&r.name)
        .str(&r.preview)
        .str(&r.time)
        .i32(r.unread)
        .i32(r.state)
        .bool(r.verified)
        .bool(r.met)
        .u8((r.tint % TINT_COUNT) as u8)
        .i32(r.kind)
        .i32(r.members);
}

fn get_row(r: &mut Reader<'_>) -> Result<Row> {
    Ok(Row {
        id: r.str()?,
        name: r.str()?,
        preview: r.str()?,
        time: r.str()?,
        unread: r.i32()?,
        state: r.i32()?,
        verified: r.bool()?,
        met: r.bool()?,
        tint: tint(r.u8()?)?,
        kind: r.i32()?,
        members: r.i32()?,
    })
}

fn tint(v: u8) -> Result<usize> {
    let v = v as usize;
    if v < TINT_COUNT {
        Ok(v)
    } else {
        Err(IpcError::Malformed)
    }
}

fn put_rows(w: &mut Writer, rows: &[Row]) {
    w.len(rows.len());
    for r in rows {
        put_row(w, r);
    }
}

fn get_rows(r: &mut Reader<'_>) -> Result<Vec<Row>> {
    let n = r.len()?;
    (0..n).map(|_| get_row(r)).collect()
}

impl Snapshot {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.str(&self.my_name).str(&self.my_link);
        put_rows(&mut w, &self.contacts);
        put_rows(&mut w, &self.requests);
        match &self.current {
            Some(c) => {
                w.u8(1);
                put_row(&mut w, c);
            }
            None => {
                w.u8(0);
            }
        }
        w.len(self.messages.len());
        for m in &self.messages {
            w.str(&m.text)
                .bool(m.outgoing)
                .str(&m.time)
                .i32(m.status)
                .str(&m.sender);
        }
        w.strs(&self.code_groups)
            .str(&self.status)
            .strs(&self.recovery_words)
            .bool(self.recovery_saved)
            .str(&self.add_error)
            .bool(self.busy);
        w.len(self.pick.len());
        for p in &self.pick {
            w.str(&p.id)
                .str(&p.name)
                .u8((p.tint % TINT_COUNT) as u8)
                .bool(p.selected);
        }
        w.len(self.devices.len());
        for d in &self.devices {
            w.str(&d.id)
                .str(&d.label)
                .str(&d.detail)
                .bool(d.removable)
                .bool(d.history_pending);
        }
        w.strs(&self.link_choices)
            .str(&self.link_status)
            .bool(self.can_link)
            .str(&self.my_username)
            .bool(self.usernames)
            .str(&self.username_error)
            .bool(self.can_join)
            .str(&self.join_code)
            .str(&self.join_words)
            .str(&self.recovery_alert)
            .str(&self.meet_code)
            .str(&self.meet_words)
            .str(&self.meet_name)
            .str(&self.meet_error)
            .str(&self.meet_done);
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let my_name = r.str()?;
        let my_link = r.str()?;
        let contacts = get_rows(&mut r)?;
        let requests = get_rows(&mut r)?;
        let current = match r.u8()? {
            0 => None,
            1 => Some(get_row(&mut r)?),
            _ => return Err(IpcError::Malformed),
        };
        let n = r.len()?;
        let messages = (0..n)
            .map(|_| {
                Ok(Msg {
                    text: r.str()?,
                    outgoing: r.bool()?,
                    time: r.str()?,
                    status: r.i32()?,
                    sender: r.str()?,
                })
            })
            .collect::<Result<_>>()?;
        let code_groups = r.strs()?;
        let status = r.str()?;
        let recovery_words = r.strs()?;
        let recovery_saved = r.bool()?;
        let add_error = r.str()?;
        let busy = r.bool()?;
        let n = r.len()?;
        let pick = (0..n)
            .map(|_| {
                Ok(Pick {
                    id: r.str()?,
                    name: r.str()?,
                    tint: tint(r.u8()?)?,
                    selected: r.bool()?,
                })
            })
            .collect::<Result<_>>()?;
        let n = r.len()?;
        let devices = (0..n)
            .map(|_| {
                Ok(Device {
                    id: r.str()?,
                    label: r.str()?,
                    detail: r.str()?,
                    removable: r.bool()?,
                    history_pending: r.bool()?,
                })
            })
            .collect::<Result<_>>()?;
        let s = Self {
            my_name,
            my_link,
            contacts,
            requests,
            current,
            messages,
            code_groups,
            status,
            recovery_words,
            recovery_saved,
            add_error,
            busy,
            pick,
            devices,
            link_choices: r.strs()?,
            link_status: r.str()?,
            can_link: r.bool()?,
            my_username: r.str()?,
            usernames: r.bool()?,
            username_error: r.str()?,
            can_join: r.bool()?,
            join_code: r.str()?,
            join_words: r.str()?,
            recovery_alert: r.str()?,
            meet_code: r.str()?,
            meet_words: r.str()?,
            meet_name: r.str()?,
            meet_error: r.str()?,
            meet_done: r.str()?,
        };
        r.end()?;
        Ok(s)
    }
}

impl Cmd {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        match self {
            Cmd::Create(s) => w.u8(1).str(s),
            Cmd::Select(s) => w.u8(2).str(s),
            Cmd::Send(a, b) => w.u8(3).str(a).str(b),
            Cmd::Accept(s) => w.u8(4).str(s),
            Cmd::Decline(s) => w.u8(5).str(s),
            Cmd::Add(a, b) => w.u8(6).str(a).str(b),
            Cmd::Check(s) => w.u8(7).str(s),
            Cmd::Privacy(i) => w.u8(8).i32(*i),
            Cmd::WordsSaved => w.u8(9),
            Cmd::TogglePick(s) => w.u8(10).str(s),
            Cmd::CreateGroup(s) => w.u8(11).str(s),
            Cmd::LinkScan(s) => w.u8(12).str(s),
            Cmd::LinkPick(i) => w.u8(13).i32(*i),
            Cmd::ClaimUsername(s) => w.u8(14).str(s),
            Cmd::RemoveDevice(s) => w.u8(15).str(s),
            Cmd::StartJoin => w.u8(16),
            Cmd::CancelJoin => w.u8(17),
            Cmd::RevealWords(b) => w.u8(18).bool(*b),
            Cmd::SendHistory(s) => w.u8(19).str(s),
            Cmd::StopRecovery => w.u8(20),
            Cmd::ApproveRecovery => w.u8(21),
            Cmd::Meet(b) => w.u8(22).bool(*b),
            Cmd::MeetScan(s) => w.u8(23).str(s),
            Cmd::MeetConfirm => w.u8(24),
        };
        w.0
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader(b);
        let c = match r.u8()? {
            1 => Cmd::Create(r.str()?),
            2 => Cmd::Select(r.str()?),
            3 => Cmd::Send(r.str()?, r.str()?),
            4 => Cmd::Accept(r.str()?),
            5 => Cmd::Decline(r.str()?),
            6 => Cmd::Add(r.str()?, r.str()?),
            7 => Cmd::Check(r.str()?),
            8 => Cmd::Privacy(r.i32()?),
            9 => Cmd::WordsSaved,
            10 => Cmd::TogglePick(r.str()?),
            11 => Cmd::CreateGroup(r.str()?),
            12 => Cmd::LinkScan(r.str()?),
            13 => Cmd::LinkPick(r.i32()?),
            14 => Cmd::ClaimUsername(r.str()?),
            15 => Cmd::RemoveDevice(r.str()?),
            16 => Cmd::StartJoin,
            17 => Cmd::CancelJoin,
            18 => Cmd::RevealWords(r.bool()?),
            19 => Cmd::SendHistory(r.str()?),
            20 => Cmd::StopRecovery,
            21 => Cmd::ApproveRecovery,
            22 => Cmd::Meet(r.bool()?),
            23 => Cmd::MeetScan(r.str()?),
            24 => Cmd::MeetConfirm,
            _ => return Err(IpcError::Malformed),
        };
        r.end()?;
        Ok(c)
    }
}

impl Out {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Out::Snapshot(s) => [&[1u8][..], &s.encode()].concat(),
            Out::Effect(e) => vec![
                2,
                match e {
                    Effect::ContactAdded => 1,
                    Effect::GroupCreated => 2,
                    Effect::UsernameClaimed => 3,
                    Effect::RemovalDone => 4,
                },
            ],
        }
    }

    /// Decode.
    pub fn decode(b: &[u8]) -> Result<Self> {
        match b {
            [1, rest @ ..] => Ok(Out::Snapshot(Box::new(Snapshot::decode(rest)?))),
            [2, e] => Ok(Out::Effect(match e {
                1 => Effect::ContactAdded,
                2 => Effect::GroupCreated,
                3 => Effect::UsernameClaimed,
                4 => Effect::RemovalDone,
                _ => return Err(IpcError::Malformed),
            })),
            _ => Err(IpcError::Malformed),
        }
    }
}
