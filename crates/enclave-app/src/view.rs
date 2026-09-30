//! Display data: plain `Send` structs built by the engine and turned into
//! Slint models on the UI thread.

use crate::{AppWindow, ContactRow, DeviceRow, MessageRow, PickRow, Screen};
use slint::{Color, Image, ModelRc, Rgb8Pixel, SharedPixelBuffer, SharedString, VecModel};
use std::rc::Rc;

/// Contact art tints: muted, each at least 7:1 against the Paper initials.
const TINTS: [(u8, u8, u8); 6] = [
    (0x3F, 0x5A, 0x7A),
    (0x6B, 0x4E, 0x2E),
    (0x7A, 0x3F, 0x5A),
    (0x4E, 0x5F, 0x2E),
    (0x2E, 0x5F, 0x6B),
    (0x6B, 0x2E, 0x2E),
];

/// A contact for display.
#[derive(Clone, Debug, Default)]
pub struct Row {
    /// Hex id (root prefix).
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
    /// Tint index from the key.
    pub tint: usize,
    /// 0 person, 1 group.
    pub kind: i32,
    /// Members (groups).
    pub members: i32,
}

/// A contact that can be picked for a new group.
#[derive(Clone, Debug, Default)]
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

/// A message for display.
#[derive(Clone, Debug, Default)]
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
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Our name.
    pub my_name: String,
    /// Invite link.
    pub my_link: String,
    /// Conversations.
    pub contacts: Vec<Row>,
    /// Message requests.
    pub requests: Vec<Row>,
    /// Selected contact.
    pub current: Option<Row>,
    /// Its messages.
    pub messages: Vec<Msg>,
    /// Security code in groups of five digits.
    pub code_groups: Vec<String>,
    /// Status line under the list.
    pub status: String,
    /// Recovery words.
    pub recovery_words: Vec<String>,
    /// Recovery words saved.
    pub recovery_saved: bool,
    /// Error for the add sheet.
    pub add_error: String,
    /// A request is in flight.
    pub busy: bool,
    /// Contacts to pick for a new group.
    pub pick: Vec<Pick>,
    /// Devices: (label, detail).
    pub devices: Vec<(String, String)>,
    /// Link word choices (when a link code was scanned).
    pub link_choices: Vec<String>,
    /// Link status line.
    pub link_status: String,
    /// This device can link others.
    pub can_link: bool,
}

/// Initials for contact art: first letters of up to two words.
pub fn initials(name: &str) -> String {
    let s: String = name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect();
    if s.is_empty() {
        "?".into()
    } else {
        s.to_uppercase()
    }
}

/// Tint index derived from key bytes.
pub fn tint_for(key: &[u8]) -> usize {
    key.first().map(|b| *b as usize % TINTS.len()).unwrap_or(0)
}

fn tint(i: usize) -> Color {
    let (r, g, b) = TINTS[i % TINTS.len()];
    Color::from_rgb_u8(r, g, b)
}

fn row(r: &Row) -> ContactRow {
    ContactRow {
        id: r.id.clone().into(),
        name: r.name.clone().into(),
        initials: initials(&r.name).into(),
        tint: tint(r.tint),
        preview: r.preview.clone().into(),
        time: r.time.clone().into(),
        unread: r.unread,
        state: r.state,
        verified: r.verified,
        kind: r.kind,
        members: r.members,
    }
}

fn strings(v: &[String]) -> ModelRc<SharedString> {
    ModelRc::from(Rc::new(VecModel::from(
        v.iter().map(SharedString::from).collect::<Vec<_>>(),
    )))
}

/// A QR code as a Slint image (Ink modules on white, 4-module quiet zone).
pub fn qr_image(text: &str) -> Image {
    let Ok(qr) = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium) else {
        return Image::default();
    };
    let border = 4;
    let size = (qr.size() + 2 * border) as u32;
    let mut buf = SharedPixelBuffer::<Rgb8Pixel>::new(size, size);
    let px = buf.make_mut_slice();
    for y in 0..size as i32 {
        for x in 0..size as i32 {
            let dark = qr.get_module(x - border, y - border);
            let c = if dark {
                Rgb8Pixel::new(0x1C, 0x1F, 0x1D)
            } else {
                Rgb8Pixel::new(0xFF, 0xFF, 0xFF)
            };
            px[(y as u32 * size + x as u32) as usize] = c;
        }
    }
    Image::from_rgb8(buf)
}

/// Push a snapshot into the window.
pub fn apply(ui: &AppWindow, s: &Snapshot) {
    ui.set_my_name(s.my_name.clone().into());
    ui.set_my_initials(initials(&s.my_name).into());
    if ui.get_my_link().as_str() != s.my_link {
        ui.set_my_link(s.my_link.clone().into());
        ui.set_my_qr(qr_image(&s.my_link));
    }
    ui.set_contacts(ModelRc::from(Rc::new(VecModel::from(
        s.contacts.iter().map(row).collect::<Vec<_>>(),
    ))));
    ui.set_requests(ModelRc::from(Rc::new(VecModel::from(
        s.requests.iter().map(row).collect::<Vec<_>>(),
    ))));
    match &s.current {
        Some(c) => {
            ui.set_current(row(c));
            ui.set_current_id(c.id.clone().into());
        }
        None => ui.set_current_id(SharedString::new()),
    }
    let msgs: Vec<MessageRow> = s
        .messages
        .iter()
        .map(|m| MessageRow {
            text: m.text.clone().into(),
            outgoing: m.outgoing,
            time: m.time.clone().into(),
            status: m.status,
            sender: m.sender.clone().into(),
        })
        .collect();
    ui.set_messages(ModelRc::from(Rc::new(VecModel::from(msgs))));
    ui.set_code_groups(strings(&s.code_groups));
    ui.set_status_line(s.status.clone().into());
    ui.set_recovery_words(strings(&s.recovery_words));
    ui.set_recovery_saved(s.recovery_saved);
    ui.set_add_error(s.add_error.clone().into());
    ui.set_busy(s.busy);
    let pick: Vec<PickRow> = s
        .pick
        .iter()
        .map(|p| PickRow {
            id: p.id.clone().into(),
            name: p.name.clone().into(),
            initials: initials(&p.name).into(),
            tint: tint(p.tint),
            selected: p.selected,
        })
        .collect();
    ui.set_pick(ModelRc::from(Rc::new(VecModel::from(pick))));
    let devices: Vec<DeviceRow> = s
        .devices
        .iter()
        .map(|(l, d)| DeviceRow {
            label: l.clone().into(),
            detail: d.clone().into(),
        })
        .collect();
    ui.set_devices(ModelRc::from(Rc::new(VecModel::from(devices))));
    ui.set_link_choices(strings(&s.link_choices));
    ui.set_link_status(s.link_status.clone().into());
    ui.set_can_link(s.can_link);
    if !s.my_name.is_empty() && ui.get_screen() != Screen::Main {
        ui.set_screen(Screen::Main);
    }
}
