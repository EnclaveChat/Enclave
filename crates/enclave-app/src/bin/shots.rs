//! Headless screenshots of every screen, light and dark, phone and desktop,
//! rendered with Slint's software renderer. Used for design review and the
//! screenshot diff in CI: `cargo run -p enclave-app --bin enclave-shots -- OUT_DIR`.
//!
//! The people and messages here are illustrative placeholders.
#![deny(unsafe_code)]

use enclave_app::view::{self, Msg, Row, Snapshot};
use enclave_app::{AppWindow, Screen, Sheet, Tokens};
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize, Rgb8Pixel};
use std::path::{Path, PathBuf};
use std::rc::Rc;

struct Headless(Rc<MinimalSoftwareWindow>);

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

fn fixture() -> Snapshot {
    let row = |id: &str,
               name: &str,
               preview: &str,
               time: &str,
               unread: i32,
               state: i32,
               verified: bool,
               tint: usize| Row {
        id: id.into(),
        name: name.into(),
        preview: preview.into(),
        time: time.into(),
        unread,
        state,
        verified,
        met: verified,
        tint,
        kind: 0,
        members: 0,
    };
    let seq = std::cell::Cell::new(0u64);
    let msg = |text: &str, outgoing: bool, time: &str, status: i32| {
        seq.set(seq.get() + 1);
        Msg {
            text: text.into(),
            outgoing,
            time: time.into(),
            status,
            sender: String::new(),
            seq: seq.get(),
            can_edit: outgoing,
            ..Default::default()
        }
    };
    let words = "absurd amount arctic brisk canyon cedar civil cluster dove eager ember fabric glide harbor ivory jungle kettle lunar meadow noble orbit pepper quartz ridge";
    Snapshot {
        my_name: "Robin Ahmadi".into(),
        my_link:
            "enclave:add#AQx7c2Vh-bGVkIHdpdGggYSBmb2xkZWQgY29ybmVy_c28gdGhlIGxpbmsgbG9va3MgcmVhbA"
                .into(),
        contacts: vec![
            row(
                "a1",
                "Sam Okafor",
                "Tomorrow works. Same café?",
                "14:02",
                2,
                2,
                true,
                0,
            ),
            row(
                "b2",
                "Priya Raman",
                "You: I'll send the draft tonight",
                "11:47",
                0,
                2,
                false,
                1,
            ),
            row("c3", "Lucía Fernández", "", "", 0, 0, false, 2),
            row(
                "d4",
                "Tomasz",
                "Thanks for checking in 🙂",
                "Mon",
                0,
                2,
                false,
                4,
            ),
        ],
        requests: vec![row(
            "e5",
            "Mara Lindqvist",
            "Hi, we met at the workshop on Thursday.",
            "13:20",
            1,
            1,
            false,
            3,
        )],
        current: Some(row(
            "a1",
            "Sam Okafor",
            "Tomorrow works. Same café?",
            "14:02",
            0,
            2,
            true,
            0,
        )),
        messages: vec![
            msg(
                "Are we still on for the interview prep this week?",
                false,
                "13:41",
                2,
            ),
            msg(
                "Yes. I've read the brief twice and have a few questions about the timeline.",
                true,
                "13:44",
                2,
            ),
            msg(
                "Good. Bring them. I'd rather we sort it out face to face.",
                false,
                "13:52",
                2,
            ),
            msg("Tomorrow at ten?", true, "13:58", 2),
            msg("Tomorrow works. Same café?", false, "14:02", 2),
            msg("Same café.", true, "14:03", 0),
        ],
        code_groups: [
            "38201", "99465", "10273", "58830", "47112", "20958", "61347", "80025", "13690",
            "72481", "56039", "04418",
        ]
        .map(String::from)
        .to_vec(),
        status: String::new(),
        recovery_words: words.split(' ').map(String::from).collect(),
        recovery_saved: false,
        add_error: String::new(),
        busy: false,
        pick: vec![
            enclave_app::view::Pick {
                id: "a1".into(),
                name: "Sam Okafor".into(),
                tint: 0,
                selected: true,
            },
            enclave_app::view::Pick {
                id: "b2".into(),
                name: "Priya Raman".into(),
                tint: 1,
                selected: true,
            },
            enclave_app::view::Pick {
                id: "d4".into(),
                name: "Tomasz".into(),
                tint: 4,
                selected: false,
            },
        ],
        devices: vec![
            view::Device {
                id: "a1".into(),
                label: "This device".into(),
                detail: "Added 2 Sep 2026".into(),
                removable: false,
                history_pending: false,
            },
            view::Device {
                id: "b2".into(),
                label: "Linked device".into(),
                detail: "Added 30 Sep 2026 · Message history follows 24 hours after linking".into(),
                removable: true,
                history_pending: true,
            },
        ],
        link_choices: Vec::new(),
        link_status: String::new(),
        can_link: true,
        my_username: "@robin@enclave.example".into(),
        usernames: true,
        username_error: String::new(),
        can_join: false,
        join_code: String::new(),
        join_words: String::new(),
        recovery_alert: String::new(),
        meet_code: String::new(),
        meet_words: String::new(),
        meet_name: String::new(),
        meet_error: String::new(),
        meet_done: String::new(),
        timer: 0,
        search: Vec::new(),
    }
}

fn group_fixture(base: &Snapshot) -> Snapshot {
    let mut g = base.clone();
    let row = Row {
        id: "g1".into(),
        name: "Book club".into(),
        preview: "Priya: Chapter 4 by Friday?".into(),
        time: "15:10".into(),
        unread: 0,
        state: 2,
        verified: false,
        met: false,
        tint: 5,
        kind: 1,
        members: 4,
    };
    g.contacts.insert(0, row.clone());
    g.current = Some(row);
    let m = |text: &str, sender: &str, outgoing: bool, time: &str| Msg {
        text: text.into(),
        outgoing,
        time: time.into(),
        status: 1,
        sender: sender.into(),
        ..Default::default()
    };
    g.messages = vec![
        m(
            "Welcome, everyone. First book is on the shelf by the door.",
            "Sam Okafor",
            false,
            "14:40",
        ),
        m("Chapter 4 by Friday?", "Priya Raman", false, "15:02"),
        m("Friday works for me.", "", true, "15:08"),
        m("Same here. I'll bring tea.", "Tomasz", false, "15:10"),
    ];
    g
}

fn render(window: &MinimalSoftwareWindow, ui: &AppWindow, size: (u32, u32), out: &Path) {
    window.set_size(PhysicalSize::new(size.0, size.1));
    ui.window().request_redraw();
    // Let layouts settle (Flickable viewport bindings run after the first pass).
    for _ in 0..3 {
        slint::platform::update_timers_and_animations();
        window.request_redraw();
        let mut buf = vec![Rgb8Pixel::default(); (size.0 * size.1) as usize];
        window.draw_if_needed(|r| {
            r.render(&mut buf, size.0 as usize);
        });
        if let Ok(file) = std::fs::File::create(out) {
            let mut enc = png::Encoder::new(std::io::BufWriter::new(file), size.0, size.1);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            if let Ok(mut w) = enc.write_header() {
                let bytes: Vec<u8> = buf.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
                let _ = w.write_image_data(&bytes);
            }
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "target/shots".into()),
    );
    let _ = std::fs::create_dir_all(&out);
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Headless(window.clone())))
        .map_err(|e| slint::PlatformError::Other(e.to_string()))?;
    let ui = AppWindow::new()?;
    ui.show()?;

    let desktop = (1180, 780);
    let phone = (390, 844);
    let data = fixture();

    for dark in [false, true] {
        let mode = if dark { "dark" } else { "light" };
        ui.global::<Tokens>().set_dark(dark);
        let shot =
            |name: &str, size| render(&window, &ui, size, &out.join(format!("{name}-{mode}.png")));

        ui.set_screen(Screen::Welcome);
        ui.set_sheet(Sheet::None);
        shot("01-welcome", desktop);
        shot("01-welcome-phone", phone);
        let mut joining = Snapshot {
            can_join: true,
            join_code:
                "enclave:link#AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w"
                    .into(),
            ..Default::default()
        };
        view::apply(&ui, &joining);
        shot("01-welcome-server-phone", phone);
        ui.set_screen(Screen::Join);
        ui.set_status_line("Waiting for your other device…".into());
        shot("18-join-code-phone", phone);
        joining.join_words = "harbor ivory kettle".into();
        view::apply(&ui, &joining);
        ui.set_status_line("Waiting for you to pick them there…".into());
        shot("18-join-words-phone", phone);
        view::apply(&ui, &Snapshot::default());
        ui.set_screen(Screen::Name);
        ui.set_name_input("Robin".into());
        shot("02-name", phone);
        ui.set_screen(Screen::SettingUp);
        ui.set_status_line("This takes a few seconds.".into());
        shot("03-setting-up", phone);

        let mut empty = data.clone();
        empty.contacts.clear();
        empty.requests.clear();
        empty.current = None;
        empty.messages.clear();
        view::apply(&ui, &empty);
        shot("04-home-empty", desktop);

        view::apply(&ui, &data);
        shot("05-conversation", desktop);
        shot("05-conversation-phone", phone);

        let mut request = data.clone();
        request.current = Some(data.requests[0].clone());
        request.messages = vec![Msg {
            text: "Hi, we met at the workshop on Thursday.".into(),
            outgoing: false,
            time: "13:20".into(),
            status: 2,
            sender: String::new(),
            ..Default::default()
        }];
        view::apply(&ui, &request);
        shot("06-request", desktop);

        let mut pending = data.clone();
        pending.current = Some(data.contacts[2].clone());
        pending.messages = vec![Msg {
            text: "Hi Lucía, it's Robin from the book club.".into(),
            outgoing: true,
            time: "09:12".into(),
            status: 2,
            sender: String::new(),
            ..Default::default()
        }];
        view::apply(&ui, &pending);
        shot("07-pending", phone);

        let mut unverified = data.clone();
        unverified.current = Some(data.contacts[1].clone());
        view::apply(&ui, &unverified);
        ui.set_sheet(Sheet::CheckCode);
        shot("08-check-code", desktop);
        shot("08-check-code-phone", phone);

        view::apply(&ui, &data);
        ui.set_sheet(Sheet::MyCode);
        shot("09-my-code", desktop);
        ui.set_sheet(Sheet::Add);
        ui.set_add_link("enclave:link#AAECAwQF".into());
        let mut err = data.clone();
        err.add_error = "This code links a device to your account. Only scan it from Settings → Your devices, on your own new device. No one from Enclave will ever ask you to scan one.".into();
        view::apply(&ui, &err);
        shot("10-add-error", desktop);
        let mut unverified_name = data.clone();
        unverified_name.add_error = "Enclave couldn't confirm that this username is genuine, so it didn't add anyone. Ask them for their invite link instead.".into();
        view::apply(&ui, &unverified_name);
        ui.set_add_link("@sam@enclave.example".into());
        ui.set_add_text("Hi Sam, it's Robin".into());
        shot("10-add-username-phone", phone);
        ui.set_add_link("".into());
        ui.set_add_text("".into());
        let group = group_fixture(&data);
        view::apply(&ui, &group);
        ui.set_sheet(Sheet::None);
        shot("14-group", desktop);
        shot("14-group-phone", phone);
        view::apply(&ui, &data);
        ui.set_group_name("Book club".into());
        ui.set_sheet(Sheet::NewGroup);
        shot("15-new-group", desktop);
        let mut linking = data.clone();
        linking.link_choices = vec![
            "harbor ivory kettle".into(),
            "glide ember noble".into(),
            "cedar orbit brisk".into(),
            "quartz amount lunar".into(),
        ];
        view::apply(&ui, &linking);
        ui.set_sheet(Sheet::Devices);
        shot("16-devices-link", desktop);
        view::apply(&ui, &data);
        shot("16-devices-phone", phone);
        ui.set_confirm_remove("b2".into());
        shot("17-devices-remove-phone", phone);
        ui.set_confirm_remove("".into());
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::Settings);
        shot("11-privacy", desktop);
        shot("11-privacy-phone", phone);
        let mut alert = data.clone();
        alert.recovery_alert = "3 Oct 14:02".into();
        alert.current = None;
        view::apply(&ui, &alert);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        shot("19-recovery-alert-phone", phone);
        let mut meet = data.clone();
        meet.meet_code = "enclave:meet#AQCDAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4A".into();
        view::apply(&ui, &meet);
        ui.set_sheet(Sheet::Meet);
        shot("20-meet-code-phone", phone);
        meet.meet_words = "harbor ivory kettle".into();
        meet.meet_name = "Sam Okafor".into();
        view::apply(&ui, &meet);
        shot("20-meet-words-phone", phone);
        meet.meet_words.clear();
        meet.meet_done = "Sam Okafor".into();
        view::apply(&ui, &meet);
        shot("20-meet-done-phone", phone);
        // A selected message with its actions, and the timer sheet.
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::None);
        if let Some(m) = data.messages.iter().rev().find(|m| m.outgoing) {
            ui.set_selected_seq(m.seq.to_string().into());
        }
        shot("21-message-actions", desktop);
        ui.set_selected_seq("".into());
        let mut timed = data.clone();
        timed.timer = 86_400;
        view::apply(&ui, &timed);
        ui.set_sheet(Sheet::Timer);
        shot("22-timer-phone", phone);
        let mut found = data.clone();
        found.current = None;
        found.search = vec![Row {
            id: "s1".into(),
            name: "Sam Okafor".into(),
            preview: "…Tomorrow works. Same café?".into(),
            time: "14:02".into(),
            state: 2,
            tint: 0,
            ..Default::default()
        }];
        view::apply(&ui, &found);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        ui.set_search_query("café".into());
        shot("23-search-phone", phone);
        ui.set_search_query("".into());
        view::apply(&ui, &data);
        view::apply(&ui, &data);
        ui.set_sheet(Sheet::Settings);
        ui.set_sheet(Sheet::Recovery);
        shot("12-recovery", desktop);
        shot("12-recovery-phone", phone);
        ui.set_sheet(Sheet::None);
        ui.set_current_id("".into());
        shot("13-list-phone", phone);
    }
    eprintln!("screenshots written to {}", out.display());
    Ok(())
}
