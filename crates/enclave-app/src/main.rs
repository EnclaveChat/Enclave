//! Desktop entry point.
//!
//! `enclave` runs a self-contained demo (local server, demo contact, nothing
//! leaves the computer). `enclave --server HOST:PORT --profile DIR` talks to
//! a dev server (`enclave-server`) over TCP; the Tor and Nym transports are
//! wired in by M4's gate.
#![deny(unsafe_code)]

use enclave_app::engine::{self, Cmd, Mode};
use enclave_app::{AppWindow, Screen, Sheet};
use slint::ComponentHandle;
use std::time::Duration;

fn main() -> Result<(), slint::PlatformError> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |k: &str| {
        args.iter()
            .position(|a| a == k)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let mode = match (
        arg("--server").and_then(|s| s.parse().ok()),
        arg("--profile"),
    ) {
        (Some(addr), Some(p)) => Mode::Server {
            profile: p.into(),
            addr,
        },
        _ => Mode::Demo,
    };

    let ui = AppWindow::new()?;
    let tx = engine::spawn(ui.as_weak(), mode);

    let t = tx.clone();
    ui.on_get_started({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                ui.set_screen(Screen::Name);
            }
            let _ = &t;
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_create_account(move |name| {
        if name.trim().is_empty() {
            return;
        }
        if let Some(ui) = w.upgrade() {
            ui.set_screen(Screen::SettingUp);
            ui.set_status_line("This takes a few seconds.".into());
        }
        let _ = t.send(Cmd::Create(name.to_string()));
    });
    let t = tx.clone();
    ui.on_select(move |id| {
        let _ = t.send(Cmd::Select(id.to_string()));
    });
    let t = tx.clone();
    ui.on_send(move |id, text| {
        let _ = t.send(Cmd::Send(id.to_string(), text.to_string()));
    });
    let t = tx.clone();
    ui.on_accept(move |id| {
        let _ = t.send(Cmd::Accept(id.to_string()));
    });
    let t = tx.clone();
    ui.on_decline(move |id| {
        let _ = t.send(Cmd::Decline(id.to_string()));
    });
    let t = tx.clone();
    ui.on_add_contact(move |link, text| {
        let _ = t.send(Cmd::Add(link.to_string(), text.to_string()));
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_mark_checked(move |id| {
        let _ = t.send(Cmd::Check(id.to_string()));
        if let Some(ui) = w.upgrade() {
            let mut cur = ui.get_current();
            cur.verified = true;
            ui.set_current(cur);
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_set_privacy(move |p| {
        if let Some(ui) = w.upgrade() {
            ui.set_privacy(p);
        }
        let _ = t.send(Cmd::Privacy(p));
    });
    let t = tx.clone();
    ui.on_words_saved(move || {
        let _ = t.send(Cmd::WordsSaved);
    });
    let t = tx.clone();
    ui.on_toggle_pick(move |id| {
        let _ = t.send(Cmd::TogglePick(id.to_string()));
    });
    let t = tx.clone();
    ui.on_create_group(move |name| {
        let _ = t.send(Cmd::CreateGroup(name.to_string()));
    });
    let t = tx.clone();
    ui.on_link_scan(move |code| {
        let _ = t.send(Cmd::LinkScan(code.to_string()));
    });
    let t = tx.clone();
    ui.on_link_pick(move |i| {
        let _ = t.send(Cmd::LinkPick(i));
    });
    let w = ui.as_weak();
    ui.on_open_sheet(move |s| {
        if let Some(ui) = w.upgrade() {
            ui.set_sheet(s);
        }
    });
    let w = ui.as_weak();
    ui.on_copy_text(move |text| {
        copy_with_timeout(text.to_string());
        if let Some(ui) = w.upgrade() {
            ui.set_status_line(
                "Invite link copied. It's cleared from the clipboard after 60 seconds.".into(),
            );
        }
    });
    let _ = Sheet::None;
    ui.run()
}

/// Copy, then clear the clipboard after 60 s if it still holds our text.
fn copy_with_timeout(text: String) {
    let Ok(mut cb) = arboard::Clipboard::new() else {
        return;
    };
    if cb.set_text(text.clone()).is_err() {
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(60));
        if let Ok(mut cb) = arboard::Clipboard::new()
            && cb.get_text().ok().as_deref() == Some(text.as_str())
        {
            let _ = cb.clear();
        }
    });
}
