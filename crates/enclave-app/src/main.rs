//! Desktop entry point.
//!
//! `enclave` runs a self-contained demo (local server, demo contact, nothing
//! leaves the computer). Keys live in a separate `enclave-vault` process when
//! it is installed next to this binary (`--single-process` keeps them in a
//! thread instead). `enclave --server HOST:PORT --profile DIR` talks to
//! a dev server (`enclave-server`) over TCP (add `--kt-pins FILE`, written by
//! the server, to use usernames); the Tor and Nym transports are
//! wired in by M4's gate.
#![deny(unsafe_code)]

use enclave_app::{AppWindow, Screen, Sheet, vault, view};
use enclave_ipc::{Cmd, Out};
use enclave_vault::Mode;
use slint::ComponentHandle;
use std::time::Duration;

/// Largest file sent from here (it crosses to the vault in one message).
const MAX_FILE: u64 = 15 * 1024 * 1024;

/// Write a downloaded attachment into the Downloads folder without
/// overwriting anything. The name is the sender's, so only its last
/// component is used.
fn save_download(name: &str, bytes: &[u8]) -> std::io::Result<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = [home.join("Downloads"), home]
        .into_iter()
        .find(|d| d.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let base = std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && !n.is_empty())
        .unwrap_or_else(|| "file".into());
    for i in 0..1000 {
        let candidate = if i == 0 {
            dir.join(&base)
        } else {
            dir.join(format!("{i} {base}"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(bytes)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("too many files with that name"))
}

fn main() -> Result<(), slint::PlatformError> {
    let args: Vec<String> = std::env::args().collect();
    let mode = Mode::from_args(&args);
    let single_process = args.iter().any(|a| a == "--single-process");

    let ui = AppWindow::new()?;
    let ((tx, mut out), _separate) = vault::start(mode, single_process);
    // Outputs from the vault, applied on the UI thread.
    let w = ui.as_weak();
    std::thread::Builder::new()
        .name("enclave-ui-feed".into())
        .spawn(move || {
            while let Some(o) = out.blocking_recv() {
                // Files are written here, in the UI process: the vault can't
                // reach anything outside its profile.
                let o = match o {
                    Out::File(name, bytes) => {
                        let note = match save_download(&name, &bytes) {
                            Ok(path) => format!("Saved to {}", path.display()),
                            Err(e) => format!("Couldn't save {name}: {e}"),
                        };
                        let _ = w.upgrade_in_event_loop(move |ui| ui.set_file_note(note.into()));
                        continue;
                    }
                    other => other,
                };
                let _ = w.upgrade_in_event_loop(move |ui| match o {
                    Out::Snapshot(s) => view::apply(&ui, &s),
                    Out::Effect(e) => view::apply_effect(&ui, e),
                    Out::File(..) => {}
                });
            }
        })
        .map_err(|e| slint::PlatformError::Other(e.to_string()))?;
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
        let passphrase = w
            .upgrade()
            .map(|ui| {
                let p = ui.get_new_passphrase().to_string();
                ui.set_new_passphrase("".into());
                p
            })
            .unwrap_or_default();
        let _ = t.send(Cmd::Create(name.to_string(), passphrase));
    });
    let t = tx.clone();
    ui.on_unlock(move |p| {
        let _ = t.send(Cmd::Unlock(p.to_string()));
    });
    let t = tx.clone();
    ui.on_lock_now(move || {
        let _ = t.send(Cmd::Lock);
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
    let t = tx.clone();
    ui.on_add_members(move |id| {
        let _ = t.send(Cmd::AddMembers(id.to_string()));
    });
    let t = tx.clone();
    ui.on_remove_member(move |id, member| {
        let _ = t.send(Cmd::RemoveMember(id.to_string(), member.to_string()));
    });
    let t = tx.clone();
    ui.on_leave_group(move |id| {
        let _ = t.send(Cmd::LeaveGroup(id.to_string()));
    });
    let t = tx.clone();
    ui.on_search(move |q| {
        let _ = t.send(Cmd::Search(q.to_string()));
    });
    let t = tx.clone();
    ui.on_react(move |id, seq, emoji| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::React(id.to_string(), seq, emoji.to_string()));
        }
    });
    let t = tx.clone();
    ui.on_edit_message(move |id, seq, text| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Edit(id.to_string(), seq, text.to_string()));
        }
    });
    let t = tx.clone();
    ui.on_delete_message(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::Delete(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    ui.on_set_timer(move |id, secs| {
        let _ = t.send(Cmd::Timer(id.to_string(), secs.max(0) as u32));
    });
    let t = tx.clone();
    ui.on_save_file(move |id, seq| {
        if let Ok(seq) = seq.parse() {
            let _ = t.send(Cmd::SaveFile(id.to_string(), seq));
        }
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_send_file(move |id, path, caption| {
        let path = std::path::PathBuf::from(path.trim());
        let result = std::fs::metadata(&path).and_then(|m| {
            if m.len() > MAX_FILE {
                Err(std::io::Error::other("larger than 15 MB"))
            } else {
                std::fs::read(&path)
            }
        });
        match result {
            Ok(bytes) => {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".into());
                let _ = t.send(Cmd::SendFile(
                    id.to_string(),
                    name,
                    bytes,
                    caption.to_string(),
                ));
            }
            Err(e) => {
                if let Some(ui) = w.upgrade() {
                    ui.set_attach_error(format!("Couldn't read that file: {e}.").into());
                }
            }
        }
    });
    let t = tx.clone();
    ui.on_claim_username(move |name| {
        let _ = t.send(Cmd::ClaimUsername(name.to_string()));
    });
    let t = tx.clone();
    ui.on_remove_device(move |id| {
        let _ = t.send(Cmd::RemoveDevice(id.to_string()));
    });
    let t = tx.clone();
    ui.on_send_history(move |id| {
        let _ = t.send(Cmd::SendHistory(id.to_string()));
    });
    let t = tx.clone();
    ui.on_stop_recovery(move || {
        let _ = t.send(Cmd::StopRecovery);
    });
    let t = tx.clone();
    ui.on_approve_recovery(move || {
        let _ = t.send(Cmd::ApproveRecovery);
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_start_join(move || {
        if let Some(ui) = w.upgrade() {
            ui.set_screen(Screen::Join);
        }
        let _ = t.send(Cmd::StartJoin);
    });
    let t = tx.clone();
    let w = ui.as_weak();
    ui.on_cancel_join(move || {
        if let Some(ui) = w.upgrade() {
            ui.set_screen(Screen::Welcome);
        }
        let _ = t.send(Cmd::CancelJoin);
    });
    let t = tx.clone();
    ui.on_sheet_changed(move |s| {
        let _ = t.send(Cmd::RevealWords(s == Sheet::Recovery));
        let _ = t.send(Cmd::Meet(s == Sheet::Meet));
    });
    let t = tx.clone();
    ui.on_meet_scan(move |code| {
        let _ = t.send(Cmd::MeetScan(code.to_string()));
    });
    let t = tx.clone();
    ui.on_meet_confirm(move || {
        let _ = t.send(Cmd::MeetConfirm);
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
