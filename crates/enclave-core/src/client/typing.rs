//! Typing indicators, 1:1 only (`docs/16-features.md`,
//! `docs/09-transport.md` §6.7).
//!
//! Off by default. With them on, we tell contacts when we type and see
//! when they do; with them off, neither. A typing indicator is
//! `Content::Typing`, end-to-end encrypted like any message, and sent only
//! in a tick slot that would otherwise carry cover
//! ([`Transport::exchange_droppable`](enclave_net::transport::Transport::exchange_droppable)):
//! one that finds no free slot within two ticks is dropped. So turning them
//! on never changes what an observer sees, and an indicator can always be
//! lost. It carries no PQ slot (a dropped unit must not take a PQ step
//! with it) and no copy for our other devices.
//!
//! Each one spends a write token, so none is sent while fewer than
//! [`TYPING_RESERVE`] are left: real messages always come first.

use super::{Client, ContactState, Event};
use crate::Result;
use crate::content::Content;
use crate::rpc::Sending;

const SETTING: &str = "typing";
/// Write tokens kept back from typing indicators for real messages.
pub const TYPING_RESERVE: usize = 8;
/// How long the app shows "typing…" after the last indicator, since a
/// "stopped" may never arrive. Senders repeat "typing" more often than this.
pub const TYPING_SHOW_SECS: u64 = 10;

impl Client {
    /// Whether typing indicators are on (off unless turned on).
    pub fn typing_enabled(&self) -> bool {
        matches!(self.setting(SETTING), Ok(Some(v)) if v == [1])
    }

    /// Turn typing indicators on or off, both ways.
    pub fn set_typing_enabled(&mut self, on: bool) -> Result<()> {
        self.set_setting(SETTING, &[u8::from(on)])
    }

    /// Tell `root` that we started (`on`) or stopped typing. Returns the
    /// sending, which the caller can leave to run on its own (it waits for a
    /// free slot and fails with `NetError::Dropped` if none comes), or
    /// `None` when typing indicators are off, the contact isn't accepted or
    /// is blocked, or tokens are short.
    pub async fn send_typing(&mut self, root: &[u8; 64], on: bool) -> Result<Option<Sending>> {
        if !self.typing_enabled() || self.is_blocked(root) {
            return Ok(None);
        }
        match self.contacts.get(root) {
            Some(c) if c.state == ContactState::Accepted && c.tokens.len() > TYPING_RESERVE => {}
            _ => return Ok(None),
        }
        let now = self.now();
        let (server, h, env) = self.seal_content(root, &Content::Typing { on }, true)?;
        Ok(Some(
            self.rpc
                .prepare_droppable(&server, h, &env, now, &mut self.rng)
                .await?,
        ))
    }

    pub(crate) fn on_typing(&self, root: &[u8; 64], on: bool) -> Option<Event> {
        let accepted = self
            .contacts
            .get(root)
            .is_some_and(|c| c.state == ContactState::Accepted);
        (self.typing_enabled() && accepted && !self.is_blocked(root))
            .then_some(Event::Typing { root: *root, on })
    }
}
