//! Reporting an account to its server's operator
//! (`docs/13-operators.md` §2, RT-25).
//!
//! A report goes to the reported person's home server, sealed to that
//! server like every request (so only its operator reads it), with a proof
//! of work. It names their request inbox, the only handle an operator can
//! act on, and the reason. Quoting their recent messages is the reporter's
//! choice. Conversations here are off the record, so quotes are an
//! unverifiable claim and the operator is told so. The report carries
//! nothing about the reporter; the request comes through the mixnet like
//! any other.

use super::{Client, ContactState};
use crate::{CoreError, Result};
use enclave_rpc::api::{self, MAX_REPORT_MESSAGES, ReportBody, ReportReason};

impl Client {
    /// Report `root` to their server's operator, quoting up to
    /// `quote` of their latest messages (0 for none).
    pub async fn report(
        &mut self,
        root: &[u8; 64],
        reason: ReportReason,
        quote: usize,
    ) -> Result<()> {
        let c = self.contacts.get(root).ok_or(CoreError::NotFound)?;
        if c.state == ContactState::Pending {
            return Err(CoreError::NotAccepted); // nothing of theirs to report
        }
        let (server, inbox) = (c.server, c.request_inbox);
        let mut quotes: Vec<String> = self
            .messages(root)?
            .into_iter()
            .filter(|m| !m.outgoing && !m.deleted && !m.text.is_empty())
            .map(|m| m.text)
            .collect();
        let keep = quote.min(MAX_REPORT_MESSAGES);
        quotes.drain(..quotes.len().saturating_sub(keep));
        let body = ReportBody {
            reason,
            on_record: false,
            quotes,
        };
        let env = api::frame(&body.encode(), &mut self.rng)?;
        let now = self.now();
        self.rpc
            .report(&server, inbox, &env, now, &mut self.rng)
            .await
    }
}
