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
//!
//! After reporting spam, the reporter can make message requests to them
//! cost more for a month ([`Client::raise_request_effort`]): their server
//! asks every writer to their request inbox for that proof of work.

use super::{Client, ContactState};
use crate::{CoreError, Result};
use enclave_rpc::api::{
    self, FLAG_EFFORT, MAX_INBOX_EFFORT, MAX_REPORT_MESSAGES, ReportBody, ReportReason,
};
use enclave_wire::{Op, RequestHeader};

const EFFORT: &str = "request-effort";
/// How long a raised request effort lasts.
pub const RAISED_EFFORT_SECS: u64 = 30 * 86_400;
/// The first raise (above the server's default of 64).
const FIRST_RAISE: u32 = 256;

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

    /// Make message requests to us cost more for [`RAISED_EFFORT_SECS`]:
    /// four times the last raise (256 the first time), up to
    /// [`MAX_INBOX_EFFORT`]. Returns the new effort.
    pub async fn raise_request_effort(&mut self) -> Result<u32> {
        let (now_effort, _) = self.request_effort()?;
        let effort = (now_effort.saturating_mul(4)).clamp(FIRST_RAISE, MAX_INBOX_EFFORT);
        let now = self.now();
        self.set_request_effort(effort, now).await?;
        Ok(effort)
    }

    /// The effort we asked for our request inbox and since when (0: the
    /// server's own).
    pub fn request_effort(&self) -> Result<(u32, u64)> {
        Ok(self
            .setting(EFFORT)?
            .filter(|b| b.len() == 12)
            .map_or((0, 0), |b| {
                (
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                    u64::from_be_bytes([b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11]]),
                )
            }))
    }

    async fn set_request_effort(&mut self, effort: u32, now: u64) -> Result<()> {
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: FLAG_EFFORT,
            mailbox: self.profile.request_inbox,
            token: self.profile.request_owner,
        };
        let env = api::frame(&effort.to_be_bytes(), &mut self.rng)?;
        let server = self.profile.server;
        self.rpc
            .call_ok(&server, h, &env, now, &mut self.rng)
            .await?;
        let rec = [&effort.to_be_bytes()[..], &now.to_be_bytes()].concat();
        self.set_setting(EFFORT, &rec)
    }

    /// A month after the last raise, requests cost what the server asks
    /// again (from `sync`).
    pub(crate) async fn relax_request_effort(&mut self, now: u64) -> Result<()> {
        let (effort, since) = self.request_effort()?;
        if effort > 0 && now >= since + RAISED_EFFORT_SECS {
            self.set_request_effort(0, now).await?;
        }
        Ok(())
    }
}
