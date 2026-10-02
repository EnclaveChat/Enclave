//! The device clock against trusted time (RT-23, `docs/12-servers.md`
//! §3.4).
//!
//! Trusted time is the median of the witness timestamps on a cosigned
//! key-transparency head. Every head a lookup verifies gives one, and every
//! [`CHECK_EVERY_SECS`] the client fetches a fresh head from its home
//! server's log to get one. Witnesses sign at the time they cosign, so a
//! device clock behind trusted time by more than [`BEHIND_SECS`] is wrong.
//! A head may be up to a day old when its log is quiet, so a clock ahead
//! is only certain past [`AHEAD_SECS`], where heads would be refused as
//! stale anyway. A wrong clock raises [`crate::Event::ClockSkew`] once; the
//! app shows it until the clock is right again (a second event with no
//! skew).

use super::Client;
use crate::Result;
use enclave_kt::LookupReply;
use enclave_rpc::api::{self, DirAction, DirKind};

/// A device clock this far behind trusted time is wrong.
pub const BEHIND_SECS: u64 = 600;
/// A device clock this far ahead of trusted time is wrong (the longest a
/// head stays fresh, 25 hours).
pub const AHEAD_SECS: u64 = 25 * 3600;
/// How often the home log is asked for a fresh head.
pub const CHECK_EVERY_SECS: u64 = 6 * 3600;

const SKEW: &str = "clock-skew";
const SHOWN: &str = "clock-skew-shown";
const CHECKED: &str = "clock-checked";

/// `Some(skew)` (device time minus trusted time, in seconds) if `now`
/// is wrong against `trusted`.
pub fn judge(now: u64, trusted: u64) -> Option<i64> {
    let skew = i64::try_from(now).unwrap_or(i64::MAX) - i64::try_from(trusted).unwrap_or(i64::MAX);
    let wrong = (skew < 0 && skew.unsigned_abs() > BEHIND_SECS)
        || (skew > 0 && skew.unsigned_abs() > AHEAD_SECS);
    wrong.then_some(skew)
}

fn encode(skew: Option<i64>) -> Vec<u8> {
    skew.map(|s| s.to_be_bytes().to_vec()).unwrap_or_default()
}

fn decode(b: Option<Vec<u8>>) -> Option<i64> {
    b.and_then(|b| b.try_into().ok()).map(i64::from_be_bytes)
}

impl Client {
    /// How wrong the device clock is (device time minus trusted time, in
    /// seconds), if the last trusted time showed it wrong.
    pub fn clock_skew(&self) -> Result<Option<i64>> {
        Ok(decode(self.setting(SKEW)?))
    }

    /// Compare the device clock with trusted time from a verified head.
    pub(crate) fn observe_trusted_time(&mut self, trusted: u64, now: u64) -> Result<()> {
        self.set_setting(SKEW, &encode(judge(now, trusted)))
    }

    /// Fetch a fresh head from the home log when due, then report a change
    /// in the clock's state.
    pub(crate) async fn check_clock(&mut self, now: u64) -> Result<Vec<crate::Event>> {
        let last = self
            .setting(CHECKED)?
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes);
        // A clock set back past the last check counts as due.
        if last.is_none_or(|l| now >= l + CHECK_EVERY_SECS || now < l) {
            if let Some(trusted) = self.home_trusted_time(now).await? {
                self.observe_trusted_time(trusted, now)?;
            }
            self.set_setting(CHECKED, &now.to_be_bytes())?;
        }
        let skew = self.clock_skew()?;
        let shown = decode(self.setting(SHOWN)?);
        // Report a new state; a skew that only drifted isn't news.
        if skew.is_some() != shown.is_some() {
            self.set_setting(SHOWN, &encode(skew))?;
            return Ok(vec![crate::Event::ClockSkew { skew }]);
        }
        Ok(Vec::new())
    }

    /// Trusted time from a fresh head of the home server's log: its server
    /// signature and witness quorum verify. Not its freshness, which is what
    /// is being checked. `None` without a pinned log or an answer.
    async fn home_trusted_time(&mut self, now: u64) -> Result<Option<u64>> {
        let Some(policy) = self.kt.clone() else {
            return Ok(None);
        };
        let Some(info) = policy.by_server(&self.profile.server).cloned() else {
            return Ok(None);
        };
        let reply = match self
            .rpc
            .dir_get(
                &info.server,
                DirKind::Username,
                DirAction::Get,
                api::DESCRIPTOR_LOOKUP_KEY,
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(r) => r,
            Err(crate::CoreError::Server(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let Ok(reply) = LookupReply::decode(&reply) else {
            return Ok(None);
        };
        let sh = &reply.head;
        Ok(policy
            .witnesses
            .check(sh, &info.head_key, &info.operator, sh.head.time)
            .ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judging_the_clock() {
        let t = 1_800_000_000;
        assert_eq!(judge(t, t), None);
        assert_eq!(judge(t - 300, t), None, "a little behind");
        assert_eq!(judge(t - 3600, t), Some(-3600), "an hour behind");
        assert_eq!(judge(t + 3 * 3600, t), None, "the head may be hours old");
        assert_eq!(judge(t + 2 * 86_400, t), Some(2 * 86_400), "two days ahead");
    }
}
