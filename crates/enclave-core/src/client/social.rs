//! Social recovery (`docs/03-identity.md` §8.3).
//!
//! The 256-bit recovery secret is split with SLIP-0039 (`enclave-slip39`)
//! into one share per chosen contact, any `threshold` of which rebuild it.
//! Each share travels to its holder over the pairwise session
//! (`Content::RecoveryShare`) and is kept in the holder's sealed store.
//!
//! When someone loses every device, they meet each holder in person; the
//! holder's app shows the share (words, or a QR code) only on request, and
//! the new device combines `threshold` shares back into the recovery words
//! ([`words_from_shares`]). From there it is an ordinary restore, so the
//! 72-hour guard (§8.1) still protects the account: a restore no device
//! co-signed waits, and any remaining device can stop it.
//!
//! Giving shares again makes a new split. Old shares still rebuild the same
//! secret (it doesn't change), so a holder who should no longer have one
//! means the recovery words themselves should change (not built yet).

use super::Client;
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_proto::recovery::RecoverySecret;
use zeroize::Zeroizing;

const NS_HELD_SHARES: &str = "held-shares";
const GIVEN: &str = "recovery-shares-given";
/// Most holders.
pub const MAX_HOLDERS: usize = 16;

/// The recovery words rebuilt from `threshold` SLIP-0039 shares.
pub fn words_from_shares(shares: &[&str]) -> Result<String> {
    let secret = enclave_slip39::combine(shares, b"").map_err(|_| CoreError::Crypto)?;
    let arr: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Crypto)?;
    Ok(RecoverySecret::from_bytes(arr).to_words()?.join(" "))
}

impl Client {
    /// Split the recovery secret among `holders` (accepted contacts), any
    /// `threshold` of whom can help rebuild it, and send each their share.
    pub async fn give_recovery_shares(
        &mut self,
        holders: &[[u8; 64]],
        threshold: u8,
    ) -> Result<()> {
        let n = holders.len();
        if !(2..=MAX_HOLDERS).contains(&n) || threshold < 2 || usize::from(threshold) > n {
            return Err(CoreError::TooLong);
        }
        for h in holders {
            let c = self.contact(h).ok_or(CoreError::NotFound)?;
            if c.state != super::ContactState::Accepted {
                return Err(CoreError::NotAccepted);
            }
        }
        let secret = Zeroizing::new(
            self.store
                .get(super::NS_SECRETS, b"recovery")?
                .ok_or(CoreError::NotFound)?,
        );
        let rng = &mut self.rng;
        let mut fill = |b: &mut [u8]| {
            if rng.fill("core/slip39", b).is_err() {
                b.fill(0);
            }
        };
        let shares =
            enclave_slip39::generate(1, &[(threshold, n as u8)], &secret, b"", true, 1, &mut fill)
                .map_err(|_| CoreError::Crypto)?;
        let now = self.now();
        for (h, share) in holders.iter().zip(shares.into_iter().flatten()) {
            self.send_content(h, &Content::RecoveryShare(share), now)
                .await?;
        }
        let mut record = vec![threshold];
        for h in holders {
            record.extend_from_slice(h);
        }
        self.set_setting(GIVEN, &record)?;
        Ok(())
    }

    /// Who holds a share of our recovery, and how many are needed.
    pub fn recovery_holders(&self) -> Option<(u8, Vec<[u8; 64]>)> {
        let r = self.setting(GIVEN).ok()??;
        let (&t, rest) = r.split_first()?;
        Some((
            t,
            rest.chunks_exact(64)
                .filter_map(|c| c.try_into().ok())
                .collect(),
        ))
    }

    /// A share `from` gave us to keep.
    pub(crate) fn keep_recovery_share(&mut self, from: &[u8; 64], share: &str) -> Result<()> {
        self.store
            .put(NS_HELD_SHARES, from, share.as_bytes(), &mut self.rng)?;
        Ok(())
    }

    /// Whether we hold part of `root`'s recovery.
    pub fn holds_recovery_share(&self, root: &[u8; 64]) -> bool {
        matches!(self.store.get(NS_HELD_SHARES, root), Ok(Some(_)))
    }

    /// The share we hold for `root`, to show them in person.
    pub fn recovery_share_for(&self, root: &[u8; 64]) -> Option<Zeroizing<String>> {
        let b = self.store.get(NS_HELD_SHARES, root).ok()??;
        Some(Zeroizing::new(String::from_utf8(b).ok()?))
    }
}
