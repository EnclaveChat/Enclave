//! The relay's key chain on disk (`docs/10-push.md` §2).
//!
//! One seed per 30-day epoch, stepped with `L_RELAY_CHAIN`; each epoch's
//! key is derived from its seed ([`RelaySecret::from_seed`]). The file holds
//! the current epoch's seed and, for the first [`OVERLAP_DAYS`] of an epoch,
//! the previous one; after that the previous seed is erased.

use crate::{EPOCH_DAYS, OVERLAP_DAYS, RelayPublic, RelaySecret, epoch_of};
use enclave_crypto::rng::HedgedRng;
use enclave_service::keyfile::create_key_dir;
use enclave_service::{KeyError, SeedChain};
use std::path::Path;
use zeroize::Zeroizing;

const CHAIN_FILE: &str = "push-relay-chain.key";

/// The relay's keys.
pub struct RelayKeys {
    chain: SeedChain,
}

impl RelayKeys {
    /// Create the key directory and a fresh chain for `day`'s epoch.
    pub fn init(dir: &Path, day: u32) -> Result<Self, KeyError> {
        create_key_dir(dir)?;
        let mut rng = HedgedRng::new().map_err(|_| KeyError::Crypto)?;
        let seed = Zeroizing::new(
            rng.array::<32>("push/relay-chain")
                .map_err(|_| KeyError::Crypto)?,
        );
        let chain = SeedChain::create(
            &dir.join(CHAIN_FILE),
            epoch_of(day),
            seed,
            RelaySecret::next_seed,
        )?;
        Ok(Self { chain })
    }

    /// Load the chain in `dir`.
    pub fn load(dir: &Path) -> Result<Self, KeyError> {
        Ok(Self {
            chain: SeedChain::load(&dir.join(CHAIN_FILE), RelaySecret::next_seed)?,
        })
    }

    /// Bring the keys to `day`: step to its epoch, and erase the previous
    /// epoch's seed once the overlap is over. Returns whether the set of
    /// keys changed.
    pub fn advance(&mut self, day: u32) -> Result<bool, KeyError> {
        let mut changed = self.chain.advance_to(epoch_of(day))?;
        let into_epoch = day.saturating_sub(self.chain.period() * EPOCH_DAYS);
        if into_epoch >= OVERLAP_DAYS && self.chain.previous().is_some() {
            self.chain.forget_previous()?;
            changed = true;
        }
        Ok(changed)
    }

    /// The keys to hold: the current epoch's, and the previous epoch's
    /// during the overlap. Newest first.
    pub fn secrets(&self) -> Vec<RelaySecret> {
        let e = self.chain.period();
        let mut v = vec![RelaySecret::from_seed(e, self.chain.current())];
        if let Some(p) = self.chain.previous() {
            v.push(RelaySecret::from_seed(e.saturating_sub(1), p));
        }
        v
    }

    /// What the foundation's list publishes: the current epoch's key and
    /// the next one, so devices can seal to it before it takes over.
    pub fn published(&self) -> [RelayPublic; 2] {
        let e = self.chain.period();
        [
            RelaySecret::from_seed(e, self.chain.current())
                .public()
                .clone(),
            RelaySecret::from_seed(e + 1, &self.chain.next())
                .public()
                .clone(),
        ]
    }
}
