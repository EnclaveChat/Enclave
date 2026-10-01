//! Shared plumbing for Enclave's service binaries: the server
//! (`enclave-server`), the call relay (`enclave-relay`) and the push relay
//! (`enclave-push-relay`). Each keeps long-term secrets in a key directory
//! and reads a TOML configuration file that the compose stack overrides
//! from the environment; this crate does both the same way for all of them
//! (`docs/12-servers.md` §1).
//!
//! * [`keyfile`]: key directories (mode 0700) and secret files (mode 0600,
//!   written atomically, never left half-written).
//! * [`SeedChain`]: a forward-secure chain of 32-byte seeds, one per period
//!   (a day, a 30-day epoch). Keys for a period are derived from its seed;
//!   stepping the chain erases older seeds, so a seized disk can't recreate
//!   keys from before the previous period.
//! * [`config`]: a TOML file plus `ENCLAVE_<SECTION>__<KEY>` overrides,
//!   with unknown keys refused.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod keyfile;

use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub use keyfile::KeyError;

/// A forward-secure seed chain stored in one file.
///
/// The file is `u32(period) ‖ seed (32) ‖ 0x00`, or `… ‖ 0x01 ‖ previous
/// seed (32)` while the previous period's keys are still served.
pub struct SeedChain {
    period: u32,
    seed: Zeroizing<[u8; 32]>,
    prev: Option<Zeroizing<[u8; 32]>>,
    path: PathBuf,
    step: fn(&[u8; 32]) -> [u8; 32],
}

impl SeedChain {
    /// Start a chain at `period` with `seed`, and write it to `path`.
    /// `step` derives the next period's seed (a KMAC under the owner's
    /// label). Refuses to overwrite an existing file.
    pub fn create(
        path: &Path,
        period: u32,
        seed: Zeroizing<[u8; 32]>,
        step: fn(&[u8; 32]) -> [u8; 32],
    ) -> Result<Self, KeyError> {
        if path.exists() {
            return Err(KeyError::Exists(path.to_path_buf()));
        }
        let c = Self {
            period,
            seed,
            prev: None,
            path: path.to_path_buf(),
            step,
        };
        c.save()?;
        Ok(c)
    }

    /// Load the chain in `path`.
    pub fn load(path: &Path, step: fn(&[u8; 32]) -> [u8; 32]) -> Result<Self, KeyError> {
        let b = keyfile::read_secret(path)?;
        let bad = || KeyError::Damaged(path.to_path_buf());
        if b.len() != 37 && b.len() != 69 {
            return Err(bad());
        }
        let period = u32::from_be_bytes(b[..4].try_into().map_err(|_| bad())?);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&b[4..36]);
        let prev = match b[36] {
            0 if b.len() == 37 => None,
            1 if b.len() == 69 => {
                let mut p = Zeroizing::new([0u8; 32]);
                p.copy_from_slice(&b[37..69]);
                Some(p)
            }
            _ => return Err(bad()),
        };
        Ok(Self {
            period,
            seed,
            prev,
            path: path.to_path_buf(),
            step,
        })
    }

    /// The period the chain is at.
    pub fn period(&self) -> u32 {
        self.period
    }

    /// This period's seed.
    pub fn current(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The previous period's seed, while it is kept.
    pub fn previous(&self) -> Option<&[u8; 32]> {
        self.prev.as_deref()
    }

    /// The next period's seed (for publishing its key ahead of time).
    pub fn next(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new((self.step)(&self.seed))
    }

    /// Step the chain to `period` and save it. The seed of the period just
    /// before `period` is kept as the previous one; every older seed is
    /// gone. Returns whether the chain moved.
    pub fn advance_to(&mut self, period: u32) -> Result<bool, KeyError> {
        if period <= self.period {
            return Ok(false);
        }
        while self.period < period {
            let next = Zeroizing::new((self.step)(&self.seed));
            self.prev = (self.period + 1 == period).then(|| self.seed.clone());
            self.seed = next;
            self.period += 1;
        }
        self.save()?;
        Ok(true)
    }

    /// Erase the previous period's seed (its overlap is over).
    pub fn forget_previous(&mut self) -> Result<(), KeyError> {
        if self.prev.take().is_some() {
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<(), KeyError> {
        let mut b = Zeroizing::new(Vec::with_capacity(69));
        b.extend_from_slice(&self.period.to_be_bytes());
        b.extend_from_slice(&self.seed[..]);
        match &self.prev {
            Some(p) => {
                b.push(1);
                b.extend_from_slice(&p[..]);
            }
            None => b.push(0),
        }
        keyfile::write_secret(&self.path, &b)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn step(s: &[u8; 32]) -> [u8; 32] {
        let mut n = *s;
        n[0] = n[0].wrapping_add(1);
        n
    }

    #[test]
    fn chain_steps_forgets_and_reloads() {
        let d = std::env::temp_dir().join(format!("enclave-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        keyfile::create_key_dir(&d).unwrap();
        let p = d.join("chain.key");
        let mut c = SeedChain::create(&p, 10, Zeroizing::new([0; 32]), step).unwrap();
        assert!(SeedChain::create(&p, 10, Zeroizing::new([0; 32]), step).is_err());
        assert_eq!(c.next()[0], 1);
        assert!(!c.advance_to(10).unwrap());
        assert!(c.advance_to(11).unwrap());
        assert_eq!((c.current()[0], c.previous().map(|p| p[0])), (1, Some(0)));
        assert!(c.advance_to(14).unwrap());
        assert_eq!((c.current()[0], c.previous().map(|p| p[0])), (4, Some(3)));
        let r = SeedChain::load(&p, step).unwrap();
        assert_eq!(
            (r.period(), r.current()[0], r.previous().map(|p| p[0])),
            (14, 4, Some(3))
        );
        c.forget_previous().unwrap();
        assert!(SeedChain::load(&p, step).unwrap().previous().is_none());
        std::fs::write(&p, [0u8; 36]).unwrap();
        assert!(matches!(
            SeedChain::load(&p, step),
            Err(KeyError::Damaged(_))
        ));
        let _ = std::fs::remove_dir_all(&d);
    }
}
