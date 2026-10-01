//! Write tokens from a shared pool (`docs/09-transport.md` §3.2).
//!
//! The owner registers token hashes at its server ahead of time, in
//! batches of [`POOL_BATCH`] fresh tokens shuffled with [`POOL_DUMMIES`]
//! random values, and hands each contact tokens from that pool when they
//! need them. A batch therefore mixes tokens that end up with different
//! contacts, so the server can't group writes by sender from which batch
//! their tokens came in. (Registering one contact's tokens as their own
//! batch, as before, would let it: every token in a batch that is ever
//! burned would be the same person's.)
//!
//! The hashes of the tokens each contact was given are kept (the last
//! [`MAX_ISSUED`]), so a block can revoke the ones still outstanding.
//! The pool is per device and never in a backup: a restored device starts
//! with an empty one, so no token is handed out twice.

use super::Client;
use crate::persist::NS_ISSUERS;
use crate::{CoreError, Result};
use enclave_rpc::api;
use enclave_tokens::{Token, token_hash};
use enclave_wire::{Op, RequestHeader};

pub(crate) const NS_TOKEN_POOL: &str = "token-pool";
const POOL_KEY: &[u8] = b"pool";
/// Fresh tokens per registration batch.
pub const POOL_BATCH: usize = 64;
/// Random values shuffled into each batch.
pub const POOL_DUMMIES: usize = 16;
/// Hashes kept per contact for revocation.
pub const MAX_ISSUED: usize = 128;

pub(crate) fn load_pool(store: &enclave_store::Store) -> Result<Vec<Token>> {
    Ok(store
        .get(NS_TOKEN_POOL, POOL_KEY)?
        .map(|b| {
            b.chunks_exact(32)
                .filter_map(|c| c.try_into().ok())
                .collect()
        })
        .unwrap_or_default())
}

impl Client {
    fn save_pool(&mut self) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(self.token_pool.concat());
        self.store
            .put(NS_TOKEN_POOL, POOL_KEY, &bytes, &mut self.rng)?;
        Ok(())
    }

    /// Register a batch of fresh tokens and add them to the pool.
    async fn refill_pool(&mut self, at_least: usize, now: u64) -> Result<()> {
        let n = at_least.max(POOL_BATCH);
        let fresh: Vec<Token> = (0..n)
            .map(|_| self.rng.array("core/write-token"))
            .collect::<std::result::Result<_, _>>()?;
        let hashes: Vec<[u8; 32]> = fresh.iter().map(token_hash).collect();
        let batch = enclave_tokens::registration_batch(&hashes, POOL_DUMMIES, &mut self.rng)?;
        let payload = api::frame(&batch.concat(), &mut self.rng)?;
        let h = RequestHeader {
            op: Op::RegisterTokens,
            flags: 0,
            mailbox: self.profile.inbox,
            token: self.profile.inbox_owner,
        };
        self.rpc
            .call_ok(&self.profile.server, h, &payload, now, &mut self.rng)
            .await?;
        // Hand out the oldest first; new ones go to the back.
        self.token_pool.extend(fresh);
        self.save_pool()
    }

    /// `n` tokens for `root`, from the pool (registered first if it runs
    /// short).
    pub(crate) async fn issue_tokens(
        &mut self,
        root: &[u8; 64],
        n: usize,
        now: u64,
    ) -> Result<Vec<Token>> {
        if self.token_pool.len() < n {
            let missing = n - self.token_pool.len();
            self.refill_pool(missing, now).await?;
        }
        if self.token_pool.len() < n {
            return Err(CoreError::OutOfTokens);
        }
        let toks: Vec<Token> = self.token_pool.drain(..n).collect();
        self.save_pool()?;
        let mut issued = self.issued_hashes(root);
        issued.extend(toks.iter().map(token_hash));
        let drop = issued.len().saturating_sub(MAX_ISSUED);
        issued.drain(..drop);
        self.store
            .put(NS_ISSUERS, root, &issued.concat(), &mut self.rng)?;
        Ok(toks)
    }

    /// Hashes of the tokens `root` was given (the last [`MAX_ISSUED`]).
    pub(crate) fn issued_hashes(&self, root: &[u8; 64]) -> Vec<[u8; 32]> {
        self.store
            .get(NS_ISSUERS, root)
            .ok()
            .flatten()
            .map(|b| {
                b.chunks_exact(32)
                    .filter_map(|c| c.try_into().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Forget the pool (a restored device must not reuse the old one).
    pub(crate) fn clear_pool(&mut self) -> Result<()> {
        self.token_pool.clear();
        self.store.delete(NS_TOKEN_POOL, POOL_KEY)?;
        Ok(())
    }
}
