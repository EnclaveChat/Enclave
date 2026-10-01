//! The relay's long-term keys on disk.
//!
//! | File | Contents |
//! |---|---|
//! | `relay-id` | 16-byte relay id |
//! | `link.key` | X448 secret for relay↔relay links (56 B) |
//! | `ticket-chain.key` | Daily ticket-key seed chain (`enclave_service::SeedChain`) |
//!
//! The link key is published in the relay's descriptor and must not change;
//! ticket keys rotate daily, derived from the chain
//! (`TicketSecretKey::from_seed`), and yesterday's is kept a day for
//! requests sealed just before midnight.

use enclave_calls::ticket::TicketSecretKey;
use enclave_crypto::kem::{X448_LEN, X448Secret};
use enclave_crypto::rng::HedgedRng;
use enclave_service::keyfile::{create_key_dir, create_secret, read_array};
use enclave_service::{KeyError, SeedChain};
use std::path::Path;
use zeroize::Zeroizing;

const ID_FILE: &str = "relay-id";
const LINK_FILE: &str = "link.key";
const CHAIN_FILE: &str = "ticket-chain.key";

/// The relay's keys.
pub struct RelayKeys {
    /// Relay id.
    pub id: [u8; 16],
    link: Zeroizing<[u8; X448_LEN]>,
    chain: SeedChain,
}

impl RelayKeys {
    /// Create the key directory and fresh keys, starting the ticket chain
    /// at `day`. Refuses to overwrite keys.
    pub fn init(dir: &Path, day: u32) -> Result<Self, KeyError> {
        if [ID_FILE, LINK_FILE, CHAIN_FILE]
            .iter()
            .any(|f| dir.join(f).exists())
        {
            return Err(KeyError::Exists(dir.to_path_buf()));
        }
        create_key_dir(dir)?;
        let crypto = |_| KeyError::Crypto;
        let mut rng = HedgedRng::new().map_err(crypto)?;
        let id: [u8; 16] = rng.array("relay/id").map_err(crypto)?;
        let link = Zeroizing::new(rng.array::<X448_LEN>("relay/link-key").map_err(crypto)?);
        let seed = Zeroizing::new(rng.array::<32>("relay/ticket-chain").map_err(crypto)?);
        create_secret(&dir.join(ID_FILE), &id)?;
        create_secret(&dir.join(LINK_FILE), &link[..])?;
        let chain =
            SeedChain::create(&dir.join(CHAIN_FILE), day, seed, TicketSecretKey::next_seed)?;
        Ok(Self { id, link, chain })
    }

    /// Load the keys in `dir`.
    pub fn load(dir: &Path) -> Result<Self, KeyError> {
        Ok(Self {
            id: *read_array::<16>(&dir.join(ID_FILE))?,
            link: read_array::<X448_LEN>(&dir.join(LINK_FILE))?,
            chain: SeedChain::load(&dir.join(CHAIN_FILE), TicketSecretKey::next_seed)?,
        })
    }

    /// The link secret.
    pub fn link_secret(&self) -> X448Secret {
        X448Secret::from_bytes(*self.link)
    }

    /// Step the ticket chain to `day`. Returns whether it moved.
    pub fn advance(&mut self, day: u32) -> Result<bool, KeyError> {
        self.chain.advance_to(day)
    }

    /// Ticket keys, newest first: today's, and yesterday's if kept.
    pub fn tickets(&self) -> Vec<TicketSecretKey> {
        let day = self.chain.period();
        let mut v = vec![TicketSecretKey::from_seed(
            self.id,
            day,
            self.chain.current(),
        )];
        if let Some(p) = self.chain.previous() {
            v.push(TicketSecretKey::from_seed(
                self.id,
                day.saturating_sub(1),
                p,
            ));
        }
        v
    }

    /// Tomorrow's ticket key (published ahead in the relay descriptor).
    pub fn next_ticket(&self) -> TicketSecretKey {
        TicketSecretKey::from_seed(self.id, self.chain.period() + 1, &self.chain.next())
    }
}
