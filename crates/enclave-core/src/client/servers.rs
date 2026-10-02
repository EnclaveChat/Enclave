//! The foundation's server list on the client (`docs/12-servers.md` §4.1).
//!
//! The app supplies the foundation's public key at every start (it is
//! built into the app). The client then holds the newest list it has
//! verified, kept in the store across restarts: from the app's build, from
//! a file during development, or fetched from the home server
//! (`DirKind::ServerList`). A list is taken only if both foundation
//! signatures verify and its sequence number is higher than the one held,
//! so a server can't roll a client back to an older list. The
//! key-transparency pins come from the list, merged with any the app adds
//! (development servers).

use super::Client;
use crate::{CoreError, Result};
use enclave_federation::{FoundationPublic, ServerList};
use enclave_kt::KtPolicy;
use enclave_rpc::api::{DirAction, DirKind};

/// Store namespace (not in backups: the list is public and comes back on
/// its own).
pub(crate) const NS_SERVERS: &str = "servers";
const KEY_LIST: &[u8] = b"list";

/// What became of a list offered to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListUpdate {
    /// Taken: the new sequence number.
    Updated(u64),
    /// Not newer than the list held (or the same one).
    Unchanged,
}

impl Client {
    /// The foundation's public key, from the app's build. Loads the list
    /// held in the store, if any, and re-derives the pins.
    pub fn set_foundation(&mut self, key: FoundationPublic) -> Result<()> {
        self.foundation = Some(key);
        if let Some(b) = self.store.get(NS_SERVERS, KEY_LIST)? {
            // Already accepted once: check the signatures again, not the
            // expiry (an old list beats none until a newer one arrives).
            if let Some(k) = &self.foundation
                && let Ok(list) = ServerList::verify(&b, k, 0, 0)
            {
                self.servers = Some(list);
            }
        }
        self.apply_pins();
        Ok(())
    }

    /// Offer a signed list (built into the app, read from a file, or
    /// fetched). Refused if it doesn't verify under the foundation key or
    /// has expired; ignored if it isn't newer than the one held.
    pub fn offer_server_list(&mut self, bytes: &[u8]) -> Result<ListUpdate> {
        let key = self.foundation.clone().ok_or(CoreError::NotFound)?;
        let held = self.servers.as_ref().map_or(0, |l| l.seq);
        let list = match ServerList::verify(bytes, &key, self.now(), held) {
            Ok(l) => l,
            Err(enclave_federation::FedError::Stale) => return Ok(ListUpdate::Unchanged),
            Err(e) => return Err(CoreError::Federation(e)),
        };
        self.store.put(NS_SERVERS, KEY_LIST, bytes, &mut self.rng)?;
        let seq = list.seq;
        self.servers = Some(list);
        self.apply_pins();
        Ok(ListUpdate::Updated(seq))
    }

    /// Fetch the list the home server mirrors and offer it.
    pub async fn refresh_server_list(&mut self) -> Result<ListUpdate> {
        let now = self.now();
        let server = self.profile.server;
        let bytes = self
            .rpc
            .dir_get(
                &server,
                DirKind::ServerList,
                DirAction::Get,
                [0; 32],
                [0; 32],
                now,
                &mut self.rng,
            )
            .await?;
        self.offer_server_list(&bytes)
    }

    /// The list held, if any.
    pub fn server_list(&self) -> Option<&ServerList> {
        self.servers.as_ref()
    }

    /// The domain of server `id`, from the list or the pins.
    pub fn server_domain(&self, id: &[u8; 16]) -> Option<String> {
        self.servers
            .as_ref()
            .and_then(|l| l.server(id))
            .map(|s| s.domain.clone())
            .or_else(|| {
                self.kt
                    .as_ref()
                    .and_then(|p| p.by_server(id))
                    .map(|i| i.domain.clone())
            })
    }

    /// Pins from the list, merged with the ones the app added.
    pub(crate) fn apply_pins(&mut self) {
        let mut pins = self.extra_pins.clone();
        if let Some(l) = &self.servers {
            let from_list = KtPolicy::from_server_list(l);
            pins = Some(match pins {
                Some(mut p) => {
                    p.merge(from_list);
                    p
                }
                None => from_list,
            });
        }
        self.kt = pins;
    }
}
