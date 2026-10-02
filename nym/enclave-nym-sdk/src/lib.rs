//! The nym-sdk mixnet driver (`enclave_nym::MixnetDriver`,
//! `docs/09-transport.md` §1).
//!
//! Configuration, per [`Role`]:
//! - **Ingress** (a server's Nym client): a persistent identity (its
//!   address is in the server's descriptor) kept in a directory. It never
//!   asks a sender for more reply blocks: every request brings what its
//!   reply needs.
//! - **Client** (a device): an ephemeral identity. Nym's own Poisson stream
//!   of real packets is off, because Enclave's scheduler already sends at a
//!   fixed rate (`enclave_net::shaped`); loop cover runs every 10 seconds
//!   (`docs/completion-plan.md` N1).
//!
//! Every message gets a fresh sender tag (our patch to nym-client-core,
//! `third_party/PATCHES.md`) and, when it expects an answer, enough single-use
//! reply blocks for all of it ([`surbs_for`]).

use enclave_nym::{Incoming, MixnetDriver, NymError, ReplyTag, Result};
use nym_sdk::mixnet::{
    AnonymousSenderTag, IncludedSurbs, MixnetClientBuilder, MixnetClientSender,
    MixnetMessageSender, Recipient, StoragePaths,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

/// Plaintext a reply block carries, conservatively: a regular Sphinx
/// packet holds 2 KiB, less the fragment header and reply encryption.
pub const SURB_PAYLOAD: usize = 1_800;

/// Reply blocks for an answer of `len` bytes, with one to spare.
pub fn surbs_for(len: usize) -> u32 {
    u32::try_from(len.div_ceil(SURB_PAYLOAD) + 1).unwrap_or(u32::MAX)
}

/// Which side of Enclave this client is.
#[derive(Clone, Debug)]
pub enum Role {
    /// A stack's ingress, keeping its identity in `dir`.
    Ingress {
        /// Where nym-sdk keeps keys and gateway registration.
        dir: PathBuf,
    },
    /// A device.
    Client,
}

/// Connection options.
#[derive(Clone, Debug)]
pub struct Options {
    /// Ingress or client.
    pub role: Role,
    /// Ask for this gateway (identity key), or let nym-sdk choose.
    pub gateway: Option<String>,
    /// Network details from the environment (`NYM_*` variables, for a
    /// local mixnet or the sandbox), or mainnet.
    pub from_env: bool,
}

fn client_error(e: impl std::fmt::Display) -> NymError {
    NymError::Client(e.to_string())
}

/// A connected nym-sdk client.
pub struct NymDriver {
    sender: MixnetClientSender,
    address: String,
    rx: Mutex<mpsc::UnboundedReceiver<Incoming>>,
    reader: tokio::task::JoinHandle<()>,
}

impl NymDriver {
    /// Connect to the mixnet.
    pub async fn connect(opts: Options) -> Result<Self> {
        let mut debug = nym_sdk::DebugConfig::default();
        debug.traffic.disable_main_poisson_packet_distribution = true;
        debug.stats_reporting.enabled = false;
        if matches!(opts.role, Role::Client) {
            debug.cover_traffic.loop_cover_traffic_average_delay = Duration::from_secs(10);
        }
        if matches!(opts.role, Role::Ingress { .. }) {
            // Every request carries all the reply blocks its reply needs.
            debug.reply_surbs.maximum_reply_surbs_rerequests = 0;
        }
        let network = if opts.from_env {
            nym_sdk::NymNetworkDetails::new_from_env()
        } else {
            nym_sdk::NymNetworkDetails::default()
        };
        let mut client = match &opts.role {
            Role::Ingress { dir } => {
                let paths = StoragePaths::new_from_dir(dir).map_err(client_error)?;
                let mut b = MixnetClientBuilder::new_with_default_storage(paths)
                    .await
                    .map_err(client_error)?
                    .network_details(network)
                    .debug_config(debug);
                if let Some(g) = &opts.gateway {
                    b = b.request_gateway(g.clone());
                }
                b.build()
                    .map_err(client_error)?
                    .connect_to_mixnet()
                    .await
                    .map_err(client_error)?
            }
            Role::Client => {
                let mut b = MixnetClientBuilder::new_ephemeral()
                    .network_details(network)
                    .debug_config(debug);
                if let Some(g) = &opts.gateway {
                    b = b.request_gateway(g.clone());
                }
                b.build()
                    .map_err(client_error)?
                    .connect_to_mixnet()
                    .await
                    .map_err(client_error)?
            }
        };
        let address = client.nym_address().to_string();
        let sender = client.split_sender();
        let (tx, rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            while let Some(msgs) = client.wait_for_messages().await {
                for m in msgs {
                    let incoming = Incoming {
                        data: m.message,
                        reply: m.sender_tag.map(|t| ReplyTag(t.to_bytes())),
                    };
                    if tx.send(incoming).is_err() {
                        return;
                    }
                }
            }
        });
        Ok(Self {
            sender,
            address,
            rx: Mutex::new(rx),
            reader,
        })
    }
}

impl Drop for NymDriver {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[async_trait::async_trait]
impl MixnetDriver for NymDriver {
    fn address(&self) -> String {
        self.address.clone()
    }

    async fn send(&self, to: &str, data: Vec<u8>, reply_len: usize) -> Result<()> {
        let recipient =
            Recipient::try_from_base58_string(to).map_err(|_| NymError::UnknownRecipient)?;
        let surbs = if reply_len == 0 {
            IncludedSurbs::none()
        } else {
            IncludedSurbs::new(surbs_for(reply_len))
        };
        self.sender
            .send_message(recipient, data, surbs)
            .await
            .map_err(client_error)
    }

    async fn reply(&self, tag: ReplyTag, data: Vec<u8>) -> Result<()> {
        self.sender
            .send_reply(AnonymousSenderTag::from_bytes(tag.0), data)
            .await
            .map_err(client_error)
    }

    async fn recv(&self) -> Option<Incoming> {
        self.rx.lock().await.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_unit_gets_enough_reply_blocks() {
        // 16,406 B → 10 regular packets' worth, plus one.
        assert_eq!(surbs_for(enclave_nym::frame::REPLY_LEN), 11);
        assert_eq!(surbs_for(1), 2);
    }
}
