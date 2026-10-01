//! The Enclave call relay (`docs/11-calls.md` §3, `docs/12-servers.md` §5).
//!
//! ```text
//! caller ──link (ticket keys)──▶ relay A ══relay link══ relay B ◀──link (ticket keys)── callee
//! ```
//!
//! Each caller joins its own relay with the call's rendezvous id and the
//! address of the other relay. A relay sees its own client's address, the
//! peer relay's address, and packet sizes and timing, never the other
//! client's address and never media keys (media is SFrame end to end).
//!
//! The relay core is sans-I/O ([`Relay::handle`] maps one datagram to the
//! datagrams to send); [`serve`] runs it on a UDP socket. Relay-to-relay
//! datagrams are sealed with a key from the two relays' static X448 keys.
//! In production that hop runs WireGuard with Rosenpass (D8) and the client
//! hop runs WireGuard with the ticket PSK; see `enclave_calls::link`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use enclave_calls::link::{self, Link};
use enclave_calls::ticket::{Ticket, TicketSecretKey};
use enclave_calls::{CallError, labels};
use enclave_crypto::kem::{X448Public, X448Secret};
use enclave_crypto::kmac::kmac256_parts;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod keys;
pub mod ledger;

pub use ledger::{MemorySpent, Spent};

/// Datagram type: client link.
pub const T_CLIENT: u8 = 0x01;
/// Datagram type: relay link.
pub const T_RELAY: u8 = 0x02;
/// Link payload: join a rendezvous.
pub const P_JOIN: u8 = 0x10;
/// Link payload: a media packet.
pub const P_MEDIA: u8 = 0x11;
/// Link payload: keepalive.
pub const P_KEEPALIVE: u8 = 0x12;

/// What a relay publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// Relay id.
    pub id: [u8; 16],
    /// Operator family (callers pick relays from distinct families).
    pub family: String,
    /// UDP address.
    pub addr: SocketAddr,
    /// Static X448 key for relay links.
    pub link_key: [u8; 56],
}

struct Session {
    link: Link,
    client: Option<SocketAddr>,
    rendezvous: Option<[u8; 16]>,
    peer: Option<SocketAddr>,
}

struct Peer {
    send: SealKey,
    recv: SealKey,
    counter: u64,
    top: Option<u64>,
    bits: u128,
}

/// Counters an operator may see (aggregate only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams forwarded to a peer relay.
    pub to_peer: u64,
    /// Datagrams delivered to clients.
    pub to_client: u64,
    /// Datagrams dropped (bad auth, unknown session, replay).
    pub dropped: u64,
}

/// A relay.
pub struct Relay {
    desc: Descriptor,
    link_secret: X448Secret,
    /// Ticket keys, newest first (today's, and yesterday's for requests
    /// sealed just before midnight).
    tickets: Vec<TicketSecretKey>,
    sessions: HashMap<[u8; 16], Session>,
    rendezvous: HashMap<[u8; 16], [u8; 16]>,
    peers: HashMap<SocketAddr, Peer>,
    spent: Box<dyn Spent + Send>,
    stats: Stats,
    rng: HedgedRng,
}

impl Relay {
    /// A relay at `addr` with fresh random keys and an in-memory ledger
    /// (tests, development).
    pub fn new(id: [u8; 16], family: &str, addr: SocketAddr, day: u32) -> Result<Self, CallError> {
        let mut rng = HedgedRng::new()?;
        let (link_secret, _) = X448Secret::generate(&mut rng)?;
        let tickets = TicketSecretKey::generate(id, day, &mut rng)?;
        Self::with_keys(
            id,
            family,
            addr,
            link_secret,
            vec![tickets],
            Box::new(MemorySpent::default()),
        )
    }

    /// A relay with keys from disk (`keys::RelayKeys`) and a durable
    /// ledger of spent tokens.
    pub fn with_keys(
        id: [u8; 16],
        family: &str,
        addr: SocketAddr,
        link_secret: X448Secret,
        tickets: Vec<TicketSecretKey>,
        spent: Box<dyn Spent + Send>,
    ) -> Result<Self, CallError> {
        if tickets.is_empty() {
            return Err(CallError::UnknownKey);
        }
        Ok(Self {
            desc: Descriptor {
                id,
                family: family.into(),
                addr,
                link_key: link_secret.public().0,
            },
            link_secret,
            tickets,
            sessions: HashMap::new(),
            rendezvous: HashMap::new(),
            peers: HashMap::new(),
            spent,
            stats: Stats::default(),
            rng: HedgedRng::new()?,
        })
    }

    /// Replace the ticket keys (at midnight UTC), newest first.
    pub fn set_ticket_keys(&mut self, tickets: Vec<TicketSecretKey>) {
        if !tickets.is_empty() {
            self.tickets = tickets;
        }
    }

    /// Public descriptor.
    pub fn descriptor(&self) -> &Descriptor {
        &self.desc
    }

    /// The ticket key clients request tickets with (today's).
    pub fn ticket_key(&self) -> &enclave_calls::ticket::TicketKey {
        self.tickets[0].public()
    }

    /// Aggregate counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Addresses of clients this relay has seen (for tests and audits).
    pub fn client_addrs(&self) -> Vec<SocketAddr> {
        self.sessions.values().filter_map(|s| s.client).collect()
    }

    /// Trust a peer relay (in production: a Rosenpass/WireGuard peer).
    pub fn add_peer(&mut self, peer: &Descriptor) -> Result<(), CallError> {
        let dh = self
            .link_secret
            .diffie_hellman(&X448Public(peer.link_key))?;
        let dir = |from: &[u8; 16], to: &[u8; 16]| {
            SealKey::from_bytes(kmac256_parts(&dh[..], &[from, to], labels::RELAY_LINK))
        };
        self.peers.insert(
            peer.addr,
            Peer {
                send: dir(&self.desc.id, &peer.id),
                recv: dir(&peer.id, &self.desc.id),
                counter: 0,
                top: None,
                bits: 0,
            },
        );
        Ok(())
    }

    /// Ticket service: open a request, burn its token, issue a ticket.
    /// `token_ok` verifies the Privacy Pass token (single use is enforced
    /// here as well).
    pub fn issue_ticket(
        &mut self,
        request: &[u8],
        now: u64,
        token_ok: impl Fn(&[u8; 32]) -> bool,
    ) -> Result<Vec<u8>, CallError> {
        let epoch = request
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(CallError::Malformed)?;
        let key = self
            .tickets
            .iter()
            .find(|k| k.public().epoch == epoch)
            .ok_or(CallError::UnknownKey)?;
        let accepted = key.accept(request)?;
        if !token_ok(&accepted.token) || !self.spent.spend(&accepted.token, now)? {
            return Err(CallError::Crypto);
        }
        let duration = u64::from(accepted.duration.min(4 * 3600));
        let session: [u8; 16] = self.rng.array("relay/session")?;
        let (reply, ticket): (Vec<u8>, Ticket) =
            accepted.issue(session, now, now + duration, &mut self.rng)?;
        self.sessions.insert(
            session,
            Session {
                link: Link::relay(ticket),
                client: None,
                rendezvous: None,
                peer: None,
            },
        );
        Ok(reply)
    }

    /// Drop expired sessions and spent tokens past their retention.
    pub fn expire(&mut self, now: u64) {
        if let Err(e) = self.spent.prune(now) {
            eprintln!("enclave-relay: pruning spent tokens failed: {e}");
        }
        self.sessions.retain(|_, s| !s.link.expired(now));
        let live: std::collections::HashSet<[u8; 16]> = self.sessions.keys().copied().collect();
        self.rendezvous.retain(|_, s| live.contains(s));
    }

    /// Handle one datagram; returns what to send where.
    pub fn handle(&mut self, from: SocketAddr, dg: &[u8], now: u64) -> Vec<(SocketAddr, Vec<u8>)> {
        let out = match dg.first() {
            Some(&T_CLIENT) => self.on_client(from, &dg[1..], now),
            Some(&T_RELAY) => self.on_peer(from, &dg[1..], now),
            _ => Err(CallError::Malformed),
        };
        out.unwrap_or_else(|_| {
            self.stats.dropped += 1;
            Vec::new()
        })
    }

    fn on_client(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let sid = link::session_of(dg).ok_or(CallError::Malformed)?;
        let s = self.sessions.get_mut(&sid).ok_or(CallError::UnknownKey)?;
        let pt = s.link.open(now, dg)?;
        s.client = Some(from); // roaming: follow the latest authenticated address
        match pt.first() {
            Some(&P_JOIN) => {
                let (rv, peer) = decode_join(&pt[1..])?;
                if !self.peers.contains_key(&peer) && peer != self.desc.addr {
                    return Err(CallError::UnknownKey);
                }
                s.rendezvous = Some(rv);
                s.peer = Some(peer);
                self.rendezvous.insert(rv, sid);
                Ok(Vec::new())
            }
            Some(&P_MEDIA) => {
                let (rv, peer) = (
                    s.rendezvous.ok_or(CallError::UnknownKey)?,
                    s.peer.ok_or(CallError::UnknownKey)?,
                );
                if peer == self.desc.addr {
                    // Both legs on this relay (only when families allow it).
                    return self.deliver(&rv, Some(sid), &pt[1..], now);
                }
                let p = self.peers.get_mut(&peer).ok_or(CallError::UnknownKey)?;
                let mut hdr = [0u8; 24];
                hdr[..16].copy_from_slice(&rv);
                hdr[16..].copy_from_slice(&p.counter.to_be_bytes());
                let ct = seal::seal_compact(&p.send, &hdr[16..], &hdr, &pt[1..])?;
                p.counter += 1;
                self.stats.to_peer += 1;
                Ok(vec![(peer, [&[T_RELAY][..], &hdr, &ct].concat())])
            }
            Some(&P_KEEPALIVE) => Ok(Vec::new()),
            _ => Err(CallError::Malformed),
        }
    }

    fn on_peer(
        &mut self,
        from: SocketAddr,
        dg: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let p = self.peers.get_mut(&from).ok_or(CallError::UnknownKey)?;
        if dg.len() < 24 + seal::TAG_LEN {
            return Err(CallError::Malformed);
        }
        let counter = u64::from_be_bytes(dg[16..24].try_into().map_err(|_| CallError::Malformed)?);
        if let Some(top) = p.top
            && counter <= top
            && (top - counter >= 128 || p.bits & (1u128 << (top - counter)) != 0)
        {
            return Err(CallError::Replay);
        }
        let packet = seal::open_compact(&p.recv, &dg[16..24], &dg[..24], &dg[24..])?;
        match p.top {
            None => {
                p.top = Some(counter);
                p.bits = 1;
            }
            Some(top) if counter > top => {
                let sh = counter - top;
                p.bits = if sh >= 128 { 1 } else { p.bits << sh | 1 };
                p.top = Some(counter);
            }
            Some(top) => p.bits |= 1u128 << (top - counter),
        }
        let rv: [u8; 16] = dg[..16].try_into().map_err(|_| CallError::Malformed)?;
        self.deliver(&rv, None, &packet, now)
    }

    fn deliver(
        &mut self,
        rv: &[u8; 16],
        not: Option<[u8; 16]>,
        packet: &[u8],
        now: u64,
    ) -> Result<Vec<(SocketAddr, Vec<u8>)>, CallError> {
        let mut out = Vec::new();
        // The local leg(s) of this rendezvous other than the sender.
        let targets: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(sid, s)| s.rendezvous.as_ref() == Some(rv) && Some(**sid) != not)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in targets {
            let s = self.sessions.get_mut(&sid).ok_or(CallError::UnknownKey)?;
            let Some(addr) = s.client else { continue };
            let dg = s.link.seal(now, &[&[P_MEDIA][..], packet].concat())?;
            out.push((addr, [&[T_CLIENT][..], &dg].concat()));
            self.stats.to_client += 1;
        }
        if out.is_empty() {
            return Err(CallError::UnknownKey);
        }
        Ok(out)
    }
}

/// Encode a join payload: rendezvous id and the peer relay's address.
pub fn join_payload(rendezvous: &[u8; 16], peer: SocketAddr) -> Vec<u8> {
    let mut v = vec![P_JOIN];
    v.extend_from_slice(rendezvous);
    let s = peer.to_string();
    v.push(s.len() as u8);
    v.extend_from_slice(s.as_bytes());
    v
}

fn decode_join(b: &[u8]) -> Result<([u8; 16], SocketAddr), CallError> {
    let rv: [u8; 16] = b
        .get(..16)
        .ok_or(CallError::Malformed)?
        .try_into()
        .map_err(|_| CallError::Malformed)?;
    let n = usize::from(*b.get(16).ok_or(CallError::Malformed)?);
    let s = std::str::from_utf8(b.get(17..17 + n).ok_or(CallError::Malformed)?)
        .map_err(|_| CallError::Malformed)?;
    Ok((rv, s.parse().map_err(|_| CallError::Malformed)?))
}

/// Client helper: wrap a link datagram for the wire.
pub fn client_datagram(link: &mut Link, now: u64, payload: &[u8]) -> Result<Vec<u8>, CallError> {
    Ok([&[T_CLIENT][..], &link.seal(now, payload)?].concat())
}

/// Client helper: unwrap a datagram from our relay into a media packet.
pub fn client_receive(link: &mut Link, now: u64, dg: &[u8]) -> Result<Vec<u8>, CallError> {
    if dg.first() != Some(&T_CLIENT) {
        return Err(CallError::Malformed);
    }
    let pt = link.open(now, &dg[1..])?;
    match pt.split_first() {
        Some((&P_MEDIA, packet)) => Ok(packet.to_vec()),
        _ => Err(CallError::Malformed),
    }
}

/// Run a relay on a UDP socket until the socket fails.
pub async fn serve(relay: Arc<Mutex<Relay>>, socket: tokio::net::UdpSocket) -> std::io::Result<()> {
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let out = relay.lock().await.handle(from, &buf[..n], now);
        for (to, dg) in out {
            socket.send_to(&dg, to).await?;
        }
    }
}
