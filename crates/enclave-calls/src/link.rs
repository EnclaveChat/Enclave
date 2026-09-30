//! The client↔relay link: datagrams sealed under per-direction keys derived
//! from the ticket's period PSK.
//!
//! This stands in for WireGuard (D8) until a Rust WireGuard without C or
//! assembly crypto is available: every published one (boringtun, GotaTun)
//! uses ring or aws-lc, and GotaTun 0.9 needs a newer toolchain. The key
//! schedule is the ticket PSK schedule WireGuard will use, so switching the
//! framing does not change what the relay or an observer learns. Datagram:
//! `session 16 ‖ period u32 ‖ counter u64 ‖ EnclaveSeal-compact(payload)`.

use crate::ticket::Ticket;
use crate::{CallError, Result, labels};
use enclave_crypto::seal::{self, SealKey};
use std::collections::HashMap;

/// Link header length.
pub const HEADER_LEN: usize = 16 + 4 + 8;
/// Per-datagram overhead.
pub const OVERHEAD: usize = HEADER_LEN + seal::TAG_LEN;

/// Direction of a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Client to relay.
    Up,
    /// Relay to client.
    Down,
}

fn key(t: &Ticket, period: u32, dir: Dir) -> SealKey {
    let d = [match dir {
        Dir::Up => 1u8,
        Dir::Down => 2,
    }];
    seal::derive_key(&t.psk(period)[..], &d, labels::LINK_DIR)
}

/// Session id of a datagram (for routing), without authenticating it.
pub fn session_of(datagram: &[u8]) -> Option<[u8; 16]> {
    datagram.get(..16)?.try_into().ok()
}

/// One end of a link.
pub struct Link {
    ticket: Ticket,
    send: Dir,
    counter: u64,
    seen: HashMap<u32, (u64, u128)>,
}

impl Link {
    /// The client end (sends up).
    pub fn client(ticket: Ticket) -> Self {
        Self {
            ticket,
            send: Dir::Up,
            counter: 0,
            seen: HashMap::new(),
        }
    }

    /// The relay end (sends down).
    pub fn relay(ticket: Ticket) -> Self {
        Self {
            ticket,
            send: Dir::Down,
            counter: 0,
            seen: HashMap::new(),
        }
    }

    /// Session id.
    pub fn session(&self) -> [u8; 16] {
        self.ticket.session
    }

    /// Whether the ticket has expired.
    pub fn expired(&self, now: u64) -> bool {
        now >= self.ticket.expiry
    }

    /// Seal a payload.
    pub fn seal(&mut self, now: u64, payload: &[u8]) -> Result<Vec<u8>> {
        if self.expired(now) {
            return Err(CallError::Stale);
        }
        let period = self.ticket.period(now);
        let mut hdr = [0u8; HEADER_LEN];
        hdr[..16].copy_from_slice(&self.ticket.session);
        hdr[16..20].copy_from_slice(&period.to_be_bytes());
        hdr[20..].copy_from_slice(&self.counter.to_be_bytes());
        let ct = seal::seal_compact(
            &key(&self.ticket, period, self.send),
            &hdr[16..],
            &hdr,
            payload,
        )?;
        self.counter += 1;
        Ok([&hdr[..], &ct].concat())
    }

    /// Open a datagram from the other end. The current and the previous
    /// period are accepted (a datagram may cross the boundary).
    pub fn open(&mut self, now: u64, datagram: &[u8]) -> Result<Vec<u8>> {
        if datagram.len() < OVERHEAD || datagram[..16] != self.ticket.session {
            return Err(CallError::Malformed);
        }
        let period = u32::from_be_bytes(
            datagram[16..20]
                .try_into()
                .map_err(|_| CallError::Malformed)?,
        );
        let counter = u64::from_be_bytes(
            datagram[20..28]
                .try_into()
                .map_err(|_| CallError::Malformed)?,
        );
        let cur = self.ticket.period(now);
        if period > cur || period + 1 < cur || self.expired(now) {
            return Err(CallError::Stale);
        }
        let (top, bits) = self.seen.get(&period).copied().unwrap_or((0, 0));
        let fresh = bits == 0
            || counter > top
            || (top - counter < 128 && bits & (1u128 << (top - counter)) == 0);
        if !fresh {
            return Err(CallError::Replay);
        }
        let recv = if self.send == Dir::Up {
            Dir::Down
        } else {
            Dir::Up
        };
        let pt = seal::open_compact(
            &key(&self.ticket, period, recv),
            &datagram[16..HEADER_LEN],
            &datagram[..HEADER_LEN],
            &datagram[HEADER_LEN..],
        )?;
        let entry = if bits == 0 {
            (counter, 1)
        } else if counter > top {
            let s = counter - top;
            (counter, if s >= 128 { 1 } else { bits << s | 1 })
        } else {
            (top, bits | 1u128 << (top - counter))
        };
        self.seen.insert(period, entry);
        self.seen.retain(|p, _| *p + 1 >= cur);
        Ok(pt)
    }
}
