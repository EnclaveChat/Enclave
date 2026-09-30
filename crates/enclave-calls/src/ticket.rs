//! Relay tickets (`docs/11-calls.md` §3.3).
//!
//! A client obtains a ticket from a relay's ticket service with an
//! X448 + ML-KEM-1024 exchange to the relay's daily ticket key. Both ends
//! derive `ticket_secret`, and from it a link key per 120 s period. Tickets
//! are requested anonymously (over the mixnet, paid with a Privacy Pass
//! token), so the relay cannot tie a ticket to an account.

use crate::{CallError, Result, labels};
use enclave_crypto::kem::{
    MLKEM_CT_LEN, MlKemCiphertext, MlKemPublic, MlKemSecret, Suite, X448_LEN, X448Public,
    X448Secret, combine,
};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::{self, SealKey};
use enclave_proto::codec::{Reader, Writer};
use zeroize::Zeroizing;

/// Link keys change every this many seconds.
pub const PERIOD_SECS: u64 = 120;

/// A relay's public ticket key for one day.
#[derive(Clone, PartialEq, Eq)]
pub struct TicketKey {
    /// Relay id.
    pub relay_id: [u8; 16],
    /// Key epoch (day).
    pub epoch: u32,
    /// X448 part.
    pub x448: X448Public,
    /// ML-KEM-1024 part.
    pub mlkem: MlKemPublic,
}

/// The relay's secret half.
pub struct TicketSecretKey {
    public: TicketKey,
    x: X448Secret,
    k: MlKemSecret,
}

impl TicketSecretKey {
    /// Fresh key for `epoch`.
    pub fn generate(relay_id: [u8; 16], epoch: u32, rng: &mut HedgedRng) -> Result<Self> {
        let (x, xp) = X448Secret::generate(rng)?;
        let (k, kp) = MlKemSecret::generate(rng)?;
        Ok(Self {
            public: TicketKey {
                relay_id,
                epoch,
                x448: xp,
                mlkem: kp,
            },
            x,
            k,
        })
    }

    /// Public half.
    pub fn public(&self) -> &TicketKey {
        &self.public
    }

    /// Relay: open a ticket request. Returns the Privacy Pass token (for the
    /// caller to verify and burn), the requested duration, and a responder
    /// that issues the ticket.
    pub fn accept(&self, req: &[u8]) -> Result<Accepted> {
        let mut r = Reader::new(req);
        let m = |_| CallError::Malformed;
        let epoch = r.u32().map_err(m)?;
        if epoch != self.public.epoch {
            return Err(CallError::UnknownKey);
        }
        let eph = X448Public(r.array::<X448_LEN>().map_err(m)?);
        let ct = MlKemCiphertext::from_slice(r.fixed(MLKEM_CT_LEN).map_err(m)?)?;
        let sealed = r.bytes(256).map_err(m)?;
        r.end().map_err(m)?;
        let dh = self.x.diffie_hellman(&eph)?;
        let ss_m = self.k.decapsulate(&ct);
        let (secret, k_seal) = derive(&self.public, &eph, &ct, &dh[..], &ss_m[..]);
        let pt = Zeroizing::new(seal::open(&k_seal, &ad(&self.public, b"request"), sealed)?);
        if pt.len() != 36 {
            return Err(CallError::Malformed);
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(&pt[..32]);
        let duration = u32::from_be_bytes([pt[32], pt[33], pt[34], pt[35]]);
        Ok(Accepted {
            token,
            duration,
            secret,
            k_seal,
            public: self.public.clone(),
        })
    }
}

fn ad(key: &TicketKey, what: &[u8]) -> Vec<u8> {
    [
        labels::AD_TICKET.as_bytes(),
        &key.relay_id,
        &key.epoch.to_be_bytes(),
        what,
    ]
    .concat()
}

fn derive(
    key: &TicketKey,
    eph: &X448Public,
    ct: &MlKemCiphertext,
    dh: &[u8],
    ss_m: &[u8],
) -> (Zeroizing<[u8; 32]>, SealKey) {
    let transcript = [
        labels::TICKET_TRANSCRIPT.as_bytes(),
        &key.relay_id,
        &key.epoch.to_be_bytes(),
    ]
    .concat();
    let ss = combine(
        Suite::TwoKem,
        &[dh, ss_m],
        &[
            &key.x448.0,
            &key.mlkem.0[..],
            &eph.0,
            &ct.0[..],
            &transcript,
        ],
        None,
    );
    let secret = Zeroizing::new(kmac256(&ss[..], b"", labels::TICKET_SECRET));
    let k_seal = seal::derive_key(&ss[..], b"", labels::TICKET_SEAL);
    (secret, k_seal)
}

/// Client: ask `key`'s relay for a ticket.
pub fn request(
    key: &TicketKey,
    token: [u8; 32],
    duration: u32,
    rng: &mut HedgedRng,
) -> Result<(Vec<u8>, TicketClient)> {
    let (eph, eph_pub) = X448Secret::generate(rng)?;
    let dh = eph.diffie_hellman(&key.x448)?;
    let (ct, ss_m) = key.mlkem.encapsulate(rng)?;
    let (secret, k_seal) = derive(key, &eph_pub, &ct, &dh[..], &ss_m[..]);
    let body = [&token[..], &duration.to_be_bytes()].concat();
    let sealed = seal::seal(&k_seal, &ad(key, b"request"), &body, rng)?;
    let mut w = Writer::new();
    w.u32(key.epoch)
        .fixed(&eph_pub.0)
        .fixed(&ct.0[..])
        .bytes(&sealed);
    Ok((
        w.finish(),
        TicketClient {
            secret,
            k_seal,
            key: key.clone(),
        },
    ))
}

/// Client state until the reply arrives.
pub struct TicketClient {
    secret: Zeroizing<[u8; 32]>,
    k_seal: SealKey,
    key: TicketKey,
}

impl TicketClient {
    /// Finish with the relay's reply.
    pub fn finish(self, reply: &[u8]) -> Result<Ticket> {
        let pt = seal::open(&self.k_seal, &ad(&self.key, b"reply"), reply)?;
        if pt.len() != 32 {
            return Err(CallError::Malformed);
        }
        let mut session = [0u8; 16];
        session.copy_from_slice(&pt[..16]);
        let t0 = u64::from_be_bytes(pt[16..24].try_into().map_err(|_| CallError::Malformed)?);
        let expiry = u64::from_be_bytes(pt[24..32].try_into().map_err(|_| CallError::Malformed)?);
        Ok(Ticket {
            session,
            t0,
            expiry,
            secret: self.secret,
        })
    }
}

/// A request the relay has opened.
pub struct Accepted {
    /// Privacy Pass token to verify and burn.
    pub token: [u8; 32],
    /// Requested duration in seconds.
    pub duration: u32,
    secret: Zeroizing<[u8; 32]>,
    k_seal: SealKey,
    public: TicketKey,
}

impl Accepted {
    /// Relay: issue the ticket. Returns the reply for the client and the
    /// relay's copy.
    pub fn issue(
        self,
        session: [u8; 16],
        t0: u64,
        expiry: u64,
        rng: &mut HedgedRng,
    ) -> Result<(Vec<u8>, Ticket)> {
        let pt = [&session[..], &t0.to_be_bytes(), &expiry.to_be_bytes()].concat();
        let reply = seal::seal(&self.k_seal, &ad(&self.public, b"reply"), &pt, rng)?;
        Ok((
            reply,
            Ticket {
                session,
                t0,
                expiry,
                secret: self.secret,
            },
        ))
    }
}

/// A ticket, as both the client and the relay hold it.
pub struct Ticket {
    /// Session id on the relay.
    pub session: [u8; 16],
    /// Start of period 0.
    pub t0: u64,
    /// Expiry.
    pub expiry: u64,
    secret: Zeroizing<[u8; 32]>,
}

impl Ticket {
    /// Period index at `now`.
    pub fn period(&self, now: u64) -> u32 {
        (now.saturating_sub(self.t0) / PERIOD_SECS) as u32
    }

    /// `psk_i = KMAC256(ticket_secret, u32(i), "wg-psk")`.
    pub fn psk(&self, period: u32) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(kmac256(
            &self.secret[..],
            &period.to_be_bytes(),
            labels::WG_PSK,
        ))
    }
}
