//! Sealed request/reply helpers over a [`Transport`].

use crate::{CoreError, Result};
use enclave_crypto::rng::HedgedRng;
use enclave_net::transport::{ServerId, Transport};
use enclave_rpc::ServerKey;
use enclave_rpc::api::{self, DirAction, DirKind, DirReply, DirRequest, FLAG_FOUND, Status};
use enclave_wire::{Op, RequestHeader};
use std::collections::HashMap;
use std::sync::Arc;

/// Reply to one call.
pub(crate) struct Reply {
    pub status: Status,
    pub flags: u8,
    pub header: RequestHeader,
    pub envelope: Vec<u8>,
}

/// Proof-of-work efforts tried in order when a server asks for more.
const EFFORT_LADDER: [u32; 7] = [8, 16, 64, 256, 1024, 4096, 16_384];

pub(crate) struct Rpc {
    transport: Arc<dyn Transport>,
    keys: HashMap<ServerId, ServerKey>,
}

impl Rpc {
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            keys: HashMap::new(),
        }
    }

    async fn key(&mut self, server: &ServerId, now: u64) -> Result<ServerKey> {
        let today = (now / 86_400) as u32;
        if let Some(k) = self.keys.get(server)
            && k.key_id == today
        {
            return Ok(k.clone());
        }
        let k = self.transport.server_key(server).await?;
        self.keys.insert(*server, k.clone());
        Ok(k)
    }

    pub async fn call(
        &mut self,
        server: &ServerId,
        h: RequestHeader,
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Reply> {
        let key = self.key(server, now).await?;
        let (bytes, ex) = if h.op == Op::Poll || h.op == Op::Ack {
            enclave_rpc::seal_poll(&key, &h, rng)?
        } else {
            enclave_rpc::seal_request(&key, &h, env, rng)?
        };
        let reply = self.transport.exchange(server, bytes).await?;
        let (rh, renv) = ex.open_reply(&reply)?;
        Ok(Reply {
            status: Status::from_u8(rh.flags),
            flags: rh.flags,
            header: rh,
            envelope: renv,
        })
    }

    /// A call that must succeed.
    pub async fn call_ok(
        &mut self,
        server: &ServerId,
        h: RequestHeader,
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Reply> {
        let r = self.call(server, h, env, now, rng).await?;
        if r.status != Status::Ok {
            return Err(CoreError::Server(r.status));
        }
        Ok(r)
    }

    async fn dir(
        &mut self,
        server: &ServerId,
        req: DirRequest,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<(Status, Option<DirReply>)> {
        let env = api::frame(&req.encode(), rng)?;
        let h = RequestHeader {
            op: Op::Directory,
            flags: 0,
            mailbox: [0; 32],
            token: [0; 32],
        };
        let r = self.call(server, h, &env, now, rng).await?;
        let reply = api::unframe(&r.envelope)
            .ok()
            .filter(|p| !p.is_empty())
            .and_then(|p| DirReply::decode(p).ok());
        Ok((r.status, reply))
    }

    /// Upload an object in chunks.
    pub async fn dir_put(
        &mut self,
        server: &ServerId,
        kind: DirKind,
        key: [u8; 32],
        proof: [u8; 32],
        data: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let chunks = api::chunks(data);
        let total = chunks.len() as u32;
        for (i, c) in chunks.iter().enumerate() {
            let req = DirRequest {
                kind,
                action: DirAction::Put,
                key,
                index: i as u32,
                total,
                proof,
                data: c.to_vec(),
            };
            let (s, _) = self.dir(server, req, now, rng).await?;
            if s != Status::Ok {
                return Err(CoreError::Server(s));
            }
        }
        Ok(())
    }

    /// Download an object, following chunk totals.
    pub async fn dir_get(
        &mut self,
        server: &ServerId,
        kind: DirKind,
        action: DirAction,
        key: [u8; 32],
        proof: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        let first = DirRequest {
            kind,
            action,
            key,
            index: 0,
            total: 0,
            proof,
            data: vec![],
        };
        let (s, r) = self.dir(server, first, now, rng).await?;
        if s != Status::Ok {
            return Err(CoreError::Server(s));
        }
        let r = r.ok_or(CoreError::Server(Status::Malformed))?;
        if r.total > 4096 {
            return Err(CoreError::TooLong);
        }
        let mut out = r.data;
        let (key, action) = if action == DirAction::Claim {
            (r.claim, DirAction::Get)
        } else {
            (key, action)
        };
        for i in 1..r.total {
            let req = DirRequest {
                kind,
                action,
                key,
                index: i,
                total: 0,
                proof,
                data: vec![],
            };
            let (s, rr) = self.dir(server, req, now, rng).await?;
            if s != Status::Ok {
                return Err(CoreError::Server(s));
            }
            out.extend_from_slice(&rr.ok_or(CoreError::Server(Status::Malformed))?.data);
        }
        Ok(out)
    }

    /// Claim a device bundle, escalating proof of work as the server asks.
    pub async fn claim_bundle(
        &mut self,
        server: &ServerId,
        key: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<u8>> {
        let ctx = api::pow_context_claim(&key, now / 86_400);
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, rng)?;
            match self
                .dir_get(
                    server,
                    DirKind::Bundle,
                    DirAction::Claim,
                    key,
                    proof.0,
                    now,
                    rng,
                )
                .await
            {
                Err(CoreError::Server(Status::Pow)) => continue,
                other => return other,
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Write to a request inbox, escalating proof of work as the server asks.
    pub async fn write_request(
        &mut self,
        server: &ServerId,
        inbox: [u8; 32],
        env: &[u8],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<()> {
        let ctx = api::pow_context_request(&inbox, &enclave_crypto::hash::sha3_512(env));
        for effort in EFFORT_LADDER {
            let proof = enclave_tokens::solve(&ctx, effort, rng)?;
            let h = RequestHeader {
                op: Op::WriteRequest,
                flags: 0,
                mailbox: inbox,
                token: proof.0,
            };
            match self.call(server, h, env, now, rng).await?.status {
                Status::Ok => return Ok(()),
                Status::Pow => continue,
                s => return Err(CoreError::Server(s)),
            }
        }
        Err(CoreError::Server(Status::Pow))
    }

    /// Fetch everything in `mailbox` after `cursor`. Returns the envelopes with
    /// the cursor after each one.
    pub async fn poll(
        &mut self,
        server: &ServerId,
        mailbox: [u8; 32],
        owner: &[u8; 32],
        mut cursor: u64,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Vec<(Vec<u8>, u64)>> {
        let cred = api::read_credential(owner);
        let mut out = Vec::new();
        // Bounded so a hostile server cannot keep us polling forever.
        for _ in 0..1024 {
            let mut token = [0u8; 32];
            token[..24].copy_from_slice(&cred);
            token[24..].copy_from_slice(&cursor.to_be_bytes());
            let h = RequestHeader {
                op: Op::Poll,
                flags: 0,
                mailbox,
                token,
            };
            let r = self.call_ok(server, h, &[], now, rng).await?;
            if r.flags & FLAG_FOUND == 0 {
                break;
            }
            let mut c = [0u8; 8];
            c.copy_from_slice(&r.header.token[24..]);
            let next = u64::from_be_bytes(c);
            if next <= cursor {
                return Err(CoreError::Server(Status::Malformed));
            }
            cursor = next;
            out.push((r.envelope, cursor));
        }
        Ok(out)
    }
}
