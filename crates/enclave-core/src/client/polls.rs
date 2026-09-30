//! Polls in groups (`docs/07-groups.md` §7.5, `docs/16-features.md`).
//!
//! A poll, each vote and the close are group messages flagged `FLAG_RICH`,
//! so they are sealed and MAC-authenticated like any other: members know
//! who voted how, outsiders learn nothing, and nobody can prove it to
//! outsiders (the MAC vector is deniable). A later vote from the same
//! member replaces their earlier one. Only the creator can close a poll;
//! the close carries `tally_hash = SHA3-512("enclave/v1/proto/poll-tally-hash"
//! ‖ poll_id ‖ u32 counts…)`, and every member compares it with the tally
//! they counted themselves, so a vote that didn't reach someone shows.

use super::{Client, Event};
use crate::content::MAX_TEXT;
use crate::{CoreError, Result};
use enclave_crypto::hash::sha3_512_parts;
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};
use enclave_proto::group::FLAG_RICH;
use enclave_proto::labels;
use std::collections::BTreeMap;

const NS_POLLS: &str = "polls";
/// Options per poll.
pub const MAX_OPTIONS: usize = 10;
/// Longest option, in bytes.
pub const MAX_OPTION: usize = 200;

const K_POLL: u8 = 1;
const K_VOTE: u8 = 2;
const K_CLOSE: u8 = 3;

enum Rich {
    Poll {
        id: [u8; 16],
        question: String,
        options: Vec<String>,
    },
    Vote {
        poll: [u8; 16],
        choice: u8,
    },
    Close {
        poll: [u8; 16],
        tally: [u8; 64],
    },
}

fn get_str(r: &mut Reader<'_>, max: usize) -> enclave_proto::Result<String> {
    String::from_utf8(r.bytes(max)?.to_vec()).map_err(|_| ProtoError::Decode)
}

impl Rich {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Rich::Poll {
                id,
                question,
                options,
            } => {
                w.u8(K_POLL)
                    .fixed(id)
                    .bytes(question.as_bytes())
                    .u8(options.len() as u8);
                for o in options {
                    w.bytes(o.as_bytes());
                }
            }
            Rich::Vote { poll, choice } => {
                w.u8(K_VOTE).fixed(poll).u8(*choice);
            }
            Rich::Close { poll, tally } => {
                w.u8(K_CLOSE).fixed(poll).fixed(tally);
            }
        }
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        let v = match r.u8()? {
            K_POLL => {
                let id = r.array()?;
                let question = get_str(&mut r, MAX_TEXT)?;
                let n = usize::from(r.u8()?);
                if !(2..=MAX_OPTIONS).contains(&n) {
                    return Err(ProtoError::Decode);
                }
                let options = (0..n)
                    .map(|_| get_str(&mut r, MAX_OPTION))
                    .collect::<enclave_proto::Result<_>>()?;
                Rich::Poll {
                    id,
                    question,
                    options,
                }
            }
            K_VOTE => Rich::Vote {
                poll: r.array()?,
                choice: r.u8()?,
            },
            K_CLOSE => Rich::Close {
                poll: r.array()?,
                tally: r.array()?,
            },
            _ => return Err(ProtoError::Decode),
        };
        r.end()?;
        Ok(v)
    }
}

/// A stored poll.
struct Poll {
    creator: [u8; 64],
    question: String,
    options: Vec<String>,
    votes: BTreeMap<[u8; 64], u8>,
    /// The creator's tally hash, once closed.
    closed: Option<[u8; 64]>,
}

impl Poll {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(&self.creator)
            .bytes(self.question.as_bytes())
            .u8(self.options.len() as u8);
        for o in &self.options {
            w.bytes(o.as_bytes());
        }
        w.u32(self.votes.len() as u32);
        for (r, c) in &self.votes {
            w.fixed(r).u8(*c);
        }
        match &self.closed {
            Some(t) => w.u8(1).fixed(t),
            None => w.u8(0),
        };
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let creator = r.array()?;
        let question = get_str(&mut r, MAX_TEXT)?;
        let n = usize::from(r.u8()?);
        let options = (0..n)
            .map(|_| get_str(&mut r, MAX_OPTION))
            .collect::<enclave_proto::Result<_>>()?;
        let mut votes = BTreeMap::new();
        for _ in 0..r.u32()?.min(1000) {
            votes.insert(r.array()?, r.u8()?);
        }
        let closed = match r.u8()? {
            1 => Some(r.array()?),
            _ => None,
        };
        r.end()?;
        Ok(Self {
            creator,
            question,
            options,
            votes,
            closed,
        })
    }

    fn counts(&self) -> Vec<u32> {
        let mut c = vec![0u32; self.options.len()];
        for &v in self.votes.values() {
            if let Some(x) = c.get_mut(usize::from(v)) {
                *x += 1;
            }
        }
        c
    }
}

/// `SHA3-512(label ‖ poll_id ‖ u32 counts…)`.
fn tally_hash(poll: &[u8; 16], counts: &[u32]) -> [u8; 64] {
    let counts: Vec<u8> = counts.iter().flat_map(|c| c.to_be_bytes()).collect();
    sha3_512_parts(&[labels::POLL_TALLY_HASH.as_bytes(), poll, &counts])
}

/// A poll as the app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollView {
    /// Poll id.
    pub id: [u8; 16],
    /// The question.
    pub question: String,
    /// Options with their vote counts.
    pub options: Vec<(String, u32)>,
    /// Our vote.
    pub mine: Option<u8>,
    /// We created it (and so may close it).
    pub ours: bool,
    /// Closed by its creator.
    pub closed: bool,
    /// Once closed: whether the creator's tally matches ours.
    pub tally_agrees: Option<bool>,
}

fn key(gid: &[u8; 32], id: &[u8; 16]) -> Vec<u8> {
    [&gid[..], &id[..]].concat()
}

impl Client {
    fn load_poll(&self, gid: &[u8; 32], id: &[u8; 16]) -> Result<Option<Poll>> {
        Ok(match self.store.get(NS_POLLS, &key(gid, id))? {
            Some(b) => Some(Poll::decode(&b)?),
            None => None,
        })
    }

    fn save_poll(&mut self, gid: &[u8; 32], id: &[u8; 16], p: &Poll) -> Result<()> {
        self.store
            .put(NS_POLLS, &key(gid, id), &p.encode(), &mut self.rng)?;
        Ok(())
    }

    /// Ask the group a question with 2 to 10 options.
    pub async fn create_poll(
        &mut self,
        gid: &[u8; 32],
        question: &str,
        options: &[String],
    ) -> Result<[u8; 16]> {
        let options: Vec<String> = options
            .iter()
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect();
        if question.trim().is_empty()
            || !(2..=MAX_OPTIONS).contains(&options.len())
            || question.len() > MAX_TEXT
            || options.iter().any(|o| o.len() > MAX_OPTION)
        {
            return Err(CoreError::TooLong);
        }
        let now = self.now();
        self.prepare_group_send(gid, now).await?;
        let id: [u8; 16] = self.rng.array("core/poll-id")?;
        let me = self.account.root_public.0;
        let poll = Poll {
            creator: me,
            question: question.trim().to_string(),
            options: options.clone(),
            votes: BTreeMap::new(),
            closed: None,
        };
        self.save_poll(gid, &id, &poll)?;
        let mut m = self.store_group_message(gid, None, &poll.question, now)?;
        m.poll = Some(id);
        let rich = Rich::Poll {
            id,
            question: poll.question.clone(),
            options,
        };
        self.post_group(gid, &rich.encode(), FLAG_RICH, now).await?;
        m.delivered = true;
        self.put_group_message(gid, &m)?;
        Ok(id)
    }

    /// Vote (again, to change it) while the poll is open.
    pub async fn vote(&mut self, gid: &[u8; 32], id: &[u8; 16], choice: u8) -> Result<()> {
        let mut p = self.load_poll(gid, id)?.ok_or(CoreError::NotFound)?;
        if p.closed.is_some() || usize::from(choice) >= p.options.len() {
            return Err(CoreError::NotAccepted);
        }
        let now = self.now();
        self.prepare_group_send(gid, now).await?;
        p.votes.insert(self.account.root_public.0, choice);
        self.save_poll(gid, id, &p)?;
        let rich = Rich::Vote { poll: *id, choice };
        self.post_group(gid, &rich.encode(), FLAG_RICH, now).await
    }

    /// Close our poll: no more votes, and everyone checks the tally.
    pub async fn close_poll(&mut self, gid: &[u8; 32], id: &[u8; 16]) -> Result<()> {
        let mut p = self.load_poll(gid, id)?.ok_or(CoreError::NotFound)?;
        if p.creator != self.account.root_public.0 {
            return Err(CoreError::NotAccepted);
        }
        if p.closed.is_some() {
            return Ok(());
        }
        let now = self.now();
        self.prepare_group_send(gid, now).await?;
        let tally = tally_hash(id, &p.counts());
        p.closed = Some(tally);
        self.save_poll(gid, id, &p)?;
        let rich = Rich::Close { poll: *id, tally };
        self.post_group(gid, &rich.encode(), FLAG_RICH, now).await
    }

    /// A poll in `gid`.
    pub fn poll(&self, gid: &[u8; 32], id: &[u8; 16]) -> Option<PollView> {
        let p = self.load_poll(gid, id).ok()??;
        let me = self.account.root_public.0;
        let counts = p.counts();
        let agrees = p.closed.map(|t| t == tally_hash(id, &counts));
        Some(PollView {
            id: *id,
            question: p.question.clone(),
            options: p.options.iter().cloned().zip(counts).collect(),
            mine: p.votes.get(&me).copied(),
            ours: p.creator == me,
            closed: p.closed.is_some(),
            tally_agrees: agrees,
        })
    }

    /// Structured content from a member.
    pub(crate) fn on_group_rich(
        &mut self,
        gid: &[u8; 32],
        from: &[u8; 64],
        name: String,
        content: &[u8],
        now: u64,
    ) -> Result<Option<Event>> {
        match Rich::decode(content)? {
            Rich::Poll {
                id,
                question,
                options,
            } => {
                if self.load_poll(gid, &id)?.is_some() {
                    return Ok(None);
                }
                let poll = Poll {
                    creator: *from,
                    question: question.clone(),
                    options,
                    votes: BTreeMap::new(),
                    closed: None,
                };
                self.save_poll(gid, &id, &poll)?;
                let mut m = self.store_group_message(gid, Some((*from, name)), &question, now)?;
                m.poll = Some(id);
                self.put_group_message(gid, &m)?;
                if let Some(e) = self.groups.get_mut(gid) {
                    e.unread = e.unread.saturating_add(1);
                }
                Ok(Some(Event::GroupMessage {
                    group_id: *gid,
                    message: m,
                }))
            }
            Rich::Vote { poll, choice } => {
                let Some(mut p) = self.load_poll(gid, &poll)? else {
                    return Ok(None);
                };
                if p.closed.is_some() || usize::from(choice) >= p.options.len() {
                    return Ok(None);
                }
                p.votes.insert(*from, choice);
                self.save_poll(gid, &poll, &p)?;
                Ok(Some(Event::PollChanged {
                    group_id: *gid,
                    poll,
                }))
            }
            Rich::Close { poll, tally } => {
                let Some(mut p) = self.load_poll(gid, &poll)? else {
                    return Ok(None);
                };
                if p.creator != *from || p.closed.is_some() {
                    return Ok(None);
                }
                p.closed = Some(tally);
                self.save_poll(gid, &poll, &p)?;
                Ok(Some(Event::PollChanged {
                    group_id: *gid,
                    poll,
                }))
            }
        }
    }
}
