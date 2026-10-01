//! The pre-rekey PQ step (`docs/07-groups.md` §5.2).
//!
//! A rotation wraps the new chain seed under each member device's pairwise
//! exporter key, which comes from that pair's ML-KEM ratchet. If a pair
//! hasn't taken a PQ step since the group's last epoch change, an attacker
//! who held that pair's state then could still derive the exporter. So,
//! before rotating, the device pings every such member with
//! `Content::PqStep`: every unit carries a full PQ slot, so the ping and
//! its reply are one ML-KEM round trip. This client doesn't make the send
//! wait: it rotates at once (the spec's "pre-step incomplete"), and when
//! every pinged pair has stepped, it rotates again, under the new keys.
//! A pair that never answers is pinged again at the next rotation.

use super::Client;
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_proto::ProtoError;
use enclave_proto::codec::{Reader, Writer};
use std::collections::BTreeSet;

const NS_GROUP_PQ: &str = "group-pq";
pub(crate) const NS_PQ_REPLIES: &str = "pq-replies";
/// No epoch recorded yet.
const NONE: u32 = u32::MAX;

/// One pair: member root, device id, and its PQ epochs `(out, in)`.
type Pair = ([u8; 64], [u8; 16], (u32, u32));

/// What a group remembers for the pre-step.
#[derive(Default)]
struct Track {
    /// The group epoch the marks were taken at.
    epoch: u32,
    /// Each pair's PQ epochs when the group epoch last changed.
    marks: Vec<Pair>,
    /// Pairs pinged, with their PQ epochs when pinged.
    pending: Vec<Pair>,
    /// Rotations made after a completed pre-step.
    healed: u32,
}

fn put_pairs(w: &mut Writer, v: &[Pair]) {
    w.u32(v.len() as u32);
    for (r, d, (o, i)) in v {
        w.fixed(r).fixed(d).u32(*o).u32(*i);
    }
}

fn get_pairs(r: &mut Reader<'_>) -> enclave_proto::Result<Vec<Pair>> {
    let n = r.u32()?;
    if n > 100 * 5 {
        return Err(ProtoError::Decode);
    }
    (0..n)
        .map(|_| Ok((r.array()?, r.array()?, (r.u32()?, r.u32()?))))
        .collect()
}

impl Track {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).u32(self.epoch);
        put_pairs(&mut w, &self.marks);
        put_pairs(&mut w, &self.pending);
        w.u32(self.healed);
        w.finish()
    }

    fn decode(b: &[u8]) -> enclave_proto::Result<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return Err(ProtoError::Decode);
        }
        let t = Self {
            epoch: r.u32()?,
            marks: get_pairs(&mut r)?,
            pending: get_pairs(&mut r)?,
            healed: r.u32()?,
        };
        r.end()?;
        Ok(t)
    }
}

impl Client {
    fn track(&self, gid: &[u8; 32]) -> Track {
        match self.store.get(NS_GROUP_PQ, gid) {
            Ok(Some(b)) => Track::decode(&b).unwrap_or_default(),
            _ => Track {
                epoch: NONE,
                ..Default::default()
            },
        }
    }

    fn save_track(&mut self, gid: &[u8; 32], t: &Track) -> Result<()> {
        self.store
            .put(NS_GROUP_PQ, gid, &t.encode(), &mut self.rng)?;
        Ok(())
    }

    /// Every member device we have a session with, and its PQ epochs now.
    fn member_pairs(&self, gid: &[u8; 32]) -> Vec<Pair> {
        let Some(e) = self.groups.get(gid) else {
            return Vec::new();
        };
        let me = e.group.me;
        let mut v = Vec::new();
        for (m, member) in e.group.state.active() {
            if m == me {
                continue;
            }
            let root = super::migrate::resolve(&self.store, &member.root);
            let Some(c) = self.contacts.get(&root) else {
                continue;
            };
            for dev in &c.manifest.devices {
                if let Some(s) = self.sessions.get(&(root, dev.id)) {
                    v.push((root, dev.id, s.pq_epochs()));
                }
            }
        }
        v
    }

    /// Record each pair's PQ epochs when the group epoch has changed.
    pub(crate) fn refresh_pq_marks(&mut self, gid: &[u8; 32]) -> Result<()> {
        let Some(epoch) = self.groups.get(gid).map(|e| e.group.epoch()) else {
            return Ok(());
        };
        let mut t = self.track(gid);
        if t.epoch == epoch {
            return Ok(());
        }
        t.epoch = epoch;
        t.marks = self.member_pairs(gid);
        self.save_track(gid, &t)
    }

    /// Before a rotation: ping every pair that hasn't taken a PQ step since
    /// the group's last epoch change, and remember them.
    pub(crate) async fn pre_rekey_step(&mut self, gid: &[u8; 32], now: u64) -> Result<()> {
        let mut t = self.track(gid);
        if t.epoch == NONE {
            return self.refresh_pq_marks(gid);
        }
        let stale: Vec<Pair> = self
            .member_pairs(gid)
            .into_iter()
            .filter(|(r, d, pq)| {
                t.marks
                    .iter()
                    .any(|(mr, md, mpq)| mr == r && md == d && mpq == pq)
            })
            .collect();
        let roots: BTreeSet<[u8; 64]> = stale.iter().map(|(r, _, _)| *r).collect();
        for root in roots {
            // A member we can't reach now is pinged at the next rotation.
            let _ = self
                .send_content(&root, &Content::PqStep { reply: true }, now)
                .await;
        }
        t.pending = stale;
        self.save_track(gid, &t)
    }

    /// A member asked for a PQ round trip: answer at the next sync.
    pub(crate) fn queue_pq_reply(&mut self, root: &[u8; 64]) -> Result<()> {
        self.store.put(NS_PQ_REPLIES, root, &[1], &mut self.rng)?;
        Ok(())
    }

    /// Answer queued PQ pings, and rotate again in groups whose pinged pairs
    /// have all stepped.
    pub(crate) async fn finish_pre_steps(&mut self, now: u64) -> Result<()> {
        for (k, _) in self.store.scan(NS_PQ_REPLIES)? {
            self.store.delete(NS_PQ_REPLIES, &k)?;
            if let Ok(root) = <[u8; 64]>::try_from(k.as_slice()) {
                let _ = self
                    .send_content(&root, &Content::PqStep { reply: false }, now)
                    .await;
            }
        }
        let ids: Vec<[u8; 32]> = self
            .groups
            .iter()
            .filter(|(_, e)| !e.left)
            .map(|(k, _)| *k)
            .collect();
        for gid in ids {
            // Marks taken close to each epoch change, not only when we rotate.
            if self.track(&gid).epoch != NONE {
                self.refresh_pq_marks(&gid)?;
            }
            let mut t = self.track(&gid);
            if t.pending.is_empty() {
                continue;
            }
            let now_pairs = self.member_pairs(&gid);
            let before = t.pending.len();
            t.pending.retain(|(r, d, pq)| {
                now_pairs
                    .iter()
                    .any(|(nr, nd, npq)| nr == r && nd == d && npq == pq)
            });
            if t.pending.is_empty() && before > 0 {
                t.healed += 1;
                self.save_track(&gid, &t)?;
                self.rotate_group_after_pre_step(&gid, now).await?;
            } else {
                self.save_track(&gid, &t)?;
            }
        }
        Ok(())
    }

    /// Pairs still waiting for their pre-rekey PQ step in `gid`, and how many
    /// rotations followed a completed one.
    pub fn group_pre_step(&self, gid: &[u8; 32]) -> Result<(usize, u32)> {
        if !self.groups.contains_key(gid) {
            return Err(CoreError::NotFound);
        }
        let t = self.track(gid);
        Ok((t.pending.len(), t.healed))
    }
}
