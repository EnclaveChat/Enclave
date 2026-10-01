//! The 72-hour guard on account changes made without an existing device
//! (`03-identity.md` §7.1, RT-22).
//!
//! Whoever holds the recovery words holds the root, so the root's signature
//! alone can't tell the owner restoring their account from a thief. A new
//! manifest version takes effect at once only when a device listed in the
//! version it replaces co-signs it (`Attestation`, `Verdict::Cosign`); the
//! primary does this for every change it makes. Otherwise each contact holds
//! the change for 72 hours **from when that contact first saw it** (the
//! manifest's own `issued_at` is chosen by whoever signed it), and any device
//! of the old manifest can veto it during that time. A veto is stored in the
//! directory and also sent straight to contacts and our devices, so a server
//! that withholds it doesn't win.
//!
//! While a change is held, a contact keeps the greeting that came with it and
//! processes it once the change is accepted. Our own devices notice changes to
//! our manifest they didn't co-sign and raise [`Event::RecoveryPending`]; the
//! person then stops it ([`Client::stop_recovery`]) or confirms it
//! ([`Client::approve_recovery`]).

use super::{Client, ContactState, Event};
use crate::content::Content;
use crate::{CoreError, Result};
use enclave_crypto::sig::RootPublic;
use enclave_net::transport::ServerId;
use enclave_proto::attest::{self, Attestation, RECOVERY_WAIT_SECS, Verdict};
use enclave_proto::manifest::{Manifest, SignedManifest};
use enclave_rpc::api::{DirAction, DirKind, manifest_key};

/// root → version ‖ hash ‖ first seen
pub(crate) const NS_PENDING: &str = "pending-manifests";
/// replay id → next try ‖ envelope
pub(crate) const NS_HELD: &str = "held-requests";
/// root ‖ version → hash
const NS_VETOES: &str = "vetoes";
/// How often held greetings and our own manifest are re-checked.
const RECHECK_SECS: u64 = 600;

/// What to do with a manifest change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Judgement {
    /// Take it.
    Accept,
    /// Hold it until this time (unless co-signed or vetoed first).
    Wait(u64),
    /// Never take it.
    Vetoed,
}

/// A change to our own account that none of our devices made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryAlert {
    /// The manifest version.
    pub version: u64,
    /// Its hash.
    pub hash: [u8; 64],
    /// When contacts will accept it unless it is stopped.
    pub until: u64,
}

fn veto_key(root: &[u8; 64], version: u64) -> Vec<u8> {
    [&root[..], &version.to_be_bytes()].concat()
}

impl Client {
    /// Decide on `new` (signed as `signed`), which replaces `old` for the
    /// account `root` whose directory is on `server`.
    pub(crate) async fn judge(
        &mut self,
        root: &[u8; 64],
        server: &ServerId,
        old: &Manifest,
        signed: &SignedManifest,
        new: &Manifest,
        now: u64,
    ) -> Result<Judgement> {
        let hash = signed.hash();
        let atts = self.fetch_attestations(server, root, now).await?;
        let about = |v: Verdict| {
            atts.iter()
                .any(|a| a.verdict == v && a.is_about(new.version, &hash) && a.verify(root, old))
        };
        if about(Verdict::Cosign) {
            self.store.delete(NS_PENDING, root)?;
            return Ok(Judgement::Accept);
        }
        let local_veto = self
            .store
            .get(NS_VETOES, &veto_key(root, new.version))?
            .is_some_and(|h| h == hash);
        if about(Verdict::Veto) || local_veto {
            return Ok(Judgement::Vetoed);
        }
        let first = match self.store.get(NS_PENDING, root)? {
            Some(b) if b.len() == 80 && b[..8] == new.version.to_be_bytes() && b[8..72] == hash => {
                u64::from_be_bytes(b[72..80].try_into().map_err(|_| CoreError::NotFound)?)
            }
            _ => {
                let rec = [&new.version.to_be_bytes()[..], &hash, &now.to_be_bytes()].concat();
                self.store.put(NS_PENDING, root, &rec, &mut self.rng)?;
                now
            }
        };
        if first + RECOVERY_WAIT_SECS <= now {
            self.store.delete(NS_PENDING, root)?;
            Ok(Judgement::Accept)
        } else {
            Ok(Judgement::Wait(first + RECOVERY_WAIT_SECS))
        }
    }

    async fn fetch_attestations(
        &mut self,
        server: &ServerId,
        root: &[u8; 64],
        now: u64,
    ) -> Result<Vec<Attestation>> {
        match self
            .rpc
            .dir_get(
                server,
                DirKind::Attest,
                DirAction::Get,
                manifest_key(root),
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(b) => Ok(attest::decode_list(&b).unwrap_or_default()),
            Err(e @ CoreError::Net(_)) => Err(e),
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Co-sign the manifest we are about to publish (we are in the current
    /// one). Uploaded before the manifest, so no contact sees it unsigned.
    pub(crate) async fn cosign_own(
        &mut self,
        signed: &SignedManifest,
        version: u64,
        now: u64,
    ) -> Result<()> {
        let root = self.account.root_public.0;
        let a = Attestation::sign(
            Verdict::Cosign,
            &root,
            version,
            signed.hash(),
            &self.device,
            &mut self.rng,
        )?;
        let server = self.profile.server;
        self.rpc
            .dir_put(
                &server,
                DirKind::Attest,
                manifest_key(&root),
                [0; 32],
                &a.encode(),
                now,
                &mut self.rng,
            )
            .await
    }

    /// Keep a greeting whose sender's manifest change is held.
    pub(crate) fn hold_request(
        &mut self,
        rid: &[u8],
        env: &[u8],
        until: u64,
        now: u64,
    ) -> Result<()> {
        let next = until.min(now + RECHECK_SECS);
        let v = [&next.to_be_bytes()[..], env].concat();
        self.store.put(NS_HELD, rid, &v, &mut self.rng)?;
        Ok(())
    }

    /// Re-run held greetings that are due for another look.
    pub(crate) async fn release_held(&mut self, now: u64) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        for (k, v) in self.store.scan(NS_HELD)? {
            if v.len() < 8 {
                self.store.delete(NS_HELD, &k)?;
                continue;
            }
            let next = u64::from_be_bytes(v[..8].try_into().map_err(|_| CoreError::NotFound)?);
            if next > now {
                continue;
            }
            // Removed first; `handle_request` holds it again if still waiting.
            self.store.delete(NS_HELD, &k)?;
            match self.handle_request(&v[8..], now).await {
                Ok(Some(e)) => events.push(e),
                Ok(None) => {}
                Err(e @ CoreError::Net(_)) => {
                    self.store.put(NS_HELD, &k, &v, &mut self.rng)?;
                    return Err(e);
                }
                Err(_) => {}
            }
        }
        Ok(events)
    }

    /// Look for changes to our own manifest that none of our devices made
    /// (every 10 minutes). Co-signed changes are adopted.
    pub(crate) async fn check_own_manifest(&mut self, now: u64) -> Result<Vec<Event>> {
        let last = self
            .setting("own-check")?
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        if last + RECHECK_SECS > now {
            return Ok(Vec::new());
        }
        self.set_setting("own-check", &now.to_be_bytes())?;
        let root = self.account.root_public.0;
        let server = self.profile.server;
        let bytes = match self
            .rpc
            .dir_get(
                &server,
                DirKind::Manifest,
                DirAction::Get,
                manifest_key(&root),
                [0; 32],
                now,
                &mut self.rng,
            )
            .await
        {
            Ok(b) => b,
            Err(e @ CoreError::Net(_)) => return Err(e),
            Err(_) => return Ok(Vec::new()),
        };
        let Ok(signed) = SignedManifest::from_bytes(&bytes) else {
            return Ok(Vec::new());
        };
        let Ok(new) = signed.verify(&RootPublic(root), now) else {
            return Ok(Vec::new());
        };
        if new.version <= self.manifest.version {
            return Ok(Vec::new());
        }
        let old = self.manifest.clone();
        match self.judge(&root, &server, &old, &signed, &new, now).await? {
            Judgement::Accept => {
                self.set_manifest(new.clone(), &signed)?;
                self.recovery_alert = None;
                let gone: Vec<[u8; 16]> = self
                    .sessions
                    .keys()
                    .filter(|(r, d)| *r == root && new.device(d).is_none())
                    .map(|(_, d)| *d)
                    .collect();
                for d in gone {
                    self.sessions.remove(&(root, d));
                    self.store
                        .delete(crate::persist::NS_SESSIONS, &super::session_key(&root, &d))?;
                }
                Ok(vec![if new.device(&self.device.id).is_none() {
                    Event::RemovedFromAccount
                } else {
                    Event::DevicesChanged
                }])
            }
            Judgement::Wait(until) => {
                let alert = RecoveryAlert {
                    version: new.version,
                    hash: signed.hash(),
                    until,
                };
                let fresh = self.recovery_alert.as_ref() != Some(&alert);
                self.recovery_alert = Some(alert);
                Ok(if fresh {
                    vec![Event::RecoveryPending { until }]
                } else {
                    Vec::new()
                })
            }
            Judgement::Vetoed => Ok(Vec::new()),
        }
    }

    /// A change to our account that none of our devices made, if one is
    /// waiting.
    pub fn recovery_alert(&self) -> Option<&RecoveryAlert> {
        self.recovery_alert.as_ref()
    }

    /// "This wasn't me": veto the pending change. Contacts will never accept
    /// it, and it is published and sent to them directly.
    pub async fn stop_recovery(&mut self) -> Result<()> {
        self.attest_pending(Verdict::Veto).await
    }

    /// "It's me": co-sign the pending change so contacts accept it now.
    pub async fn approve_recovery(&mut self) -> Result<()> {
        self.attest_pending(Verdict::Cosign).await
    }

    async fn attest_pending(&mut self, verdict: Verdict) -> Result<()> {
        let alert = self.recovery_alert.clone().ok_or(CoreError::NotFound)?;
        let now = self.now();
        let root = self.account.root_public.0;
        let a = Attestation::sign(
            verdict,
            &root,
            alert.version,
            alert.hash,
            &self.device,
            &mut self.rng,
        )?;
        let server = self.profile.server;
        // The directory copy first: that is what contacts check.
        let published = self
            .rpc
            .dir_put(
                &server,
                DirKind::Attest,
                manifest_key(&root),
                [0; 32],
                &a.encode(),
                now,
                &mut self.rng,
            )
            .await;
        if verdict == Verdict::Veto {
            self.store.put(
                NS_VETOES,
                &veto_key(&root, alert.version),
                &alert.hash,
                &mut self.rng,
            )?;
            // Also straight to contacts and our devices, in case the server
            // withholds it.
            let notice = Content::Veto(a.encode());
            let _ = self.send_own(&notice.encode()?, now).await;
            let roots: Vec<[u8; 64]> = self
                .contacts
                .values()
                .filter(|c| c.state == ContactState::Accepted && c.inbox.is_some())
                .map(|c| c.root)
                .collect();
            for r in roots {
                let _ = self.send_content(&r, &notice, now).await;
            }
            self.recovery_alert = None;
        } else {
            published?;
            // Adopt it on the next check.
            self.set_setting("own-check", &0u64.to_be_bytes())?;
        }
        Ok(())
    }

    /// A veto received from a device of `root` (a contact, or us).
    pub(crate) fn on_veto(&mut self, root: &[u8; 64], bytes: &[u8]) -> Result<()> {
        let Ok(a) = Attestation::decode(bytes) else {
            return Ok(());
        };
        let listed = if *root == self.account.root_public.0 {
            Some(self.manifest.clone())
        } else {
            self.contacts.get(root).map(|c| c.manifest.clone())
        };
        if a.verdict == Verdict::Veto && listed.is_some_and(|m| a.verify(root, &m)) {
            self.store.put(
                NS_VETOES,
                &veto_key(root, a.version),
                &a.manifest_hash,
                &mut self.rng,
            )?;
            if *root == self.account.root_public.0
                && self
                    .recovery_alert
                    .as_ref()
                    .is_some_and(|al| a.is_about(al.version, &al.hash))
            {
                self.recovery_alert = None;
            }
        }
        Ok(())
    }
}
