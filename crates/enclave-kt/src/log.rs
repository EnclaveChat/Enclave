//! The server-side log (`KtLog`), witnesses, and client lookup verification.

use crate::config::EnclaveKtConfig;
use crate::head::{CTX_COSIGN, Cosignature, SignedHead, TreeHead, WitnessPolicy, cosign_message};
use crate::store::KtStore;
use crate::username::{normalize, skeleton};
use crate::{KtError, Result};
use akd::ecvrf::{VRFKeyStorage, VrfError};
use akd::storage::StorageManager;
use akd::{AkdLabel, AkdValue, AppendOnlyProof, AzksParallelismConfig, Directory, LookupProof};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositePublic, CompositeSigningKey};
use std::collections::HashMap;
use std::sync::Arc;

/// The key-transparency label under which a server commits its
/// descriptor's digest (not a valid username: it starts with a zero byte).
pub const DESCRIPTOR_LABEL: &[u8] = b"\0descriptor";

/// VRF key held in memory for the life of the process.
#[derive(Clone)]
pub struct VrfKey(Arc<[u8; 32]>);

#[async_trait::async_trait]
impl VRFKeyStorage for VrfKey {
    async fn retrieve(&self) -> core::result::Result<Vec<u8>, VrfError> {
        Ok(self.0.to_vec())
    }
}

fn akd_err(e: impl core::fmt::Display) -> KtError {
    KtError::Directory(e.to_string())
}

type Dir = Directory<EnclaveKtConfig, KtStore, VrfKey>;

/// A server's key-transparency log.
pub struct KtLog {
    server: [u8; 16],
    store: KtStore,
    dir: Dir,
    signing: CompositeSigningKey,
    heads: Vec<SignedHead>,
    vrf_public: Vec<u8>,
    /// skeleton → registered name
    skeletons: HashMap<String, String>,
}

impl KtLog {
    /// Create an empty log in memory. `vrf_secret` must stay fixed for the
    /// life of the log.
    pub async fn new(
        server: [u8; 16],
        signing: CompositeSigningKey,
        vrf_secret: [u8; 32],
    ) -> Result<Self> {
        let mut rng = HedgedRng::new().map_err(|_| KtError::Directory("rng".into()))?;
        Self::open(KtStore::memory()?, server, signing, vrf_secret, 0, &mut rng).await
    }

    /// Open the log kept in `store` (empty or written by an earlier run with
    /// the same keys). The signing key and VRF secret must be the ones the
    /// log was started with: a head that doesn't verify under the signing
    /// key, or a tree whose root doesn't match the last signed head, is
    /// refused rather than served. If the process stopped between
    /// committing an epoch and storing its head, that one head is signed
    /// now (at `now`).
    pub async fn open(
        store: KtStore,
        server: [u8; 16],
        signing: CompositeSigningKey,
        vrf_secret: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Self> {
        let storage = StorageManager::new_no_cache(store.clone());
        let vrf = VrfKey(Arc::new(vrf_secret));
        let dir = Directory::new(storage, vrf, AzksParallelismConfig::default())
            .await
            .map_err(akd_err)?;
        let vrf_public = dir
            .get_public_key()
            .await
            .map_err(akd_err)?
            .as_bytes()
            .to_vec();
        let heads = store.heads()?;
        for (i, h) in heads.iter().enumerate() {
            h.verify_server(signing.public())?;
            if h.head.server != server || h.head.epoch != i as u64 + 1 {
                return Err(KtError::Directory(
                    "stored heads don't belong to this log".into(),
                ));
            }
        }
        let mut log = Self {
            server,
            store,
            dir,
            signing,
            heads,
            vrf_public,
            skeletons: HashMap::new(),
        };
        log.skeletons = log.store.skeletons()?;
        let tree = log.dir.get_epoch_hash().await.map_err(akd_err)?;
        let signed = log.heads.last().map_or(0, |h| h.head.epoch);
        if tree.epoch() == signed + 1 {
            log.sign_head(tree.epoch(), tree.hash(), now, rng)?;
        } else if tree.epoch() != signed
            || log.heads.last().is_some_and(|h| h.head.root != tree.hash())
        {
            return Err(KtError::Directory(format!(
                "tree is at epoch {}, last signed head at {signed}",
                tree.epoch()
            )));
        }
        Ok(log)
    }

    /// Server identifier.
    pub fn server(&self) -> [u8; 16] {
        self.server
    }

    /// The server's head-signing public key.
    pub fn public_key(&self) -> &CompositePublic {
        self.signing.public()
    }

    /// VRF public key clients need to verify lookups.
    pub fn vrf_public(&self) -> &[u8] {
        &self.vrf_public
    }

    /// Register or update `name → value` (value = SHA3-512 of the root key and
    /// the manifest locator). A new name must not share a confusable skeleton
    /// with an existing different name.
    pub async fn publish(
        &mut self,
        name: &str,
        value: Vec<u8>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        let n = normalize(name)?;
        let sk = skeleton(&n);
        if let Some(existing) = self.skeletons.get(&sk)
            && existing != &n
        {
            return Err(KtError::Username);
        }
        let sh = self
            .publish_raw(AkdLabel::from(n.as_str()), value, now, rng)
            .await?;
        self.store.put_skeleton(&sk, &n)?;
        self.skeletons.insert(sk, n);
        Ok(sh)
    }

    /// Start a new epoch with no username changes, so heads stay fresh for
    /// clients (they refuse heads older than a day). The label is not a valid
    /// username, so no lookup can reach it.
    pub async fn heartbeat(&mut self, now: u64, rng: &mut HedgedRng) -> Result<SignedHead> {
        self.publish_raw(
            AkdLabel(b"\0heartbeat".to_vec()),
            now.to_be_bytes().to_vec(),
            now,
            rng,
        )
        .await
    }

    /// Commit the digest of the server's current descriptor
    /// (`12-servers.md` §4.3) in a new epoch, under a label no username
    /// can equal, so a server can't show different people different
    /// descriptors without the log showing it.
    pub async fn commit_descriptor(
        &mut self,
        digest: [u8; 64],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        self.publish_raw(
            AkdLabel(DESCRIPTOR_LABEL.to_vec()),
            digest.to_vec(),
            now,
            rng,
        )
        .await
    }

    /// Lookup proof for the committed descriptor digest against the latest
    /// head.
    pub async fn lookup_descriptor(&self) -> Result<(LookupProof, SignedHead)> {
        let head = self.latest().cloned().ok_or(KtError::Lookup)?;
        let (proof, eh) = self
            .dir
            .lookup(AkdLabel(DESCRIPTOR_LABEL.to_vec()))
            .await
            .map_err(|_| KtError::Lookup)?;
        if eh.epoch() != head.head.epoch {
            return Err(KtError::Stale);
        }
        Ok((proof, head))
    }

    async fn publish_raw(
        &mut self,
        label: AkdLabel,
        value: Vec<u8>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        let eh = self
            .dir
            .publish(vec![(label, AkdValue(value))])
            .await
            .map_err(akd_err)?;
        self.sign_head(eh.epoch(), eh.hash(), now, rng)
    }

    fn sign_head(
        &mut self,
        epoch: u64,
        root: [u8; 32],
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<SignedHead> {
        let head = TreeHead {
            server: self.server,
            epoch,
            root,
            time: now,
        };
        let sh = SignedHead::sign(head, &self.signing, rng)?;
        self.store.put_head(&sh)?;
        self.heads.push(sh.clone());
        Ok(sh)
    }

    /// Latest head (with whatever cosignatures it has collected).
    pub fn latest(&self) -> Option<&SignedHead> {
        self.heads.last()
    }

    /// Heads with epochs in `(after, upto]`, oldest first.
    pub fn heads_after(&self, after: u64, upto: u64) -> Vec<SignedHead> {
        self.heads
            .iter()
            .filter(|h| h.head.epoch > after && h.head.epoch <= upto)
            .cloned()
            .collect()
    }

    /// Attach a witness cosignature to the head of `epoch`.
    pub fn add_cosignature(&mut self, epoch: u64, c: Cosignature) -> Result<()> {
        if let Some(h) = self.heads.iter_mut().find(|h| h.head.epoch == epoch)
            && !h.cosignatures.iter().any(|x| x.witness == c.witness)
        {
            h.cosignatures.push(c);
            self.store.put_head(h)?;
        }
        Ok(())
    }

    /// Lookup proof for `name` against the latest head.
    pub async fn lookup(&self, name: &str) -> Result<(LookupProof, SignedHead)> {
        let n = normalize(name)?;
        let head = self.latest().cloned().ok_or(KtError::Lookup)?;
        let (proof, eh) = self
            .dir
            .lookup(AkdLabel::from(n.as_str()))
            .await
            .map_err(|_| KtError::Lookup)?;
        if eh.epoch() != head.head.epoch {
            return Err(KtError::Stale);
        }
        Ok((proof, head))
    }

    /// Append-only proof from epoch `from` to epoch `to`.
    pub async fn audit(&self, from: u64, to: u64) -> Result<AppendOnlyProof> {
        self.dir.audit(from, to).await.map_err(akd_err)
    }
}

/// Client: verify a lookup, returning `(value, version, trusted time)`.
pub fn verify_lookup(
    policy: &WitnessPolicy,
    server_key: &CompositePublic,
    server_operator: &str,
    vrf_public: &[u8],
    sh: &SignedHead,
    name: &str,
    proof: LookupProof,
    now: u64,
) -> Result<(Vec<u8>, u64, u64)> {
    let trusted = policy.check(sh, server_key, server_operator, now)?;
    let n = normalize(name)?;
    let r = akd::verify::lookup_verify::<EnclaveKtConfig>(
        vrf_public,
        sh.head.root,
        sh.head.epoch,
        AkdLabel::from(n.as_str()),
        proof,
    )
    .map_err(|_| KtError::Lookup)?;
    Ok((r.value.0, r.version, trusted))
}

/// A witness: cosigns heads only after checking they extend what it saw before.
pub struct Witness {
    /// Identifier.
    pub id: [u8; 16],
    /// Operator (for the independence rule).
    pub operator: String,
    signing: CompositeSigningKey,
    last: HashMap<[u8; 16], TreeHead>,
    store: Option<KtStore>,
}

impl Witness {
    /// New witness that remembers what it cosigned only in memory.
    pub fn new(id: [u8; 16], operator: &str, signing: CompositeSigningKey) -> Self {
        Self {
            id,
            operator: operator.to_string(),
            signing,
            last: HashMap::new(),
            store: None,
        }
    }

    /// A witness that keeps what it last cosigned for each server in
    /// `store`, so after a restart it still refuses a head that doesn't
    /// extend the one it cosigned before.
    pub fn with_store(
        id: [u8; 16],
        operator: &str,
        signing: CompositeSigningKey,
        store: KtStore,
    ) -> Result<Self> {
        Ok(Self {
            id,
            operator: operator.to_string(),
            signing,
            last: store.witnessed(&id)?,
            store: Some(store),
        })
    }

    /// The last epoch this witness cosigned for `server`.
    pub fn last_epoch(&self, server: &[u8; 16]) -> Option<u64> {
        self.last.get(server).map(|h| h.epoch)
    }

    /// Public key clients pin.
    pub fn public_key(&self) -> &CompositePublic {
        self.signing.public()
    }

    /// Cosign the newest of `heads` (consecutive epochs following the last head
    /// this witness cosigned for that server). `proof` is the append-only proof
    /// from the last cosigned epoch to the newest. The first time a witness sees
    /// a server it cosigns on first use.
    pub async fn cosign(
        &mut self,
        server_key: &CompositePublic,
        heads: &[SignedHead],
        proof: Option<AppendOnlyProof>,
        now: u64,
        rng: &mut HedgedRng,
    ) -> Result<Cosignature> {
        let newest = heads.last().ok_or(KtError::Stale)?;
        for h in heads {
            h.verify_server(server_key)?;
            if h.head.server != newest.head.server {
                return Err(KtError::Signature);
            }
        }
        for w in heads.windows(2) {
            if w[1].head.epoch != w[0].head.epoch + 1 {
                return Err(KtError::NotAppendOnly);
            }
        }
        let server = newest.head.server;
        if let Some(last) = self.last.get(&server).copied() {
            let first = &heads[0].head;
            if first.epoch != last.epoch + 1 {
                return Err(KtError::NotAppendOnly);
            }
            let mut hashes = vec![last.root];
            hashes.extend(heads.iter().map(|h| h.head.root));
            let p = proof.ok_or(KtError::NotAppendOnly)?;
            akd::auditor::audit_verify::<EnclaveKtConfig>(hashes, p)
                .await
                .map_err(|_| KtError::NotAppendOnly)?;
        }
        let signature = self
            .signing
            .sign(CTX_COSIGN, &cosign_message(&newest.head, now), rng)
            .map_err(|_| KtError::Signature)?;
        // Remember the head before handing out the cosignature: a witness
        // that forgot it could later be talked into cosigning a fork.
        if let Some(store) = &self.store {
            store.put_witnessed(&self.id, &newest.head)?;
        }
        self.last.insert(server, newest.head);
        Ok(Cosignature {
            witness: self.id,
            time: now,
            signature,
        })
    }
}
