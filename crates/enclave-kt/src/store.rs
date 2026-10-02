//! Durable key-transparency state in redb (`docs/12-servers.md` §3.1).
//!
//! [`KtStore`] is akd's storage layer (the [`Database`] trait) over a redb
//! file, plus the tables Enclave keeps next to the tree: signed heads with
//! their cosignatures, the confusable-skeleton index, and what each local
//! witness last cosigned. akd commits an epoch with one `batch_set`, which
//! is one redb write transaction, so a crash leaves either the whole epoch
//! or none of it. Tests and the development server use redb's in-memory
//! backend: the same code, no file.
//!
//! akd's records are encoded here, field by field, in a fixed binary
//! layout (no serde): `NodeLabel = label_val (32) ‖ u32(label_len)`.

use crate::head::{SignedHead, TreeHead};
use crate::{KtError, Result};
use akd::errors::StorageError;
use akd::storage::types::{
    DbRecord, KeyData, StorageType, ValueState, ValueStateKey, ValueStateRetrievalFlag,
};
use akd::storage::{Database, DbSetState, Storable};
use akd::tree_node::{TreeNode, TreeNodeType, TreeNodeWithPreviousValue};
use akd::{AkdLabel, AkdValue, Azks, AzksValue, NodeLabel};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

type Bytes = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// akd tree records (the azks and tree nodes): akd's full binary id → record.
const RECORDS: Bytes = TableDefinition::new("kt-records");
/// Value states: `u16(len) ‖ username ‖ u64(epoch)` → record.
const VALUES: Bytes = TableDefinition::new("kt-values");
/// Signed heads with cosignatures: `u64(epoch)` → encoded `SignedHead`.
const HEADS: Bytes = TableDefinition::new("kt-heads");
/// Confusable skeleton → registered name.
const SKELETONS: Bytes = TableDefinition::new("kt-skeletons");
/// Local witnesses: `witness id ‖ server id` → the 64-byte head it last cosigned.
const WITNESSED: Bytes = TableDefinition::new("kt-witnessed");
/// Proofs that a log equivocated (`Equivocation`), kept by witnesses:
/// server id → encoded proof.
const EQUIVOCATIONS: Bytes = TableDefinition::new("kt-equivocations");
/// Schema version.
const META: Bytes = TableDefinition::new("kt-meta");

/// The schema this code writes.
pub const SCHEMA_VERSION: u32 = 2;

/// Every table; `META` last (it is open while the others are created).
/// 1 → 2 added `kt-equivocations`.
const ALL: [Bytes; 7] = [
    RECORDS,
    VALUES,
    HEADS,
    SKELETONS,
    WITNESSED,
    EQUIVOCATIONS,
    META,
];

/// Key-transparency storage. Cloning shares the database.
#[derive(Clone)]
pub struct KtStore {
    db: Arc<redb::Database>,
}

impl core::fmt::Debug for KtStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KtStore")
    }
}

fn db_err(e: impl core::fmt::Display) -> KtError {
    KtError::Directory(format!("storage: {e}"))
}

fn st_err(e: impl core::fmt::Display) -> StorageError {
    StorageError::Other(format!("redb: {e}"))
}

impl KtStore {
    /// Open (or create) the store at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let db = redb::Database::create(path).map_err(db_err)?;
        Self::init(db)
    }

    /// A store in memory (tests, development).
    pub fn memory() -> Result<Self> {
        let db = redb::Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(db_err)?;
        Self::init(db)
    }

    fn init(db: redb::Database) -> Result<Self> {
        let w = db.begin_write().map_err(db_err)?;
        {
            let mut meta = w.open_table(META).map_err(db_err)?;
            let current = meta
                .get(&b"schema"[..])
                .map_err(db_err)?
                .and_then(|v| v.value().try_into().ok().map(u32::from_be_bytes))
                .unwrap_or(0);
            if current > SCHEMA_VERSION {
                return Err(KtError::Directory(format!(
                    "key-transparency store schema {current} is newer than this server ({SCHEMA_VERSION})"
                )));
            }
            for t in &ALL[..ALL.len() - 1] {
                w.open_table(*t).map_err(db_err)?;
            }
            meta.insert(&b"schema"[..], &SCHEMA_VERSION.to_be_bytes()[..])
                .map_err(db_err)?;
        }
        w.commit().map_err(db_err)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Write a consistent copy of the whole store to `path`.
    pub fn snapshot(&self, path: &Path) -> Result<()> {
        let out = redb::Database::create(path).map_err(db_err)?;
        let r = self.db.begin_read().map_err(db_err)?;
        let w = out.begin_write().map_err(db_err)?;
        for t in ALL {
            let src = r.open_table(t).map_err(db_err)?;
            let mut dst = w.open_table(t).map_err(db_err)?;
            for item in src.iter().map_err(db_err)? {
                let (k, v) = item.map_err(db_err)?;
                dst.insert(k.value(), v.value()).map_err(db_err)?;
            }
        }
        w.commit().map_err(db_err)?;
        Ok(())
    }

    fn put(&self, t: Bytes, k: &[u8], v: &[u8]) -> Result<()> {
        let w = self.db.begin_write().map_err(db_err)?;
        w.open_table(t)
            .map_err(db_err)?
            .insert(k, v)
            .map_err(db_err)?;
        w.commit().map_err(db_err)
    }

    fn all(&self, t: Bytes) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let r = self.db.begin_read().map_err(db_err)?;
        let table = r.open_table(t).map_err(db_err)?;
        let mut out = Vec::new();
        for item in table.iter().map_err(db_err)? {
            let (k, v) = item.map_err(db_err)?;
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }

    /// Store (or replace) a signed head.
    pub fn put_head(&self, h: &SignedHead) -> Result<()> {
        self.put(HEADS, &h.head.epoch.to_be_bytes(), &h.encode())
    }

    /// Every stored head, oldest first.
    pub fn heads(&self) -> Result<Vec<SignedHead>> {
        self.all(HEADS)?
            .into_iter()
            .map(|(_, v)| SignedHead::decode(&v))
            .collect()
    }

    /// Record that `name` holds `skeleton`.
    pub fn put_skeleton(&self, skeleton: &str, name: &str) -> Result<()> {
        self.put(SKELETONS, skeleton.as_bytes(), name.as_bytes())
    }

    /// The skeleton index.
    pub fn skeletons(&self) -> Result<HashMap<String, String>> {
        self.all(SKELETONS)?
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    String::from_utf8(k).map_err(|_| KtError::Malformed)?,
                    String::from_utf8(v).map_err(|_| KtError::Malformed)?,
                ))
            })
            .collect()
    }

    /// Record the head witness `witness` last cosigned for its server.
    pub fn put_witnessed(&self, witness: &[u8; 16], head: &TreeHead) -> Result<()> {
        let mut k = witness.to_vec();
        k.extend_from_slice(&head.server);
        self.put(WITNESSED, &k, &head.encode())
    }

    /// What witness `witness` last cosigned, per server.
    pub fn witnessed(&self, witness: &[u8; 16]) -> Result<HashMap<[u8; 16], TreeHead>> {
        let mut out = HashMap::new();
        for (k, v) in self.all(WITNESSED)? {
            if k.len() != 32 || k[..16] != witness[..] {
                continue;
            }
            let h = TreeHead::decode(&v)?;
            out.insert(h.server, h);
        }
        Ok(out)
    }

    /// Keep the proof that a log equivocated (the first one per log).
    pub fn put_equivocation(&self, e: &crate::Equivocation) -> Result<()> {
        if self.equivocations()?.contains_key(&e.server()) {
            return Ok(());
        }
        self.put(EQUIVOCATIONS, &e.server(), &e.encode())
    }

    /// The proofs kept, per log.
    pub fn equivocations(&self) -> Result<HashMap<[u8; 16], crate::Equivocation>> {
        let mut out = HashMap::new();
        for (_, v) in self.all(EQUIVOCATIONS)? {
            let e = crate::Equivocation::decode(&v)?;
            out.insert(e.server(), e);
        }
        Ok(out)
    }

    fn get_record(&self, bin_id: &[u8]) -> core::result::Result<Option<DbRecord>, StorageError> {
        let r = self.db.begin_read().map_err(st_err)?;
        if bin_id.first() == Some(&(StorageType::ValueState as u8)) {
            let ValueStateKey(user, epoch) =
                ValueState::key_from_full_binary(bin_id).map_err(StorageError::Other)?;
            let t = r.open_table(VALUES).map_err(st_err)?;
            return t
                .get(&value_key(&user, epoch)[..])
                .map_err(st_err)?
                .map(|v| decode_record(v.value()))
                .transpose();
        }
        let t = r.open_table(RECORDS).map_err(st_err)?;
        t.get(bin_id)
            .map_err(st_err)?
            .map(|v| decode_record(v.value()))
            .transpose()
    }

    fn user_states(&self, user: &[u8]) -> core::result::Result<Vec<ValueState>, StorageError> {
        let r = self.db.begin_read().map_err(st_err)?;
        let t = r.open_table(VALUES).map_err(st_err)?;
        let lo = value_key(user, 0);
        let hi = value_key(user, u64::MAX);
        let mut out = Vec::new();
        for item in t.range(&lo[..]..=&hi[..]).map_err(st_err)? {
            let (_, v) = item.map_err(st_err)?;
            match decode_record(v.value())? {
                DbRecord::ValueState(s) => out.push(s),
                _ => {
                    return Err(StorageError::Other(
                        "value table holds a tree record".into(),
                    ));
                }
            }
        }
        // The key ends in a big-endian epoch, so this is already oldest first.
        Ok(out)
    }
}

/// `u16(len) ‖ username ‖ u64(epoch)`: one user's states are contiguous and
/// sorted by epoch.
fn value_key(user: &[u8], epoch: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + user.len() + 8);
    k.extend_from_slice(&(user.len().min(u16::MAX as usize) as u16).to_be_bytes());
    k.extend_from_slice(user);
    k.extend_from_slice(&epoch.to_be_bytes());
    k
}

#[async_trait::async_trait]
impl Database for KtStore {
    async fn set(&self, record: DbRecord) -> core::result::Result<(), StorageError> {
        self.batch_set(vec![record], DbSetState::General).await
    }

    async fn batch_set(
        &self,
        records: Vec<DbRecord>,
        _state: DbSetState,
    ) -> core::result::Result<(), StorageError> {
        let w = self.db.begin_write().map_err(st_err)?;
        {
            let mut rec = w.open_table(RECORDS).map_err(st_err)?;
            let mut val = w.open_table(VALUES).map_err(st_err)?;
            for r in &records {
                if r.get_full_binary_id().len() > u16::MAX as usize {
                    return Err(StorageError::Other("record id too long".into()));
                }
                let bytes = encode_record(r);
                match r {
                    DbRecord::ValueState(s) => {
                        if s.username.0.len() > u16::MAX as usize {
                            return Err(StorageError::Other("label too long".into()));
                        }
                        val.insert(&value_key(&s.username.0, s.epoch)[..], &bytes[..])
                            .map_err(st_err)?;
                    }
                    _ => {
                        rec.insert(&r.get_full_binary_id()[..], &bytes[..])
                            .map_err(st_err)?;
                    }
                }
            }
        }
        w.commit().map_err(st_err)
    }

    async fn get<St: Storable>(
        &self,
        id: &St::StorageKey,
    ) -> core::result::Result<DbRecord, StorageError> {
        self.get_record(&St::get_full_binary_key_id(id))?
            .ok_or_else(|| StorageError::NotFound(format!("{:?} {id:?}", St::data_type())))
    }

    async fn batch_get<St: Storable>(
        &self,
        ids: &[St::StorageKey],
    ) -> core::result::Result<Vec<DbRecord>, StorageError> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            // Like akd's own stores: what isn't there is left out.
            if let Some(r) = self.get_record(&St::get_full_binary_key_id(id))? {
                out.push(r);
            }
        }
        Ok(out)
    }

    async fn get_user_data(
        &self,
        username: &AkdLabel,
    ) -> core::result::Result<KeyData, StorageError> {
        let states = self.user_states(&username.0)?;
        if states.is_empty() {
            return Err(StorageError::NotFound(format!("ValueState {username:?}")));
        }
        Ok(KeyData { states })
    }

    async fn get_user_state(
        &self,
        username: &AkdLabel,
        flag: ValueStateRetrievalFlag,
    ) -> core::result::Result<ValueState, StorageError> {
        let states = self.user_states(&username.0)?;
        pick(states, flag).ok_or_else(|| StorageError::NotFound(format!("ValueState {username:?}")))
    }

    async fn get_user_state_versions(
        &self,
        usernames: &[AkdLabel],
        flag: ValueStateRetrievalFlag,
    ) -> core::result::Result<HashMap<AkdLabel, (u64, AkdValue)>, StorageError> {
        let mut out = HashMap::new();
        for u in usernames {
            if let Some(s) = pick(self.user_states(&u.0)?, flag) {
                out.insert(AkdLabel(s.username.0.clone()), (s.version, s.value));
            }
        }
        Ok(out)
    }
}

/// The state `flag` asks for among one user's states (oldest first), with
/// the same meaning as akd's in-memory store.
fn pick(states: Vec<ValueState>, flag: ValueStateRetrievalFlag) -> Option<ValueState> {
    match flag {
        ValueStateRetrievalFlag::MaxEpoch => states.into_iter().last(),
        ValueStateRetrievalFlag::MinEpoch => states.into_iter().next(),
        ValueStateRetrievalFlag::SpecificVersion(v) => states.into_iter().find(|s| s.version == v),
        ValueStateRetrievalFlag::SpecificEpoch(e) => states.into_iter().find(|s| s.epoch == e),
        ValueStateRetrievalFlag::LeqEpoch(e) => states.into_iter().rfind(|s| s.epoch <= e),
    }
}

// ---- Record encoding ----

const TAG_AZKS: u8 = 1;
const TAG_NODE: u8 = 2;
const TAG_VALUE: u8 = 4;

fn put_label(b: &mut Vec<u8>, l: &NodeLabel) {
    b.extend_from_slice(&l.label_val);
    b.extend_from_slice(&l.label_len.to_be_bytes());
}

fn put_opt_label(b: &mut Vec<u8>, l: &Option<NodeLabel>) {
    match l {
        Some(l) => {
            b.push(1);
            put_label(b, l);
        }
        None => b.push(0),
    }
}

fn put_node(b: &mut Vec<u8>, n: &TreeNode) {
    put_label(b, &n.label);
    b.extend_from_slice(&n.last_epoch.to_be_bytes());
    b.extend_from_slice(&n.min_descendant_epoch.to_be_bytes());
    put_label(b, &n.parent);
    b.push(n.node_type as u8);
    put_opt_label(b, &n.left_child);
    put_opt_label(b, &n.right_child);
    b.extend_from_slice(&n.hash.0);
}

fn put_bytes(b: &mut Vec<u8>, v: &[u8]) {
    b.extend_from_slice(&(v.len() as u32).to_be_bytes());
    b.extend_from_slice(v);
}

/// Encode one akd record.
pub fn encode_record(r: &DbRecord) -> Vec<u8> {
    let mut b = Vec::new();
    match r {
        DbRecord::Azks(a) => {
            b.push(TAG_AZKS);
            b.extend_from_slice(&a.latest_epoch.to_be_bytes());
            b.extend_from_slice(&a.num_nodes.to_be_bytes());
        }
        DbRecord::TreeNode(n) => {
            b.push(TAG_NODE);
            put_label(&mut b, &n.label);
            put_node(&mut b, &n.latest_node);
            match &n.previous_node {
                Some(p) => {
                    b.push(1);
                    put_node(&mut b, p);
                }
                None => b.push(0),
            }
        }
        DbRecord::ValueState(s) => {
            b.push(TAG_VALUE);
            b.extend_from_slice(&s.version.to_be_bytes());
            put_label(&mut b, &s.label);
            b.extend_from_slice(&s.epoch.to_be_bytes());
            put_bytes(&mut b, &s.username.0);
            put_bytes(&mut b, &s.value.0);
        }
    }
    b
}

struct Reader<'a>(&'a [u8]);

fn bad() -> StorageError {
    StorageError::Other("damaged key-transparency record".into())
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> core::result::Result<&'a [u8], StorageError> {
        if self.0.len() < n {
            return Err(bad());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> core::result::Result<u8, StorageError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> core::result::Result<u32, StorageError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| bad())?,
        ))
    }
    fn u64(&mut self) -> core::result::Result<u64, StorageError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| bad())?,
        ))
    }
    fn arr32(&mut self) -> core::result::Result<[u8; 32], StorageError> {
        self.take(32)?.try_into().map_err(|_| bad())
    }
    fn label(&mut self) -> core::result::Result<NodeLabel, StorageError> {
        let v = self.arr32()?;
        let len = self.u32()?;
        if len > 256 {
            return Err(bad());
        }
        Ok(NodeLabel::new(v, len))
    }
    fn opt_label(&mut self) -> core::result::Result<Option<NodeLabel>, StorageError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.label()?)),
            _ => Err(bad()),
        }
    }
    fn bytes(&mut self) -> core::result::Result<Vec<u8>, StorageError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn node(&mut self) -> core::result::Result<TreeNode, StorageError> {
        let label = self.label()?;
        let last_epoch = self.u64()?;
        let min_descendant_epoch = self.u64()?;
        let parent = self.label()?;
        let node_type = match self.u8()? {
            1 => TreeNodeType::Leaf,
            2 => TreeNodeType::Root,
            3 => TreeNodeType::Interior,
            _ => return Err(bad()),
        };
        let left_child = self.opt_label()?;
        let right_child = self.opt_label()?;
        let hash = AzksValue(self.arr32()?);
        Ok(TreeNode {
            label,
            last_epoch,
            min_descendant_epoch,
            parent,
            node_type,
            left_child,
            right_child,
            hash,
        })
    }
}

/// Decode [`encode_record`].
pub fn decode_record(b: &[u8]) -> core::result::Result<DbRecord, StorageError> {
    let mut r = Reader(b);
    let rec = match r.u8()? {
        TAG_AZKS => DbRecord::Azks(Azks {
            latest_epoch: r.u64()?,
            num_nodes: r.u64()?,
        }),
        TAG_NODE => {
            let label = r.label()?;
            let latest_node = r.node()?;
            let previous_node = match r.u8()? {
                0 => None,
                1 => Some(r.node()?),
                _ => return Err(bad()),
            };
            DbRecord::TreeNode(TreeNodeWithPreviousValue {
                label,
                latest_node,
                previous_node,
            })
        }
        TAG_VALUE => {
            let version = r.u64()?;
            let label = r.label()?;
            let epoch = r.u64()?;
            let username = AkdLabel(r.bytes()?);
            let value = AkdValue(r.bytes()?);
            DbRecord::ValueState(ValueState {
                value,
                version,
                label,
                epoch,
                username,
            })
        }
        _ => return Err(bad()),
    };
    if !r.0.is_empty() {
        return Err(bad());
    }
    Ok(rec)
}
