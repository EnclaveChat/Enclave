//! Durable server state in redb (`docs/12-servers.md` §1.3).
//!
//! Every table maps bytes to bytes; the server encodes values itself. A
//! request that changes state does so in one write transaction, committed
//! (fsync'd) before the reply is sealed, so a token burned or an envelope
//! stored survives a crash, and a replayed request after a restart finds
//! the token gone. Tests and the simulator use redb's in-memory backend:
//! the same code, no files.

use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, TableError,
    WriteTransaction,
};
use std::path::Path;

type Bytes = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// Inbox metadata: owner and read credential hashes, flags, next sequence.
pub const INBOXES: Bytes = TableDefinition::new("inboxes");
/// Registered write tokens: `mailbox ‖ token hash` → empty.
pub const TOKENS: Bytes = TableDefinition::new("tokens");
/// Stored envelopes: `mailbox ‖ seq` → `time ‖ envelope`.
pub const ENVELOPES: Bytes = TableDefinition::new("envelopes");
/// Account manifests: key → `version ‖ signed manifest`.
pub const MANIFESTS: Bytes = TableDefinition::new("manifests");
/// Devices any manifest of an account listed: key → encoded list.
pub const DEVICES_SEEN: Bytes = TableDefinition::new("devices-seen");
/// Device attestations: key → encoded list (newest last).
pub const ATTESTATIONS: Bytes = TableDefinition::new("attestations");
/// Changes of recovery words: old root's key → migration record.
pub const MIGRATIONS: Bytes = TableDefinition::new("migrations");
/// Old root → new root.
pub const MOVED: Bytes = TableDefinition::new("moved");
/// Accounts that moved to another server: manifest key → `ServerMove`.
pub const SERVER_MOVES: Bytes = TableDefinition::new("server-moves");
/// Deleted accounts: manifest key → root-signed `Tombstone`.
pub const TOMBSTONES: Bytes = TableDefinition::new("tombstones");
/// Device id → the manifest key of the account that lists it.
pub const DEVICE_OWNER: Bytes = TableDefinition::new("device-owner");
/// Prekey publications: device → `next opk ‖ publication`.
pub const BUNDLES: Bytes = TableDefinition::new("bundles");
/// Encrypted vault keys: locator → `owner hash ‖ bytes`.
pub const VAULTS: Bytes = TableDefinition::new("vaults");
/// Blob chunks: id → `time ‖ bytes`.
pub const BLOBS: Bytes = TableDefinition::new("blobs");
/// Sealed push tokens: mailbox → sealed token.
pub const PUSH: Bytes = TableDefinition::new("push");
/// Usernames: name → `root ‖ last claim time`.
pub const USERNAMES: Bytes = TableDefinition::new("usernames");
/// Root → its current name.
pub const NAMES_BY_ROOT: Bytes = TableDefinition::new("names-by-root");
/// Reports for the operator: sequence → encoded report.
pub const REPORTS: Bytes = TableDefinition::new("reports");
/// Server metadata (schema version, counters).
pub const META: Bytes = TableDefinition::new("meta");

/// The schema this code writes. Older files are migrated on open.
pub const SCHEMA_VERSION: u32 = 3;

/// Storage failure. The server answers `Status::Internal` and logs it.
#[derive(Debug, thiserror::Error)]
#[error("storage: {0}")]
pub struct DbError(String);

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for DbError {
            fn from(e: $t) -> Self {
                DbError(e.to_string())
            }
        }
    )*};
}
from_redb!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

/// Result of a storage operation.
pub type Result<T> = core::result::Result<T, DbError>;

/// The server database.
pub struct Db {
    db: Database,
}

impl Db {
    /// Open (or create) the database file at `path`, migrating it.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Self {
            db: Database::create(path)?,
        };
        db.migrate()?;
        Ok(db)
    }

    /// A database that lives in memory (tests, simulator, dev demo).
    pub fn memory() -> Result<Self> {
        let db = Self {
            db: Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?,
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        let w = self.db.begin_write()?;
        {
            let mut meta = w.open_table(META)?;
            let current = meta
                .get(&b"schema"[..])?
                .and_then(|v| v.value().try_into().ok().map(u32::from_be_bytes))
                .unwrap_or(0);
            if current > SCHEMA_VERSION {
                return Err(DbError(format!(
                    "database schema {current} is newer than this server ({SCHEMA_VERSION})"
                )));
            }
            // Every table is opened (so created) at each start: 0 → 1 made
            // them all, 1 → 2 added `server-moves`, 2 → 3 `tombstones`.
            for t in [
                INBOXES,
                TOKENS,
                ENVELOPES,
                MANIFESTS,
                DEVICES_SEEN,
                ATTESTATIONS,
                MIGRATIONS,
                MOVED,
                SERVER_MOVES,
                TOMBSTONES,
                DEVICE_OWNER,
                BUNDLES,
                VAULTS,
                BLOBS,
                PUSH,
                USERNAMES,
                NAMES_BY_ROOT,
                REPORTS,
            ] {
                w.open_table(t)?;
            }
            meta.insert(&b"schema"[..], &SCHEMA_VERSION.to_be_bytes()[..])?;
        }
        w.commit()?;
        Ok(())
    }

    /// Run `f` in one write transaction and commit it.
    pub fn write<R>(&self, f: impl FnOnce(&mut Tx<'_>) -> Result<R>) -> Result<R> {
        let w = self.db.begin_write()?;
        let r = f(&mut Tx { w: &w })?;
        w.commit()?;
        Ok(r)
    }

    /// Run `f` in a read transaction.
    pub fn read<R>(&self, f: impl FnOnce(&Rx) -> Result<R>) -> Result<R> {
        let r = self.db.begin_read()?;
        f(&Rx { r })
    }

    /// Copy every table into a fresh database file at `path` (a consistent
    /// snapshot for backups: one read transaction).
    pub fn snapshot(&self, path: &Path) -> Result<()> {
        let out = Database::create(path)?;
        let r = self.db.begin_read()?;
        let w = out.begin_write()?;
        for t in ALL {
            let src = match r.open_table(t) {
                Ok(s) => s,
                Err(TableError::TableDoesNotExist(_)) => continue,
                Err(e) => return Err(e.into()),
            };
            let mut dst = w.open_table(t)?;
            for item in src.iter()? {
                let (k, v) = item?;
                dst.insert(k.value(), v.value())?;
            }
        }
        w.commit()?;
        Ok(())
    }
}

/// Every table, for snapshots.
const ALL: [Bytes; 19] = [
    INBOXES,
    TOKENS,
    ENVELOPES,
    MANIFESTS,
    DEVICES_SEEN,
    ATTESTATIONS,
    MIGRATIONS,
    MOVED,
    SERVER_MOVES,
    TOMBSTONES,
    DEVICE_OWNER,
    BUNDLES,
    VAULTS,
    BLOBS,
    PUSH,
    USERNAMES,
    NAMES_BY_ROOT,
    REPORTS,
    META,
];

/// A write transaction.
pub struct Tx<'a> {
    w: &'a WriteTransaction,
}

/// A read transaction.
pub struct Rx {
    r: ReadTransaction,
}

impl Tx<'_> {
    /// Value at `key`.
    pub fn get(&self, t: Bytes, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let table = self.w.open_table(t)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Whether `key` exists.
    pub fn has(&self, t: Bytes, key: &[u8]) -> Result<bool> {
        let table = self.w.open_table(t)?;
        Ok(table.get(key)?.is_some())
    }

    /// Set `key`.
    pub fn put(&mut self, t: Bytes, key: &[u8], value: &[u8]) -> Result<()> {
        let mut table = self.w.open_table(t)?;
        table.insert(key, value)?;
        Ok(())
    }

    /// Remove `key`; returns whether it existed.
    pub fn del(&mut self, t: Bytes, key: &[u8]) -> Result<bool> {
        let mut table = self.w.open_table(t)?;
        Ok(table.remove(key)?.is_some())
    }

    /// Every `(key, value)` whose key starts with `prefix`, in key order.
    pub fn scan(&self, t: Bytes, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let table = self.w.open_table(t)?;
        scan_table(&table, prefix)
    }

    /// Number of keys starting with `prefix`.
    pub fn count(&self, t: Bytes, prefix: &[u8]) -> Result<usize> {
        let table = self.w.open_table(t)?;
        let mut n = 0;
        for item in table.range(prefix..)? {
            let (k, _) = item?;
            if !k.value().starts_with(prefix) {
                break;
            }
            n += 1;
        }
        Ok(n)
    }

    /// The first `(key, value)` with `from ≤ key` that starts with `prefix`.
    pub fn first_from(
        &self,
        t: Bytes,
        prefix: &[u8],
        from: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let table = self.w.open_table(t)?;
        let Some(item) = table.range(from..)?.next() else {
            return Ok(None);
        };
        let (k, v) = item?;
        Ok(k.value()
            .starts_with(prefix)
            .then(|| (k.value().to_vec(), v.value().to_vec())))
    }

    /// Remove every key starting with `prefix` for which `drop` is true;
    /// returns how many were removed.
    pub fn remove_where(
        &mut self,
        t: Bytes,
        prefix: &[u8],
        mut drop: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<usize> {
        let doomed: Vec<Vec<u8>> = self
            .scan(t, prefix)?
            .into_iter()
            .filter(|(k, v)| drop(k, v))
            .map(|(k, _)| k)
            .collect();
        let mut table = self.w.open_table(t)?;
        for k in &doomed {
            table.remove(k.as_slice())?;
        }
        Ok(doomed.len())
    }
}

impl Rx {
    /// Value at `key`.
    pub fn get(&self, t: Bytes, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let table = match self.r.open_table(t) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Every `(key, value)` whose key starts with `prefix`.
    pub fn scan(&self, t: Bytes, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let table = match self.r.open_table(t) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        scan_table(&table, prefix)
    }

    /// The first two `(key, value)` pairs with `from ≤ key` under `prefix`
    /// (a poll needs the next envelope and whether another follows).
    pub fn next_two(
        &self,
        t: Bytes,
        prefix: &[u8],
        from: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let table = match self.r.open_table(t) {
            Ok(t) => t,
            Err(TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for item in table.range(from..)? {
            let (k, v) = item?;
            if !k.value().starts_with(prefix) || out.len() == 2 {
                break;
            }
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(out)
    }
}

fn scan_table(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    for item in table.range(prefix..)? {
        let (k, v) = item?;
        if !k.value().starts_with(prefix) {
            break;
        }
        out.push((k.value().to_vec(), v.value().to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn put_scan_snapshot() {
        let db = Db::memory().unwrap();
        db.write(|t| {
            t.put(ENVELOPES, b"aa\x00\x01", b"x")?;
            t.put(ENVELOPES, b"aa\x00\x02", b"y")?;
            t.put(ENVELOPES, b"ab\x00\x01", b"z")
        })
        .unwrap();
        let s = db.read(|r| r.scan(ENVELOPES, b"aa")).unwrap();
        assert_eq!(s.len(), 2);
        let two = db
            .read(|r| r.next_two(ENVELOPES, b"aa", b"aa\x00\x02"))
            .unwrap();
        assert_eq!(two.len(), 1, "stops at the prefix");
        let n = db
            .write(|t| t.remove_where(ENVELOPES, b"aa", |k, _| k[3] <= 1))
            .unwrap();
        assert_eq!(n, 1);
        let dir = std::env::temp_dir().join(format!("enclave-db-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        db.snapshot(&dir).unwrap();
        let copy = Db::open(&dir).unwrap();
        assert_eq!(
            copy.read(|r| r.get(ENVELOPES, b"ab\x00\x01"))
                .unwrap()
                .unwrap(),
            b"z"
        );
        let _ = std::fs::remove_file(&dir);
    }
}
