//! The PostgreSQL backend of [`crate::db::Db`]: every table is rows of one
//! relation, keyed by table name and key.
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS enclave_kv (tbl text, k bytea, v bytea NOT NULL, PRIMARY KEY (tbl, k))
//! ```
//!
//! The synchronous `postgres` client drives its own runtime; inside the
//! server's (multi-thread) tokio runtime each transaction runs under
//! `block_in_place`.

use crate::db::{DbError, Result};
use std::sync::Mutex;

const CREATE: &str = "CREATE TABLE IF NOT EXISTS enclave_kv (\
    tbl text NOT NULL, k bytea NOT NULL, v bytea NOT NULL, PRIMARY KEY (tbl, k))";

/// One open transaction's key-value operations.
pub(crate) trait Kv {
    fn get(&mut self, tbl: &str, k: &[u8]) -> Result<Option<Vec<u8>>>;
    fn put(&mut self, tbl: &str, k: &[u8], v: &[u8]) -> Result<()>;
    fn del(&mut self, tbl: &str, k: &[u8]) -> Result<bool>;
    /// Up to `limit` pairs with `from ≤ k < end` (no upper bound without
    /// `end`), in key order.
    fn range(
        &mut self,
        tbl: &str,
        from: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
    /// Keys with `from ≤ k < end`.
    fn count(&mut self, tbl: &str, from: &[u8], end: Option<&[u8]>) -> Result<usize>;
}

impl Kv for postgres::Transaction<'_> {
    fn get(&mut self, tbl: &str, k: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .query_opt(
                "SELECT v FROM enclave_kv WHERE tbl = $1 AND k = $2",
                &[&tbl, &k],
            )?
            .map(|r| r.get(0)))
    }

    fn put(&mut self, tbl: &str, k: &[u8], v: &[u8]) -> Result<()> {
        self.execute(
            "INSERT INTO enclave_kv (tbl, k, v) VALUES ($1, $2, $3) \
             ON CONFLICT (tbl, k) DO UPDATE SET v = EXCLUDED.v",
            &[&tbl, &k, &v],
        )?;
        Ok(())
    }

    fn del(&mut self, tbl: &str, k: &[u8]) -> Result<bool> {
        Ok(self.execute(
            "DELETE FROM enclave_kv WHERE tbl = $1 AND k = $2",
            &[&tbl, &k],
        )? > 0)
    }

    fn range(
        &mut self,
        tbl: &str,
        from: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = match end {
            Some(end) => self.query(
                "SELECT k, v FROM enclave_kv WHERE tbl = $1 AND k >= $2 AND k < $3 \
                 ORDER BY k LIMIT $4",
                &[&tbl, &from, &end, &limit],
            )?,
            None => self.query(
                "SELECT k, v FROM enclave_kv WHERE tbl = $1 AND k >= $2 ORDER BY k LIMIT $3",
                &[&tbl, &from, &limit],
            )?,
        };
        Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    fn count(&mut self, tbl: &str, from: &[u8], end: Option<&[u8]>) -> Result<usize> {
        let row = match end {
            Some(end) => self.query_one(
                "SELECT count(*) FROM enclave_kv WHERE tbl = $1 AND k >= $2 AND k < $3",
                &[&tbl, &from, &end],
            )?,
            None => self.query_one(
                "SELECT count(*) FROM enclave_kv WHERE tbl = $1 AND k >= $2",
                &[&tbl, &from],
            )?,
        };
        let n: i64 = row.get(0);
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

/// A connection to the database.
pub(crate) struct Pg {
    /// `None` only while being dropped.
    client: Mutex<Option<postgres::Client>>,
}

impl Pg {
    /// Connect and create the table.
    pub(crate) fn connect(url: &str) -> Result<Self> {
        blocking(|| {
            let mut client = postgres::Client::connect(url, postgres::NoTls)?;
            client.batch_execute(CREATE)?;
            Ok(Self {
                client: Mutex::new(Some(client)),
            })
        })
    }

    /// Run `f` in one transaction, committed if it returns `Ok`; without
    /// waiting for the commit to reach disk unless `durable`.
    pub(crate) fn transaction<R>(
        &self,
        durable: bool,
        f: impl FnOnce(&mut dyn Kv) -> Result<R>,
    ) -> Result<R> {
        blocking(|| {
            let mut client = self
                .client
                .lock()
                .map_err(|_| DbError::new("postgres connection poisoned"))?;
            let client = client
                .as_mut()
                .ok_or_else(|| DbError::new("postgres connection closed"))?;
            let mut t = client.transaction()?;
            if !durable {
                t.batch_execute("SET LOCAL synchronous_commit TO OFF")?;
            }
            let r = f(&mut t)?;
            t.commit()?;
            Ok(r)
        })
    }
}

impl Drop for Pg {
    /// Closing the connection blocks too: the same care as a transaction.
    fn drop(&mut self) {
        use tokio::runtime::{Handle, RuntimeFlavor};
        let Some(c) = self.client.get_mut().ok().and_then(Option::take) else {
            return;
        };
        match Handle::try_current() {
            Err(_) => drop(c),
            Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(move || drop(c));
            }
            // It can't close here without panicking; the server's end
            // notices the closed socket.
            Ok(_) => std::mem::forget(c),
        }
    }
}

/// Run blocking database work: directly outside a runtime, under
/// `block_in_place` inside a multi-thread one. A current-thread runtime
/// can't host it.
fn blocking<R>(f: impl FnOnce() -> Result<R>) -> Result<R> {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Err(_) => f(),
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        Ok(_) => Err(DbError::new(
            "the postgres backend needs a multi-thread runtime",
        )),
    }
}
