//! The storage backends a test runs against (`docs/12-servers.md` §6): a
//! redb file always, and PostgreSQL when `ENCLAVE_TEST_POSTGRES` holds an
//! admin URL (each test gets a database of its own). CI sets
//! `ENCLAVE_REQUIRE_POSTGRES`, so a missing database fails instead of
//! skipping.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use enclave_server::db::Db;
use std::path::{Path, PathBuf};

/// Where a test's state lives; opening it again is a restart.
pub enum Store {
    Redb(PathBuf),
    Postgres(String),
}

impl Store {
    pub fn open(&self) -> Db {
        match self {
            Store::Redb(p) => Db::open(p).unwrap(),
            Store::Postgres(url) => Db::connect(url).unwrap(),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Store::Redb(_) => "redb",
            Store::Postgres(_) => "postgres",
        }
    }
}

/// Every backend for test `name`, with state in `dir` for redb.
pub fn stores(name: &str, dir: &Path) -> Vec<Store> {
    let mut v = vec![Store::Redb(dir.join("server.redb"))];
    match std::env::var("ENCLAVE_TEST_POSTGRES") {
        Ok(admin) if !admin.is_empty() => v.push(Store::Postgres(fresh_database(&admin, name))),
        _ => assert!(
            std::env::var_os("ENCLAVE_REQUIRE_POSTGRES").is_none(),
            "ENCLAVE_REQUIRE_POSTGRES is set but ENCLAVE_TEST_POSTGRES isn't"
        ),
    }
    v
}

/// Drop and create database `enclave_test_<name>`; its URL.
fn fresh_database(admin: &str, name: &str) -> String {
    let db = format!("enclave_test_{}", name.replace('-', "_"));
    let mut c = postgres::Client::connect(admin, postgres::NoTls).unwrap();
    // Each in a statement of its own: neither runs inside a transaction.
    c.batch_execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        .unwrap();
    c.batch_execute(&format!("CREATE DATABASE {db}")).unwrap();
    let base = admin.rsplit_once('/').map_or(admin, |(b, _)| b);
    format!("{base}/{db}")
}
