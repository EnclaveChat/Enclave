//! Encrypted backups (`docs/14-storage.md`).
//!
//! A backup is every record outside the excluded namespaces (ratchet
//! sessions, sender keys, shred keyring), sealed under a key derived from the
//! 256-bit recovery secret. Restoring onto a new device re-establishes
//! sessions; old session state never comes back, so a restored backup cannot
//! cause key reuse.

use crate::store::{Store, open_chunked, seal_chunked};
use crate::{Result, StoreError};
use enclave_crypto::kmac::kmac256;
use enclave_crypto::labels;
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::seal::SealKey;

/// Namespaces that are never backed up.
pub const EXCLUDED: &[&str] = &["sessions", "sender-keys", "__shred", "prekeys"];

fn backup_key(recovery: &[u8; 32]) -> SealKey {
    SealKey::from_bytes(kmac256(recovery, b"", labels::BACKUP_KEY))
}

/// Export the listed namespaces into an encrypted archive.
pub fn export(
    store: &Store,
    namespaces: &[&str],
    recovery: &[u8; 32],
    rng: &mut HedgedRng,
) -> Result<Vec<u8>> {
    let mut pt = Vec::new();
    for ns in namespaces {
        if EXCLUDED.contains(ns) {
            continue;
        }
        for (k, v) in store.scan(ns)? {
            for part in [ns.as_bytes(), &k, &v] {
                pt.extend_from_slice(&(part.len() as u32).to_be_bytes());
                pt.extend_from_slice(part);
            }
        }
    }
    seal_chunked(&backup_key(recovery), b"enclave-backup-v1", &pt, rng)
}

/// Import an archive into `store`.
pub fn import(
    store: &Store,
    archive: &[u8],
    recovery: &[u8; 32],
    rng: &mut HedgedRng,
) -> Result<usize> {
    let pt = open_chunked(&backup_key(recovery), b"enclave-backup-v1", archive)?;
    let mut off = 0usize;
    let mut n = 0usize;
    let next = |off: &mut usize| -> Result<Vec<u8>> {
        let l = u32::from_be_bytes(
            pt.get(*off..*off + 4)
                .ok_or(StoreError::Malformed)?
                .try_into()
                .map_err(|_| StoreError::Malformed)?,
        ) as usize;
        *off += 4;
        let v = pt
            .get(*off..*off + l)
            .ok_or(StoreError::Malformed)?
            .to_vec();
        *off += l;
        Ok(v)
    };
    while off < pt.len() {
        let ns = String::from_utf8(next(&mut off)?).map_err(|_| StoreError::Malformed)?;
        let k = next(&mut off)?;
        let v = next(&mut off)?;
        if EXCLUDED.contains(&ns.as_str()) {
            continue;
        }
        store.put(&ns, &k, &v, rng)?;
        n += 1;
    }
    Ok(n)
}
