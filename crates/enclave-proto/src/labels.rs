//! Protocol-layer KMAC labels (see `docs/label-registry.md`).

/// Root-signature context for account manifests.
pub const CTX_MANIFEST: &str = "enclave/v1/ctx/manifest";
/// Composite-signature context for signed prekeys.
pub const CTX_SIGNED_PREKEY: &str = "enclave/v1/ctx/signed-prekey";
/// Composite-signature context for one-time prekey batches.
pub const CTX_OPK_BATCH: &str = "enclave/v1/ctx/opk-batch";
/// Composite-signature context for last-resort PQ prekeys.
pub const CTX_LAST_RESORT: &str = "enclave/v1/ctx/last-resort";
/// Composite-signature context for On-the-record message signatures.
pub const CTX_SIGNED_MESSAGE: &str = "enclave/v1/ctx/signed-msg";
/// Composite-signature context for the initiator's transcript signature.
pub const CTX_EQXDH_TRANSCRIPT: &str = "enclave/v1/ctx/eqxdh-transcript";

/// EQXDH stage-1 key that seals the initiator's identity.
pub const EQXDH_IDENTITY: &str = "enclave/v1/eqxdh/identity";
/// Initial ratchet root key.
pub const RATCHET_INIT_RK: &str = "enclave/v1/ratchet/init-rk";
/// Initial header keys.
pub const RATCHET_INIT_HK: &str = "enclave/v1/ratchet/init-hk";
/// Initial PQ roots.
pub const RATCHET_INIT_PQ: &str = "enclave/v1/ratchet/init-pq";
/// Root-key step (DH ratchet).
pub const RATCHET_RK: &str = "enclave/v1/ratchet/rk";
/// Chain-key step.
pub const RATCHET_CK: &str = "enclave/v1/ratchet/ck";
/// Lookup tag.
pub const RATCHET_TAG: &str = "enclave/v1/ratchet/tag";
/// Final message key (DR ‖ PQ).
pub const RATCHET_MSG: &str = "enclave/v1/ratchet/msg";
/// Body-key wrap.
pub const RATCHET_WRAP: &str = "enclave/v1/ratchet/wrap";
/// PQ slot sealing key.
pub const RATCHET_PQ_SLOT: &str = "enclave/v1/ratchet/pq-slot";
/// PQ root step.
pub const PQ_STEP: &str = "enclave/v1/pq/step";
/// PQ epoch key from (out root, in root).
pub const PQ_KEY: &str = "enclave/v1/pq/key";
/// Merkle leaf and node hashing for one-time prekey batches.
pub const MERKLE: &str = "enclave/v1/prekey/merkle";
/// In-person bond PSK.
pub const BOND: &str = "enclave/v1/bond/psk";
/// Seal words shown after an in-person scan.
pub const BOND_SEAL_WORDS: &str = "enclave/v1/bond/seal-words";

/// All labels in this crate, for uniqueness checks.
pub const ALL: &[&str] = &[
    CTX_MANIFEST,
    CTX_SIGNED_PREKEY,
    CTX_OPK_BATCH,
    CTX_LAST_RESORT,
    CTX_SIGNED_MESSAGE,
    CTX_EQXDH_TRANSCRIPT,
    EQXDH_IDENTITY,
    RATCHET_INIT_RK,
    RATCHET_INIT_HK,
    RATCHET_INIT_PQ,
    RATCHET_RK,
    RATCHET_CK,
    RATCHET_TAG,
    RATCHET_MSG,
    RATCHET_WRAP,
    RATCHET_PQ_SLOT,
    PQ_STEP,
    PQ_KEY,
    MERKLE,
    BOND,
    BOND_SEAL_WORDS,
];

#[cfg(test)]
mod tests {
    #[test]
    fn unique_and_disjoint_from_crypto() {
        let mut all: Vec<&str> = super::ALL.to_vec();
        all.extend_from_slice(enclave_crypto::labels::ALL);
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
    }
}
