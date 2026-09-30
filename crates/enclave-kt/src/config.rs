//! The Enclave `akd` configuration: akd's experimental configuration with every
//! hash replaced by domain-separated SHAKE256-256.

use akd::hash::{DIGEST_BYTES, Digest};
use akd::{
    AkdLabel, AkdValue, AzksValue, AzksValueWithEpoch, Configuration, NodeLabel, VersionFreshness,
};
use enclave_crypto::hash::shake256;

/// Domain label mixed into every hash.
pub const DOMAIN: &[u8] = b"enclave/v1/kt/akd";

/// Enclave's akd configuration.
#[derive(Clone)]
pub struct EnclaveKtConfig;

fn i2osp(input: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + input.len());
    v.extend_from_slice(&(input.len() as u64).to_be_bytes());
    v.extend_from_slice(input);
    v
}

impl Configuration for EnclaveKtConfig {
    fn hash(item: &[u8]) -> Digest {
        let mut buf = Vec::with_capacity(DOMAIN.len() + item.len());
        buf.extend_from_slice(DOMAIN);
        buf.extend_from_slice(item);
        shake256::<DIGEST_BYTES>(&buf)
    }

    fn empty_root_value() -> AzksValue {
        AzksValue([0u8; 32])
    }

    fn empty_node_hash() -> AzksValue {
        AzksValue([0u8; 32])
    }

    fn hash_leaf_with_value(value: &AkdValue, epoch: u64, nonce: &[u8]) -> AzksValueWithEpoch {
        let commitment = AzksValue(Self::hash(&[i2osp(value), i2osp(nonce)].concat()));
        Self::hash_leaf_with_commitment(commitment, epoch)
    }

    fn hash_leaf_with_commitment(commitment: AzksValue, epoch: u64) -> AzksValueWithEpoch {
        let mut data = [0u8; DIGEST_BYTES + 8];
        data[..DIGEST_BYTES].copy_from_slice(&commitment.0);
        data[DIGEST_BYTES..].copy_from_slice(&epoch.to_be_bytes());
        AzksValueWithEpoch(Self::hash(&data))
    }

    fn get_commitment_nonce(
        commitment_key: &[u8],
        label: &NodeLabel,
        _version: u64,
        _value: &AkdValue,
    ) -> Digest {
        let label_bytes = [&label.label_len.to_be_bytes()[..], &label.label_val[..]].concat();
        Self::hash(&[commitment_key, &label_bytes].concat())
    }

    fn compute_fresh_azks_value(
        commitment_key: &[u8],
        label: &NodeLabel,
        version: u64,
        value: &AkdValue,
    ) -> AzksValue {
        let nonce = Self::get_commitment_nonce(commitment_key, label, version, value);
        AzksValue(Self::hash(&[i2osp(value), i2osp(&nonce)].concat()))
    }

    fn get_hash_from_label_input(
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
    ) -> Vec<u8> {
        let fresh = [freshness as u8];
        Self::hash(&[&i2osp(label)[..], &fresh, &version.to_be_bytes()].concat()).to_vec()
    }

    fn compute_parent_hash_from_children(
        left_val: &AzksValue,
        left_label: &[u8],
        right_val: &AzksValue,
        right_label: &[u8],
    ) -> AzksValue {
        AzksValue(Self::hash(
            &[&left_val.0, left_label, &right_val.0, right_label].concat(),
        ))
    }

    fn compute_root_hash_from_val(root_val: &AzksValue) -> Digest {
        root_val.0
    }

    fn stale_azks_value() -> AzksValue {
        AzksValue(akd::hash::EMPTY_DIGEST)
    }

    fn compute_node_label_value(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    fn empty_label() -> NodeLabel {
        let mut label_val = [0u8; 32];
        label_val[0] = 1;
        NodeLabel {
            label_val,
            label_len: 0,
        }
    }
}
