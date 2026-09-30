//! Account and device key material (`docs/03-identity.md`).
//!
//! * Account level (shared with linked devices over the linking channel):
//!   the SLH-DSA root (derived from the recovery secret, primary only), the
//!   X448 identity key, and the Classic McEliece "vault" key.
//! * Device level (never leaves the device): a composite Ed448 + ML-DSA-87
//!   signing key and an ML-KEM-1024 "auth" key used for post-quantum
//!   authentication in EQXDH.

use crate::error::Result;
use crate::recovery::RecoverySecret;
use enclave_crypto::kem::{
    McEliecePublic, McElieceSecret, MlKemPublic, MlKemSecret, X448Public, X448Secret,
};
use enclave_crypto::rng::HedgedRng;
use enclave_crypto::sig::{CompositeSigningKey, RootPublic, RootSigningKey};

/// Device identifier (random, 16 bytes).
pub type DeviceId = [u8; 16];

/// Account-level secrets.
pub struct AccountKeys {
    /// Root signing key. `None` on linked devices without "may add devices".
    pub root: Option<RootSigningKey>,
    /// Root public key (always known).
    pub root_public: RootPublic,
    /// Account X448 identity key.
    pub identity: X448Secret,
    /// Account X448 identity public key.
    pub identity_public: X448Public,
    /// Classic McEliece vault key (decapsulation).
    pub vault: McElieceSecret,
    /// Classic McEliece vault public key (1.36 MB; published as an encrypted blob).
    pub vault_public: McEliecePublic,
}

impl AccountKeys {
    /// Create a new account from a recovery secret. Generates the McEliece key,
    /// which takes a few seconds; run in the background during onboarding.
    pub fn create(recovery: &RecoverySecret, rng: &mut HedgedRng) -> Result<Self> {
        let root = RootSigningKey::from_recovery_secret(recovery.as_bytes());
        let root_public = root.public();
        let (identity, identity_public) = X448Secret::generate(rng)?;
        let (vault, vault_public) = McElieceSecret::generate(rng)?;
        Ok(Self {
            root: Some(root),
            root_public,
            identity,
            identity_public,
            vault,
            vault_public,
        })
    }

    /// SHA3-512 of the McEliece vault public key, committed in the manifest.
    pub fn vault_hash(&self) -> [u8; 64] {
        enclave_crypto::hash::sha3_512(&self.vault_public.0[..])
    }
}

/// Device-level secrets.
pub struct DeviceKeys {
    /// Device identifier.
    pub id: DeviceId,
    /// Composite signing key.
    pub signing: CompositeSigningKey,
    /// ML-KEM-1024 authentication key.
    pub auth: MlKemSecret,
    /// ML-KEM-1024 authentication public key.
    pub auth_public: MlKemPublic,
}

impl DeviceKeys {
    /// Generate keys for a new device.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        let id: DeviceId = rng.array("device/id")?;
        let signing = CompositeSigningKey::generate(rng)?;
        let (auth, auth_public) = MlKemSecret::generate(rng)?;
        Ok(Self {
            id,
            signing,
            auth,
            auth_public,
        })
    }
}
