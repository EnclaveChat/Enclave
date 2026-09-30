//! Recovery words: the 256-bit recovery secret as 24 BIP-39 words.
//!
//! The recovery secret deterministically derives the SLH-DSA account root
//! (`enclave_crypto::sig::RootSigningKey::from_recovery_secret`) and the backup
//! key. Whoever holds the words can take over the account after the 72-hour
//! pending window, so the UI treats them like a house key.

use crate::error::{ProtoError, Result};
use enclave_crypto::rng::HedgedRng;
use zeroize::Zeroizing;

/// A 256-bit recovery secret. Zeroized on drop.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);

impl RecoverySecret {
    /// Generate a fresh secret.
    pub fn generate(rng: &mut HedgedRng) -> Result<Self> {
        Ok(Self(Zeroizing::new(rng.array("recovery/secret")?)))
    }

    /// Wrap existing bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 24 English words.
    pub fn to_words(&self) -> Result<Vec<String>> {
        let m = bip39::Mnemonic::from_entropy(&self.0[..]).map_err(|_| ProtoError::Recovery)?;
        Ok(m.words().map(str::to_owned).collect())
    }

    /// Parse 24 words (case and extra whitespace are ignored).
    pub fn from_words(phrase: &str) -> Result<Self> {
        let normalized = phrase
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" ");
        let m = bip39::Mnemonic::parse_normalized(&normalized).map_err(|_| ProtoError::Recovery)?;
        let entropy = Zeroizing::new(m.to_entropy());
        let arr: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| ProtoError::Recovery)?;
        Ok(Self::from_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_roundtrip() {
        let mut rng = HedgedRng::new().unwrap();
        let s = RecoverySecret::generate(&mut rng).unwrap();
        let words = s.to_words().unwrap();
        assert_eq!(words.len(), 24);
        let back = RecoverySecret::from_words(&words.join("  ").to_uppercase()).unwrap();
        assert_eq!(back.as_bytes(), s.as_bytes());
    }

    #[test]
    fn checksum_catches_typos() {
        let s = RecoverySecret::from_bytes([7; 32]);
        let mut words = s.to_words().unwrap();
        words.swap(0, 1);
        // A swap changes the checksum with overwhelming probability.
        assert!(RecoverySecret::from_words(&words.join(" ")).is_err() || words[0] == words[1]);
        assert!(RecoverySecret::from_words("abandon abandon").is_err());
    }
}
