//! Error type for the crypto core. Variants deliberately carry no detail about
//! *why* an authentication check failed.

/// Errors returned by `enclave-crypto`.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// Authentication failed (bad tag, bad signature, wrong key). Never says which.
    #[error("authentication failed")]
    Auth,
    /// Input has the wrong length or structure.
    #[error("malformed input")]
    Malformed,
    /// Input exceeds a size limit.
    #[error("input too large")]
    TooLarge,
    /// A public key failed validation.
    #[error("invalid public key")]
    InvalidKey,
    /// The operating system random number generator failed.
    #[error("random number generator failure")]
    Rng,
    /// A password hashing parameter is out of range.
    #[error("invalid password hashing parameters")]
    Params,
}

/// Result alias.
pub type Result<T> = core::result::Result<T, Error>;
