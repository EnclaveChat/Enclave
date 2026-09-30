//! Protocol errors.

/// Errors from `enclave-proto`.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum ProtoError {
    /// Cryptographic failure (authentication, bad key). Deliberately vague.
    #[error("cryptographic failure")]
    Crypto,
    /// Malformed or truncated encoding.
    #[error("malformed encoding")]
    Decode,
    /// A signature or signature chain did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// The object has expired or is not yet valid.
    #[error("expired or not yet valid")]
    Expired,
    /// A version, suite or epoch went backwards or was replayed.
    #[error("rollback or replay detected")]
    Rollback,
    /// No session matched an incoming message.
    #[error("no matching session")]
    NoSession,
    /// Too many skipped messages, or a counter out of range.
    #[error("message counter out of range")]
    Counter,
    /// The content does not fit in the envelope.
    #[error("content too large")]
    TooLarge,
    /// A limit (devices, prekeys, members) was exceeded.
    #[error("limit exceeded")]
    Limit,
    /// The recovery phrase is invalid.
    #[error("invalid recovery phrase")]
    Recovery,
    /// Required key material is missing (for example the McEliece key).
    #[error("missing key material")]
    Missing,
}

impl From<enclave_crypto::Error> for ProtoError {
    fn from(_: enclave_crypto::Error) -> Self {
        ProtoError::Crypto
    }
}

impl From<enclave_wire::WireError> for ProtoError {
    fn from(_: enclave_wire::WireError) -> Self {
        ProtoError::Decode
    }
}

/// Result alias.
pub type Result<T> = core::result::Result<T, ProtoError>;
