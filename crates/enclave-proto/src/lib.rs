//! Enclave protocols (`docs/03`–`docs/07`).
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod attest;
pub mod bundle;
pub mod codec;
pub mod envelope;
pub mod eqxdh;
pub mod error;
pub mod group;
pub mod identity;
pub mod labels;
pub mod manifest;
pub mod ratchet;
pub mod recovery;

pub use error::{ProtoError, Result};
