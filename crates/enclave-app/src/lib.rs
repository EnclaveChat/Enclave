//! The Enclave app. The UI (Slint) never touches key material: it sends
//! commands to the engine thread, which owns `enclave_core::Client`, and
//! receives plain display data back.

pub mod engine;
pub mod view;

/// Code generated from `ui/*.slint`. The only place `unsafe` is allowed.
#[allow(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo
)]
mod ui {
    slint::include_modules!();
}
pub use ui::*;
