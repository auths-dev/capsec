//! Capability-gated environment variable access.
//!
//! Drop-in replacements for `std::env` functions that require a capability token.

use capsec_core::has::Has;
use capsec_core::permission::{EnvRead, EnvWrite};

/// Reads an environment variable.
/// Requires [`EnvRead`] permission.
pub fn var(key: &str, _cap: &impl Has<EnvRead>) -> Result<String, std::env::VarError> {
    std::env::var(key)
}

/// Returns an iterator of all environment variables.
/// Requires [`EnvRead`] permission.
pub fn vars(_cap: &impl Has<EnvRead>) -> std::env::Vars {
    std::env::vars()
}

/// Sets an environment variable.
/// Requires [`EnvWrite`] permission.
///
/// # Safety note
///
/// In Rust edition 2024, `std::env::set_var` is `unsafe` because it's not
/// thread-safe. This wrapper encapsulates that unsafety.
pub fn set_var(
    key: impl AsRef<std::ffi::OsStr>,
    value: impl AsRef<std::ffi::OsStr>,
    _cap: &impl Has<EnvWrite>,
) {
    unsafe {
        std::env::set_var(key, value);
    }
}
