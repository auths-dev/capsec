//! Adversarial security tests for capsec.
//!
//! This crate exists solely to attack the capsec type system and audit tool,
//! proving what works and what doesn't. It serves as a living security audit.
//!
//! # Test categories
//!
//! - **Type system attacks** (`tests/type_system.rs`) — attempts to forge capabilities
//! - **Audit evasion** (`tests/audit_evasion.rs`) — code that dodges `cargo capsec audit`
//! - **Scope escapes** (`tests/scope_escapes.rs`) — attempts to break DirScope/HostScope
//! - **Compile-fail attacks** (`tests/compile_attacks.rs`) — attacks that SHOULD fail to compile

// Re-export nothing — this crate is test-only.
