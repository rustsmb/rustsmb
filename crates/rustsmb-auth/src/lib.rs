//! Authentication providers for RustSMB.
//!
//! This crate provides the AuthProvider trait and implementations
//! for NTLM and simple password authentication.

pub mod provider;
pub mod simple;

pub use provider::*;

// TODO: Implement in Phase 5
// - NTLM authentication
// - SPNEGO/GSS-API wrapper
// - Kerberos support (future)
