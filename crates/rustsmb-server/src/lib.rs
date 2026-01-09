//! SMB2/SMB3 server implementation for RustSMB.
//!
//! This crate provides the main server implementation including:
//! - TCP listener
//! - Connection handling
//! - Command dispatch
//! - Share management

pub mod config;
pub mod server;
pub mod shares;

pub use config::*;
pub use server::*;
pub use shares::*;

// TODO: Implement in Phase 6
// - TCP listener with tokio
// - Connection handler
// - Command dispatcher
// - Share management
