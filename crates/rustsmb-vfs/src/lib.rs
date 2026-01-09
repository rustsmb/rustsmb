//! Virtual filesystem abstraction layer for RustSMB.
//!
//! This crate defines the `StorageBackend` trait that all storage backends must implement.

pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;
