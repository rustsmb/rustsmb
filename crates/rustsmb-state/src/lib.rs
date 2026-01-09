//! State store abstraction for RustSMB.
//!
//! This crate defines the `StateStore` trait for externalized session state,
//! enabling high availability deployments.
//!
//! It also defines the `CoordinationBackend` trait for distributed
//! coordination operations like server membership, cache invalidation,
//! and lease management.

pub mod coordination;
pub mod traits;
pub mod types;

pub use coordination::*;
pub use traits::*;
pub use types::*;
