//! State store abstraction for RustSMB.
//!
//! This crate defines the `StateStore` trait for externalized session state,
//! enabling high availability deployments.

pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;
