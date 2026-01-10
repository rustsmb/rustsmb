//! gRPC client for the RustSMB coordinator service.
//!
//! This crate provides `CoordinatorClient`, which implements the `CoordinationBackend` trait
//! by connecting to the coordinator service via gRPC.
//!
//! # Example
//!
//! ```rust,ignore
//! use rustsmb_coordinator_client::CoordinatorClient;
//!
//! let client = CoordinatorClient::connect("http://coordinator:9000").await?;
//!
//! // Register this server
//! client.register_server(&registration).await?;
//!
//! // Subscribe to epoch changes for cache invalidation
//! let epoch_stream = client.subscribe_epoch_changes().await;
//! ```

mod client;

pub use client::{CoordinatorClient, CoordinatorClientConfig, CoordinatorClientError};
