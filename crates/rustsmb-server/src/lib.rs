//! SMB2/SMB3 server implementation for RustSMB.
//!
//! This crate provides the main server implementation including:
//!
//! - TCP listener with connection limiting
//! - TLS support (optional)
//! - TOML configuration
//! - Command dispatch for all 19 SMB2 commands
//! - Share management
//! - Graceful shutdown with connection draining
//!
//! # Example
//!
//! ```no_run
//! use rustsmb_server::{ServerConfig, SmbServer, ShareConfig, ShareManager};
//! use rustsmb_state_memory::MemoryStateStore;
//! use rustsmb_auth::AnonymousAuthProvider;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configuration
//!     let config = ServerConfig::default();
//!
//!     // Create state store
//!     let state = Arc::new(MemoryStateStore::new());
//!
//!     // Create auth provider
//!     let auth = Arc::new(AnonymousAuthProvider::guest_only());
//!
//!     // Create and run server
//!     let server = SmbServer::new(config, state, auth);
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod handler;
pub mod server;
pub mod shares;

pub use config::{ConfigError, ServerConfig, SessionConfig};
pub use handler::{ConnectionHandler, HandlerError};
pub use server::{ServerError, SmbServer};
pub use shares::{Share, ShareConfig, ShareManager};
