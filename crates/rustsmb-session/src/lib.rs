//! Session and connection management for RustSMB.
//!
//! This crate provides stateless session management using the StateStore abstraction.
//!
//! # Modules
//!
//! - `connection`: Per-TCP-connection state management
//! - `manager`: Stateless session manager with StateStore integration
//! - `credits`: SMB2/3 credit flow control
//! - `compound`: Compound request handling
//! - `async_request`: Async operation tracking (CHANGE_NOTIFY, etc.)
//! - `validation`: Request context validation
//!
//! # Architecture
//!
//! This crate is designed for stateless operation. While `Connection` holds
//! local per-connection state (credits, async requests, etc.), all session
//! data is stored in the `StateStore` to enable HA failover.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Connection (local)                      │
//! │  - Credits                                                  │
//! │  - Async request tracking                                   │
//! │  - Compound request state                                   │
//! │  - Active session IDs                                       │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   SessionManager (facade)                   │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                StateStore (external, shared)                │
//! │  - Sessions                                                 │
//! │  - Trees                                                    │
//! │  - Handles                                                  │
//! │  - Locks                                                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod async_request;
pub mod compound;
pub mod connection;
pub mod credits;
pub mod manager;
pub mod validation;

pub use async_request::{
    AsyncOperationType, AsyncRequest, AsyncRequestConfig, AsyncRequestTracker,
};
pub use compound::{
    compound_padding, parse_compound_offsets, CompoundContext, CompoundQueue, CompoundResult,
    FileId, PendingCompound, MAX_COMPOUND_COMMANDS,
};
pub use connection::{
    Connection, ConnectionConfig, ConnectionState, DEFAULT_MAX_SESSIONS_PER_CONNECTION,
};
pub use credits::{
    CreditConfig, CreditError, CreditManager, DEFAULT_INITIAL_CREDITS, DEFAULT_MAX_CREDITS,
};
pub use manager::{SessionManager, SessionManagerConfig};
pub use validation::{
    HandleLookup, HandleValidator, RequestContext, RequestContextBuilder, SessionValidator,
    TreeValidator,
};
