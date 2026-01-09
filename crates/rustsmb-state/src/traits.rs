//! State store trait definition.

use crate::types::*;
use rustsmb_core::StateError;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Type alias for boxed async results.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// State store trait for externalized session state.
///
/// All state stores (memory, Redis, etc.) must implement this trait.
/// This enables stateless SMB server deployments with HA failover support.
pub trait StateStore: Send + Sync + 'static {
    // ========== Session Management ==========

    /// Create a new session.
    fn create_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Get a session by ID.
    fn get_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Option<SessionState>, StateError>>;

    /// Update an existing session.
    fn update_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Delete a session.
    fn delete_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), StateError>>;

    /// Refresh session TTL.
    fn refresh_session(
        &self,
        session_id: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<(), StateError>>;

    /// List sessions for a user.
    fn list_sessions<'a>(
        &'a self,
        user_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<SessionState>, StateError>>;

    // ========== Tree Connection Management ==========

    /// Create a tree connection.
    fn create_tree<'a>(&'a self, tree: &'a TreeState) -> BoxFuture<'a, Result<(), StateError>>;

    /// Get a tree connection.
    fn get_tree(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> BoxFuture<'_, Result<Option<TreeState>, StateError>>;

    /// List tree connections for a session.
    fn get_trees_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<TreeState>, StateError>>;

    /// Delete a tree connection.
    fn delete_tree(&self, session_id: u64, tree_id: u32) -> BoxFuture<'_, Result<(), StateError>>;

    // ========== Handle Management ==========

    /// Create a file handle.
    fn create_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Get a file handle by persistent ID.
    fn get_handle(
        &self,
        persistent_id: u128,
    ) -> BoxFuture<'_, Result<Option<HandleState>, StateError>>;

    /// List handles for a session.
    fn get_handles_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<HandleState>, StateError>>;

    /// Delete a file handle.
    fn delete_handle(&self, persistent_id: u128) -> BoxFuture<'_, Result<(), StateError>>;

    // ========== Lock Management ==========

    /// Create a byte-range lock.
    fn create_lock<'a>(&'a self, lock: &'a LockState) -> BoxFuture<'a, Result<(), StateError>>;

    /// Get locks for a handle.
    fn get_locks(&self, persistent_id: u128) -> BoxFuture<'_, Result<Vec<LockState>, StateError>>;

    /// Delete a lock.
    fn delete_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>>;

    // ========== Distributed Locking ==========

    /// Acquire a distributed lock.
    ///
    /// Returns a lock token on success, None if lock is held by another.
    fn acquire_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Option<String>, StateError>>;

    /// Release a distributed lock.
    fn release_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Extend a distributed lock TTL.
    fn extend_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, StateError>>;

    // ========== ID Generation ==========

    /// Generate next session ID.
    fn next_session_id(&self) -> BoxFuture<'_, Result<u64, StateError>>;

    /// Generate next tree ID for a session.
    fn next_tree_id(&self, session_id: u64) -> BoxFuture<'_, Result<u32, StateError>>;

    /// Generate next handle ID.
    fn next_handle_id(&self) -> BoxFuture<'_, Result<u128, StateError>>;
}

/// Dynamic dispatch wrapper for state stores.
pub type DynStateStore = std::sync::Arc<dyn StateStore>;
