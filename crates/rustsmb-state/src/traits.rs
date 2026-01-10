//! State store trait definition.

use crate::coordination::{DistributedLock, LeaseConflictResult, LeaseEntry};
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

    /// Update an existing handle.
    fn update_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>>;

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

    // ========== SMB Lease Management ==========
    //
    // Leases allow clients to cache file data locally. These methods manage
    // lease state in the StateStore (Redis), with WATCH-based conflict detection.

    /// Create a new SMB lease.
    ///
    /// Fails if a lease with the same key already exists.
    fn create_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), StateError>>;

    /// Get a lease by its key.
    fn get_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<Option<LeaseEntry>, StateError>>;

    /// Update an existing lease (e.g., after lease break acknowledgment).
    fn update_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), StateError>>;

    /// Delete a lease.
    fn delete_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<(), StateError>>;

    /// Get all leases for a specific file path.
    fn get_leases_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<LeaseEntry>, StateError>>;

    /// Atomically check for conflicts and create a lease.
    ///
    /// This method uses optimistic locking (WATCH in Redis) to:
    /// 1. Check for conflicting leases on the file
    /// 2. Create the lease if no conflicts (or reduce state if partial grant)
    ///
    /// Returns a LeaseConflictResult indicating:
    /// - Whether the lease was granted
    /// - Any conflicting leases that need to be broken
    /// - The actual lease state that was granted (may be reduced)
    fn check_and_create_lease<'a>(
        &'a self,
        file_path: &'a str,
        lease: &'a LeaseEntry,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseConflictResult, StateError>>;

    /// Delete all leases owned by a server (called on server failure).
    fn delete_leases_for_server(&self, server_id: &str) -> BoxFuture<'_, Result<(), StateError>>;

    // ========== File Lock Management (Cluster-wide) ==========
    //
    // Byte-range locks coordinated across the cluster. These are different from
    // the single-handle LockState - they track locks across all servers.

    /// Acquire a file lock with conflict detection.
    ///
    /// Returns true if the lock was granted, false if there's a conflict.
    fn acquire_file_lock<'a>(
        &'a self,
        lock: &'a DistributedLock,
    ) -> BoxFuture<'a, Result<bool, StateError>>;

    /// Release a file lock.
    fn release_file_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>>;

    /// Get all locks for a file path.
    fn get_file_locks(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<DistributedLock>, StateError>>;

    /// Release all locks held by a session.
    fn release_file_locks_for_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<(), StateError>>;

    /// Release all locks held by a handle.
    fn release_file_locks_for_handle(
        &self,
        handle_id: u128,
    ) -> BoxFuture<'_, Result<(), StateError>>;

    /// Release all locks held by a server (called on server failure).
    fn release_file_locks_for_server(
        &self,
        server_id: &str,
    ) -> BoxFuture<'_, Result<(), StateError>>;

    /// Generate next file lock ID.
    fn next_file_lock_id(&self) -> BoxFuture<'_, Result<u64, StateError>>;
}

/// Dynamic dispatch wrapper for state stores.
pub type DynStateStore = std::sync::Arc<dyn StateStore>;
