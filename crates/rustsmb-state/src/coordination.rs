//! Coordination layer traits and types for distributed SMB servers.
//!
//! This module defines the `CoordinationBackend` trait for distributed
//! coordination operations like server membership, cache invalidation,
//! lease management, and distributed locking.

use crate::BoxFuture;
use rustsmb_core::CoordError;
use serde::{Deserialize, Serialize};
use std::pin::Pin;

/// Stream of epoch changes for cache invalidation.
pub type EpochStream = Pin<Box<dyn futures::Stream<Item = u64> + Send>>;

/// Stream of server failure events.
pub type ServerFailureStream = Pin<Box<dyn futures::Stream<Item = String> + Send>>;

/// Stream of lease break requests.
pub type LeaseBreakStream = Pin<Box<dyn futures::Stream<Item = LeaseBreakRequest> + Send>>;

/// Server registration information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRegistration {
    /// Unique server identifier.
    pub server_id: String,
    /// Server hostname.
    pub hostname: String,
    /// Server port.
    pub port: u16,
    /// Raft peer address (for cluster communication).
    pub raft_addr: String,
    /// Registration timestamp (Unix epoch seconds).
    pub registered_at: u64,
    /// Last heartbeat timestamp (Unix epoch seconds).
    pub last_heartbeat: u64,
    /// Number of active sessions on this server.
    pub active_sessions: u64,
    /// Number of active handles on this server.
    pub active_handles: u64,
}

impl ServerRegistration {
    /// Create a new server registration.
    pub fn new(server_id: String, hostname: String, port: u16, raft_addr: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            server_id,
            hostname,
            port,
            raft_addr,
            registered_at: now,
            last_heartbeat: now,
            active_sessions: 0,
            active_handles: 0,
        }
    }
}

/// SMB lease entry for coordination.
///
/// Leases allow clients to cache file data locally. When another client
/// needs conflicting access, a lease break must be coordinated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseEntry {
    /// Unique lease key (16 bytes, hex-encoded for storage).
    pub lease_key: String,
    /// Client GUID that owns this lease.
    pub client_guid: String,
    /// Session ID owning the lease.
    pub session_id: u64,
    /// Server currently serving this lease.
    pub server_id: String,
    /// File path this lease applies to.
    pub file_path: String,
    /// Current lease state flags (R=1, W=2, H=4).
    pub lease_state: u32,
    /// Lease epoch (incremented on state changes).
    pub epoch: u16,
    /// Creation timestamp.
    pub created_at: u64,
}

impl LeaseEntry {
    /// Lease state: Read caching.
    pub const READ_CACHING: u32 = 0x01;
    /// Lease state: Write caching.
    pub const WRITE_CACHING: u32 = 0x02;
    /// Lease state: Handle caching.
    pub const HANDLE_CACHING: u32 = 0x04;

    /// Create a new lease entry.
    pub fn new(
        lease_key: [u8; 16],
        client_guid: String,
        session_id: u64,
        server_id: String,
        file_path: String,
        lease_state: u32,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            lease_key: hex::encode(lease_key),
            client_guid,
            session_id,
            server_id,
            file_path,
            lease_state,
            epoch: 1,
            created_at: now,
        }
    }

    /// Get the lease key as bytes.
    pub fn get_lease_key(&self) -> Option<[u8; 16]> {
        let bytes = hex::decode(&self.lease_key).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(&bytes);
        Some(key)
    }
}

/// Lease break request sent to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseBreakRequest {
    /// Lease key being broken.
    pub lease_key: String,
    /// Current lease state.
    pub current_state: u32,
    /// New lease state to transition to.
    pub new_state: u32,
    /// Server that should notify the client.
    pub target_server_id: String,
}

/// Result of checking for lease conflicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseConflictResult {
    /// Whether the requested lease can be granted immediately.
    pub can_grant: bool,
    /// Leases that conflict and need to be broken.
    pub conflicts: Vec<LeaseEntry>,
    /// The lease state that can be granted (may be reduced from requested).
    pub granted_state: u32,
}

impl LeaseConflictResult {
    /// Create a result indicating the lease can be granted as requested.
    pub fn granted(requested_state: u32) -> Self {
        Self {
            can_grant: true,
            conflicts: vec![],
            granted_state: requested_state,
        }
    }

    /// Create a result indicating conflicts exist.
    pub fn conflict(conflicts: Vec<LeaseEntry>, reduced_state: u32) -> Self {
        Self {
            can_grant: false,
            conflicts,
            granted_state: reduced_state,
        }
    }

    /// Check if there are any conflicts.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Distributed byte-range lock for conflict detection.
///
/// Byte-range locks prevent concurrent write access to file regions.
/// The coordination layer tracks these to detect conflicts across servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedLock {
    /// Unique lock ID.
    pub lock_id: u64,
    /// Handle ID that owns this lock.
    pub handle_id: u128,
    /// Session ID.
    pub session_id: u64,
    /// Server that granted the lock.
    pub server_id: String,
    /// File path (for grouping locks).
    pub file_path: String,
    /// Lock start offset.
    pub offset: u64,
    /// Lock length (0 = to end of file).
    pub length: u64,
    /// Is exclusive (write) lock.
    pub exclusive: bool,
    /// Creation timestamp.
    pub created_at: u64,
}

impl DistributedLock {
    /// Create a new distributed lock.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lock_id: u64,
        handle_id: u128,
        session_id: u64,
        server_id: String,
        file_path: String,
        offset: u64,
        length: u64,
        exclusive: bool,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            lock_id,
            handle_id,
            session_id,
            server_id,
            file_path,
            offset,
            length,
            exclusive,
            created_at: now,
        }
    }

    /// Check if this lock conflicts with another lock.
    pub fn conflicts_with(&self, other: &DistributedLock) -> bool {
        // Same file?
        if self.file_path != other.file_path {
            return false;
        }

        // Same handle can't conflict with itself
        if self.handle_id == other.handle_id {
            return false;
        }

        // Check range overlap
        let self_end = if self.length == 0 {
            u64::MAX
        } else {
            self.offset.saturating_add(self.length)
        };
        let other_end = if other.length == 0 {
            u64::MAX
        } else {
            other.offset.saturating_add(other.length)
        };

        let overlaps = self.offset < other_end && other.offset < self_end;

        if !overlaps {
            return false;
        }

        // Overlapping ranges - shared locks don't conflict
        self.exclusive || other.exclusive
    }
}

/// Coordination backend trait for distributed SMB server coordination.
///
/// This trait abstracts the coordination layer, allowing different
/// implementations (e.g., embedded Raft, etcd).
///
/// All operations that modify shared state go through consensus
/// to ensure strong consistency.
pub trait CoordinationBackend: Send + Sync + 'static {
    // ========== Server Membership ==========

    /// Register this server with the cluster.
    ///
    /// Returns when the server is part of the cluster and can participate.
    fn register_server<'a>(
        &'a self,
        registration: &'a ServerRegistration,
    ) -> BoxFuture<'a, Result<(), CoordError>>;

    /// Leave the cluster gracefully.
    fn leave_cluster(&self) -> BoxFuture<'_, Result<(), CoordError>>;

    /// Get all registered servers.
    fn get_servers(&self) -> BoxFuture<'_, Result<Vec<ServerRegistration>, CoordError>>;

    /// Subscribe to server failure events.
    ///
    /// Returns a stream that yields server IDs when they are detected as failed.
    fn subscribe_server_failures(&self) -> BoxFuture<'_, ServerFailureStream>;

    // ========== Cache Epoch ==========

    /// Get the current cache epoch.
    ///
    /// All cached entries with epoch < current are considered stale.
    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>>;

    /// Subscribe to epoch changes.
    ///
    /// When a server fails, the epoch is incremented to invalidate all caches.
    fn subscribe_epoch_changes(&self) -> BoxFuture<'_, EpochStream>;

    // ========== Lease Coordination ==========

    /// Create a new lease.
    ///
    /// Fails with `Conflict` if a conflicting lease exists.
    fn create_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), CoordError>>;

    /// Get a lease by key.
    fn get_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<Option<LeaseEntry>, CoordError>>;

    /// Update a lease (e.g., after lease break acknowledgment).
    fn update_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), CoordError>>;

    /// Delete a lease.
    fn delete_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<(), CoordError>>;

    /// Request a lease break.
    ///
    /// This notifies the server owning the lease to break it.
    fn request_lease_break<'a>(
        &'a self,
        lease_key: &'a str,
        new_state: u32,
    ) -> BoxFuture<'a, Result<(), CoordError>>;

    /// Subscribe to lease break requests for this server.
    fn subscribe_lease_breaks(&self, server_id: &str) -> BoxFuture<'_, LeaseBreakStream>;

    /// Get all leases for a specific file path.
    fn get_leases_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<LeaseEntry>, CoordError>>;

    /// Check if a requested lease conflicts with existing leases.
    ///
    /// Returns a LeaseConflictResult indicating whether the lease can be granted
    /// and any conflicting leases that need to be broken first.
    ///
    /// # Arguments
    /// * `file_path` - The file path to check
    /// * `requestor_lease_key` - The lease key of the requestor (excluded from conflict check)
    /// * `requested_state` - The lease state being requested
    fn check_lease_conflict<'a>(
        &'a self,
        file_path: &'a str,
        requestor_lease_key: Option<&'a str>,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseConflictResult, CoordError>>;

    // ========== Lock Coordination ==========

    /// Acquire a distributed lock.
    ///
    /// Returns `true` if the lock was granted, `false` if there's a conflict.
    fn acquire_lock<'a>(
        &'a self,
        lock: &'a DistributedLock,
    ) -> BoxFuture<'a, Result<bool, CoordError>>;

    /// Release a distributed lock.
    fn release_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), CoordError>>;

    /// Get all locks for a file path.
    fn get_locks_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<DistributedLock>, CoordError>>;

    /// Release all locks held by a session.
    fn release_locks_for_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), CoordError>>;

    /// Release all locks held by a handle.
    fn release_locks_for_handle(&self, handle_id: u128) -> BoxFuture<'_, Result<(), CoordError>>;
}

/// Dynamic dispatch wrapper for coordination backends.
pub type DynCoordinationBackend = std::sync::Arc<dyn CoordinationBackend>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_registration_new() {
        let reg = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:8080".to_string(),
        );
        assert_eq!(reg.server_id, "srv1");
        assert!(reg.registered_at > 0);
    }

    #[test]
    fn test_lease_entry_new() {
        let key = [1u8; 16];
        let lease = LeaseEntry::new(
            key,
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/share/file.txt".to_string(),
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
        );
        assert_eq!(lease.get_lease_key(), Some(key));
        assert_eq!(lease.lease_state, 0x03);
    }

    #[test]
    fn test_lock_conflict_detection() {
        let lock1 = DistributedLock::new(
            1,
            100,
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            0,
            100,
            true, // exclusive
        );

        // Overlapping exclusive lock - conflicts
        let lock2 = DistributedLock::new(
            2,
            200,
            2,
            "srv2".to_string(),
            "/file.txt".to_string(),
            50,
            100,
            true,
        );
        assert!(lock1.conflicts_with(&lock2));

        // Non-overlapping - no conflict
        let lock3 = DistributedLock::new(
            3,
            300,
            3,
            "srv1".to_string(),
            "/file.txt".to_string(),
            200,
            100,
            true,
        );
        assert!(!lock1.conflicts_with(&lock3));

        // Different file - no conflict
        let lock4 = DistributedLock::new(
            4,
            400,
            4,
            "srv1".to_string(),
            "/other.txt".to_string(),
            0,
            100,
            true,
        );
        assert!(!lock1.conflicts_with(&lock4));

        // Shared locks don't conflict
        let shared1 = DistributedLock::new(
            5,
            500,
            5,
            "srv1".to_string(),
            "/file.txt".to_string(),
            0,
            100,
            false,
        );
        let shared2 = DistributedLock::new(
            6,
            600,
            6,
            "srv2".to_string(),
            "/file.txt".to_string(),
            50,
            100,
            false,
        );
        assert!(!shared1.conflicts_with(&shared2));
    }
}
