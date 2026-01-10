//! Coordination state machine.
//!
//! This module defines the coordination state that would be replicated
//! across all Raft nodes in a multi-node deployment.

use rustsmb_state::{DistributedLock, LeaseConflictResult, LeaseEntry, ServerRegistration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Request/command to the coordination state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordRequest {
    // Server membership
    RegisterServer(ServerRegistration),
    UnregisterServer(String),
    UpdateHeartbeat {
        server_id: String,
        timestamp: u64,
    },

    // Cache epoch
    IncrementEpoch,

    // Lease management
    CreateLease(LeaseEntry),
    UpdateLease(LeaseEntry),
    DeleteLease(String),
    /// Get all leases for a specific file path.
    GetLeasesForFile(String),
    /// Check if a requested lease conflicts with existing leases.
    /// Returns LeaseConflictResult with conflicts and reduced state if needed.
    CheckLeaseConflict {
        file_path: String,
        /// The lease key of the requestor (to exclude from conflict check).
        requestor_lease_key: Option<String>,
        /// The requested lease state.
        requested_state: u32,
    },
    /// Release all leases owned by a server (on server failure).
    ReleaseLeasesForServer(String),

    // Lock management
    AcquireLock(DistributedLock),
    ReleaseLock(u64),
    ReleaseLocksForSession(u64),
    ReleaseLocksForHandle(u128),
    /// Release all locks held by a server (on server failure).
    ReleaseLocksForServer(String),
}

/// Response from the coordination state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordResponse {
    Ok,
    Epoch(u64),
    Server(Option<ServerRegistration>),
    Servers(Vec<ServerRegistration>),
    Lease(Option<LeaseEntry>),
    Leases(Vec<LeaseEntry>),
    LeaseConflict(LeaseConflictResult),
    LockGranted(bool),
    LockGrantedWithId(bool, u64),
    Locks(Vec<DistributedLock>),
    Error(String),
}

/// The coordination state replicated across all nodes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoordinationState {
    /// Global cache epoch (incremented on server failure).
    pub cache_epoch: u64,

    /// Active server membership.
    pub servers: HashMap<String, ServerRegistration>,

    /// SMB lease table (lease_key -> LeaseEntry).
    pub leases: HashMap<String, LeaseEntry>,

    /// Active byte-range locks (file_path -> locks).
    pub locks: HashMap<String, Vec<DistributedLock>>,

    /// Next lock ID.
    next_lock_id: u64,
}

impl CoordinationState {
    /// Create a new empty coordination state.
    pub fn new() -> Self {
        Self {
            cache_epoch: 1,
            servers: HashMap::new(),
            leases: HashMap::new(),
            locks: HashMap::new(),
            next_lock_id: 1,
        }
    }

    /// Apply a request to the state machine.
    pub fn apply(&mut self, request: CoordRequest) -> CoordResponse {
        match request {
            CoordRequest::RegisterServer(reg) => {
                self.servers.insert(reg.server_id.clone(), reg);
                CoordResponse::Ok
            }

            CoordRequest::UnregisterServer(server_id) => {
                self.servers.remove(&server_id);
                // Increment epoch when a server leaves (cache invalidation)
                self.cache_epoch += 1;
                CoordResponse::Epoch(self.cache_epoch)
            }

            CoordRequest::UpdateHeartbeat {
                server_id,
                timestamp,
            } => {
                if let Some(server) = self.servers.get_mut(&server_id) {
                    server.last_heartbeat = timestamp;
                }
                CoordResponse::Ok
            }

            CoordRequest::IncrementEpoch => {
                self.cache_epoch += 1;
                CoordResponse::Epoch(self.cache_epoch)
            }

            CoordRequest::CreateLease(lease) => {
                // Check for conflicts
                if self.leases.contains_key(&lease.lease_key) {
                    return CoordResponse::Error("Lease already exists".to_string());
                }
                self.leases.insert(lease.lease_key.clone(), lease);
                CoordResponse::Ok
            }

            CoordRequest::UpdateLease(lease) => {
                self.leases.insert(lease.lease_key.clone(), lease);
                CoordResponse::Ok
            }

            CoordRequest::DeleteLease(lease_key) => {
                self.leases.remove(&lease_key);
                CoordResponse::Ok
            }

            CoordRequest::GetLeasesForFile(file_path) => {
                let leases = self.get_leases_for_file(&file_path);
                CoordResponse::Leases(leases)
            }

            CoordRequest::CheckLeaseConflict {
                file_path,
                requestor_lease_key,
                requested_state,
            } => {
                let result = self.check_lease_conflict(
                    &file_path,
                    requestor_lease_key.as_deref(),
                    requested_state,
                );
                CoordResponse::LeaseConflict(result)
            }

            CoordRequest::ReleaseLeasesForServer(server_id) => {
                self.leases.retain(|_, lease| lease.server_id != server_id);
                CoordResponse::Ok
            }

            CoordRequest::AcquireLock(mut lock) => {
                // Assign lock ID
                lock.lock_id = self.next_lock_id;
                self.next_lock_id += 1;

                // Check for conflicts
                let existing_locks = self.locks.entry(lock.file_path.clone()).or_default();
                for existing in existing_locks.iter() {
                    if lock.conflicts_with(existing) {
                        return CoordResponse::LockGranted(false);
                    }
                }

                // No conflict, grant the lock
                existing_locks.push(lock);
                CoordResponse::LockGranted(true)
            }

            CoordRequest::ReleaseLock(lock_id) => {
                for locks in self.locks.values_mut() {
                    locks.retain(|l| l.lock_id != lock_id);
                }
                CoordResponse::Ok
            }

            CoordRequest::ReleaseLocksForSession(session_id) => {
                for locks in self.locks.values_mut() {
                    locks.retain(|l| l.session_id != session_id);
                }
                CoordResponse::Ok
            }

            CoordRequest::ReleaseLocksForHandle(handle_id) => {
                for locks in self.locks.values_mut() {
                    locks.retain(|l| l.handle_id != handle_id);
                }
                CoordResponse::Ok
            }

            CoordRequest::ReleaseLocksForServer(server_id) => {
                for locks in self.locks.values_mut() {
                    locks.retain(|l| l.server_id != server_id);
                }
                CoordResponse::Ok
            }
        }
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u64 {
        self.cache_epoch
    }

    /// Get a server by ID.
    pub fn get_server(&self, server_id: &str) -> Option<&ServerRegistration> {
        self.servers.get(server_id)
    }

    /// Get all servers.
    pub fn get_servers(&self) -> Vec<ServerRegistration> {
        self.servers.values().cloned().collect()
    }

    /// Get a lease by key.
    pub fn get_lease(&self, lease_key: &str) -> Option<&LeaseEntry> {
        self.leases.get(lease_key)
    }

    /// Get all leases for a specific file path.
    pub fn get_leases_for_file(&self, file_path: &str) -> Vec<LeaseEntry> {
        self.leases
            .values()
            .filter(|lease| lease.file_path == file_path)
            .cloned()
            .collect()
    }

    /// Check if a requested lease state conflicts with existing leases.
    ///
    /// SMB Lease conflict rules:
    /// - Read caching (R): Can be shared unless someone wants write caching
    /// - Write caching (W): Exclusive - conflicts with any other W
    /// - Handle caching (H): Can be shared unless file will be deleted
    ///
    /// Returns a LeaseConflictResult indicating whether the lease can be granted
    /// and any conflicting leases that need to be broken.
    pub fn check_lease_conflict(
        &self,
        file_path: &str,
        requestor_lease_key: Option<&str>,
        requested_state: u32,
    ) -> LeaseConflictResult {
        let existing_leases: Vec<_> = self
            .leases
            .values()
            .filter(|lease| {
                lease.file_path == file_path
                    && requestor_lease_key.map_or(true, |k| lease.lease_key != k)
            })
            .cloned()
            .collect();

        if existing_leases.is_empty() {
            return LeaseConflictResult::granted(requested_state);
        }

        let mut conflicts = Vec::new();
        let mut granted_state = requested_state;

        // Check for conflicts with each existing lease
        for existing in &existing_leases {
            let conflict = self.leases_conflict(existing.lease_state, requested_state);

            if conflict {
                conflicts.push(existing.clone());
            }
        }

        // If there are conflicts, reduce the granted state
        if !conflicts.is_empty() {
            // Reduce to the maximum compatible state
            granted_state = self.reduce_lease_state(requested_state, &conflicts);
        }

        if conflicts.is_empty() {
            LeaseConflictResult::granted(granted_state)
        } else {
            LeaseConflictResult::conflict(conflicts, granted_state)
        }
    }

    /// Check if two lease states conflict.
    ///
    /// Conflicts occur when:
    /// - Either lease has write caching (W) and the other has any caching
    /// - Both leases have handle caching (H) when deletion is involved
    fn leases_conflict(&self, existing_state: u32, requested_state: u32) -> bool {
        // Write caching is exclusive
        let existing_has_write = (existing_state & LeaseEntry::WRITE_CACHING) != 0;
        let requested_has_write = (requested_state & LeaseEntry::WRITE_CACHING) != 0;

        // If either has write caching and the other has any caching, conflict
        if existing_has_write && requested_state != 0 {
            return true;
        }
        if requested_has_write && existing_state != 0 {
            return true;
        }

        false
    }

    /// Reduce a requested lease state to avoid conflicts.
    fn reduce_lease_state(&self, requested_state: u32, conflicts: &[LeaseEntry]) -> u32 {
        let mut state = requested_state;

        // Check what the existing leases have
        let any_write = conflicts
            .iter()
            .any(|l| (l.lease_state & LeaseEntry::WRITE_CACHING) != 0);

        // If any existing lease has write caching, we can't get any caching
        if any_write {
            return 0;
        }

        // If we're requesting write caching, reduce to read
        if (state & LeaseEntry::WRITE_CACHING) != 0 {
            state &= !LeaseEntry::WRITE_CACHING;
        }

        state
    }

    /// Get locks for a file.
    pub fn get_locks_for_file(&self, file_path: &str) -> Vec<DistributedLock> {
        self.locks.get(file_path).cloned().unwrap_or_default()
    }

    /// Get servers with stale heartbeats (last heartbeat older than threshold).
    ///
    /// Returns server IDs that have not sent a heartbeat since `threshold_timestamp`.
    pub fn get_stale_servers(&self, threshold_timestamp: u64) -> Vec<String> {
        self.servers
            .iter()
            .filter(|(_, server)| server.last_heartbeat < threshold_timestamp)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// In-memory state machine wrapper.
pub struct CoordStateMachine {
    /// The coordination state.
    state: RwLock<CoordinationState>,
}

impl CoordStateMachine {
    /// Create a new state machine.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(CoordinationState::new()),
        }
    }

    /// Apply a request to the state machine.
    pub async fn apply(&self, request: CoordRequest) -> CoordResponse {
        let mut state = self.state.write().await;
        state.apply(request)
    }

    /// Get a read lock on the state.
    pub async fn state(&self) -> tokio::sync::RwLockReadGuard<'_, CoordinationState> {
        self.state.read().await
    }

    /// Get a write lock on the state.
    pub async fn state_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, CoordinationState> {
        self.state.write().await
    }
}

impl Default for CoordStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordination_state_epoch() {
        let mut state = CoordinationState::new();
        assert_eq!(state.epoch(), 1);

        state.apply(CoordRequest::IncrementEpoch);
        assert_eq!(state.epoch(), 2);
    }

    #[test]
    fn test_server_registration() {
        let mut state = CoordinationState::new();

        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:8080");

        state.apply(CoordRequest::RegisterServer(server.clone()));
        assert!(state.get_server("srv1").is_some());
        assert_eq!(state.get_servers().len(), 1);

        // Unregister increments epoch
        let resp = state.apply(CoordRequest::UnregisterServer("srv1".to_string()));
        assert!(matches!(resp, CoordResponse::Epoch(2)));
        assert!(state.get_server("srv1").is_none());
    }

    #[test]
    fn test_lease_management() {
        let mut state = CoordinationState::new();

        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );

        state.apply(CoordRequest::CreateLease(lease.clone()));
        assert!(state.get_lease(&lease.lease_key).is_some());

        // Duplicate should fail
        let resp = state.apply(CoordRequest::CreateLease(lease.clone()));
        assert!(matches!(resp, CoordResponse::Error(_)));

        state.apply(CoordRequest::DeleteLease(lease.lease_key.clone()));
        assert!(state.get_lease(&lease.lease_key).is_none());
    }

    #[test]
    fn test_lock_conflict_detection() {
        let mut state = CoordinationState::new();

        let lock1 = DistributedLock::new(
            0, // Will be assigned
            100,
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            0,
            100,
            true, // exclusive
        );

        let resp = state.apply(CoordRequest::AcquireLock(lock1));
        assert!(matches!(resp, CoordResponse::LockGranted(true)));

        // Conflicting lock should fail
        let lock2 = DistributedLock::new(
            0,
            200,
            2,
            "srv2".to_string(),
            "/file.txt".to_string(),
            50,
            100,
            true,
        );
        let resp = state.apply(CoordRequest::AcquireLock(lock2));
        assert!(matches!(resp, CoordResponse::LockGranted(false)));

        // Non-overlapping lock should succeed
        let lock3 = DistributedLock::new(
            0,
            300,
            3,
            "srv1".to_string(),
            "/file.txt".to_string(),
            200,
            100,
            true,
        );
        let resp = state.apply(CoordRequest::AcquireLock(lock3));
        assert!(matches!(resp, CoordResponse::LockGranted(true)));
    }

    #[test]
    fn test_release_locks_by_session() {
        let mut state = CoordinationState::new();

        // Create locks for different sessions
        let lock1 = DistributedLock::new(
            0,
            100,
            1,
            "srv1".to_string(),
            "/a.txt".to_string(),
            0,
            100,
            true,
        );
        let lock2 = DistributedLock::new(
            0,
            200,
            1,
            "srv1".to_string(),
            "/b.txt".to_string(),
            0,
            100,
            true,
        );
        let lock3 = DistributedLock::new(
            0,
            300,
            2,
            "srv1".to_string(),
            "/c.txt".to_string(),
            0,
            100,
            true,
        );

        state.apply(CoordRequest::AcquireLock(lock1));
        state.apply(CoordRequest::AcquireLock(lock2));
        state.apply(CoordRequest::AcquireLock(lock3));

        // Release all locks for session 1
        state.apply(CoordRequest::ReleaseLocksForSession(1));

        // Session 1 locks should be gone
        assert!(state.get_locks_for_file("/a.txt").is_empty());
        assert!(state.get_locks_for_file("/b.txt").is_empty());

        // Session 2 lock should remain
        assert_eq!(state.get_locks_for_file("/c.txt").len(), 1);
    }

    #[tokio::test]
    async fn test_state_machine_async() {
        let sm = CoordStateMachine::new();

        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:8080");

        sm.apply(CoordRequest::RegisterServer(server)).await;

        let state = sm.state().await;
        assert!(state.get_server("srv1").is_some());
    }

    #[test]
    fn test_get_leases_for_file() {
        let mut state = CoordinationState::new();

        // Create leases for different files
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file1.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        let lease2 = LeaseEntry::new(
            [2u8; 16],
            "client2".to_string(),
            2,
            "srv1".to_string(),
            "/file1.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        let lease3 = LeaseEntry::new(
            [3u8; 16],
            "client3".to_string(),
            3,
            "srv1".to_string(),
            "/file2.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );

        state.apply(CoordRequest::CreateLease(lease1));
        state.apply(CoordRequest::CreateLease(lease2));
        state.apply(CoordRequest::CreateLease(lease3));

        // Get leases for file1
        let leases = state.get_leases_for_file("/file1.txt");
        assert_eq!(leases.len(), 2);

        // Get leases for file2
        let leases = state.get_leases_for_file("/file2.txt");
        assert_eq!(leases.len(), 1);

        // Non-existent file
        let leases = state.get_leases_for_file("/nonexistent.txt");
        assert!(leases.is_empty());
    }

    #[test]
    fn test_lease_conflict_no_existing_leases() {
        let state = CoordinationState::new();

        // No existing leases - should grant requested state
        let result = state.check_lease_conflict(
            "/file.txt",
            None,
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
        );

        assert!(result.can_grant);
        assert!(result.conflicts.is_empty());
        assert_eq!(
            result.granted_state,
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING
        );
    }

    #[test]
    fn test_lease_conflict_read_vs_read() {
        let mut state = CoordinationState::new();

        // Create a read-caching lease
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        state.apply(CoordRequest::CreateLease(lease1));

        // Request another read-caching lease - should not conflict
        let result = state.check_lease_conflict("/file.txt", None, LeaseEntry::READ_CACHING);

        assert!(result.can_grant);
        assert!(result.conflicts.is_empty());
        assert_eq!(result.granted_state, LeaseEntry::READ_CACHING);
    }

    #[test]
    fn test_lease_conflict_write_vs_any() {
        let mut state = CoordinationState::new();

        // Create a write-caching lease
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::WRITE_CACHING,
        );
        state.apply(CoordRequest::CreateLease(lease1.clone()));

        // Request any caching - conflicts with write
        let result = state.check_lease_conflict("/file.txt", None, LeaseEntry::READ_CACHING);

        assert!(!result.can_grant);
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.granted_state, 0); // Reduced to no caching
    }

    #[test]
    fn test_lease_conflict_request_write_vs_existing() {
        let mut state = CoordinationState::new();

        // Create a read-caching lease
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        state.apply(CoordRequest::CreateLease(lease1.clone()));

        // Request write-caching - conflicts with existing read
        let result = state.check_lease_conflict(
            "/file.txt",
            None,
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
        );

        assert!(!result.can_grant);
        assert_eq!(result.conflicts.len(), 1);
        // Should reduce to read-only (remove write)
        assert_eq!(result.granted_state, LeaseEntry::READ_CACHING);
    }

    #[test]
    fn test_lease_conflict_excludes_requestor() {
        let mut state = CoordinationState::new();

        // Create a lease
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
        );
        state.apply(CoordRequest::CreateLease(lease1.clone()));

        // Request as the same lease key - should not conflict with itself
        let result = state.check_lease_conflict(
            "/file.txt",
            Some(&lease1.lease_key),
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
        );

        assert!(result.can_grant);
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn test_get_leases_for_file_request() {
        let mut state = CoordinationState::new();

        // Create leases
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        state.apply(CoordRequest::CreateLease(lease1));

        // Request leases for file via CoordRequest
        let resp = state.apply(CoordRequest::GetLeasesForFile("/file.txt".to_string()));

        if let CoordResponse::Leases(leases) = resp {
            assert_eq!(leases.len(), 1);
        } else {
            panic!("Expected Leases response");
        }
    }

    #[test]
    fn test_check_lease_conflict_request() {
        let mut state = CoordinationState::new();

        // Create a read lease
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        state.apply(CoordRequest::CreateLease(lease1));

        // Check conflict via CoordRequest
        let resp = state.apply(CoordRequest::CheckLeaseConflict {
            file_path: "/file.txt".to_string(),
            requestor_lease_key: None,
            requested_state: LeaseEntry::WRITE_CACHING,
        });

        if let CoordResponse::LeaseConflict(result) = resp {
            assert!(!result.can_grant);
            assert_eq!(result.conflicts.len(), 1);
        } else {
            panic!("Expected LeaseConflict response");
        }
    }
}
