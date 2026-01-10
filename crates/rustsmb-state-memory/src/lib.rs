//! In-memory state store for RustSMB.
//!
//! This implementation is suitable for development and testing.
//! For production HA deployments, use `rustsmb-state-redis`.

use rustsmb_core::StateError;
use rustsmb_state::{
    BoxFuture, DistributedLock, HandleState, LeaseConflictResult, LeaseEntry, LockState,
    SessionState, StateStore, TreeState,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// In-memory state store.
pub struct MemoryStateStore {
    sessions: RwLock<HashMap<u64, SessionState>>,
    trees: RwLock<HashMap<(u64, u32), TreeState>>,
    handles: RwLock<HashMap<u128, HandleState>>,
    locks: RwLock<HashMap<u64, LockState>>,
    distributed_locks: RwLock<HashMap<String, String>>,
    /// SMB leases (lease_key -> LeaseEntry).
    leases: RwLock<HashMap<String, LeaseEntry>>,
    /// Cluster-wide file locks (lock_id -> DistributedLock).
    file_locks: RwLock<HashMap<u64, DistributedLock>>,
    session_counter: AtomicU64,
    tree_counters: RwLock<HashMap<u64, AtomicU64>>,
    handle_counter: AtomicU64,
    #[allow(dead_code)]
    lock_counter: AtomicU64,
    /// Counter for file lock IDs.
    file_lock_counter: AtomicU64,
}

impl MemoryStateStore {
    /// Create a new in-memory state store.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            trees: RwLock::new(HashMap::new()),
            handles: RwLock::new(HashMap::new()),
            locks: RwLock::new(HashMap::new()),
            distributed_locks: RwLock::new(HashMap::new()),
            leases: RwLock::new(HashMap::new()),
            file_locks: RwLock::new(HashMap::new()),
            session_counter: AtomicU64::new(1),
            tree_counters: RwLock::new(HashMap::new()),
            handle_counter: AtomicU64::new(1),
            lock_counter: AtomicU64::new(1),
            file_lock_counter: AtomicU64::new(1),
        }
    }

    /// Create as Arc for use as DynStateStore.
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl Default for MemoryStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore for MemoryStateStore {
    fn create_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.session_id, session.clone());
            Ok(())
        })
    }

    fn get_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Option<SessionState>, StateError>> {
        Box::pin(async move {
            let sessions = self.sessions.read().await;
            Ok(sessions.get(&session_id).cloned())
        })
    }

    fn update_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.session_id, session.clone());
            Ok(())
        })
    }

    fn delete_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut sessions = self.sessions.write().await;
            sessions.remove(&session_id);
            Ok(())
        })
    }

    fn refresh_session(
        &self,
        session_id: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_mut(&session_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                session.last_access = now;
                session.expires_at = now + ttl.as_secs();
            }
            Ok(())
        })
    }

    fn list_sessions<'a>(
        &'a self,
        user_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<SessionState>, StateError>> {
        Box::pin(async move {
            let sessions = self.sessions.read().await;
            let result: Vec<SessionState> = sessions
                .values()
                .filter(|s| user_id.map_or(true, |u| s.user_id == u))
                .cloned()
                .collect();
            Ok(result)
        })
    }

    fn create_tree<'a>(&'a self, tree: &'a TreeState) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut trees = self.trees.write().await;
            trees.insert((tree.session_id, tree.tree_id), tree.clone());
            Ok(())
        })
    }

    fn get_tree(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> BoxFuture<'_, Result<Option<TreeState>, StateError>> {
        Box::pin(async move {
            let trees = self.trees.read().await;
            Ok(trees.get(&(session_id, tree_id)).cloned())
        })
    }

    fn get_trees_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<TreeState>, StateError>> {
        Box::pin(async move {
            let trees = self.trees.read().await;
            let result: Vec<TreeState> = trees
                .iter()
                .filter(|((sid, _), _)| *sid == session_id)
                .map(|(_, t)| t.clone())
                .collect();
            Ok(result)
        })
    }

    fn delete_tree(&self, session_id: u64, tree_id: u32) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut trees = self.trees.write().await;
            trees.remove(&(session_id, tree_id));
            Ok(())
        })
    }

    fn create_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            handles.insert(handle.persistent_id, handle.clone());
            Ok(())
        })
    }

    fn get_handle(
        &self,
        persistent_id: u128,
    ) -> BoxFuture<'_, Result<Option<HandleState>, StateError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            Ok(handles.get(&persistent_id).cloned())
        })
    }

    fn update_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            handles.insert(handle.persistent_id, handle.clone());
            Ok(())
        })
    }

    fn get_handles_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<HandleState>, StateError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let result: Vec<HandleState> = handles
                .values()
                .filter(|h| h.session_id == session_id)
                .cloned()
                .collect();
            Ok(result)
        })
    }

    fn delete_handle(&self, persistent_id: u128) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            handles.remove(&persistent_id);
            Ok(())
        })
    }

    fn create_lock<'a>(&'a self, lock: &'a LockState) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut locks = self.locks.write().await;
            locks.insert(lock.lock_id, lock.clone());
            Ok(())
        })
    }

    fn get_locks(&self, persistent_id: u128) -> BoxFuture<'_, Result<Vec<LockState>, StateError>> {
        Box::pin(async move {
            let locks = self.locks.read().await;
            let result: Vec<LockState> = locks
                .values()
                .filter(|l| l.persistent_id == persistent_id)
                .cloned()
                .collect();
            Ok(result)
        })
    }

    fn delete_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut locks = self.locks.write().await;
            locks.remove(&lock_id);
            Ok(())
        })
    }

    fn acquire_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        _ttl: Duration,
    ) -> BoxFuture<'a, Result<Option<String>, StateError>> {
        Box::pin(async move {
            let mut locks = self.distributed_locks.write().await;
            if locks.contains_key(key) {
                Ok(None)
            } else {
                let token = uuid_v4();
                locks.insert(key.to_string(), token.clone());
                Ok(Some(token))
            }
        })
    }

    fn release_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut locks = self.distributed_locks.write().await;
            if let Some(stored_token) = locks.get(key) {
                if stored_token == token {
                    locks.remove(key);
                }
            }
            Ok(())
        })
    }

    fn extend_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
        _ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, StateError>> {
        Box::pin(async move {
            let locks = self.distributed_locks.read().await;
            Ok(locks.get(key).is_some_and(|t| t == token))
        })
    }

    fn next_session_id(&self) -> BoxFuture<'_, Result<u64, StateError>> {
        Box::pin(async move { Ok(self.session_counter.fetch_add(1, Ordering::Relaxed)) })
    }

    fn next_tree_id(&self, session_id: u64) -> BoxFuture<'_, Result<u32, StateError>> {
        Box::pin(async move {
            let mut counters = self.tree_counters.write().await;
            let counter = counters
                .entry(session_id)
                .or_insert_with(|| AtomicU64::new(1));
            Ok(counter.fetch_add(1, Ordering::Relaxed) as u32)
        })
    }

    fn next_handle_id(&self) -> BoxFuture<'_, Result<u128, StateError>> {
        Box::pin(async move { Ok(self.handle_counter.fetch_add(1, Ordering::Relaxed) as u128) })
    }

    // ========== SMB Lease Management ==========

    fn create_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut leases = self.leases.write().await;
            if leases.contains_key(&lease.lease_key) {
                return Err(StateError::AlreadyExists(format!(
                    "Lease {} already exists",
                    lease.lease_key
                )));
            }
            leases.insert(lease.lease_key.clone(), lease.clone());
            Ok(())
        })
    }

    fn get_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<Option<LeaseEntry>, StateError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move {
            let leases = self.leases.read().await;
            Ok(leases.get(&lease_key).cloned())
        })
    }

    fn update_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut leases = self.leases.write().await;
            leases.insert(lease.lease_key.clone(), lease.clone());
            Ok(())
        })
    }

    fn delete_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<(), StateError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move {
            let mut leases = self.leases.write().await;
            leases.remove(&lease_key);
            Ok(())
        })
    }

    fn get_leases_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<LeaseEntry>, StateError>> {
        let file_path = file_path.to_string();
        Box::pin(async move {
            let leases = self.leases.read().await;
            let result: Vec<LeaseEntry> = leases
                .values()
                .filter(|l| l.file_path == file_path)
                .cloned()
                .collect();
            Ok(result)
        })
    }

    fn check_and_create_lease<'a>(
        &'a self,
        file_path: &'a str,
        lease: &'a LeaseEntry,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseConflictResult, StateError>> {
        Box::pin(async move {
            let mut leases = self.leases.write().await;

            // Get existing leases for this file (excluding requestor)
            let existing: Vec<LeaseEntry> = leases
                .values()
                .filter(|l| l.file_path == file_path && l.lease_key != lease.lease_key)
                .cloned()
                .collect();

            if existing.is_empty() {
                // No conflicts, grant full requested state
                let mut new_lease = lease.clone();
                new_lease.lease_state = requested_state;
                leases.insert(new_lease.lease_key.clone(), new_lease);
                return Ok(LeaseConflictResult::granted(requested_state));
            }

            // Check for conflicts
            let mut conflicts = Vec::new();
            let mut granted_state = requested_state;

            for existing_lease in &existing {
                if leases_conflict(existing_lease.lease_state, requested_state) {
                    conflicts.push(existing_lease.clone());
                }
            }

            if !conflicts.is_empty() {
                // Reduce the granted state
                granted_state = reduce_lease_state(requested_state, &conflicts);
            }

            // Create the lease with the (possibly reduced) state
            let mut new_lease = lease.clone();
            new_lease.lease_state = granted_state;
            leases.insert(new_lease.lease_key.clone(), new_lease);

            if conflicts.is_empty() {
                Ok(LeaseConflictResult::granted(granted_state))
            } else {
                Ok(LeaseConflictResult::conflict(conflicts, granted_state))
            }
        })
    }

    fn delete_leases_for_server(&self, server_id: &str) -> BoxFuture<'_, Result<(), StateError>> {
        let server_id = server_id.to_string();
        Box::pin(async move {
            let mut leases = self.leases.write().await;
            leases.retain(|_, lease| lease.server_id != server_id);
            Ok(())
        })
    }

    // ========== File Lock Management ==========

    fn acquire_file_lock<'a>(
        &'a self,
        lock: &'a DistributedLock,
    ) -> BoxFuture<'a, Result<bool, StateError>> {
        Box::pin(async move {
            let mut file_locks = self.file_locks.write().await;

            // Check for conflicts with existing locks
            for existing in file_locks.values() {
                if lock.conflicts_with(existing) {
                    return Ok(false);
                }
            }

            // No conflict, grant the lock
            file_locks.insert(lock.lock_id, lock.clone());
            Ok(true)
        })
    }

    fn release_file_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut file_locks = self.file_locks.write().await;
            file_locks.remove(&lock_id);
            Ok(())
        })
    }

    fn get_file_locks(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<DistributedLock>, StateError>> {
        let file_path = file_path.to_string();
        Box::pin(async move {
            let file_locks = self.file_locks.read().await;
            let result: Vec<DistributedLock> = file_locks
                .values()
                .filter(|l| l.file_path == file_path)
                .cloned()
                .collect();
            Ok(result)
        })
    }

    fn release_file_locks_for_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut file_locks = self.file_locks.write().await;
            file_locks.retain(|_, lock| lock.session_id != session_id);
            Ok(())
        })
    }

    fn release_file_locks_for_handle(
        &self,
        handle_id: u128,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut file_locks = self.file_locks.write().await;
            file_locks.retain(|_, lock| lock.handle_id != handle_id);
            Ok(())
        })
    }

    fn release_file_locks_for_server(
        &self,
        server_id: &str,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        let server_id = server_id.to_string();
        Box::pin(async move {
            let mut file_locks = self.file_locks.write().await;
            file_locks.retain(|_, lock| lock.server_id != server_id);
            Ok(())
        })
    }

    fn next_file_lock_id(&self) -> BoxFuture<'_, Result<u64, StateError>> {
        Box::pin(async move { Ok(self.file_lock_counter.fetch_add(1, Ordering::Relaxed)) })
    }
}

/// Check if two lease states conflict.
fn leases_conflict(existing_state: u32, requested_state: u32) -> bool {
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
fn reduce_lease_state(requested_state: u32, conflicts: &[LeaseEntry]) -> u32 {
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

/// Simple UUID v4 generation (for token generation).
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_crud() {
        let store = MemoryStateStore::new();

        let session = SessionState {
            session_id: 1,
            user_id: "testuser".to_string(),
            ..Default::default()
        };

        // Create
        store.create_session(&session).await.unwrap();

        // Read
        let retrieved = store.get_session(1).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "testuser");

        // Delete
        store.delete_session(1).await.unwrap();
        let retrieved = store.get_session(1).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_next_session_id() {
        let store = MemoryStateStore::new();

        let id1 = store.next_session_id().await.unwrap();
        let id2 = store.next_session_id().await.unwrap();
        let id3 = store.next_session_id().await.unwrap();

        assert!(id2 > id1);
        assert!(id3 > id2);
    }
}
