//! In-memory state store for RustSMB.
//!
//! This implementation is suitable for development and testing.
//! For production HA deployments, use `rustsmb-state-redis`.

use rustsmb_core::StateError;
use rustsmb_state::{BoxFuture, HandleState, LockState, SessionState, StateStore, TreeState};
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
    session_counter: AtomicU64,
    tree_counters: RwLock<HashMap<u64, AtomicU64>>,
    handle_counter: AtomicU64,
    #[allow(dead_code)]
    lock_counter: AtomicU64,
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
            session_counter: AtomicU64::new(1),
            tree_counters: RwLock::new(HashMap::new()),
            handle_counter: AtomicU64::new(1),
            lock_counter: AtomicU64::new(1),
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
