//! Cached state store with LRU eviction and epoch-based invalidation.
//!
//! This crate provides `CachedStateStore`, a wrapper around any `StateStore`
//! implementation that adds local caching with epoch-based invalidation for
//! distributed server deployments.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────┐
//! │   CachedStateStore  │
//! │  ┌───────────────┐  │
//! │  │  LocalCache   │  │  ← Fast local lookups (~10μs)
//! │  │  (LRU+Epoch)  │  │
//! │  └───────┬───────┘  │
//! │          │          │
//! │  ┌───────▼───────┐  │
//! │  │  BulkStore    │  │  ← Redis/etcd (~1-5ms)
//! │  │  (StateStore) │  │
//! │  └───────────────┘  │
//! └─────────────────────┘
//! ```
//!
//! # Cache Invalidation
//!
//! When a server fails, all caches must be invalidated to maintain strong
//! consistency. This is done by incrementing a global epoch - all cached
//! entries with a stale epoch are considered invalid.

pub mod cache;

pub use cache::{CacheConfig, CacheEntry, CacheStats, LocalCache};

use rustsmb_core::StateError;
use rustsmb_state::{
    BoxFuture, DynStateStore, HandleState, LockState, SessionState, StateStore, TreeState,
};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Cached state store that wraps a bulk storage backend.
///
/// This store maintains a local LRU cache with epoch-based invalidation.
/// Cache hits are fast (~10μs), while misses fall through to the bulk store.
pub struct CachedStateStore {
    /// Local cache.
    cache: Arc<LocalCache>,
    /// Bulk storage backend (Redis, etcd, etc.).
    bulk_store: DynStateStore,
}

impl CachedStateStore {
    /// Create a new cached state store.
    pub fn new(bulk_store: DynStateStore, cache_config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(LocalCache::new(cache_config)),
            bulk_store,
        }
    }

    /// Create with default cache configuration.
    pub fn with_defaults(bulk_store: DynStateStore) -> Self {
        Self::new(bulk_store, CacheConfig::default())
    }

    /// Get the local cache (for epoch management).
    pub fn cache(&self) -> &Arc<LocalCache> {
        &self.cache
    }

    /// Get the bulk store.
    pub fn bulk_store(&self) -> &DynStateStore {
        &self.bulk_store
    }

    /// Invalidate all cached entries.
    ///
    /// Call this when a server failure is detected.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Set the cache epoch (from coordinator).
    pub fn set_epoch(&self, epoch: u64) {
        self.cache.set_epoch(epoch);
    }

    /// Get cache statistics.
    pub async fn stats(&self) -> CacheStats {
        self.cache.stats().await
    }
}

impl StateStore for CachedStateStore {
    // ========== Session Management ==========

    fn create_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            // Write-through: write to bulk store first
            self.bulk_store.create_session(session).await?;
            // Then cache
            self.cache.put_session(session.clone()).await;
            debug!(
                session_id = session.session_id,
                "Session created and cached"
            );
            Ok(())
        })
    }

    fn get_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Option<SessionState>, StateError>> {
        Box::pin(async move {
            // Try cache first
            if let Some(session) = self.cache.get_session(session_id).await {
                debug!(session_id, "Session cache hit");
                return Ok(Some(session));
            }

            // Cache miss - fetch from bulk store
            debug!(session_id, "Session cache miss");
            let session = self.bulk_store.get_session(session_id).await?;

            // Cache the result if found
            if let Some(ref s) = session {
                self.cache.put_session(s.clone()).await;
            }

            Ok(session)
        })
    }

    fn update_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            // Write-through
            self.bulk_store.update_session(session).await?;
            self.cache.put_session(session.clone()).await;
            Ok(())
        })
    }

    fn delete_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.delete_session(session_id).await?;
            self.cache.remove_session(session_id).await;
            Ok(())
        })
    }

    fn refresh_session(
        &self,
        session_id: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.refresh_session(session_id, ttl).await?;
            // Invalidate cache entry so next read gets fresh data
            self.cache.remove_session(session_id).await;
            Ok(())
        })
    }

    fn list_sessions<'a>(
        &'a self,
        user_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<SessionState>, StateError>> {
        // List operations go directly to bulk store (not cached)
        self.bulk_store.list_sessions(user_id)
    }

    // ========== Tree Connection Management ==========

    fn create_tree<'a>(&'a self, tree: &'a TreeState) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.create_tree(tree).await?;
            self.cache.put_tree(tree.clone()).await;
            Ok(())
        })
    }

    fn get_tree(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> BoxFuture<'_, Result<Option<TreeState>, StateError>> {
        Box::pin(async move {
            // Try cache first
            if let Some(tree) = self.cache.get_tree(session_id, tree_id).await {
                debug!(session_id, tree_id, "Tree cache hit");
                return Ok(Some(tree));
            }

            // Cache miss
            debug!(session_id, tree_id, "Tree cache miss");
            let tree = self.bulk_store.get_tree(session_id, tree_id).await?;

            if let Some(ref t) = tree {
                self.cache.put_tree(t.clone()).await;
            }

            Ok(tree)
        })
    }

    fn get_trees_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<TreeState>, StateError>> {
        // List operations go directly to bulk store
        self.bulk_store.get_trees_by_session(session_id)
    }

    fn delete_tree(&self, session_id: u64, tree_id: u32) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.delete_tree(session_id, tree_id).await?;
            self.cache.remove_tree(session_id, tree_id).await;
            Ok(())
        })
    }

    // ========== Handle Management ==========

    fn create_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.create_handle(handle).await?;
            self.cache.put_handle(handle.clone()).await;
            debug!(
                persistent_id = handle.persistent_id,
                "Handle created and cached"
            );
            Ok(())
        })
    }

    fn get_handle(
        &self,
        persistent_id: u128,
    ) -> BoxFuture<'_, Result<Option<HandleState>, StateError>> {
        Box::pin(async move {
            // Try cache first
            if let Some(handle) = self.cache.get_handle(persistent_id).await {
                debug!(persistent_id, "Handle cache hit");
                return Ok(Some(handle));
            }

            // Cache miss
            debug!(persistent_id, "Handle cache miss");
            let handle = self.bulk_store.get_handle(persistent_id).await?;

            if let Some(ref h) = handle {
                self.cache.put_handle(h.clone()).await;
            }

            Ok(handle)
        })
    }

    fn update_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.update_handle(handle).await?;
            self.cache.put_handle(handle.clone()).await;
            Ok(())
        })
    }

    fn get_handles_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<HandleState>, StateError>> {
        // List operations go directly to bulk store
        self.bulk_store.get_handles_by_session(session_id)
    }

    fn delete_handle(&self, persistent_id: u128) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            self.bulk_store.delete_handle(persistent_id).await?;
            self.cache.remove_handle(persistent_id).await;
            Ok(())
        })
    }

    // ========== Lock Management ==========
    // Locks are not cached - they go directly to bulk store for consistency

    fn create_lock<'a>(&'a self, lock: &'a LockState) -> BoxFuture<'a, Result<(), StateError>> {
        self.bulk_store.create_lock(lock)
    }

    fn get_locks(&self, persistent_id: u128) -> BoxFuture<'_, Result<Vec<LockState>, StateError>> {
        self.bulk_store.get_locks(persistent_id)
    }

    fn delete_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        self.bulk_store.delete_lock(lock_id)
    }

    // ========== Distributed Locking ==========
    // Distributed locks go directly to bulk store

    fn acquire_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Option<String>, StateError>> {
        self.bulk_store.acquire_distributed_lock(key, ttl)
    }

    fn release_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        self.bulk_store.release_distributed_lock(key, token)
    }

    fn extend_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, StateError>> {
        self.bulk_store.extend_distributed_lock(key, token, ttl)
    }

    // ========== ID Generation ==========
    // ID generation goes directly to bulk store for uniqueness

    fn next_session_id(&self) -> BoxFuture<'_, Result<u64, StateError>> {
        self.bulk_store.next_session_id()
    }

    fn next_tree_id(&self, session_id: u64) -> BoxFuture<'_, Result<u32, StateError>> {
        self.bulk_store.next_tree_id(session_id)
    }

    fn next_handle_id(&self) -> BoxFuture<'_, Result<u128, StateError>> {
        self.bulk_store.next_handle_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_state_memory::MemoryStateStore;

    #[tokio::test]
    async fn test_cached_session_crud() {
        let bulk_store = MemoryStateStore::new_arc();
        let cached_store = CachedStateStore::with_defaults(bulk_store);

        // Create
        let session_id = cached_store.next_session_id().await.unwrap();
        let session = SessionState {
            session_id,
            user_id: "testuser".to_string(),
            ..Default::default()
        };
        cached_store.create_session(&session).await.unwrap();

        // Get (should be cache hit)
        let retrieved = cached_store.get_session(session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "testuser");

        // Check cache stats
        let stats = cached_store.stats().await;
        assert_eq!(stats.sessions_cached, 1);

        // Delete
        cached_store.delete_session(session_id).await.unwrap();
        let retrieved = cached_store.get_session(session_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cached_handle_crud() {
        let bulk_store = MemoryStateStore::new_arc();
        let cached_store = CachedStateStore::with_defaults(bulk_store);

        let handle_id = cached_store.next_handle_id().await.unwrap();
        let handle = HandleState {
            persistent_id: handle_id,
            volatile_id: handle_id,
            session_id: 1,
            tree_id: 1,
            path: "/test.txt".to_string(),
            ..Default::default()
        };

        cached_store.create_handle(&handle).await.unwrap();
        let retrieved = cached_store.get_handle(handle_id).await.unwrap();
        assert!(retrieved.is_some());

        cached_store.delete_handle(handle_id).await.unwrap();
        assert!(cached_store.get_handle(handle_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let bulk_store = MemoryStateStore::new_arc();
        let cached_store = CachedStateStore::with_defaults(bulk_store.clone());

        // Create a session
        let session = SessionState {
            session_id: 1,
            user_id: "testuser".to_string(),
            ..Default::default()
        };
        cached_store.create_session(&session).await.unwrap();

        // Verify it's cached
        assert!(cached_store.cache.get_session(1).await.is_some());

        // Invalidate all
        cached_store.invalidate_all();

        // Cache should miss, but bulk store should still have it
        assert!(cached_store.cache.get_session(1).await.is_none());

        // Get should fetch from bulk store and re-cache
        let retrieved = cached_store.get_session(1).await.unwrap();
        assert!(retrieved.is_some());

        // Now it should be cached again
        assert!(cached_store.cache.get_session(1).await.is_some());
    }

    #[tokio::test]
    async fn test_write_through() {
        let bulk_store = MemoryStateStore::new_arc();
        let cached_store = CachedStateStore::with_defaults(bulk_store.clone());

        // Create via cached store
        let session = SessionState {
            session_id: 1,
            user_id: "testuser".to_string(),
            ..Default::default()
        };
        cached_store.create_session(&session).await.unwrap();

        // Verify it's in bulk store too
        let from_bulk = bulk_store.get_session(1).await.unwrap();
        assert!(from_bulk.is_some());
        assert_eq!(from_bulk.unwrap().user_id, "testuser");
    }

    #[tokio::test]
    async fn test_cache_miss_populates_cache() {
        let bulk_store = MemoryStateStore::new_arc();

        // Write directly to bulk store (bypassing cache)
        let session = SessionState {
            session_id: 1,
            user_id: "testuser".to_string(),
            ..Default::default()
        };
        bulk_store.create_session(&session).await.unwrap();

        // Create cached store
        let cached_store = CachedStateStore::with_defaults(bulk_store);

        // Cache should be empty
        assert!(cached_store.cache.get_session(1).await.is_none());

        // Get should fetch from bulk and populate cache
        let retrieved = cached_store.get_session(1).await.unwrap();
        assert!(retrieved.is_some());

        // Now cache should have it
        assert!(cached_store.cache.get_session(1).await.is_some());
    }
}
