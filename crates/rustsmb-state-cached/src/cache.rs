//! Local LRU cache with epoch-based invalidation.
//!
//! The cache uses epochs to handle server failures. When any server fails,
//! the global epoch is incremented, invalidating all cached entries across
//! all surviving servers.

use lru::LruCache;
use rustsmb_state::{HandleState, SessionState, TreeState};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cached sessions.
    pub max_sessions: usize,
    /// Maximum cached handles.
    pub max_handles: usize,
    /// Maximum cached trees.
    pub max_trees: usize,
    /// Default TTL for cache entries.
    pub default_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_handles: 100_000,
            max_trees: 50_000,
            default_ttl: Duration::from_secs(60),
        }
    }
}

/// A cached entry with metadata.
#[derive(Debug, Clone)]
pub struct CacheEntry<T> {
    /// The cached data.
    pub data: T,
    /// Cache epoch when this entry was created.
    pub epoch: u64,
    /// When this entry was cached.
    pub cached_at: Instant,
    /// TTL for this entry.
    pub ttl: Duration,
}

impl<T> CacheEntry<T> {
    /// Create a new cache entry.
    pub fn new(data: T, epoch: u64, ttl: Duration) -> Self {
        Self {
            data,
            epoch,
            cached_at: Instant::now(),
            ttl,
        }
    }

    /// Check if this entry is expired (by TTL).
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    /// Check if this entry is stale (wrong epoch).
    pub fn is_stale(&self, current_epoch: u64) -> bool {
        self.epoch != current_epoch
    }

    /// Check if this entry is valid (not expired and not stale).
    pub fn is_valid(&self, current_epoch: u64) -> bool {
        !self.is_expired() && !self.is_stale(current_epoch)
    }
}

/// Local LRU cache with epoch-based invalidation.
///
/// This cache provides fast local access to session state while supporting
/// global invalidation when servers fail.
pub struct LocalCache {
    /// Cached sessions (key: session_id).
    sessions: RwLock<LruCache<u64, CacheEntry<SessionState>>>,
    /// Cached handles (key: persistent_id).
    handles: RwLock<LruCache<u128, CacheEntry<HandleState>>>,
    /// Cached trees (key: (session_id, tree_id)).
    trees: RwLock<LruCache<(u64, u32), CacheEntry<TreeState>>>,
    /// Current global cache epoch.
    current_epoch: AtomicU64,
    /// Configuration.
    config: CacheConfig,
}

impl LocalCache {
    /// Create a new local cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            sessions: RwLock::new(LruCache::new(
                NonZeroUsize::new(config.max_sessions).unwrap_or(NonZeroUsize::new(1).unwrap()),
            )),
            handles: RwLock::new(LruCache::new(
                NonZeroUsize::new(config.max_handles).unwrap_or(NonZeroUsize::new(1).unwrap()),
            )),
            trees: RwLock::new(LruCache::new(
                NonZeroUsize::new(config.max_trees).unwrap_or(NonZeroUsize::new(1).unwrap()),
            )),
            current_epoch: AtomicU64::new(1),
            config,
        }
    }

    /// Create a new local cache with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Get the current cache epoch.
    pub fn epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Acquire)
    }

    /// Set the cache epoch (called when receiving epoch updates from coordinator).
    pub fn set_epoch(&self, epoch: u64) {
        self.current_epoch.store(epoch, Ordering::Release);
    }

    /// Invalidate all cached entries by incrementing the epoch.
    ///
    /// This is called when a server fails. All entries with the old epoch
    /// will be considered stale on next access.
    pub fn invalidate_all(&self) {
        self.current_epoch.fetch_add(1, Ordering::Release);
        tracing::info!(
            epoch = self.epoch(),
            "Cache invalidated - all entries now stale"
        );
    }

    // ========== Session Cache ==========

    /// Get a session from cache.
    pub async fn get_session(&self, session_id: u64) -> Option<SessionState> {
        let mut cache = self.sessions.write().await;
        let entry = cache.get(&session_id)?;

        if entry.is_valid(self.epoch()) {
            Some(entry.data.clone())
        } else {
            // Remove stale/expired entry
            cache.pop(&session_id);
            None
        }
    }

    /// Put a session in cache.
    pub async fn put_session(&self, session: SessionState) {
        let entry = CacheEntry::new(session.clone(), self.epoch(), self.config.default_ttl);
        let mut cache = self.sessions.write().await;
        cache.put(session.session_id, entry);
    }

    /// Remove a session from cache.
    pub async fn remove_session(&self, session_id: u64) {
        let mut cache = self.sessions.write().await;
        cache.pop(&session_id);
    }

    // ========== Handle Cache ==========

    /// Get a handle from cache.
    pub async fn get_handle(&self, persistent_id: u128) -> Option<HandleState> {
        let mut cache = self.handles.write().await;
        let entry = cache.get(&persistent_id)?;

        if entry.is_valid(self.epoch()) {
            Some(entry.data.clone())
        } else {
            cache.pop(&persistent_id);
            None
        }
    }

    /// Put a handle in cache.
    pub async fn put_handle(&self, handle: HandleState) {
        let entry = CacheEntry::new(handle.clone(), self.epoch(), self.config.default_ttl);
        let mut cache = self.handles.write().await;
        cache.put(handle.persistent_id, entry);
    }

    /// Remove a handle from cache.
    pub async fn remove_handle(&self, persistent_id: u128) {
        let mut cache = self.handles.write().await;
        cache.pop(&persistent_id);
    }

    // ========== Tree Cache ==========

    /// Get a tree from cache.
    pub async fn get_tree(&self, session_id: u64, tree_id: u32) -> Option<TreeState> {
        let mut cache = self.trees.write().await;
        let key = (session_id, tree_id);
        let entry = cache.get(&key)?;

        if entry.is_valid(self.epoch()) {
            Some(entry.data.clone())
        } else {
            cache.pop(&key);
            None
        }
    }

    /// Put a tree in cache.
    pub async fn put_tree(&self, tree: TreeState) {
        let entry = CacheEntry::new(tree.clone(), self.epoch(), self.config.default_ttl);
        let mut cache = self.trees.write().await;
        cache.put((tree.session_id, tree.tree_id), entry);
    }

    /// Remove a tree from cache.
    pub async fn remove_tree(&self, session_id: u64, tree_id: u32) {
        let mut cache = self.trees.write().await;
        cache.pop(&(session_id, tree_id));
    }

    // ========== Statistics ==========

    /// Get cache statistics.
    pub async fn stats(&self) -> CacheStats {
        let sessions = self.sessions.read().await;
        let handles = self.handles.read().await;
        let trees = self.trees.read().await;

        CacheStats {
            epoch: self.epoch(),
            sessions_cached: sessions.len(),
            sessions_capacity: sessions.cap().get(),
            handles_cached: handles.len(),
            handles_capacity: handles.cap().get(),
            trees_cached: trees.len(),
            trees_capacity: trees.cap().get(),
        }
    }
}

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Current cache epoch.
    pub epoch: u64,
    /// Number of cached sessions.
    pub sessions_cached: usize,
    /// Session cache capacity.
    pub sessions_capacity: usize,
    /// Number of cached handles.
    pub handles_cached: usize,
    /// Handle cache capacity.
    pub handles_capacity: usize,
    /// Number of cached trees.
    pub trees_cached: usize,
    /// Tree cache capacity.
    pub trees_capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_core::SmbDialect;

    fn make_session(id: u64) -> SessionState {
        SessionState {
            session_id: id,
            user_id: format!("user_{}", id),
            domain: None,
            session_key: vec![],
            dialect: SmbDialect::default(),
            signing_required: false,
            encryption_required: false,
            is_guest: false,
            is_anonymous: false,
            created_at: 0,
            last_access: 0,
            expires_at: 0,
            bound_server_id: None,
        }
    }

    fn make_handle(id: u128) -> HandleState {
        HandleState {
            persistent_id: id,
            volatile_id: id,
            tree_id: 1,
            session_id: 1,
            path: "/test".to_string(),
            ..Default::default()
        }
    }

    fn make_tree(session_id: u64, tree_id: u32) -> TreeState {
        TreeState {
            tree_id,
            session_id,
            share_name: "share".to_string(),
            share_path: "/share".to_string(),
            access_flags: 0,
            is_dfs: false,
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn test_session_cache() {
        let cache = LocalCache::with_defaults();

        // Put and get
        let session = make_session(1);
        cache.put_session(session.clone()).await;
        let retrieved = cache.get_session(1).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, 1);

        // Remove
        cache.remove_session(1).await;
        assert!(cache.get_session(1).await.is_none());
    }

    #[tokio::test]
    async fn test_handle_cache() {
        let cache = LocalCache::with_defaults();

        let handle = make_handle(100);
        cache.put_handle(handle.clone()).await;
        let retrieved = cache.get_handle(100).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().persistent_id, 100);

        cache.remove_handle(100).await;
        assert!(cache.get_handle(100).await.is_none());
    }

    #[tokio::test]
    async fn test_tree_cache() {
        let cache = LocalCache::with_defaults();

        let tree = make_tree(1, 2);
        cache.put_tree(tree.clone()).await;
        let retrieved = cache.get_tree(1, 2).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().tree_id, 2);

        cache.remove_tree(1, 2).await;
        assert!(cache.get_tree(1, 2).await.is_none());
    }

    #[tokio::test]
    async fn test_epoch_invalidation() {
        let cache = LocalCache::with_defaults();

        // Add some entries
        cache.put_session(make_session(1)).await;
        cache.put_handle(make_handle(100)).await;
        cache.put_tree(make_tree(1, 2)).await;

        // Verify they're cached
        assert!(cache.get_session(1).await.is_some());
        assert!(cache.get_handle(100).await.is_some());
        assert!(cache.get_tree(1, 2).await.is_some());

        // Invalidate all
        cache.invalidate_all();

        // All entries should now be stale
        assert!(cache.get_session(1).await.is_none());
        assert!(cache.get_handle(100).await.is_none());
        assert!(cache.get_tree(1, 2).await.is_none());
    }

    #[tokio::test]
    async fn test_set_epoch() {
        let cache = LocalCache::with_defaults();

        cache.put_session(make_session(1)).await;
        assert!(cache.get_session(1).await.is_some());

        // External epoch update (simulating coordinator)
        cache.set_epoch(100);

        // Entry is now stale
        assert!(cache.get_session(1).await.is_none());
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let config = CacheConfig {
            max_sessions: 3,
            ..Default::default()
        };
        let cache = LocalCache::new(config);

        // Add 4 sessions to a cache with capacity 3
        for i in 0..4 {
            cache.put_session(make_session(i)).await;
        }

        // Session 0 should have been evicted (LRU)
        assert!(cache.get_session(0).await.is_none());

        // Sessions 1, 2, 3 should still be cached
        assert!(cache.get_session(1).await.is_some());
        assert!(cache.get_session(2).await.is_some());
        assert!(cache.get_session(3).await.is_some());
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let config = CacheConfig {
            default_ttl: Duration::from_millis(10),
            ..Default::default()
        };
        let cache = LocalCache::new(config);

        cache.put_session(make_session(1)).await;
        assert!(cache.get_session(1).await.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Entry should be expired
        assert!(cache.get_session(1).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = LocalCache::with_defaults();

        cache.put_session(make_session(1)).await;
        cache.put_session(make_session(2)).await;
        cache.put_handle(make_handle(100)).await;

        let stats = cache.stats().await;
        assert_eq!(stats.sessions_cached, 2);
        assert_eq!(stats.handles_cached, 1);
        assert_eq!(stats.trees_cached, 0);
        assert_eq!(stats.epoch, 1);
    }
}
