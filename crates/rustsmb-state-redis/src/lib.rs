//! Redis state store for RustSMB.
//!
//! This implementation is suitable for production HA deployments.
//! It provides:
//! - Connection pooling via deadpool-redis
//! - Session state serialization with serde_json
//! - TTL-based session expiration
//! - Distributed locking with SET NX EX pattern
//! - Atomic ID generation via INCR

use deadpool_redis::{Config, Connection, Pool, Runtime};
use redis::AsyncCommands;
use rustsmb_core::StateError;
use rustsmb_state::{
    coordination::{DistributedLock, LeaseConflictResult, LeaseEntry},
    BoxFuture, HandleState, LockState, SessionState, StateStore, TreeState,
};
use std::sync::Arc;
use std::time::Duration;

/// Redis key prefixes for different entity types.
mod keys {
    pub const SESSION: &str = "smb:session:";
    pub const SESSION_USER_INDEX: &str = "smb:session:user:";
    pub const TREE: &str = "smb:tree:";
    pub const TREE_SESSION_INDEX: &str = "smb:tree:session:";
    pub const HANDLE: &str = "smb:handle:";
    pub const HANDLE_SESSION_INDEX: &str = "smb:handle:session:";
    pub const LOCK: &str = "smb:lock:";
    pub const LOCK_HANDLE_INDEX: &str = "smb:lock:handle:";
    pub const DISTLOCK: &str = "smb:distlock:";
    pub const COUNTER_SESSION: &str = "smb:counter:session";
    pub const COUNTER_TREE: &str = "smb:counter:tree:";
    pub const COUNTER_HANDLE: &str = "smb:counter:handle";

    // SMB Lease keys
    pub const LEASE: &str = "smb:lease:";
    pub const LEASE_FILE_INDEX: &str = "smb:lease:file:";
    pub const LEASE_SERVER_INDEX: &str = "smb:lease:server:";

    // Cluster-wide file locks
    pub const FILE_LOCK: &str = "smb:filelock:";
    pub const FILE_LOCK_FILE_INDEX: &str = "smb:filelock:file:";
    pub const FILE_LOCK_SESSION_INDEX: &str = "smb:filelock:session:";
    pub const FILE_LOCK_HANDLE_INDEX: &str = "smb:filelock:handle:";
    pub const FILE_LOCK_SERVER_INDEX: &str = "smb:filelock:server:";
    pub const COUNTER_FILE_LOCK: &str = "smb:counter:filelock";
}

/// Redis state store for production HA deployments.
pub struct RedisStateStore {
    pool: Pool,
}

impl RedisStateStore {
    /// Create a new Redis state store.
    ///
    /// # Arguments
    ///
    /// * `url` - Redis connection URL (e.g., "redis://localhost:6379")
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use rustsmb_state_redis::RedisStateStore;
    ///
    /// let store = RedisStateStore::new("redis://localhost:6379").unwrap();
    /// ```
    pub fn new(url: &str) -> Result<Self, StateError> {
        let cfg = Config::from_url(url);
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| StateError::ConnectionFailed(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Create a new Redis state store with custom pool configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - Redis connection URL
    /// * `max_size` - Maximum pool size
    pub fn with_pool_size(url: &str, max_size: usize) -> Result<Self, StateError> {
        let mut cfg = Config::from_url(url);
        cfg.pool = Some(deadpool_redis::PoolConfig {
            max_size,
            ..Default::default()
        });

        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| StateError::ConnectionFailed(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Create as Arc for use as DynStateStore.
    pub fn new_arc(url: &str) -> Result<Arc<Self>, StateError> {
        Ok(Arc::new(Self::new(url)?))
    }

    /// Get a connection from the pool.
    async fn get_conn(&self) -> Result<Connection, StateError> {
        self.pool
            .get()
            .await
            .map_err(|e| StateError::ConnectionFailed(e.to_string()))
    }

    /// Generate a random token for distributed locks.
    fn generate_token() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Add some randomness by including thread ID
        let tid = std::thread::current().id();
        format!("{:032x}-{:?}", now, tid)
    }

    /// Check for lease conflicts and compute granted state.
    ///
    /// Returns (conflicting_leases, granted_state).
    fn check_lease_conflicts(
        existing_leases: &[LeaseEntry],
        requested_state: u32,
    ) -> (Vec<LeaseEntry>, u32) {
        let mut conflicts = Vec::new();
        let mut granted_state = requested_state;

        for existing in existing_leases {
            // Write caching is exclusive - conflicts with any other lease
            let existing_has_write = (existing.lease_state & LeaseEntry::WRITE_CACHING) != 0;
            let requested_has_write = (requested_state & LeaseEntry::WRITE_CACHING) != 0;

            if existing_has_write && requested_state != 0 {
                // Existing lease has write caching - we conflict
                conflicts.push(existing.clone());
                granted_state = 0;
            } else if requested_has_write && existing.lease_state != 0 {
                // We want write caching but there's an existing lease - conflict
                conflicts.push(existing.clone());
                // Can't grant write caching, try to reduce
                granted_state &= !LeaseEntry::WRITE_CACHING;
            }
        }

        // If any existing lease has write caching, we get nothing
        let any_write = existing_leases
            .iter()
            .any(|l| (l.lease_state & LeaseEntry::WRITE_CACHING) != 0);
        if any_write {
            granted_state = 0;
        }

        (conflicts, granted_state)
    }

    /// Check if two byte-range locks conflict.
    fn locks_conflict(existing: &DistributedLock, new: &DistributedLock) -> bool {
        // Same file?
        if existing.file_path != new.file_path {
            return false;
        }

        // Check for range overlap
        let existing_end = existing.offset + existing.length;
        let new_end = new.offset + new.length;

        if new.offset >= existing_end || existing.offset >= new_end {
            // No overlap
            return false;
        }

        // Ranges overlap - check exclusivity
        // Exclusive locks conflict with everything
        // Shared locks only conflict with exclusive locks
        existing.exclusive || new.exclusive
    }
}

impl StateStore for RedisStateStore {
    // ========== Session Management ==========

    fn create_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::SESSION, session.session_id);
            let json = serde_json::to_string(session)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            // Calculate TTL from expires_at
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let ttl_secs = session.expires_at.saturating_sub(now);

            // Set with TTL
            if ttl_secs > 0 {
                conn.set_ex::<_, _, ()>(&key, &json, ttl_secs)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            } else {
                conn.set::<_, _, ()>(&key, &json)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            }

            // Add to user index
            let user_index_key = format!("{}{}", keys::SESSION_USER_INDEX, session.user_id);
            conn.sadd::<_, _, ()>(&user_index_key, session.session_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Option<SessionState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::SESSION, session_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            match json {
                Some(j) => {
                    let session: SessionState = serde_json::from_str(&j)
                        .map_err(|e| StateError::Serialization(e.to_string()))?;
                    Ok(Some(session))
                }
                None => Ok(None),
            }
        })
    }

    fn update_session<'a>(
        &'a self,
        session: &'a SessionState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        // Update is the same as create - just overwrite
        self.create_session(session)
    }

    fn delete_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get session first to find user_id for index cleanup
            let key = format!("{}{}", keys::SESSION, session_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if let Some(j) = json {
                if let Ok(session) = serde_json::from_str::<SessionState>(&j) {
                    // Remove from user index
                    let user_index_key = format!("{}{}", keys::SESSION_USER_INDEX, session.user_id);
                    let _: () = conn
                        .srem(&user_index_key, session_id)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;
                }
            }

            // Delete session key
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn refresh_session(
        &self,
        session_id: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::SESSION, session_id);

            // Get existing session
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if let Some(j) = json {
                let mut session: SessionState = serde_json::from_str(&j)
                    .map_err(|e| StateError::Serialization(e.to_string()))?;

                // Update timestamps
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                session.last_access = now;
                session.expires_at = now + ttl.as_secs();

                // Save back with new TTL
                let updated_json = serde_json::to_string(&session)
                    .map_err(|e| StateError::Serialization(e.to_string()))?;

                conn.set_ex::<_, _, ()>(&key, &updated_json, ttl.as_secs())
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            }

            Ok(())
        })
    }

    fn list_sessions<'a>(
        &'a self,
        user_id: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Vec<SessionState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let session_ids: Vec<u64> = if let Some(uid) = user_id {
                // Get from user index
                let user_index_key = format!("{}{}", keys::SESSION_USER_INDEX, uid);
                conn.smembers(&user_index_key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?
            } else {
                // Scan for all session keys
                let pattern = format!("{}*", keys::SESSION);
                let mut ids = Vec::new();
                let mut iter: redis::AsyncIter<String> = conn
                    .scan_match(&pattern)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                while let Some(key) = iter.next_item().await {
                    if let Some(id_str) = key.strip_prefix(keys::SESSION) {
                        if let Ok(id) = id_str.parse::<u64>() {
                            ids.push(id);
                        }
                    }
                }
                ids
            };

            // Fetch all sessions
            let mut sessions = Vec::new();
            for id in session_ids {
                if let Some(session) = self.get_session(id).await? {
                    sessions.push(session);
                }
            }

            Ok(sessions)
        })
    }

    // ========== Tree Connection Management ==========

    fn create_tree<'a>(&'a self, tree: &'a TreeState) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}:{}", keys::TREE, tree.session_id, tree.tree_id);
            let json = serde_json::to_string(tree)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            conn.set::<_, _, ()>(&key, &json)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Add to session index
            let session_index_key = format!("{}{}", keys::TREE_SESSION_INDEX, tree.session_id);
            conn.sadd::<_, _, ()>(&session_index_key, tree.tree_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_tree(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> BoxFuture<'_, Result<Option<TreeState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}:{}", keys::TREE, session_id, tree_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            match json {
                Some(j) => {
                    let tree: TreeState = serde_json::from_str(&j)
                        .map_err(|e| StateError::Serialization(e.to_string()))?;
                    Ok(Some(tree))
                }
                None => Ok(None),
            }
        })
    }

    fn get_trees_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<TreeState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get tree IDs from session index
            let session_index_key = format!("{}{}", keys::TREE_SESSION_INDEX, session_id);
            let tree_ids: Vec<u32> = conn
                .smembers(&session_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Fetch all trees
            let mut trees = Vec::new();
            for tree_id in tree_ids {
                if let Some(tree) = self.get_tree(session_id, tree_id).await? {
                    trees.push(tree);
                }
            }

            Ok(trees)
        })
    }

    fn delete_tree(&self, session_id: u64, tree_id: u32) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Delete tree key
            let key = format!("{}{}:{}", keys::TREE, session_id, tree_id);
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Remove from session index
            let session_index_key = format!("{}{}", keys::TREE_SESSION_INDEX, session_id);
            conn.srem::<_, _, ()>(&session_index_key, tree_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    // ========== Handle Management ==========

    fn create_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::HANDLE, handle.persistent_id);
            let json = serde_json::to_string(handle)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            conn.set::<_, _, ()>(&key, &json)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Add to session index
            let session_index_key = format!("{}{}", keys::HANDLE_SESSION_INDEX, handle.session_id);
            conn.sadd::<_, _, ()>(&session_index_key, handle.persistent_id.to_string())
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_handle(
        &self,
        persistent_id: u128,
    ) -> BoxFuture<'_, Result<Option<HandleState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::HANDLE, persistent_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            match json {
                Some(j) => {
                    let handle: HandleState = serde_json::from_str(&j)
                        .map_err(|e| StateError::Serialization(e.to_string()))?;
                    Ok(Some(handle))
                }
                None => Ok(None),
            }
        })
    }

    fn update_handle<'a>(
        &'a self,
        handle: &'a HandleState,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        // Update is the same as create - just overwrite
        self.create_handle(handle)
    }

    fn get_handles_by_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<Vec<HandleState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get handle IDs from session index
            let session_index_key = format!("{}{}", keys::HANDLE_SESSION_INDEX, session_id);
            let handle_ids: Vec<String> = conn
                .smembers(&session_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Fetch all handles
            let mut handles = Vec::new();
            for id_str in handle_ids {
                if let Ok(persistent_id) = id_str.parse::<u128>() {
                    if let Some(handle) = self.get_handle(persistent_id).await? {
                        handles.push(handle);
                    }
                }
            }

            Ok(handles)
        })
    }

    fn get_handles_for_file(
        &self,
        share_name: &str,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<HandleState>, StateError>> {
        let share_name = share_name.to_string();
        let file_path = file_path.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Scan all handle keys and filter by share_name and path
            // This is inefficient but works for now - could be optimized with a secondary index
            let pattern = format!("{}*", keys::HANDLE);
            let keys: Vec<String> = redis::cmd("KEYS")
                .arg(&pattern)
                .query_async(&mut conn)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            let mut handles = Vec::new();
            for key in keys {
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(handle) = serde_json::from_str::<HandleState>(&j) {
                        if handle.share_name == share_name && handle.path == file_path {
                            handles.push(handle);
                        }
                    }
                }
            }

            Ok(handles)
        })
    }

    fn delete_handle(&self, persistent_id: u128) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get handle first to find session_id for index cleanup
            let key = format!("{}{}", keys::HANDLE, persistent_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if let Some(j) = json {
                if let Ok(handle) = serde_json::from_str::<HandleState>(&j) {
                    // Remove from session index
                    let session_index_key =
                        format!("{}{}", keys::HANDLE_SESSION_INDEX, handle.session_id);
                    let _: () = conn
                        .srem(&session_index_key, persistent_id.to_string())
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;
                }
            }

            // Delete handle key
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    // ========== Lock Management ==========

    fn create_lock<'a>(&'a self, lock: &'a LockState) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::LOCK, lock.lock_id);
            let json = serde_json::to_string(lock)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            conn.set::<_, _, ()>(&key, &json)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Add to handle index
            let handle_index_key = format!("{}{}", keys::LOCK_HANDLE_INDEX, lock.persistent_id);
            conn.sadd::<_, _, ()>(&handle_index_key, lock.lock_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_locks(&self, persistent_id: u128) -> BoxFuture<'_, Result<Vec<LockState>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get lock IDs from handle index
            let handle_index_key = format!("{}{}", keys::LOCK_HANDLE_INDEX, persistent_id);
            let lock_ids: Vec<u64> = conn
                .smembers(&handle_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Fetch all locks
            let mut locks = Vec::new();
            for lock_id in lock_ids {
                let key = format!("{}{}", keys::LOCK, lock_id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    let lock: LockState = serde_json::from_str(&j)
                        .map_err(|e| StateError::Serialization(e.to_string()))?;
                    locks.push(lock);
                }
            }

            Ok(locks)
        })
    }

    fn delete_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get lock first to find persistent_id for index cleanup
            let key = format!("{}{}", keys::LOCK, lock_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if let Some(j) = json {
                if let Ok(lock) = serde_json::from_str::<LockState>(&j) {
                    // Remove from handle index
                    let handle_index_key =
                        format!("{}{}", keys::LOCK_HANDLE_INDEX, lock.persistent_id);
                    let _: () = conn
                        .srem(&handle_index_key, lock_id)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;
                }
            }

            // Delete lock key
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    // ========== Distributed Locking ==========

    fn acquire_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<Option<String>, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let lock_key = format!("{}{}", keys::DISTLOCK, key);
            let token = Self::generate_token();

            // Use SET NX EX for atomic lock acquisition
            let result: Option<String> = redis::cmd("SET")
                .arg(&lock_key)
                .arg(&token)
                .arg("NX")
                .arg("EX")
                .arg(ttl.as_secs())
                .query_async(&mut *conn)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if result.is_some() {
                Ok(Some(token))
            } else {
                Ok(None)
            }
        })
    }

    fn release_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
    ) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let lock_key = format!("{}{}", keys::DISTLOCK, key);

            // Use Lua script for atomic check-and-delete
            let script = redis::Script::new(
                r#"
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("del", KEYS[1])
                else
                    return 0
                end
                "#,
            );

            let _: i32 = script
                .key(&lock_key)
                .arg(token)
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn extend_distributed_lock<'a>(
        &'a self,
        key: &'a str,
        token: &'a str,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<bool, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let lock_key = format!("{}{}", keys::DISTLOCK, key);

            // Use Lua script for atomic check-and-extend
            let script = redis::Script::new(
                r#"
                if redis.call("get", KEYS[1]) == ARGV[1] then
                    return redis.call("expire", KEYS[1], ARGV[2])
                else
                    return 0
                end
                "#,
            );

            let result: i32 = script
                .key(&lock_key)
                .arg(token)
                .arg(ttl.as_secs())
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(result == 1)
        })
    }

    // ========== ID Generation ==========

    fn next_session_id(&self) -> BoxFuture<'_, Result<u64, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let id: u64 = conn
                .incr(keys::COUNTER_SESSION, 1u64)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(id)
        })
    }

    fn next_tree_id(&self, session_id: u64) -> BoxFuture<'_, Result<u32, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let counter_key = format!("{}{}", keys::COUNTER_TREE, session_id);
            let id: u64 = conn
                .incr(&counter_key, 1u64)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(id as u32)
        })
    }

    fn next_handle_id(&self) -> BoxFuture<'_, Result<u128, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let id: u64 = conn
                .incr(keys::COUNTER_HANDLE, 1u64)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(id as u128)
        })
    }

    // ========== SMB Lease Management ==========

    fn create_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::LEASE, lease.lease_key);

            // Check if lease already exists
            let existing: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if existing.is_some() {
                return Err(StateError::AlreadyExists(lease.lease_key.clone()));
            }

            let json = serde_json::to_string(lease)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            conn.set::<_, _, ()>(&key, &json)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Add to file index
            let file_index_key = format!("{}{}", keys::LEASE_FILE_INDEX, lease.file_path);
            conn.sadd::<_, _, ()>(&file_index_key, &lease.lease_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Add to server index
            let server_index_key = format!("{}{}", keys::LEASE_SERVER_INDEX, lease.server_id);
            conn.sadd::<_, _, ()>(&server_index_key, &lease.lease_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<Option<LeaseEntry>, StateError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::LEASE, lease_key);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            match json {
                Some(j) => {
                    let lease: LeaseEntry = serde_json::from_str(&j)
                        .map_err(|e| StateError::Serialization(e.to_string()))?;
                    Ok(Some(lease))
                }
                None => Ok(None),
            }
        })
    }

    fn update_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let key = format!("{}{}", keys::LEASE, lease.lease_key);
            let json = serde_json::to_string(lease)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            conn.set::<_, _, ()>(&key, &json)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn delete_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<(), StateError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get lease first to find file_path and server_id for index cleanup
            let key = format!("{}{}", keys::LEASE, lease_key);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if let Some(j) = json {
                if let Ok(lease) = serde_json::from_str::<LeaseEntry>(&j) {
                    // Remove from file index
                    let file_index_key = format!("{}{}", keys::LEASE_FILE_INDEX, lease.file_path);
                    let _: () = conn
                        .srem(&file_index_key, &lease_key)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;

                    // Remove from server index
                    let server_index_key =
                        format!("{}{}", keys::LEASE_SERVER_INDEX, lease.server_id);
                    let _: () = conn
                        .srem(&server_index_key, &lease_key)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;
                }
            }

            // Delete lease key
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_leases_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<LeaseEntry>, StateError>> {
        let file_path = file_path.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get lease keys from file index
            let file_index_key = format!("{}{}", keys::LEASE_FILE_INDEX, file_path);
            let lease_keys: Vec<String> = conn
                .smembers(&file_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Fetch all leases
            let mut leases = Vec::new();
            for lease_key in lease_keys {
                let key = format!("{}{}", keys::LEASE, lease_key);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(lease) = serde_json::from_str::<LeaseEntry>(&j) {
                        leases.push(lease);
                    }
                }
            }

            Ok(leases)
        })
    }

    fn check_and_create_lease<'a>(
        &'a self,
        file_path: &'a str,
        lease: &'a LeaseEntry,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseConflictResult, StateError>> {
        Box::pin(async move {
            // Use WATCH-based optimistic locking with retries
            for _attempt in 0..3 {
                let mut conn = self.get_conn().await?;

                let file_index_key = format!("{}{}", keys::LEASE_FILE_INDEX, file_path);

                // WATCH the file's lease set
                let _: () = redis::cmd("WATCH")
                    .arg(&file_index_key)
                    .query_async(&mut *conn)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                // Get existing leases for conflict detection
                let lease_keys: Vec<String> = conn
                    .smembers(&file_index_key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                let mut existing_leases = Vec::new();
                for lk in &lease_keys {
                    let key = format!("{}{}", keys::LEASE, lk);
                    let json: Option<String> = conn
                        .get(&key)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;

                    if let Some(j) = json {
                        if let Ok(l) = serde_json::from_str::<LeaseEntry>(&j) {
                            existing_leases.push(l);
                        }
                    }
                }

                // Check for conflicts and reduce state if needed
                let (conflicts, granted_state) =
                    Self::check_lease_conflicts(&existing_leases, requested_state);

                if !conflicts.is_empty() && granted_state == 0 {
                    // Full conflict - cannot grant any lease state
                    // UNWATCH before returning
                    let _: Result<(), _> = redis::cmd("UNWATCH").query_async(&mut *conn).await;

                    return Ok(LeaseConflictResult {
                        can_grant: false,
                        granted_state: 0,
                        conflicts,
                    });
                }

                // Create the lease with potentially reduced state
                let mut new_lease = lease.clone();
                new_lease.lease_state = granted_state;

                let lease_json = serde_json::to_string(&new_lease)
                    .map_err(|e| StateError::Serialization(e.to_string()))?;

                let lease_key = format!("{}{}", keys::LEASE, new_lease.lease_key);
                let server_index_key =
                    format!("{}{}", keys::LEASE_SERVER_INDEX, new_lease.server_id);

                // MULTI/EXEC transaction
                let result: Option<()> = redis::pipe()
                    .atomic()
                    .set(&lease_key, &lease_json)
                    .sadd(&file_index_key, &new_lease.lease_key)
                    .sadd(&server_index_key, &new_lease.lease_key)
                    .query_async(&mut *conn)
                    .await
                    .ok();

                if result.is_some() {
                    // Transaction succeeded
                    return Ok(LeaseConflictResult {
                        can_grant: true,
                        granted_state,
                        conflicts,
                    });
                }

                // EXEC returned None - WATCH detected a change, retry
            }

            // Failed after retries
            Err(StateError::Conflict(
                "Failed to create lease after retries".to_string(),
            ))
        })
    }

    fn delete_leases_for_server(&self, server_id: &str) -> BoxFuture<'_, Result<(), StateError>> {
        let server_id = server_id.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get all lease keys for this server
            let server_index_key = format!("{}{}", keys::LEASE_SERVER_INDEX, server_id);
            let lease_keys: Vec<String> = conn
                .smembers(&server_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Delete each lease
            for lease_key in lease_keys {
                // Get lease to find file_path for index cleanup
                let key = format!("{}{}", keys::LEASE, lease_key);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(lease) = serde_json::from_str::<LeaseEntry>(&j) {
                        // Remove from file index
                        let file_index_key =
                            format!("{}{}", keys::LEASE_FILE_INDEX, lease.file_path);
                        let _: () = conn
                            .srem(&file_index_key, &lease_key)
                            .await
                            .map_err(|e| StateError::Internal(e.to_string()))?;
                    }
                }

                // Delete lease key
                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            }

            // Delete server index
            conn.del::<_, ()>(&server_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    // ========== File Lock Management (Cluster-wide) ==========

    fn acquire_file_lock<'a>(
        &'a self,
        lock: &'a DistributedLock,
    ) -> BoxFuture<'a, Result<bool, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get existing locks for the file
            let file_index_key = format!("{}{}", keys::FILE_LOCK_FILE_INDEX, lock.file_path);
            let lock_ids: Vec<u64> = conn
                .smembers(&file_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Check for conflicts
            for lock_id in lock_ids {
                let key = format!("{}{}", keys::FILE_LOCK, lock_id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(existing) = serde_json::from_str::<DistributedLock>(&j) {
                        if Self::locks_conflict(&existing, lock) {
                            return Ok(false);
                        }
                    }
                }
            }

            // No conflict, create the lock
            let key = format!("{}{}", keys::FILE_LOCK, lock.lock_id);
            let json = serde_json::to_string(lock)
                .map_err(|e| StateError::Serialization(e.to_string()))?;

            conn.set::<_, _, ()>(&key, &json)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Add to indices
            conn.sadd::<_, _, ()>(&file_index_key, lock.lock_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            let session_index_key = format!("{}{}", keys::FILE_LOCK_SESSION_INDEX, lock.session_id);
            conn.sadd::<_, _, ()>(&session_index_key, lock.lock_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            let handle_index_key = format!("{}{}", keys::FILE_LOCK_HANDLE_INDEX, lock.handle_id);
            conn.sadd::<_, _, ()>(&handle_index_key, lock.lock_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            let server_index_key = format!("{}{}", keys::FILE_LOCK_SERVER_INDEX, lock.server_id);
            conn.sadd::<_, _, ()>(&server_index_key, lock.lock_id)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(true)
        })
    }

    fn release_file_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            // Get lock to find indices
            let key = format!("{}{}", keys::FILE_LOCK, lock_id);
            let json: Option<String> = conn
                .get(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            if let Some(j) = json {
                if let Ok(lock) = serde_json::from_str::<DistributedLock>(&j) {
                    // Remove from all indices
                    let file_index_key =
                        format!("{}{}", keys::FILE_LOCK_FILE_INDEX, lock.file_path);
                    let _: () = conn
                        .srem(&file_index_key, lock_id)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;

                    let session_index_key =
                        format!("{}{}", keys::FILE_LOCK_SESSION_INDEX, lock.session_id);
                    let _: () = conn
                        .srem(&session_index_key, lock_id)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;

                    let handle_index_key =
                        format!("{}{}", keys::FILE_LOCK_HANDLE_INDEX, lock.handle_id);
                    let _: () = conn
                        .srem(&handle_index_key, lock_id)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;

                    let server_index_key =
                        format!("{}{}", keys::FILE_LOCK_SERVER_INDEX, lock.server_id);
                    let _: () = conn
                        .srem(&server_index_key, lock_id)
                        .await
                        .map_err(|e| StateError::Internal(e.to_string()))?;
                }
            }

            // Delete lock key
            conn.del::<_, ()>(&key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn get_file_locks(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<DistributedLock>, StateError>> {
        let file_path = file_path.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let file_index_key = format!("{}{}", keys::FILE_LOCK_FILE_INDEX, file_path);
            let lock_ids: Vec<u64> = conn
                .smembers(&file_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            let mut locks = Vec::new();
            for lock_id in lock_ids {
                let key = format!("{}{}", keys::FILE_LOCK, lock_id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(lock) = serde_json::from_str::<DistributedLock>(&j) {
                        locks.push(lock);
                    }
                }
            }

            Ok(locks)
        })
    }

    fn release_file_locks_for_session(
        &self,
        session_id: u64,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let session_index_key = format!("{}{}", keys::FILE_LOCK_SESSION_INDEX, session_id);
            let lock_ids: Vec<u64> = conn
                .smembers(&session_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            // Release each lock (this also removes from indices)
            for lock_id in lock_ids {
                // Get lock to find other indices
                let key = format!("{}{}", keys::FILE_LOCK, lock_id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(lock) = serde_json::from_str::<DistributedLock>(&j) {
                        let file_index_key =
                            format!("{}{}", keys::FILE_LOCK_FILE_INDEX, lock.file_path);
                        let _: () = conn.srem(&file_index_key, lock_id).await.ok().unwrap_or(());

                        let handle_index_key =
                            format!("{}{}", keys::FILE_LOCK_HANDLE_INDEX, lock.handle_id);
                        let _: () = conn
                            .srem(&handle_index_key, lock_id)
                            .await
                            .ok()
                            .unwrap_or(());

                        let server_index_key =
                            format!("{}{}", keys::FILE_LOCK_SERVER_INDEX, lock.server_id);
                        let _: () = conn
                            .srem(&server_index_key, lock_id)
                            .await
                            .ok()
                            .unwrap_or(());
                    }
                }

                // Delete lock key
                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            }

            // Delete session index
            conn.del::<_, ()>(&session_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn release_file_locks_for_handle(
        &self,
        handle_id: u128,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let handle_index_key = format!("{}{}", keys::FILE_LOCK_HANDLE_INDEX, handle_id);
            let lock_ids: Vec<u64> = conn
                .smembers(&handle_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            for lock_id in lock_ids {
                let key = format!("{}{}", keys::FILE_LOCK, lock_id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(lock) = serde_json::from_str::<DistributedLock>(&j) {
                        let file_index_key =
                            format!("{}{}", keys::FILE_LOCK_FILE_INDEX, lock.file_path);
                        let _: () = conn.srem(&file_index_key, lock_id).await.ok().unwrap_or(());

                        let session_index_key =
                            format!("{}{}", keys::FILE_LOCK_SESSION_INDEX, lock.session_id);
                        let _: () = conn
                            .srem(&session_index_key, lock_id)
                            .await
                            .ok()
                            .unwrap_or(());

                        let server_index_key =
                            format!("{}{}", keys::FILE_LOCK_SERVER_INDEX, lock.server_id);
                        let _: () = conn
                            .srem(&server_index_key, lock_id)
                            .await
                            .ok()
                            .unwrap_or(());
                    }
                }

                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            }

            conn.del::<_, ()>(&handle_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn release_file_locks_for_server(
        &self,
        server_id: &str,
    ) -> BoxFuture<'_, Result<(), StateError>> {
        let server_id = server_id.to_string();
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let server_index_key = format!("{}{}", keys::FILE_LOCK_SERVER_INDEX, server_id);
            let lock_ids: Vec<u64> = conn
                .smembers(&server_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            for lock_id in lock_ids {
                let key = format!("{}{}", keys::FILE_LOCK, lock_id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;

                if let Some(j) = json {
                    if let Ok(lock) = serde_json::from_str::<DistributedLock>(&j) {
                        let file_index_key =
                            format!("{}{}", keys::FILE_LOCK_FILE_INDEX, lock.file_path);
                        let _: () = conn.srem(&file_index_key, lock_id).await.ok().unwrap_or(());

                        let session_index_key =
                            format!("{}{}", keys::FILE_LOCK_SESSION_INDEX, lock.session_id);
                        let _: () = conn
                            .srem(&session_index_key, lock_id)
                            .await
                            .ok()
                            .unwrap_or(());

                        let handle_index_key =
                            format!("{}{}", keys::FILE_LOCK_HANDLE_INDEX, lock.handle_id);
                        let _: () = conn
                            .srem(&handle_index_key, lock_id)
                            .await
                            .ok()
                            .unwrap_or(());
                    }
                }

                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StateError::Internal(e.to_string()))?;
            }

            conn.del::<_, ()>(&server_index_key)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(())
        })
    }

    fn next_file_lock_id(&self) -> BoxFuture<'_, Result<u64, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;

            let id: u64 = conn
                .incr(keys::COUNTER_FILE_LOCK, 1u64)
                .await
                .map_err(|e| StateError::Internal(e.to_string()))?;

            Ok(id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running Redis instance.
    // They are marked with #[ignore] by default and can be run with:
    // cargo test --package rustsmb-state-redis -- --ignored

    fn get_redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
    }

    #[tokio::test]
    #[ignore]
    async fn test_session_crud() {
        let store = RedisStateStore::new(&get_redis_url()).expect("Failed to connect to Redis");

        // Generate unique session ID
        let session_id = store.next_session_id().await.unwrap();

        let session = SessionState {
            session_id,
            user_id: "testuser_redis".to_string(),
            ..Default::default()
        };

        // Create
        store.create_session(&session).await.unwrap();

        // Read
        let retrieved = store.get_session(session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "testuser_redis");

        // Delete
        store.delete_session(session_id).await.unwrap();
        let retrieved = store.get_session(session_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_tree_crud() {
        let store = RedisStateStore::new(&get_redis_url()).expect("Failed to connect to Redis");

        let session_id = store.next_session_id().await.unwrap();
        let tree_id = store.next_tree_id(session_id).await.unwrap();

        let tree = TreeState {
            tree_id,
            session_id,
            share_name: "testshare".to_string(),
            share_path: "/test/path".to_string(),
            ..Default::default()
        };

        // Create
        store.create_tree(&tree).await.unwrap();

        // Read
        let retrieved = store.get_tree(session_id, tree_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().share_name, "testshare");

        // List by session
        let trees = store.get_trees_by_session(session_id).await.unwrap();
        assert!(!trees.is_empty());

        // Delete
        store.delete_tree(session_id, tree_id).await.unwrap();
        let retrieved = store.get_tree(session_id, tree_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_handle_crud() {
        let store = RedisStateStore::new(&get_redis_url()).expect("Failed to connect to Redis");

        let session_id = store.next_session_id().await.unwrap();
        let persistent_id = store.next_handle_id().await.unwrap();

        let handle = HandleState {
            persistent_id,
            volatile_id: persistent_id,
            session_id,
            tree_id: 1,
            path: "/test/file.txt".to_string(),
            ..Default::default()
        };

        // Create
        store.create_handle(&handle).await.unwrap();

        // Read
        let retrieved = store.get_handle(persistent_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().path, "/test/file.txt");

        // List by session
        let handles = store.get_handles_by_session(session_id).await.unwrap();
        assert!(!handles.is_empty());

        // Delete
        store.delete_handle(persistent_id).await.unwrap();
        let retrieved = store.get_handle(persistent_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_distributed_lock() {
        let store = RedisStateStore::new(&get_redis_url()).expect("Failed to connect to Redis");

        let lock_key = format!(
            "test_lock_{}",
            std::time::Instant::now().elapsed().as_nanos()
        );

        // Acquire lock
        let token = store
            .acquire_distributed_lock(&lock_key, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(token.is_some());
        let token = token.unwrap();

        // Try to acquire again (should fail)
        let token2 = store
            .acquire_distributed_lock(&lock_key, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(token2.is_none());

        // Extend lock
        let extended = store
            .extend_distributed_lock(&lock_key, &token, Duration::from_secs(20))
            .await
            .unwrap();
        assert!(extended);

        // Release lock
        store
            .release_distributed_lock(&lock_key, &token)
            .await
            .unwrap();

        // Should be able to acquire again
        let token3 = store
            .acquire_distributed_lock(&lock_key, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(token3.is_some());

        // Cleanup
        store
            .release_distributed_lock(&lock_key, &token3.unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_id_generation() {
        let store = RedisStateStore::new(&get_redis_url()).expect("Failed to connect to Redis");

        let id1 = store.next_session_id().await.unwrap();
        let id2 = store.next_session_id().await.unwrap();
        let id3 = store.next_session_id().await.unwrap();

        assert!(id2 > id1);
        assert!(id3 > id2);

        // Tree IDs are per-session
        let session_id = id1;
        let tree_id1 = store.next_tree_id(session_id).await.unwrap();
        let tree_id2 = store.next_tree_id(session_id).await.unwrap();

        assert!(tree_id2 > tree_id1);
    }

    #[tokio::test]
    #[ignore]
    async fn test_session_ttl() {
        let store = RedisStateStore::new(&get_redis_url()).expect("Failed to connect to Redis");

        let session_id = store.next_session_id().await.unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session = SessionState {
            session_id,
            user_id: "ttl_test_user".to_string(),
            expires_at: now + 2, // Expire in 2 seconds
            ..Default::default()
        };

        store.create_session(&session).await.unwrap();

        // Should exist immediately
        let retrieved = store.get_session(session_id).await.unwrap();
        assert!(retrieved.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Should be gone
        let retrieved = store.get_session(session_id).await.unwrap();
        assert!(retrieved.is_none());
    }
}
