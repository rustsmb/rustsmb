//! Stateless session manager.

use rustsmb_core::{SessionError, StateError};
use rustsmb_state::{DynStateStore, HandleState, SessionState, TreeState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, warn};

/// Stateless session manager.
///
/// Uses an external StateStore for session persistence, enabling HA failover.
pub struct SessionManager {
    /// State store for session persistence.
    state_store: DynStateStore,
    /// Connection ID counter.
    connection_counter: AtomicU64,
    /// Configuration.
    config: SessionManagerConfig,
}

/// Session manager configuration.
#[derive(Debug, Clone)]
pub struct SessionManagerConfig {
    /// Session timeout.
    pub session_timeout: Duration,
    /// Idle connection timeout.
    pub idle_timeout: Duration,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
    /// Session refresh interval.
    pub refresh_interval: Duration,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(3600), // 1 hour
            idle_timeout: Duration::from_secs(300),     // 5 minutes
            max_sessions: 10000,
            refresh_interval: Duration::from_secs(60), // 1 minute
        }
    }
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(state_store: DynStateStore, config: SessionManagerConfig) -> Self {
        Self {
            state_store,
            connection_counter: AtomicU64::new(1),
            config,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults(state_store: DynStateStore) -> Self {
        Self::new(state_store, SessionManagerConfig::default())
    }

    /// Get the state store.
    pub fn state_store(&self) -> &DynStateStore {
        &self.state_store
    }

    /// Generate a new connection ID.
    pub fn next_connection_id(&self) -> u64 {
        self.connection_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Create a new session.
    pub async fn create_session(&self, session: SessionState) -> Result<SessionState, StateError> {
        debug!("Creating session: {}", session.session_id);
        self.state_store.create_session(&session).await?;
        Ok(session)
    }

    /// Get a session by ID.
    pub async fn get_session(&self, session_id: u64) -> Result<Option<SessionState>, StateError> {
        self.state_store.get_session(session_id).await
    }

    /// Validate and get a session, returning error if not found or expired.
    pub async fn validate_session(&self, session_id: u64) -> Result<SessionState, SessionError> {
        let session = self
            .state_store
            .get_session(session_id)
            .await
            .map_err(|e| {
                warn!("Failed to get session {}: {}", session_id, e);
                SessionError::InvalidSessionId(session_id)
            })?
            .ok_or(SessionError::InvalidSessionId(session_id))?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if session.expires_at < now {
            debug!("Session {} expired", session_id);
            // Clean up expired session
            let _ = self.state_store.delete_session(session_id).await;
            return Err(SessionError::SessionExpired);
        }

        Ok(session)
    }

    /// Refresh a session's TTL.
    pub async fn refresh_session(&self, session_id: u64) -> Result<(), StateError> {
        self.state_store
            .refresh_session(session_id, self.config.session_timeout)
            .await
    }

    /// Delete a session and all associated resources.
    pub async fn delete_session(&self, session_id: u64) -> Result<(), StateError> {
        debug!("Deleting session: {}", session_id);

        // Delete all handles for this session
        let handles = self.state_store.get_handles_by_session(session_id).await?;
        for handle in handles {
            self.state_store.delete_handle(handle.persistent_id).await?;
        }

        // Delete all trees for this session
        let trees = self.state_store.get_trees_by_session(session_id).await?;
        for tree in trees {
            self.state_store
                .delete_tree(session_id, tree.tree_id)
                .await?;
        }

        // Delete the session
        self.state_store.delete_session(session_id).await
    }

    /// Create a tree connection.
    pub async fn create_tree(&self, tree: TreeState) -> Result<TreeState, StateError> {
        debug!(
            "Creating tree: session={}, tree={}",
            tree.session_id, tree.tree_id
        );
        self.state_store.create_tree(&tree).await?;
        Ok(tree)
    }

    /// Get a tree connection.
    pub async fn get_tree(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> Result<Option<TreeState>, StateError> {
        self.state_store.get_tree(session_id, tree_id).await
    }

    /// Delete a tree connection.
    pub async fn delete_tree(&self, session_id: u64, tree_id: u32) -> Result<(), StateError> {
        debug!("Deleting tree: session={}, tree={}", session_id, tree_id);

        // Delete all handles for this tree
        let handles = self.state_store.get_handles_by_session(session_id).await?;
        for handle in handles {
            if handle.tree_id == tree_id {
                self.state_store.delete_handle(handle.persistent_id).await?;
            }
        }

        self.state_store.delete_tree(session_id, tree_id).await
    }

    /// Create a file handle.
    pub async fn create_handle(&self, handle: HandleState) -> Result<HandleState, StateError> {
        debug!("Creating handle: persistent_id={}", handle.persistent_id);
        self.state_store.create_handle(&handle).await?;
        Ok(handle)
    }

    /// Get a file handle.
    pub async fn get_handle(&self, persistent_id: u128) -> Result<Option<HandleState>, StateError> {
        self.state_store.get_handle(persistent_id).await
    }

    /// Update an existing file handle.
    pub async fn update_handle(&self, handle: HandleState) -> Result<(), StateError> {
        debug!("Updating handle: persistent_id={}", handle.persistent_id);
        self.state_store.update_handle(&handle).await
    }

    /// Delete a file handle.
    pub async fn delete_handle(&self, persistent_id: u128) -> Result<(), StateError> {
        debug!("Deleting handle: persistent_id={}", persistent_id);
        self.state_store.delete_handle(persistent_id).await
    }

    /// Generate next session ID.
    pub async fn next_session_id(&self) -> Result<u64, StateError> {
        self.state_store.next_session_id().await
    }

    /// Generate next tree ID for a session.
    pub async fn next_tree_id(&self, session_id: u64) -> Result<u32, StateError> {
        self.state_store.next_tree_id(session_id).await
    }

    /// Generate next handle ID.
    pub async fn next_handle_id(&self) -> Result<u128, StateError> {
        self.state_store.next_handle_id().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_state_memory::MemoryStateStore;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let store = MemoryStateStore::new_arc();
        let manager = SessionManager::with_defaults(store);

        let session_id = manager.next_session_id().await.unwrap();
        let session = SessionState {
            session_id,
            user_id: "testuser".to_string(),
            ..Default::default()
        };

        // Create
        manager.create_session(session).await.unwrap();

        // Get
        let retrieved = manager.get_session(session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "testuser");

        // Delete
        manager.delete_session(session_id).await.unwrap();
        let retrieved = manager.get_session(session_id).await.unwrap();
        assert!(retrieved.is_none());
    }
}
