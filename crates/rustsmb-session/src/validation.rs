//! Request validation utilities.
//!
//! Provides validation for sessions, trees, and file handles.

use rustsmb_core::{SessionError, StateError};
use rustsmb_state::{DynStateStore, HandleState, SessionState, TreeState};
use std::time::Duration;
use tracing::{debug, warn};

/// Tree connection validator.
///
/// Validates tree connections and provides helper methods for tree operations.
pub struct TreeValidator<'a> {
    state_store: &'a DynStateStore,
}

impl<'a> TreeValidator<'a> {
    /// Create a new tree validator.
    pub fn new(state_store: &'a DynStateStore) -> Self {
        Self { state_store }
    }

    /// Validate a tree connection exists and belongs to the session.
    pub async fn validate(&self, session_id: u64, tree_id: u32) -> Result<TreeState, SessionError> {
        let tree = self
            .state_store
            .get_tree(session_id, tree_id)
            .await
            .map_err(|e| {
                warn!(
                    "Failed to get tree {} for session {}: {}",
                    tree_id, session_id, e
                );
                SessionError::InvalidTreeId(tree_id)
            })?
            .ok_or(SessionError::InvalidTreeId(tree_id))?;

        // Verify session ownership
        if tree.session_id != session_id {
            warn!(
                "Tree {} belongs to session {}, not {}",
                tree_id, tree.session_id, session_id
            );
            return Err(SessionError::InvalidTreeId(tree_id));
        }

        Ok(tree)
    }

    /// Get all trees for a session.
    pub async fn get_session_trees(&self, session_id: u64) -> Result<Vec<TreeState>, StateError> {
        self.state_store.get_trees_by_session(session_id).await
    }

    /// Delete a tree and all associated handles.
    pub async fn delete_tree(&self, session_id: u64, tree_id: u32) -> Result<(), StateError> {
        debug!("Deleting tree {} for session {}", tree_id, session_id);

        // First delete all handles for this tree
        let handles = self.state_store.get_handles_by_session(session_id).await?;
        for handle in handles {
            if handle.tree_id == tree_id {
                self.state_store.delete_handle(handle.persistent_id).await?;
            }
        }

        // Then delete the tree
        self.state_store.delete_tree(session_id, tree_id).await
    }

    /// Check if access is allowed based on tree flags.
    pub fn check_access(tree: &TreeState, required_access: u32) -> bool {
        // If no specific access required, allow
        if required_access == 0 {
            return true;
        }

        // Check tree access flags
        (tree.access_flags & required_access) == required_access
    }
}

/// File handle validator.
///
/// Validates file handles and maps between volatile and persistent IDs.
pub struct HandleValidator<'a> {
    state_store: &'a DynStateStore,
}

/// Handle lookup result containing both IDs.
#[derive(Debug, Clone)]
pub struct HandleLookup {
    /// The handle state from the store.
    pub handle: HandleState,
    /// Validated session ID.
    pub session_id: u64,
    /// Validated tree ID.
    pub tree_id: u32,
}

impl<'a> HandleValidator<'a> {
    /// Create a new handle validator.
    pub fn new(state_store: &'a DynStateStore) -> Self {
        Self { state_store }
    }

    /// Validate a handle by persistent ID.
    pub async fn validate(
        &self,
        persistent_id: u128,
        session_id: u64,
        tree_id: u32,
    ) -> Result<HandleLookup, SessionError> {
        let handle = self
            .state_store
            .get_handle(persistent_id)
            .await
            .map_err(|e| {
                warn!("Failed to get handle {}: {}", persistent_id, e);
                SessionError::InvalidHandleId(persistent_id)
            })?
            .ok_or(SessionError::InvalidHandleId(persistent_id))?;

        // Verify session and tree ownership
        if handle.session_id != session_id {
            warn!(
                "Handle {} belongs to session {}, not {}",
                persistent_id, handle.session_id, session_id
            );
            return Err(SessionError::InvalidHandleId(persistent_id));
        }

        if handle.tree_id != tree_id {
            warn!(
                "Handle {} belongs to tree {}, not {}",
                persistent_id, handle.tree_id, tree_id
            );
            return Err(SessionError::InvalidHandleId(persistent_id));
        }

        Ok(HandleLookup {
            handle,
            session_id,
            tree_id,
        })
    }

    /// Validate a handle by both persistent and volatile IDs.
    ///
    /// This is stricter validation that checks the volatile ID matches.
    pub async fn validate_full(
        &self,
        persistent_id: u128,
        volatile_id: u128,
        session_id: u64,
        tree_id: u32,
    ) -> Result<HandleLookup, SessionError> {
        let lookup = self.validate(persistent_id, session_id, tree_id).await?;

        // Check volatile ID matches
        if lookup.handle.volatile_id != volatile_id {
            warn!(
                "Handle {} volatile ID mismatch: expected {}, got {}",
                persistent_id, lookup.handle.volatile_id, volatile_id
            );
            return Err(SessionError::InvalidHandleId(persistent_id));
        }

        Ok(lookup)
    }

    /// Get all handles for a session.
    pub async fn get_session_handles(
        &self,
        session_id: u64,
    ) -> Result<Vec<HandleState>, StateError> {
        self.state_store.get_handles_by_session(session_id).await
    }

    /// Get all handles for a tree.
    pub async fn get_tree_handles(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> Result<Vec<HandleState>, StateError> {
        let handles = self.state_store.get_handles_by_session(session_id).await?;
        Ok(handles
            .into_iter()
            .filter(|h| h.tree_id == tree_id)
            .collect())
    }

    /// Check if access is allowed based on handle's access mask.
    pub fn check_access(handle: &HandleState, required_access: u32) -> bool {
        if required_access == 0 {
            return true;
        }
        (handle.access_mask & required_access) == required_access
    }

    /// Check if sharing mode allows the requested access.
    pub fn check_sharing(handle: &HandleState, requested_share: u32) -> bool {
        // Check if the handle's share access is compatible
        // This is simplified; real implementation needs conflict detection
        (handle.share_access & requested_share) == requested_share
    }

    /// Update handle's last access time.
    pub async fn touch_handle(&self, persistent_id: u128) -> Result<(), StateError> {
        if let Some(mut handle) = self.state_store.get_handle(persistent_id).await? {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            handle.last_access = now;
            // Note: StateStore doesn't have update_handle, so we re-create
            // In a real implementation, you'd want an update method
            self.state_store.delete_handle(persistent_id).await?;
            self.state_store.create_handle(&handle).await?;
        }
        Ok(())
    }
}

/// Session validator.
///
/// Validates sessions and handles expiration.
pub struct SessionValidator<'a> {
    state_store: &'a DynStateStore,
    session_timeout: Duration,
}

impl<'a> SessionValidator<'a> {
    /// Create a new session validator.
    pub fn new(state_store: &'a DynStateStore, session_timeout: Duration) -> Self {
        Self {
            state_store,
            session_timeout,
        }
    }

    /// Validate a session exists and is not expired.
    pub async fn validate(&self, session_id: u64) -> Result<SessionState, SessionError> {
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
            debug!(
                "Session {} expired at {}, now is {}",
                session_id, session.expires_at, now
            );
            // Clean up expired session
            let _ = self.state_store.delete_session(session_id).await;
            return Err(SessionError::SessionExpired);
        }

        Ok(session)
    }

    /// Validate and refresh a session's TTL.
    pub async fn validate_and_refresh(
        &self,
        session_id: u64,
    ) -> Result<SessionState, SessionError> {
        let session = self.validate(session_id).await?;

        // Refresh TTL
        if let Err(e) = self
            .state_store
            .refresh_session(session_id, self.session_timeout)
            .await
        {
            warn!("Failed to refresh session {}: {}", session_id, e);
        }

        Ok(session)
    }

    /// Check if signing is required for this session.
    pub fn requires_signing(session: &SessionState) -> bool {
        session.signing_required
    }

    /// Check if encryption is required for this session.
    pub fn requires_encryption(session: &SessionState) -> bool {
        session.encryption_required
    }

    /// Check if this is a guest session.
    pub fn is_guest(session: &SessionState) -> bool {
        session.is_guest
    }
}

/// Combined request context validation.
///
/// Validates the full context (session, tree, handle) for a request.
#[derive(Debug)]
pub struct RequestContext {
    /// Validated session.
    pub session: SessionState,
    /// Validated tree (if applicable).
    pub tree: Option<TreeState>,
    /// Validated handle (if applicable).
    pub handle: Option<HandleState>,
}

impl RequestContext {
    /// Get the session key (for signing/encryption).
    pub fn session_key(&self) -> &[u8] {
        &self.session.session_key
    }

    /// Check if request requires signing.
    pub fn requires_signing(&self) -> bool {
        self.session.signing_required
    }

    /// Check if request requires encryption.
    pub fn requires_encryption(&self) -> bool {
        self.session.encryption_required
    }

    /// Get the share path (if tree is present).
    pub fn share_path(&self) -> Option<&str> {
        self.tree.as_ref().map(|t| t.share_path.as_str())
    }

    /// Get the file path (if handle is present).
    pub fn file_path(&self) -> Option<&str> {
        self.handle.as_ref().map(|h| h.path.as_str())
    }
}

/// Request context builder for validation.
pub struct RequestContextBuilder<'a> {
    state_store: &'a DynStateStore,
    session_timeout: Duration,
}

impl<'a> RequestContextBuilder<'a> {
    /// Create a new context builder.
    pub fn new(state_store: &'a DynStateStore, session_timeout: Duration) -> Self {
        Self {
            state_store,
            session_timeout,
        }
    }

    /// Build context with session validation only.
    pub async fn session_only(&self, session_id: u64) -> Result<RequestContext, SessionError> {
        let validator = SessionValidator::new(self.state_store, self.session_timeout);
        let session = validator.validate(session_id).await?;

        Ok(RequestContext {
            session,
            tree: None,
            handle: None,
        })
    }

    /// Build context with session and tree validation.
    pub async fn with_tree(
        &self,
        session_id: u64,
        tree_id: u32,
    ) -> Result<RequestContext, SessionError> {
        let session_validator = SessionValidator::new(self.state_store, self.session_timeout);
        let session = session_validator.validate(session_id).await?;

        let tree_validator = TreeValidator::new(self.state_store);
        let tree = tree_validator.validate(session_id, tree_id).await?;

        Ok(RequestContext {
            session,
            tree: Some(tree),
            handle: None,
        })
    }

    /// Build context with session, tree, and handle validation.
    pub async fn with_handle(
        &self,
        session_id: u64,
        tree_id: u32,
        persistent_id: u128,
        volatile_id: u128,
    ) -> Result<RequestContext, SessionError> {
        let session_validator = SessionValidator::new(self.state_store, self.session_timeout);
        let session = session_validator.validate(session_id).await?;

        let tree_validator = TreeValidator::new(self.state_store);
        let tree = tree_validator.validate(session_id, tree_id).await?;

        let handle_validator = HandleValidator::new(self.state_store);
        let lookup = handle_validator
            .validate_full(persistent_id, volatile_id, session_id, tree_id)
            .await?;

        Ok(RequestContext {
            session,
            tree: Some(tree),
            handle: Some(lookup.handle),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_state_memory::MemoryStateStore;
    use std::sync::Arc;

    fn create_test_session(session_id: u64) -> SessionState {
        SessionState {
            session_id,
            user_id: "testuser".to_string(),
            ..Default::default()
        }
    }

    fn create_test_tree(session_id: u64, tree_id: u32) -> TreeState {
        TreeState {
            session_id,
            tree_id,
            share_name: "test".to_string(),
            share_path: "/test".to_string(),
            access_flags: 0xFFFF,
            ..Default::default()
        }
    }

    fn create_test_handle(
        session_id: u64,
        tree_id: u32,
        persistent_id: u128,
        volatile_id: u128,
    ) -> HandleState {
        HandleState {
            session_id,
            tree_id,
            persistent_id,
            volatile_id,
            path: "/test/file.txt".to_string(),
            access_mask: 0xFFFF,
            share_access: 0x7,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_session_validation() {
        let store: DynStateStore = Arc::new(MemoryStateStore::new());
        let validator = SessionValidator::new(&store, Duration::from_secs(3600));

        // Session doesn't exist
        assert!(validator.validate(999).await.is_err());

        // Create a session
        let session = create_test_session(1);
        store.create_session(&session).await.unwrap();

        // Should validate successfully
        let validated = validator.validate(1).await.unwrap();
        assert_eq!(validated.session_id, 1);
    }

    #[tokio::test]
    async fn test_tree_validation() {
        let store: DynStateStore = Arc::new(MemoryStateStore::new());
        let validator = TreeValidator::new(&store);

        // Create session first
        let session = create_test_session(1);
        store.create_session(&session).await.unwrap();

        // Tree doesn't exist
        assert!(validator.validate(1, 999).await.is_err());

        // Create a tree
        let tree = create_test_tree(1, 10);
        store.create_tree(&tree).await.unwrap();

        // Should validate successfully
        let validated = validator.validate(1, 10).await.unwrap();
        assert_eq!(validated.tree_id, 10);
        assert_eq!(validated.session_id, 1);

        // Wrong session should fail
        assert!(validator.validate(2, 10).await.is_err());
    }

    #[tokio::test]
    async fn test_handle_validation() {
        let store: DynStateStore = Arc::new(MemoryStateStore::new());
        let validator = HandleValidator::new(&store);

        // Create session and tree first
        let session = create_test_session(1);
        store.create_session(&session).await.unwrap();
        let tree = create_test_tree(1, 10);
        store.create_tree(&tree).await.unwrap();

        // Handle doesn't exist
        assert!(validator.validate(999, 1, 10).await.is_err());

        // Create a handle
        let handle = create_test_handle(1, 10, 100, 200);
        store.create_handle(&handle).await.unwrap();

        // Should validate successfully
        let lookup = validator.validate(100, 1, 10).await.unwrap();
        assert_eq!(lookup.handle.persistent_id, 100);

        // Full validation with volatile ID
        let lookup = validator.validate_full(100, 200, 1, 10).await.unwrap();
        assert_eq!(lookup.handle.volatile_id, 200);

        // Wrong volatile ID should fail
        assert!(validator.validate_full(100, 999, 1, 10).await.is_err());

        // Wrong session should fail
        assert!(validator.validate(100, 2, 10).await.is_err());

        // Wrong tree should fail
        assert!(validator.validate(100, 1, 20).await.is_err());
    }

    #[tokio::test]
    async fn test_request_context_builder() {
        let store: DynStateStore = Arc::new(MemoryStateStore::new());

        // Create session, tree, and handle
        let session = create_test_session(1);
        store.create_session(&session).await.unwrap();
        let tree = create_test_tree(1, 10);
        store.create_tree(&tree).await.unwrap();
        let handle = create_test_handle(1, 10, 100, 200);
        store.create_handle(&handle).await.unwrap();

        let builder = RequestContextBuilder::new(&store, Duration::from_secs(3600));

        // Session only
        let ctx = builder.session_only(1).await.unwrap();
        assert_eq!(ctx.session.session_id, 1);
        assert!(ctx.tree.is_none());
        assert!(ctx.handle.is_none());

        // With tree
        let ctx = builder.with_tree(1, 10).await.unwrap();
        assert!(ctx.tree.is_some());
        assert_eq!(ctx.share_path(), Some("/test"));

        // With handle
        let ctx = builder.with_handle(1, 10, 100, 200).await.unwrap();
        assert!(ctx.handle.is_some());
        assert_eq!(ctx.file_path(), Some("/test/file.txt"));
    }

    #[test]
    fn test_access_checks() {
        let handle = HandleState {
            access_mask: 0x0003,  // Read + Write
            share_access: 0x0001, // Share read
            ..Default::default()
        };

        assert!(HandleValidator::check_access(&handle, 0x0001)); // Can read
        assert!(HandleValidator::check_access(&handle, 0x0003)); // Can read+write
        assert!(!HandleValidator::check_access(&handle, 0x0004)); // Can't delete

        assert!(HandleValidator::check_sharing(&handle, 0x0001)); // Share read OK
        assert!(!HandleValidator::check_sharing(&handle, 0x0002)); // Share write not allowed
    }
}
