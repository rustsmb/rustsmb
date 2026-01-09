//! State types for session persistence.

use rustsmb_core::SmbDialect;
use serde::{Deserialize, Serialize};

/// Session state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session ID.
    pub session_id: u64,
    /// User identifier.
    pub user_id: String,
    /// User domain.
    pub domain: Option<String>,
    /// Session key (encrypted for storage).
    pub session_key: Vec<u8>,
    /// Negotiated dialect.
    pub dialect: SmbDialect,
    /// Whether signing is required.
    pub signing_required: bool,
    /// Whether encryption is required.
    pub encryption_required: bool,
    /// Whether this is a guest session.
    pub is_guest: bool,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Last access timestamp (Unix epoch seconds).
    pub last_access: u64,
    /// Expiration timestamp (Unix epoch seconds).
    pub expires_at: u64,
}

impl Default for SessionState {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            session_id: 0,
            user_id: String::new(),
            domain: None,
            session_key: Vec::new(),
            dialect: SmbDialect::default(),
            signing_required: false,
            encryption_required: false,
            is_guest: false,
            created_at: now,
            last_access: now,
            expires_at: now + 3600, // 1 hour default
        }
    }
}

/// Tree connection state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeState {
    /// Tree connection ID.
    pub tree_id: u32,
    /// Parent session ID.
    pub session_id: u64,
    /// Share name.
    pub share_name: String,
    /// Share path.
    pub share_path: String,
    /// Access flags.
    pub access_flags: u32,
    /// Is DFS share.
    pub is_dfs: bool,
    /// Creation timestamp.
    pub created_at: u64,
}

impl Default for TreeState {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            tree_id: 0,
            session_id: 0,
            share_name: String::new(),
            share_path: String::new(),
            access_flags: 0,
            is_dfs: false,
            created_at: now,
        }
    }
}

/// File handle state for persistence (durable handles).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleState {
    /// Persistent file ID.
    pub persistent_id: u128,
    /// Volatile file ID.
    pub volatile_id: u128,
    /// Parent tree ID.
    pub tree_id: u32,
    /// Parent session ID.
    pub session_id: u64,
    /// File path relative to share.
    pub path: String,
    /// Access mask.
    pub access_mask: u32,
    /// Share access.
    pub share_access: u32,
    /// Create options.
    pub create_options: u32,
    /// Is durable handle.
    pub is_durable: bool,
    /// Is persistent handle.
    pub is_persistent: bool,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last access timestamp.
    pub last_access: u64,
}

impl Default for HandleState {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            persistent_id: 0,
            volatile_id: 0,
            tree_id: 0,
            session_id: 0,
            path: String::new(),
            access_mask: 0,
            share_access: 0,
            create_options: 0,
            is_durable: false,
            is_persistent: false,
            created_at: now,
            last_access: now,
        }
    }
}

/// Byte-range lock state for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockState {
    /// Unique lock ID.
    pub lock_id: u64,
    /// Parent handle persistent ID.
    pub persistent_id: u128,
    /// Lock start offset.
    pub offset: u64,
    /// Lock length.
    pub length: u64,
    /// Is exclusive lock.
    pub exclusive: bool,
    /// Lock flags.
    pub flags: u32,
    /// Creation timestamp.
    pub created_at: u64,
}

impl Default for LockState {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            lock_id: 0,
            persistent_id: 0,
            offset: 0,
            length: 0,
            exclusive: false,
            flags: 0,
            created_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_default() {
        let state = SessionState::default();
        assert_eq!(state.session_id, 0);
        assert!(state.created_at > 0);
        assert!(state.expires_at > state.created_at);
    }

    #[test]
    fn test_session_state_serialize() {
        let state = SessionState {
            session_id: 12345,
            user_id: "testuser".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, 12345);
        assert_eq!(parsed.user_id, "testuser");
    }
}
