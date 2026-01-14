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
    /// Whether this is an anonymous session.
    /// Per MS-SMB2 3.3.5.5 line 14504, anonymous sessions cannot bind.
    #[serde(default)]
    pub is_anonymous: bool,
    /// Creation timestamp (Unix epoch seconds).
    pub created_at: u64,
    /// Last access timestamp (Unix epoch seconds).
    pub last_access: u64,
    /// Expiration timestamp (Unix epoch seconds).
    pub expires_at: u64,

    /// Server currently serving this session.
    /// Used for cleanup when a server fails.
    #[serde(default)]
    pub bound_server_id: Option<String>,
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
            is_anonymous: false,
            created_at: now,
            last_access: now,
            expires_at: now + 3600, // 1 hour default
            bound_server_id: None,
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
///
/// This structure stores all information needed to reconnect a durable
/// or persistent handle after failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleState {
    /// Persistent file ID (survives reconnection).
    pub persistent_id: u128,
    /// Volatile file ID (per-connection).
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

    /// Create GUID for reconnection validation (hex-encoded).
    /// Used by DH2Q/DH2C to verify client identity on reconnect.
    #[serde(default)]
    pub create_guid: Option<String>,

    /// Current file pointer offset.
    /// Updated on READ/WRITE operations with seek.
    #[serde(default)]
    pub file_offset: u64,

    /// Share name (for reopening file on reconnect).
    #[serde(default)]
    pub share_name: String,

    /// Create disposition used when opening.
    #[serde(default)]
    pub create_disposition: u32,

    /// File attributes at open time.
    #[serde(default)]
    pub file_attributes: u32,

    /// App instance ID for cluster failover (hex-encoded).
    #[serde(default)]
    pub app_instance_id: Option<String>,

    /// Durable timeout in milliseconds.
    /// How long to keep handle after disconnect before expiring.
    #[serde(default)]
    pub durable_timeout: u32,

    /// Reconnect deadline (Unix epoch seconds).
    /// After this time, the handle expires and cannot be reconnected.
    #[serde(default)]
    pub reconnect_deadline: Option<u64>,

    /// Lease key for this handle (hex-encoded).
    /// Links the handle to a lease for client caching.
    #[serde(default)]
    pub lease_key: Option<String>,

    /// Oplock level granted to this handle.
    #[serde(default)]
    pub oplock_level: u8,

    /// Server that opened this handle.
    /// Used for cleanup when a server fails.
    #[serde(default)]
    pub bound_server_id: Option<String>,

    /// Delete file when handle is closed.
    /// Set via FileDispositionInformation (SET_INFO).
    #[serde(default)]
    pub delete_on_close: bool,

    /// Handle is for a directory (not a file).
    /// Used to reject READ operations per MS-SMB2 3.3.5.12.
    #[serde(default)]
    pub is_directory: bool,
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
            create_guid: None,
            file_offset: 0,
            share_name: String::new(),
            create_disposition: 0,
            file_attributes: 0,
            app_instance_id: None,
            durable_timeout: 0,
            reconnect_deadline: None,
            lease_key: None,
            oplock_level: 0,
            bound_server_id: None,
            delete_on_close: false,
            is_directory: false,
        }
    }
}

impl HandleState {
    /// Convert a 16-byte GUID to hex string for storage.
    pub fn guid_to_hex(guid: &[u8; 16]) -> String {
        hex::encode(guid)
    }

    /// Parse a hex string back to 16-byte GUID.
    pub fn hex_to_guid(hex_str: &str) -> Option<[u8; 16]> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&bytes);
        Some(guid)
    }

    /// Set create GUID from bytes.
    pub fn set_create_guid(&mut self, guid: &[u8; 16]) {
        self.create_guid = Some(Self::guid_to_hex(guid));
    }

    /// Get create GUID as bytes.
    pub fn get_create_guid(&self) -> Option<[u8; 16]> {
        self.create_guid.as_ref().and_then(|s| Self::hex_to_guid(s))
    }

    /// Set lease key from bytes.
    pub fn set_lease_key(&mut self, key: &[u8; 16]) {
        self.lease_key = Some(Self::guid_to_hex(key));
    }

    /// Get lease key as bytes.
    pub fn get_lease_key(&self) -> Option<[u8; 16]> {
        self.lease_key.as_ref().and_then(|s| Self::hex_to_guid(s))
    }

    /// Set app instance ID from bytes.
    pub fn set_app_instance_id(&mut self, id: &[u8; 16]) {
        self.app_instance_id = Some(Self::guid_to_hex(id));
    }

    /// Get app instance ID as bytes.
    pub fn get_app_instance_id(&self) -> Option<[u8; 16]> {
        self.app_instance_id
            .as_ref()
            .and_then(|s| Self::hex_to_guid(s))
    }

    /// Check if this handle can be reconnected.
    pub fn can_reconnect(&self) -> bool {
        if !self.is_durable && !self.is_persistent {
            return false;
        }

        // Check if reconnect deadline has passed
        if let Some(deadline) = self.reconnect_deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > deadline {
                return false;
            }
        }

        true
    }

    /// Set reconnect deadline based on timeout.
    pub fn set_durable_timeout(&mut self, timeout_ms: u32) {
        self.durable_timeout = timeout_ms;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Convert ms to seconds for deadline
        self.reconnect_deadline = Some(now + (timeout_ms as u64 / 1000));
    }

    /// Check if this handle should be preserved for reconnect per MS-SMB2 3.3.7.1.
    ///
    /// A handle is preserved if any of these conditions is true:
    /// - Open.IsPersistent is TRUE
    /// - Open.IsDurable is TRUE (durability was already validated at grant time
    ///   to require Batch oplock or lease with HANDLE_CACHING)
    pub fn should_preserve_for_reconnect(&self) -> bool {
        self.is_persistent || self.is_durable
    }

    /// Prepare handle for preservation by clearing connection state.
    /// Per MS-SMB2 3.3.7.1, set session/tree to NULL (0).
    pub fn prepare_for_reconnect(&mut self, default_timeout_ms: u32) {
        // Set connection state to "disconnected"
        self.session_id = 0;
        self.tree_id = 0;

        // Set reconnect deadline if not already set
        if self.reconnect_deadline.is_none() {
            let timeout = if self.durable_timeout > 0 {
                self.durable_timeout
            } else {
                default_timeout_ms
            };
            self.set_durable_timeout(timeout);
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

    // MS-SMB2 3.3.7.1: Durable Handle Preservation Tests

    /// Per MS-SMB2 3.3.7.1, handles with is_durable=true should be preserved for reconnect
    #[test]
    fn test_should_preserve_for_reconnect_durable_handle() {
        let handle = HandleState {
            is_durable: true,
            is_persistent: false,
            ..Default::default()
        };
        assert!(handle.should_preserve_for_reconnect());
    }

    /// Per MS-SMB2 3.3.7.1, handles with is_persistent=true should be preserved for reconnect
    #[test]
    fn test_should_preserve_for_reconnect_persistent_handle() {
        let handle = HandleState {
            is_durable: false,
            is_persistent: true,
            ..Default::default()
        };
        assert!(handle.should_preserve_for_reconnect());
    }

    /// Non-durable, non-persistent handles should NOT be preserved
    #[test]
    fn test_should_not_preserve_regular_handle() {
        let handle = HandleState {
            is_durable: false,
            is_persistent: false,
            ..Default::default()
        };
        assert!(!handle.should_preserve_for_reconnect());
    }

    /// Per MS-SMB2 3.3.7.1, prepare_for_reconnect should clear session_id and tree_id
    #[test]
    fn test_prepare_for_reconnect_clears_session_and_tree() {
        let mut handle = HandleState {
            session_id: 12345,
            tree_id: 1,
            is_durable: true,
            ..Default::default()
        };
        handle.prepare_for_reconnect(60_000);

        assert_eq!(handle.session_id, 0);
        assert_eq!(handle.tree_id, 0);
    }

    /// Per MS-SMB2 3.3.7.1, prepare_for_reconnect should set reconnect deadline
    #[test]
    fn test_prepare_for_reconnect_sets_deadline() {
        let mut handle = HandleState {
            is_durable: true,
            reconnect_deadline: None,
            ..Default::default()
        };
        handle.prepare_for_reconnect(60_000); // 60 second timeout

        assert!(handle.reconnect_deadline.is_some());
        assert_eq!(handle.durable_timeout, 60_000);
    }

    /// Per MS-SMB2 3.3.7.1, if handle already has timeout, use that
    #[test]
    fn test_prepare_for_reconnect_preserves_existing_timeout() {
        let mut handle = HandleState {
            is_durable: true,
            durable_timeout: 120_000, // 2 minute timeout
            reconnect_deadline: None,
            ..Default::default()
        };
        handle.prepare_for_reconnect(60_000); // Default 60s, but should use 120s

        assert_eq!(handle.durable_timeout, 120_000);
        assert!(handle.reconnect_deadline.is_some());
    }

    /// Per MS-SMB2 3.3.5.9.7, can_reconnect should return false if deadline passed
    #[test]
    fn test_can_reconnect_fails_after_deadline() {
        let handle = HandleState {
            is_durable: true,
            reconnect_deadline: Some(1), // Unix epoch + 1 second (long past)
            ..Default::default()
        };
        assert!(!handle.can_reconnect());
    }

    /// Per MS-SMB2 3.3.5.9.7, can_reconnect should return true if deadline not passed
    #[test]
    fn test_can_reconnect_succeeds_before_deadline() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now

        let handle = HandleState {
            is_durable: true,
            reconnect_deadline: Some(future),
            ..Default::default()
        };
        assert!(handle.can_reconnect());
    }

    /// Non-durable handles cannot be reconnected regardless of deadline
    #[test]
    fn test_can_reconnect_fails_for_non_durable() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let handle = HandleState {
            is_durable: false,
            is_persistent: false,
            reconnect_deadline: Some(future),
            ..Default::default()
        };
        assert!(!handle.can_reconnect());
    }
}
