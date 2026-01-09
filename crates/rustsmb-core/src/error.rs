//! Error types for RustSMB.

use thiserror::Error;

/// Top-level SMB server error.
#[derive(Debug, Error)]
pub enum SmbError {
    /// Protocol-level error.
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Authentication error.
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    /// Virtual filesystem error.
    #[error("VFS error: {0}")]
    Vfs(#[from] VfsError),

    /// State store error.
    #[error("State error: {0}")]
    State(#[from] StateError),

    /// Session management error.
    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    /// Coordination layer error.
    #[error("Coordination error: {0}")]
    Coord(#[from] CoordError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// SMB protocol-level errors.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Invalid SMB header.
    #[error("Invalid SMB header")]
    InvalidHeader,

    /// Unknown command code.
    #[error("Unknown command: {0:#06x}")]
    UnknownCommand(u16),

    /// Invalid parameter in request.
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Message exceeds maximum size.
    #[error("Message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureInvalid,

    /// Decryption failed.
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Unsupported SMB dialect.
    #[error("Unsupported dialect")]
    UnsupportedDialect,

    /// Error in compound request.
    #[error("Compound request error: {0}")]
    CompoundError(String),

    /// Malformed request body.
    #[error("Malformed request: {0}")]
    MalformedRequest(String),
}

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid credentials provided.
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Account is disabled.
    #[error("Account disabled")]
    AccountDisabled,

    /// Account is locked out.
    #[error("Account locked out")]
    AccountLockedOut,

    /// Password has expired.
    #[error("Password expired")]
    PasswordExpired,

    /// Authentication mechanism not supported.
    #[error("Unsupported auth mechanism: {0}")]
    UnsupportedMechanism(String),

    /// Authentication failed with reason.
    #[error("Authentication failed: {0}")]
    Failed(String),

    /// Kerberos-specific error.
    #[error("Kerberos error: {0}")]
    Kerberos(String),

    /// NTLM-specific error.
    #[error("NTLM error: {0}")]
    Ntlm(String),

    /// SPNEGO negotiation error.
    #[error("SPNEGO error: {0}")]
    Spnego(String),
}

/// Virtual filesystem errors.
#[derive(Debug, Error)]
pub enum VfsError {
    /// File or directory not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Access denied to resource.
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// File or directory already exists.
    #[error("Already exists: {0}")]
    AlreadyExists(String),

    /// Path is not a directory.
    #[error("Not a directory: {0}")]
    NotADirectory(String),

    /// Path is a directory (expected file).
    #[error("Is a directory: {0}")]
    IsADirectory(String),

    /// Directory is not empty.
    #[error("Directory not empty: {0}")]
    DirectoryNotEmpty(String),

    /// Invalid path format.
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Disk is full.
    #[error("Disk full")]
    DiskFull,

    /// File exceeds size limit.
    #[error("File too large")]
    FileTooLarge,

    /// Sharing violation (file in use).
    #[error("Sharing violation: {0}")]
    SharingViolation(String),

    /// Lock conflict.
    #[error("Lock conflict")]
    LockConflict,

    /// Invalid file handle.
    #[error("Invalid handle")]
    InvalidHandle,

    /// Backend-specific error.
    #[error("Backend error: {0}")]
    Backend(String),

    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Operation not supported by backend.
    #[error("Not supported: {0}")]
    NotSupported(String),

    /// Read-only filesystem.
    #[error("Read-only filesystem")]
    ReadOnly,

    /// Cross-device link attempted.
    #[error("Cross-device link")]
    CrossDevice,

    /// Name too long.
    #[error("Name too long: {0}")]
    NameTooLong(String),
}

/// State store errors.
#[derive(Debug, Error)]
pub enum StateError {
    /// Connection to state store failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Operation timed out.
    #[error("Timeout")]
    Timeout,

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Key not found.
    #[error("Key not found: {0}")]
    NotFound(String),

    /// Conflict during update.
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Internal state store error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Coordination layer errors (Raft/distributed coordination).
#[derive(Debug, Error)]
pub enum CoordError {
    /// Not the leader - operation must be forwarded.
    #[error("Not leader, leader is: {0:?}")]
    NotLeader(Option<String>),

    /// No leader currently elected.
    #[error("No leader elected")]
    NoLeader,

    /// Cluster is not healthy (not enough nodes).
    #[error("Cluster unhealthy: {0}")]
    ClusterUnhealthy(String),

    /// Operation timed out waiting for consensus.
    #[error("Consensus timeout")]
    Timeout,

    /// Network error communicating with cluster.
    #[error("Network error: {0}")]
    Network(String),

    /// Conflict detected (e.g., lock conflict, lease conflict).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Server not found in cluster.
    #[error("Server not found: {0}")]
    ServerNotFound(String),

    /// Lease not found.
    #[error("Lease not found")]
    LeaseNotFound,

    /// Internal coordination error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Session management errors.
#[derive(Debug, Error)]
pub enum SessionError {
    /// Invalid session ID.
    #[error("Invalid session ID: {0}")]
    InvalidSessionId(u64),

    /// Invalid tree ID.
    #[error("Invalid tree ID: {0}")]
    InvalidTreeId(u32),

    /// Invalid file handle.
    #[error("Invalid handle ID: {0}")]
    InvalidHandleId(u128),

    /// Session has expired.
    #[error("Session expired")]
    SessionExpired,

    /// Too many concurrent connections.
    #[error("Too many connections")]
    TooManyConnections,

    /// Too many sessions.
    #[error("Too many sessions")]
    TooManySessions,

    /// Session not authenticated.
    #[error("Not authenticated")]
    NotAuthenticated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VfsError::NotFound("/path/to/file".to_string());
        assert_eq!(err.to_string(), "Not found: /path/to/file");
    }

    #[test]
    fn test_error_conversion() {
        let vfs_err = VfsError::NotFound("test".to_string());
        let smb_err: SmbError = vfs_err.into();
        assert!(matches!(smb_err, SmbError::Vfs(_)));
    }
}
