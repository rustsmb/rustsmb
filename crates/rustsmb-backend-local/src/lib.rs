//! Local filesystem backend for RustSMB.
//!
//! This backend provides access to the local filesystem via POSIX operations.

// TODO: Implement in Phase 7
// - POSIX file operations with tokio::fs
// - Path resolution and security (prevent escape from root)
// - Attribute mapping (POSIX to SMB)
// - File locking with fcntl
// - Extended attributes support

use std::path::PathBuf;

/// Local filesystem storage backend.
pub struct LocalBackend {
    /// Root directory for this share.
    root: PathBuf,
}

impl LocalBackend {
    /// Create a new local filesystem backend.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory path for the share
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Get the root path.
    pub fn root(&self) -> &PathBuf {
        &self.root
    }
}

// TODO: Implement StorageBackend trait in Phase 7
