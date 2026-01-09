//! In-memory filesystem backend for RustSMB.
//!
//! This backend provides an in-memory filesystem for testing purposes.

// TODO: Implement in Phase 2
// - In-memory file/directory tree
// - All VFS operations
// - Used for unit and integration testing

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory filesystem backend.
pub struct MemoryBackend {
    root: Arc<RwLock<MemoryNode>>,
}

/// A node in the in-memory filesystem.
#[derive(Debug, Clone)]
enum MemoryNode {
    File {
        content: Vec<u8>,
        mode: u32,
    },
    Directory {
        children: HashMap<String, MemoryNode>,
        mode: u32,
    },
}

impl MemoryBackend {
    /// Create a new empty in-memory filesystem.
    pub fn new() -> Self {
        Self {
            root: Arc::new(RwLock::new(MemoryNode::Directory {
                children: HashMap::new(),
                mode: 0o755,
            })),
        }
    }

    /// Create as Arc for use as DynStorageBackend.
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Implement StorageBackend trait in Phase 2
