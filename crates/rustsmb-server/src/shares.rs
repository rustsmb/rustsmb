//! Share management.

use rustsmb_vfs::DynStorageBackend;
use std::collections::HashMap;
use std::sync::RwLock;

/// Share configuration.
#[derive(Debug, Clone)]
pub struct ShareConfig {
    /// Share name.
    pub name: String,
    /// Share path (for display).
    pub path: String,
    /// Read-only share.
    pub read_only: bool,
    /// Allow guest access.
    pub guest_ok: bool,
    /// Valid users (empty = all).
    pub valid_users: Vec<String>,
    /// Browseable.
    pub browseable: bool,
}

impl Default for ShareConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            path: String::new(),
            read_only: false,
            guest_ok: false,
            valid_users: Vec::new(),
            browseable: true,
        }
    }
}

/// A configured share with its backend.
pub struct Share {
    /// Share configuration.
    pub config: ShareConfig,
    /// Storage backend.
    pub backend: DynStorageBackend,
}

/// Share manager.
pub struct ShareManager {
    shares: RwLock<HashMap<String, Share>>,
}

impl ShareManager {
    /// Create a new share manager.
    pub fn new() -> Self {
        Self {
            shares: RwLock::new(HashMap::new()),
        }
    }

    /// Add a share.
    pub fn add_share(&self, name: &str, backend: DynStorageBackend, config: ShareConfig) {
        let mut shares = self.shares.write().unwrap();
        shares.insert(
            name.to_lowercase(),
            Share {
                config: ShareConfig {
                    name: name.to_string(),
                    ..config
                },
                backend,
            },
        );
    }

    /// Get a share by name.
    pub fn get_share(&self, name: &str) -> Option<DynStorageBackend> {
        let shares = self.shares.read().unwrap();
        shares.get(&name.to_lowercase()).map(|s| s.backend.clone())
    }

    /// Get share configuration.
    pub fn get_share_config(&self, name: &str) -> Option<ShareConfig> {
        let shares = self.shares.read().unwrap();
        shares.get(&name.to_lowercase()).map(|s| s.config.clone())
    }

    /// List all share names.
    pub fn list_shares(&self) -> Vec<String> {
        let shares = self.shares.read().unwrap();
        shares.keys().cloned().collect()
    }

    /// Check if user can access share.
    pub fn can_access(&self, share_name: &str, username: &str, is_guest: bool) -> bool {
        let shares = self.shares.read().unwrap();
        if let Some(share) = shares.get(&share_name.to_lowercase()) {
            if is_guest && !share.config.guest_ok {
                return false;
            }
            if share.config.valid_users.is_empty() {
                return true;
            }
            share.config.valid_users.contains(&username.to_string())
        } else {
            false
        }
    }
}

impl Default for ShareManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Mock backend for testing
    struct MockBackend;

    impl rustsmb_vfs::StorageBackend for MockBackend {
        fn open<'a>(
            &'a self,
            _path: &'a str,
            _params: &'a rustsmb_vfs::CreateParams,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<rustsmb_vfs::FileHandle, rustsmb_core::VfsError>>
        {
            Box::pin(async { Ok(rustsmb_vfs::FileHandle::new()) })
        }

        fn read<'a>(
            &'a self,
            _handle: &'a rustsmb_vfs::FileHandle,
            _offset: u64,
            _length: u32,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<Vec<u8>, rustsmb_core::VfsError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn write<'a>(
            &'a self,
            _handle: &'a rustsmb_vfs::FileHandle,
            _offset: u64,
            _data: &'a [u8],
        ) -> rustsmb_vfs::BoxFuture<'a, Result<u32, rustsmb_core::VfsError>> {
            Box::pin(async { Ok(0) })
        }

        fn close(
            &self,
            _handle: rustsmb_vfs::FileHandle,
        ) -> rustsmb_vfs::BoxFuture<'_, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn fsync<'a>(
            &'a self,
            _handle: &'a rustsmb_vfs::FileHandle,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn stat<'a>(
            &'a self,
            _path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<rustsmb_vfs::Metadata, rustsmb_core::VfsError>>
        {
            Box::pin(async { Ok(rustsmb_vfs::Metadata::default()) })
        }

        fn fstat<'a>(
            &'a self,
            _handle: &'a rustsmb_vfs::FileHandle,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<rustsmb_vfs::Metadata, rustsmb_core::VfsError>>
        {
            Box::pin(async { Ok(rustsmb_vfs::Metadata::default()) })
        }

        fn chmod<'a>(
            &'a self,
            _path: &'a str,
            _mode: u32,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn chown<'a>(
            &'a self,
            _path: &'a str,
            _uid: u32,
            _gid: u32,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn truncate<'a>(
            &'a self,
            _path: &'a str,
            _size: u64,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn utimes<'a>(
            &'a self,
            _path: &'a str,
            _atime: std::time::SystemTime,
            _mtime: std::time::SystemTime,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn mkdir<'a>(
            &'a self,
            _path: &'a str,
            _mode: u32,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn rmdir<'a>(
            &'a self,
            _path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn readdir<'a>(
            &'a self,
            _path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<Vec<rustsmb_vfs::DirEntry>, rustsmb_core::VfsError>>
        {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn unlink<'a>(
            &'a self,
            _path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn rename<'a>(
            &'a self,
            _old_path: &'a str,
            _new_path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn link<'a>(
            &'a self,
            _src: &'a str,
            _dst: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn symlink<'a>(
            &'a self,
            _target: &'a str,
            _linkpath: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn readlink<'a>(
            &'a self,
            _path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<String, rustsmb_core::VfsError>> {
            Box::pin(async { Ok(String::new()) })
        }

        fn lock<'a>(
            &'a self,
            _handle: &'a rustsmb_vfs::FileHandle,
            _lock: rustsmb_vfs::FileLock,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn unlock<'a>(
            &'a self,
            _handle: &'a rustsmb_vfs::FileHandle,
            _lock: rustsmb_vfs::FileLock,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn getxattr<'a>(
            &'a self,
            _path: &'a str,
            _name: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<Vec<u8>, rustsmb_core::VfsError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn setxattr<'a>(
            &'a self,
            _path: &'a str,
            _name: &'a str,
            _value: &'a [u8],
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn listxattr<'a>(
            &'a self,
            _path: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<Vec<String>, rustsmb_core::VfsError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn removexattr<'a>(
            &'a self,
            _path: &'a str,
            _name: &'a str,
        ) -> rustsmb_vfs::BoxFuture<'a, Result<(), rustsmb_core::VfsError>> {
            Box::pin(async { Ok(()) })
        }

        fn capabilities(&self) -> rustsmb_vfs::BackendCapabilities {
            rustsmb_vfs::BackendCapabilities::default()
        }

        fn statfs(
            &self,
        ) -> rustsmb_vfs::BoxFuture<'_, Result<rustsmb_vfs::FsStats, rustsmb_core::VfsError>>
        {
            Box::pin(async { Ok(rustsmb_vfs::FsStats::default()) })
        }
    }

    #[test]
    fn test_share_manager() {
        let manager = ShareManager::new();
        let backend: DynStorageBackend = Arc::new(MockBackend);

        manager.add_share(
            "public",
            backend,
            ShareConfig {
                guest_ok: true,
                ..Default::default()
            },
        );

        assert!(manager.get_share("public").is_some());
        assert!(manager.get_share("PUBLIC").is_some()); // case-insensitive
        assert!(manager.get_share("nonexistent").is_none());

        assert!(manager.can_access("public", "guest", true));
    }
}
