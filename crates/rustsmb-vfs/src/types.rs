//! Types used by the VFS layer.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Unique file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileHandle {
    /// Unique internal ID.
    pub id: u64,
    /// SMB persistent file ID.
    pub persistent_id: u128,
    /// SMB volatile file ID.
    pub volatile_id: u128,
}

impl FileHandle {
    /// Generate a new unique handle.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            persistent_id: id as u128,
            volatile_id: id as u128,
        }
    }

    /// Create a handle with specific IDs.
    pub fn with_ids(persistent_id: u128, volatile_id: u128) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, Ordering::Relaxed),
            persistent_id,
            volatile_id,
        }
    }
}

impl Default for FileHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// File open flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Open for reading.
    pub const READ: u32 = 0x0001;
    /// Open for writing.
    pub const WRITE: u32 = 0x0002;
    /// Create file if it doesn't exist.
    pub const CREATE: u32 = 0x0040;
    /// Fail if file exists (with CREATE).
    pub const EXCL: u32 = 0x0080;
    /// Truncate file if it exists.
    pub const TRUNC: u32 = 0x0200;
    /// Append mode.
    pub const APPEND: u32 = 0x0400;
    /// Open directory.
    pub const DIRECTORY: u32 = 0x10000;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if read is requested.
    #[inline]
    pub fn is_read(self) -> bool {
        (self.0 & Self::READ) != 0
    }

    /// Check if write is requested.
    #[inline]
    pub fn is_write(self) -> bool {
        (self.0 & Self::WRITE) != 0
    }

    /// Check if create is requested.
    #[inline]
    pub fn is_create(self) -> bool {
        (self.0 & Self::CREATE) != 0
    }

    /// Check if exclusive create is requested.
    #[inline]
    pub fn is_excl(self) -> bool {
        (self.0 & Self::EXCL) != 0
    }

    /// Check if truncate is requested.
    #[inline]
    pub fn is_trunc(self) -> bool {
        (self.0 & Self::TRUNC) != 0
    }

    /// Check if directory open is requested.
    #[inline]
    pub fn is_directory(self) -> bool {
        (self.0 & Self::DIRECTORY) != 0
    }
}

/// File metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// File type.
    pub file_type: FileType,
    /// File size in bytes.
    pub size: u64,
    /// Block count.
    pub blocks: u64,
    /// Block size.
    pub block_size: u32,
    /// File mode (permissions).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Device ID (for special files).
    pub rdev: u64,
    /// Inode number.
    pub ino: u64,
    /// Last access time.
    pub atime: SystemTime,
    /// Last modification time.
    pub mtime: SystemTime,
    /// Last status change time.
    pub ctime: SystemTime,
    /// Creation time (if supported).
    pub crtime: Option<SystemTime>,
}

impl Default for Metadata {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            file_type: FileType::Regular,
            size: 0,
            blocks: 0,
            block_size: 4096,
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            rdev: 0,
            ino: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: Some(now),
        }
    }
}

/// File type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Block device.
    BlockDevice,
    /// Character device.
    CharDevice,
    /// Named pipe (FIFO).
    Fifo,
    /// Socket.
    Socket,
}

/// Directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Entry name.
    pub name: String,
    /// Entry metadata.
    pub metadata: Metadata,
}

/// Byte-range lock.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FileLock {
    /// Lock type.
    pub lock_type: LockType,
    /// Start offset.
    pub start: u64,
    /// Length (0 = until end of file).
    pub length: u64,
    /// Process ID holding the lock.
    pub pid: u32,
}

/// Lock type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockType {
    /// Shared (read) lock.
    Shared,
    /// Exclusive (write) lock.
    Exclusive,
}

/// Backend capabilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendCapabilities {
    /// Supports byte-range locking.
    pub locking: bool,
    /// Supports change notifications.
    pub notify: bool,
    /// Supports sparse files.
    pub sparse: bool,
    /// Supports extended attributes.
    pub xattr: bool,
    /// Supports hard links.
    pub hard_links: bool,
    /// Supports symbolic links.
    pub symlinks: bool,
    /// Maximum file size.
    pub max_file_size: u64,
    /// Maximum path length.
    pub max_path_length: u32,
    /// Supports case-sensitive paths.
    pub case_sensitive: bool,
    /// Supports atomic rename.
    pub atomic_rename: bool,
}

/// Filesystem statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsStats {
    /// Total blocks.
    pub blocks: u64,
    /// Free blocks.
    pub blocks_free: u64,
    /// Available blocks (for unprivileged users).
    pub blocks_available: u64,
    /// Block size.
    pub block_size: u32,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub files_free: u64,
    /// Filesystem ID.
    pub fsid: u64,
    /// Maximum filename length.
    pub namelen: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_handle_unique() {
        let h1 = FileHandle::new();
        let h2 = FileHandle::new();
        assert_ne!(h1.id, h2.id);
    }

    #[test]
    fn test_open_flags() {
        let flags = OpenFlags::new(OpenFlags::READ | OpenFlags::CREATE);
        assert!(flags.is_read());
        assert!(!flags.is_write());
        assert!(flags.is_create());
    }
}
