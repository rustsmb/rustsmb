//! Types used by the VFS layer.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Unique file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileHandle {
    /// Unique internal ID (used as key in backend handles HashMap).
    pub id: u64,
    /// SMB persistent file ID.
    pub persistent_id: u128,
    /// SMB volatile file ID.
    pub volatile_id: u128,
    /// Backend-specific stable identifier (e.g., inode on local filesystem).
    /// Used to verify file identity after rename or on durable reconnect.
    #[serde(default)]
    pub backend_internal_id: Option<u64>,
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
            backend_internal_id: None,
        }
    }

    /// Create a handle with specific IDs.
    pub fn with_ids(persistent_id: u128, volatile_id: u128) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, Ordering::Relaxed),
            persistent_id,
            volatile_id,
            backend_internal_id: None,
        }
    }

    /// Create a handle with specific IDs and backend internal ID.
    pub fn with_backend_id(
        persistent_id: u128,
        volatile_id: u128,
        backend_internal_id: Option<u64>,
    ) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self {
            id: COUNTER.fetch_add(1, Ordering::Relaxed),
            persistent_id,
            volatile_id,
            backend_internal_id,
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

/// SMB create disposition values.
pub mod disposition {
    /// If the file exists, supersede it. If not, create it.
    pub const SUPERSEDE: u32 = 0;
    /// If the file exists, open it. If not, fail.
    pub const OPEN: u32 = 1;
    /// If the file exists, fail. If not, create it.
    pub const CREATE: u32 = 2;
    /// If the file exists, open it. If not, create it.
    pub const OPEN_IF: u32 = 3;
    /// If the file exists, open and truncate it. If not, fail.
    pub const OVERWRITE: u32 = 4;
    /// If the file exists, open and truncate it. If not, create it.
    pub const OVERWRITE_IF: u32 = 5;
}

/// SMB create options flags.
pub mod create_options {
    /// The file being opened is a directory.
    pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;
    /// The file being opened must not be a directory.
    pub const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
    /// Delete the file when the last handle is closed.
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;
}

/// SMB access mask flags.
pub mod access_mask {
    /// Read data from the file.
    pub const FILE_READ_DATA: u32 = 0x00000001;
    /// Write data to the file.
    pub const FILE_WRITE_DATA: u32 = 0x00000002;
    /// Append data to the file.
    pub const FILE_APPEND_DATA: u32 = 0x00000004;
    /// Read extended attributes.
    pub const FILE_READ_EA: u32 = 0x00000008;
    /// Write extended attributes.
    pub const FILE_WRITE_EA: u32 = 0x00000010;
    /// Execute the file.
    pub const FILE_EXECUTE: u32 = 0x00000020;
    /// Delete child entries (for directories).
    pub const FILE_DELETE_CHILD: u32 = 0x00000040;
    /// Read file attributes.
    pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
    /// Write file attributes.
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x00000100;
    /// Delete the file.
    pub const DELETE: u32 = 0x00010000;
    /// Generic read access.
    pub const GENERIC_READ: u32 = 0x80000000;
    /// Generic write access.
    pub const GENERIC_WRITE: u32 = 0x40000000;
    /// Generic execute access.
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    /// Generic all access.
    pub const GENERIC_ALL: u32 = 0x10000000;
}

/// SMB share access flags.
pub mod share_access {
    /// Allow other opens for read.
    pub const FILE_SHARE_READ: u32 = 0x00000001;
    /// Allow other opens for write.
    pub const FILE_SHARE_WRITE: u32 = 0x00000002;
    /// Allow other opens for delete.
    pub const FILE_SHARE_DELETE: u32 = 0x00000004;
}

/// Parameters for opening/creating a file (SMB-native).
///
/// This struct contains SMB-level parameters that backends translate
/// to their internal representation.
#[derive(Debug, Clone, Default)]
pub struct CreateParams {
    /// Desired access mask (FILE_READ_DATA, FILE_WRITE_DATA, etc.)
    pub desired_access: u32,
    /// Share access (FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE)
    pub share_access: u32,
    /// Create disposition (Open, Create, OpenIf, Overwrite, etc.)
    pub create_disposition: u32,
    /// Create options (FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, etc.)
    pub create_options: u32,
    /// File attributes (FILE_ATTRIBUTE_NORMAL, READONLY, HIDDEN, etc.)
    pub file_attributes: u32,
}

impl CreateParams {
    /// Check if this is a directory open.
    #[inline]
    pub fn is_directory(&self) -> bool {
        (self.create_options & create_options::FILE_DIRECTORY_FILE) != 0
    }

    /// Check if read access is requested.
    #[inline]
    pub fn wants_read(&self) -> bool {
        (self.desired_access & access_mask::FILE_READ_DATA) != 0
            || (self.desired_access & access_mask::GENERIC_READ) != 0
            || (self.desired_access & access_mask::GENERIC_ALL) != 0
    }

    /// Check if write access is requested.
    #[inline]
    pub fn wants_write(&self) -> bool {
        (self.desired_access & access_mask::FILE_WRITE_DATA) != 0
            || (self.desired_access & access_mask::GENERIC_WRITE) != 0
            || (self.desired_access & access_mask::GENERIC_ALL) != 0
    }

    /// Convert to internal OpenFlags for backend use.
    pub fn to_open_flags(&self) -> OpenFlags {
        let mut flags = 0u32;

        // Set read/write based on desired access
        if self.wants_read() {
            flags |= OpenFlags::READ;
        }
        if self.wants_write() {
            flags |= OpenFlags::WRITE;
        }

        // Set create/truncate flags based on disposition
        match self.create_disposition {
            disposition::CREATE => {
                // Create new, fail if exists
                flags |= OpenFlags::CREATE | OpenFlags::EXCL;
            }
            disposition::OPEN => {
                // Open existing, fail if not exists
                // No additional flags
            }
            disposition::OPEN_IF => {
                // Open if exists, create if not
                flags |= OpenFlags::CREATE;
            }
            disposition::OVERWRITE => {
                // Open and truncate, fail if not exists
                flags |= OpenFlags::TRUNC;
            }
            disposition::OVERWRITE_IF | disposition::SUPERSEDE => {
                // Open and truncate if exists, create if not
                flags |= OpenFlags::CREATE | OpenFlags::TRUNC;
            }
            _ => {}
        }

        // Directory flag
        if self.is_directory() {
            flags |= OpenFlags::DIRECTORY;
        }

        OpenFlags::new(flags)
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
