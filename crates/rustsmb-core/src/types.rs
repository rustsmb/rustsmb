//! Common types used across RustSMB crates.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// SMB dialect versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum SmbDialect {
    /// SMB 2.0.2
    Smb202 = 0x0202,
    /// SMB 2.1
    Smb210 = 0x0210,
    /// SMB 3.0
    Smb300 = 0x0300,
    /// SMB 3.0.2
    Smb302 = 0x0302,
    /// SMB 3.1.1
    Smb311 = 0x0311,
}

impl SmbDialect {
    /// Returns the protocol revision as a u16.
    #[inline]
    pub fn revision(self) -> u16 {
        self as u16
    }

    /// Create dialect from revision number.
    pub fn from_revision(rev: u16) -> Option<Self> {
        Some(match rev {
            0x0202 => Self::Smb202,
            0x0210 => Self::Smb210,
            0x0300 => Self::Smb300,
            0x0302 => Self::Smb302,
            0x0311 => Self::Smb311,
            _ => return None,
        })
    }

    /// Returns true if encryption is supported.
    #[inline]
    pub fn supports_encryption(self) -> bool {
        self >= Self::Smb300
    }

    /// Returns true if directory leasing is supported.
    #[inline]
    pub fn supports_directory_leasing(self) -> bool {
        self >= Self::Smb300
    }

    /// Returns true if multi-channel is supported.
    #[inline]
    pub fn supports_multi_channel(self) -> bool {
        self >= Self::Smb300
    }

    /// Returns true if pre-auth integrity is required.
    #[inline]
    pub fn requires_preauth_integrity(self) -> bool {
        self >= Self::Smb311
    }
}

impl Default for SmbDialect {
    fn default() -> Self {
        Self::Smb311
    }
}

/// File attributes as used in SMB2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    pub const READONLY: u32 = 0x00000001;
    pub const HIDDEN: u32 = 0x00000002;
    pub const SYSTEM: u32 = 0x00000004;
    pub const DIRECTORY: u32 = 0x00000010;
    pub const ARCHIVE: u32 = 0x00000020;
    pub const NORMAL: u32 = 0x00000080;
    pub const TEMPORARY: u32 = 0x00000100;
    pub const SPARSE_FILE: u32 = 0x00000200;
    pub const REPARSE_POINT: u32 = 0x00000400;
    pub const COMPRESSED: u32 = 0x00000800;
    pub const OFFLINE: u32 = 0x00001000;
    pub const NOT_CONTENT_INDEXED: u32 = 0x00002000;
    pub const ENCRYPTED: u32 = 0x00004000;

    /// Create new FileAttributes.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if readonly flag is set.
    #[inline]
    pub fn is_readonly(self) -> bool {
        (self.0 & Self::READONLY) != 0
    }

    /// Check if hidden flag is set.
    #[inline]
    pub fn is_hidden(self) -> bool {
        (self.0 & Self::HIDDEN) != 0
    }

    /// Check if directory flag is set.
    #[inline]
    pub fn is_directory(self) -> bool {
        (self.0 & Self::DIRECTORY) != 0
    }

    /// Check if archive flag is set.
    #[inline]
    pub fn is_archive(self) -> bool {
        (self.0 & Self::ARCHIVE) != 0
    }
}

/// Access mask for file operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccessMask(pub u32);

impl AccessMask {
    // File-specific access rights
    pub const FILE_READ_DATA: u32 = 0x00000001;
    pub const FILE_WRITE_DATA: u32 = 0x00000002;
    pub const FILE_APPEND_DATA: u32 = 0x00000004;
    pub const FILE_READ_EA: u32 = 0x00000008;
    pub const FILE_WRITE_EA: u32 = 0x00000010;
    pub const FILE_EXECUTE: u32 = 0x00000020;
    pub const FILE_DELETE_CHILD: u32 = 0x00000040;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x00000100;

    // Standard access rights
    pub const DELETE: u32 = 0x00010000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const WRITE_DAC: u32 = 0x00040000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const SYNCHRONIZE: u32 = 0x00100000;

    // Generic access rights
    pub const GENERIC_ALL: u32 = 0x10000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_READ: u32 = 0x80000000;

    /// Create new AccessMask.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if read data is allowed.
    #[inline]
    pub fn can_read(self) -> bool {
        (self.0 & (Self::FILE_READ_DATA | Self::GENERIC_READ | Self::GENERIC_ALL)) != 0
    }

    /// Check if write data is allowed.
    #[inline]
    pub fn can_write(self) -> bool {
        (self.0 & (Self::FILE_WRITE_DATA | Self::GENERIC_WRITE | Self::GENERIC_ALL)) != 0
    }

    /// Check if delete is allowed.
    #[inline]
    pub fn can_delete(self) -> bool {
        (self.0 & (Self::DELETE | Self::GENERIC_ALL)) != 0
    }
}

/// Share access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ShareAccess(pub u32);

impl ShareAccess {
    pub const READ: u32 = 0x00000001;
    pub const WRITE: u32 = 0x00000002;
    pub const DELETE: u32 = 0x00000004;

    /// Create new ShareAccess.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if sharing for read is allowed.
    #[inline]
    pub fn share_read(self) -> bool {
        (self.0 & Self::READ) != 0
    }

    /// Check if sharing for write is allowed.
    #[inline]
    pub fn share_write(self) -> bool {
        (self.0 & Self::WRITE) != 0
    }

    /// Check if sharing for delete is allowed.
    #[inline]
    pub fn share_delete(self) -> bool {
        (self.0 & Self::DELETE) != 0
    }
}

/// Create disposition values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum CreateDisposition {
    /// If the file exists, supersede it. If not, create it.
    Supersede = 0,
    /// If the file exists, open it. If not, fail.
    Open = 1,
    /// If the file exists, fail. If not, create it.
    Create = 2,
    /// If the file exists, open it. If not, create it.
    OpenIf = 3,
    /// If the file exists, open and truncate it. If not, fail.
    Overwrite = 4,
    /// If the file exists, open and truncate it. If not, create it.
    OverwriteIf = 5,
}

impl Default for CreateDisposition {
    fn default() -> Self {
        Self::OpenIf
    }
}

/// Result action for create operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum CreateAction {
    /// File was superseded.
    Superseded = 0,
    /// Existing file was opened.
    Opened = 1,
    /// New file was created.
    Created = 2,
    /// Existing file was overwritten.
    Overwritten = 3,
}

/// File metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Creation time.
    pub creation_time: SystemTime,
    /// Last access time.
    pub last_access_time: SystemTime,
    /// Last write time.
    pub last_write_time: SystemTime,
    /// Change time.
    pub change_time: SystemTime,
    /// File size in bytes.
    pub size: u64,
    /// Allocation size in bytes.
    pub allocation_size: u64,
    /// File attributes.
    pub attributes: FileAttributes,
}

impl Default for FileMetadata {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
            size: 0,
            allocation_size: 0,
            attributes: FileAttributes::default(),
        }
    }
}

/// Directory entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// File name.
    pub name: String,
    /// File metadata.
    pub metadata: FileMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialect_ordering() {
        assert!(SmbDialect::Smb311 > SmbDialect::Smb302);
        assert!(SmbDialect::Smb302 > SmbDialect::Smb300);
        assert!(SmbDialect::Smb300 > SmbDialect::Smb210);
        assert!(SmbDialect::Smb210 > SmbDialect::Smb202);
    }

    #[test]
    fn test_dialect_features() {
        assert!(!SmbDialect::Smb210.supports_encryption());
        assert!(SmbDialect::Smb300.supports_encryption());
        assert!(SmbDialect::Smb311.requires_preauth_integrity());
    }

    #[test]
    fn test_file_attributes() {
        let attrs = FileAttributes::new(FileAttributes::DIRECTORY | FileAttributes::HIDDEN);
        assert!(attrs.is_directory());
        assert!(attrs.is_hidden());
        assert!(!attrs.is_readonly());
    }

    #[test]
    fn test_access_mask() {
        let mask = AccessMask::new(AccessMask::FILE_READ_DATA | AccessMask::FILE_WRITE_DATA);
        assert!(mask.can_read());
        assert!(mask.can_write());
        assert!(!mask.can_delete());
    }
}
