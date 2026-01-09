//! SMB2 CHANGE_NOTIFY command.
//!
//! Used to request change notifications on a directory.
//! See MS-SMB2 Section 2.2.35 and 2.2.36.

use binrw::{BinRead, BinWrite};

/// SMB2 CHANGE_NOTIFY request structure size.
pub const CHANGE_NOTIFY_REQUEST_SIZE: u16 = 32;

/// SMB2 CHANGE_NOTIFY response structure size.
pub const CHANGE_NOTIFY_RESPONSE_SIZE: u16 = 9;

/// SMB2 CHANGE_NOTIFY Request.
///
/// See MS-SMB2 Section 2.2.35.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct ChangeNotifyRequest {
    /// Structure size (must be 32).
    pub structure_size: u16,

    /// Flags.
    pub flags: ChangeNotifyFlags,

    /// Output buffer length.
    pub output_buffer_length: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Completion filter.
    pub completion_filter: CompletionFilter,

    /// Reserved (must be 0).
    pub reserved: u32,
}

impl Default for ChangeNotifyRequest {
    fn default() -> Self {
        Self {
            structure_size: CHANGE_NOTIFY_REQUEST_SIZE,
            flags: ChangeNotifyFlags(0),
            output_buffer_length: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            completion_filter: CompletionFilter(0),
            reserved: 0,
        }
    }
}

/// SMB2 CHANGE_NOTIFY Response.
///
/// See MS-SMB2 Section 2.2.36.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct ChangeNotifyResponse {
    /// Structure size (must be 9).
    pub structure_size: u16,

    /// Output buffer offset from beginning of header.
    pub output_buffer_offset: u16,

    /// Output buffer length.
    pub output_buffer_length: u32,
    // FILE_NOTIFY_INFORMATION structures follow
}

impl Default for ChangeNotifyResponse {
    fn default() -> Self {
        Self {
            structure_size: CHANGE_NOTIFY_RESPONSE_SIZE,
            output_buffer_offset: 0,
            output_buffer_length: 0,
        }
    }
}

/// Change notify flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct ChangeNotifyFlags(pub u16);

impl ChangeNotifyFlags {
    /// Watch subtree.
    pub const WATCH_TREE: u16 = 0x0001;

    /// Create new flags.
    #[inline]
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Check if watch tree.
    #[inline]
    pub fn watch_tree(self) -> bool {
        (self.0 & Self::WATCH_TREE) != 0
    }
}

/// Completion filter for change notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct CompletionFilter(pub u32);

impl CompletionFilter {
    /// File name changed.
    pub const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x00000001;
    /// Directory name changed.
    pub const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x00000002;
    /// Attributes changed.
    pub const FILE_NOTIFY_CHANGE_ATTRIBUTES: u32 = 0x00000004;
    /// Size changed.
    pub const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x00000008;
    /// Last write time changed.
    pub const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x00000010;
    /// Last access time changed.
    pub const FILE_NOTIFY_CHANGE_LAST_ACCESS: u32 = 0x00000020;
    /// Creation time changed.
    pub const FILE_NOTIFY_CHANGE_CREATION: u32 = 0x00000040;
    /// EA changed.
    pub const FILE_NOTIFY_CHANGE_EA: u32 = 0x00000080;
    /// Security changed.
    pub const FILE_NOTIFY_CHANGE_SECURITY: u32 = 0x00000100;
    /// Stream name changed.
    pub const FILE_NOTIFY_CHANGE_STREAM_NAME: u32 = 0x00000200;
    /// Stream size changed.
    pub const FILE_NOTIFY_CHANGE_STREAM_SIZE: u32 = 0x00000400;
    /// Stream written.
    pub const FILE_NOTIFY_CHANGE_STREAM_WRITE: u32 = 0x00000800;

    /// All changes.
    pub const ALL: u32 = 0x00000FFF;

    /// Create new filter.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if file name change.
    #[inline]
    pub fn notify_file_name(self) -> bool {
        (self.0 & Self::FILE_NOTIFY_CHANGE_FILE_NAME) != 0
    }

    /// Check if directory name change.
    #[inline]
    pub fn notify_dir_name(self) -> bool {
        (self.0 & Self::FILE_NOTIFY_CHANGE_DIR_NAME) != 0
    }

    /// Check if attributes change.
    #[inline]
    pub fn notify_attributes(self) -> bool {
        (self.0 & Self::FILE_NOTIFY_CHANGE_ATTRIBUTES) != 0
    }

    /// Check if size change.
    #[inline]
    pub fn notify_size(self) -> bool {
        (self.0 & Self::FILE_NOTIFY_CHANGE_SIZE) != 0
    }
}

/// File notify action (used in FILE_NOTIFY_INFORMATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileNotifyAction {
    /// File was added.
    Added = 0x00000001,
    /// File was removed.
    Removed = 0x00000002,
    /// File was modified.
    Modified = 0x00000003,
    /// File was renamed (old name).
    RenamedOldName = 0x00000004,
    /// File was renamed (new name).
    RenamedNewName = 0x00000005,
    /// Stream was added.
    AddedStream = 0x00000006,
    /// Stream was removed.
    RemovedStream = 0x00000007,
    /// Stream was modified.
    ModifiedStream = 0x00000008,
    /// Removed by delete.
    RemovedByDelete = 0x00000009,
    /// ID not tunneled.
    IdNotTunneled = 0x0000000A,
    /// Tunneled ID collision.
    TunneledIdCollision = 0x0000000B,
}

impl FileNotifyAction {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0x00000001 => Self::Added,
            0x00000002 => Self::Removed,
            0x00000003 => Self::Modified,
            0x00000004 => Self::RenamedOldName,
            0x00000005 => Self::RenamedNewName,
            0x00000006 => Self::AddedStream,
            0x00000007 => Self::RemovedStream,
            0x00000008 => Self::ModifiedStream,
            0x00000009 => Self::RemovedByDelete,
            0x0000000A => Self::IdNotTunneled,
            0x0000000B => Self::TunneledIdCollision,
            _ => return None,
        })
    }
}

/// FILE_NOTIFY_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileNotifyInformation {
    /// Offset to next entry (0 if last).
    pub next_entry_offset: u32,

    /// Action that occurred.
    pub action: u32,

    /// File name length in bytes.
    pub file_name_length: u32,
    // File name follows (Unicode, variable length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_change_notify_request_default() {
        let req = ChangeNotifyRequest::default();
        assert_eq!(req.structure_size, CHANGE_NOTIFY_REQUEST_SIZE);
    }

    #[test]
    fn test_change_notify_response_default() {
        let resp = ChangeNotifyResponse::default();
        assert_eq!(resp.structure_size, CHANGE_NOTIFY_RESPONSE_SIZE);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = ChangeNotifyRequest {
            structure_size: CHANGE_NOTIFY_REQUEST_SIZE,
            flags: ChangeNotifyFlags::new(ChangeNotifyFlags::WATCH_TREE),
            output_buffer_length: 65536,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            completion_filter: CompletionFilter::new(CompletionFilter::ALL),
            reserved: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = ChangeNotifyRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert!(parsed.flags.watch_tree());
        assert_eq!(parsed.output_buffer_length, 65536);
        assert_eq!(parsed.completion_filter.0, CompletionFilter::ALL);
    }

    #[test]
    fn test_completion_filter() {
        let filter = CompletionFilter::new(
            CompletionFilter::FILE_NOTIFY_CHANGE_FILE_NAME
                | CompletionFilter::FILE_NOTIFY_CHANGE_SIZE,
        );
        assert!(filter.notify_file_name());
        assert!(filter.notify_size());
        assert!(!filter.notify_dir_name());
        assert!(!filter.notify_attributes());
    }

    #[test]
    fn test_file_notify_action() {
        assert_eq!(FileNotifyAction::from_u32(1), Some(FileNotifyAction::Added));
        assert_eq!(
            FileNotifyAction::from_u32(3),
            Some(FileNotifyAction::Modified)
        );
        assert_eq!(FileNotifyAction::from_u32(100), None);
    }
}
