//! SMB2 command request and response structures.
//!
//! Each command has a corresponding request and response structure.

use crate::header::Smb2Command;

pub mod cancel;
pub mod change_notify;
pub mod close;
pub mod create;
pub mod echo;
pub mod flush;
pub mod ioctl;
pub mod lock;
pub mod logoff;
pub mod negotiate;
pub mod oplock_break;
pub mod query_directory;
pub mod query_info;
pub mod read;
pub mod session_setup;
pub mod set_info;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod write;

// Re-export all command types for convenience
pub use cancel::*;
pub use change_notify::*;
pub use close::*;
pub use create::{
    create_context_name, parse_create_contexts, CreateAction, CreateContext, CreateContextBuilder,
    CreateContextError, CreateContextHeader, CreateDisposition, CreateOptions, CreateRequest,
    CreateResponse, CreateResponseFlags, DurableHandleFlags, FileId, ImpersonationLevel,
    CREATE_REQUEST_SIZE, CREATE_RESPONSE_SIZE,
};
// OplockLevel is in both create and oplock_break - use oplock_break's version
pub use create::OplockLevel as CreateOplockLevel;
pub use echo::*;
pub use flush::*;
pub use ioctl::*;
pub use lock::*;
pub use logoff::*;
pub use negotiate::*;
pub use oplock_break::*;
pub use query_directory::*;
pub use query_info::*;
pub use read::*;
pub use session_setup::*;
pub use set_info::*;
pub use tree_connect::*;
pub use tree_disconnect::*;
pub use write::*;

// =============================================================================
// FileId Body Offsets
// =============================================================================
//
// These constants document where the FileId field appears in each command's
// request body, per the MS-SMB2 specification sections noted. This is critical
// for compound request handling where FileId substitution is needed.
//
// See docs/postmortem/2026-01-compound-request-bugs.md for background.

/// CLOSE request FileId offset (MS-SMB2 2.2.15)
/// Structure: StructureSize(2) + Flags(2) + Reserved(4) + FileId(16)
pub const CLOSE_FILEID_BODY_OFFSET: usize = 8;

/// FLUSH request FileId offset (MS-SMB2 2.2.17)
/// Structure: StructureSize(2) + Reserved1(2) + Reserved2(4) + FileId(16)
pub const FLUSH_FILEID_BODY_OFFSET: usize = 8;

/// LOCK request FileId offset (MS-SMB2 2.2.26)
/// Structure: StructureSize(2) + LockCount(2) + LockSequenceNumber(4) + FileId(16) + Locks(var)
pub const LOCK_FILEID_BODY_OFFSET: usize = 8;

/// QUERY_DIRECTORY request FileId offset (MS-SMB2 2.2.33)
/// Structure: StructureSize(2) + FileInfoClass(1) + Flags(1) + FileIndex(4) + FileId(16) + ...
pub const QUERY_DIRECTORY_FILEID_BODY_OFFSET: usize = 8;

/// READ request FileId offset (MS-SMB2 2.2.19)
/// Structure: StructureSize(2) + Padding(1) + Flags(1) + Length(4) + Offset(8) + FileId(16) + ...
pub const READ_FILEID_BODY_OFFSET: usize = 16;

/// WRITE request FileId offset (MS-SMB2 2.2.21)
/// Structure: StructureSize(2) + DataOffset(2) + Length(4) + Offset(8) + FileId(16) + ...
pub const WRITE_FILEID_BODY_OFFSET: usize = 16;

/// SET_INFO request FileId offset (MS-SMB2 2.2.39)
/// Structure: StructureSize(2) + InfoType(1) + FileInfoClass(1) + BufferLength(4) +
///            BufferOffset(2) + Reserved(2) + AdditionalInfo(4) + FileId(16) + Buffer(var)
pub const SET_INFO_FILEID_BODY_OFFSET: usize = 16;

/// QUERY_INFO request FileId offset (MS-SMB2 2.2.37)
/// Structure: StructureSize(2) + InfoType(1) + FileInfoClass(1) + OutputBufferLength(4) +
///            InputBufferOffset(2) + Reserved(2) + InputBufferLength(4) +
///            AdditionalInformation(4) + Flags(4) + FileId(16) + InputBuffer(var)
pub const QUERY_INFO_FILEID_BODY_OFFSET: usize = 24;

/// Get FileId body offset for a command type.
///
/// Returns the offset (in bytes) from the start of the command body where
/// the FileId field begins. Returns None for commands that don't have a
/// FileId field in their request structure.
///
/// # Example
///
/// ```
/// use rustsmb_protocol::header::Smb2Command;
/// use rustsmb_protocol::commands::fileid_body_offset;
///
/// assert_eq!(fileid_body_offset(Smb2Command::QueryInfo), Some(24));
/// assert_eq!(fileid_body_offset(Smb2Command::Close), Some(8));
/// assert_eq!(fileid_body_offset(Smb2Command::Read), Some(16));
/// assert_eq!(fileid_body_offset(Smb2Command::Negotiate), None);
/// ```
pub fn fileid_body_offset(command: Smb2Command) -> Option<usize> {
    match command {
        Smb2Command::Close => Some(CLOSE_FILEID_BODY_OFFSET),
        Smb2Command::Flush => Some(FLUSH_FILEID_BODY_OFFSET),
        Smb2Command::Lock => Some(LOCK_FILEID_BODY_OFFSET),
        Smb2Command::QueryDirectory => Some(QUERY_DIRECTORY_FILEID_BODY_OFFSET),
        Smb2Command::Read => Some(READ_FILEID_BODY_OFFSET),
        Smb2Command::Write => Some(WRITE_FILEID_BODY_OFFSET),
        Smb2Command::SetInfo => Some(SET_INFO_FILEID_BODY_OFFSET),
        Smb2Command::QueryInfo => Some(QUERY_INFO_FILEID_BODY_OFFSET),
        _ => None, // Commands without FileId in request body
    }
}

#[cfg(test)]
mod fileid_offset_tests {
    //! Tests verifying FileId is at the documented offset in serialized command buffers.
    //!
    //! These tests prevent regressions like the compound request bugs documented in
    //! docs/postmortem/2026-01-compound-request-bugs.md

    use super::*;
    use binrw::BinWrite;
    use std::io::Cursor;

    const TEST_PERSISTENT: u64 = 0x1234567890ABCDEF;
    const TEST_VOLATILE: u64 = 0xFEDCBA0987654321;

    /// Verify FileId bytes at given offset match expected values
    fn verify_fileid_at_offset(buf: &[u8], offset: usize) {
        let persistent = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
        let volatile = u64::from_le_bytes(buf[offset + 8..offset + 16].try_into().unwrap());
        assert_eq!(
            persistent, TEST_PERSISTENT,
            "FileId persistent mismatch at offset {}",
            offset
        );
        assert_eq!(
            volatile, TEST_VOLATILE,
            "FileId volatile mismatch at offset {}",
            offset
        );
    }

    #[test]
    fn test_close_fileid_at_offset_8() {
        let req = CloseRequest {
            structure_size: CLOSE_REQUEST_SIZE,
            flags: CloseFlags(0),
            reserved: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, CLOSE_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_flush_fileid_at_offset_8() {
        let req = FlushRequest {
            structure_size: FLUSH_REQUEST_SIZE,
            reserved1: 0,
            reserved2: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, FLUSH_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_lock_fileid_at_offset_8() {
        let req = LockRequest {
            structure_size: LOCK_REQUEST_SIZE,
            lock_count: 0,
            lock_sequence: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, LOCK_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_query_directory_fileid_at_offset_8() {
        let req = QueryDirectoryRequest {
            structure_size: QUERY_DIRECTORY_REQUEST_SIZE,
            file_information_class: FileInformationClass::FileDirectoryInformation,
            flags: QueryDirectoryFlags(0),
            file_index: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
            file_name_offset: 0,
            file_name_length: 0,
            output_buffer_length: 0,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, QUERY_DIRECTORY_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_read_fileid_at_offset_16() {
        let req = ReadRequest {
            structure_size: READ_REQUEST_SIZE,
            padding: 0,
            flags: ReadFlags(0),
            length: 0,
            offset: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, READ_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_write_fileid_at_offset_16() {
        let req = WriteRequest {
            structure_size: WRITE_REQUEST_SIZE,
            data_offset: 0,
            length: 0,
            offset: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: WriteFlags(0),
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, WRITE_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_set_info_fileid_at_offset_16() {
        let req = SetInfoRequest {
            structure_size: SET_INFO_REQUEST_SIZE,
            info_type: SetInfoType::File,
            file_info_class: 0,
            buffer_length: 0,
            buffer_offset: 0,
            reserved: 0,
            additional_information: 0,
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, SET_INFO_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_query_info_fileid_at_offset_24() {
        let req = QueryInfoRequest {
            structure_size: QUERY_INFO_REQUEST_SIZE,
            info_type: query_info::InfoType::File,
            file_info_class: 5,
            output_buffer_length: 24,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: AdditionalInformation(0),
            flags: QueryInfoFlags(0),
            file_id_persistent: TEST_PERSISTENT,
            file_id_volatile: TEST_VOLATILE,
        };
        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();
        verify_fileid_at_offset(&buf, QUERY_INFO_FILEID_BODY_OFFSET);
    }

    #[test]
    fn test_fileid_body_offset_helper() {
        assert_eq!(fileid_body_offset(Smb2Command::Close), Some(8));
        assert_eq!(fileid_body_offset(Smb2Command::Flush), Some(8));
        assert_eq!(fileid_body_offset(Smb2Command::Lock), Some(8));
        assert_eq!(fileid_body_offset(Smb2Command::QueryDirectory), Some(8));
        assert_eq!(fileid_body_offset(Smb2Command::Read), Some(16));
        assert_eq!(fileid_body_offset(Smb2Command::Write), Some(16));
        assert_eq!(fileid_body_offset(Smb2Command::SetInfo), Some(16));
        assert_eq!(fileid_body_offset(Smb2Command::QueryInfo), Some(24));
        // Commands without FileId
        assert_eq!(fileid_body_offset(Smb2Command::Negotiate), None);
        assert_eq!(fileid_body_offset(Smb2Command::SessionSetup), None);
        assert_eq!(fileid_body_offset(Smb2Command::TreeConnect), None);
        assert_eq!(fileid_body_offset(Smb2Command::Create), None);
    }
}
