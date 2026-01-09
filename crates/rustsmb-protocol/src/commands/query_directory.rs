//! SMB2 QUERY_DIRECTORY command.
//!
//! Used to enumerate directory contents.
//! See MS-SMB2 Section 2.2.33 and 2.2.34.

use binrw::{BinRead, BinWrite};

/// SMB2 QUERY_DIRECTORY request structure size.
pub const QUERY_DIRECTORY_REQUEST_SIZE: u16 = 33;

/// SMB2 QUERY_DIRECTORY response structure size.
pub const QUERY_DIRECTORY_RESPONSE_SIZE: u16 = 9;

/// SMB2 QUERY_DIRECTORY Request.
///
/// See MS-SMB2 Section 2.2.33.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct QueryDirectoryRequest {
    /// Structure size (must be 33).
    pub structure_size: u16,

    /// File information class.
    pub file_information_class: FileInformationClass,

    /// Flags.
    pub flags: QueryDirectoryFlags,

    /// File index (for resume).
    pub file_index: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// File name offset from beginning of header.
    pub file_name_offset: u16,

    /// File name length.
    pub file_name_length: u16,

    /// Output buffer length.
    pub output_buffer_length: u32,
    // File name pattern follows (Unicode, e.g., "*" or "*.txt")
}

impl Default for QueryDirectoryRequest {
    fn default() -> Self {
        Self {
            structure_size: QUERY_DIRECTORY_REQUEST_SIZE,
            file_information_class: FileInformationClass::FileIdBothDirectoryInformation,
            flags: QueryDirectoryFlags(0),
            file_index: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            file_name_offset: 0,
            file_name_length: 0,
            output_buffer_length: 0,
        }
    }
}

/// SMB2 QUERY_DIRECTORY Response.
///
/// See MS-SMB2 Section 2.2.34.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct QueryDirectoryResponse {
    /// Structure size (must be 9).
    pub structure_size: u16,

    /// Output buffer offset from beginning of header.
    pub output_buffer_offset: u16,

    /// Output buffer length.
    pub output_buffer_length: u32,
    // Directory entries follow
}

impl Default for QueryDirectoryResponse {
    fn default() -> Self {
        Self {
            structure_size: QUERY_DIRECTORY_RESPONSE_SIZE,
            output_buffer_offset: 0,
            output_buffer_length: 0,
        }
    }
}

/// File information class for directory queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum FileInformationClass {
    /// Directory information.
    FileDirectoryInformation = 1,
    /// Full directory information.
    FileFullDirectoryInformation = 2,
    /// Both directory information.
    FileBothDirectoryInformation = 3,
    /// Names information.
    FileNamesInformation = 12,
    /// ID both directory information.
    #[default]
    FileIdBothDirectoryInformation = 37,
    /// ID full directory information.
    FileIdFullDirectoryInformation = 38,
    /// ID extended directory information (SMB 3.1.1).
    FileIdExtdDirectoryInformation = 60,
}

/// Query directory flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct QueryDirectoryFlags(pub u8);

impl QueryDirectoryFlags {
    /// Restart the scan from the beginning.
    pub const RESTART_SCANS: u8 = 0x01;
    /// Return single entry.
    pub const RETURN_SINGLE_ENTRY: u8 = 0x02;
    /// Use file index for resume.
    pub const INDEX_SPECIFIED: u8 = 0x04;
    /// Re-open the search.
    pub const REOPEN: u8 = 0x10;

    /// Create new flags.
    #[inline]
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Check if restart scans.
    #[inline]
    pub fn restart_scans(self) -> bool {
        (self.0 & Self::RESTART_SCANS) != 0
    }

    /// Check if return single entry.
    #[inline]
    pub fn return_single_entry(self) -> bool {
        (self.0 & Self::RETURN_SINGLE_ENTRY) != 0
    }

    /// Check if index specified.
    #[inline]
    pub fn index_specified(self) -> bool {
        (self.0 & Self::INDEX_SPECIFIED) != 0
    }

    /// Check if reopen.
    #[inline]
    pub fn reopen(self) -> bool {
        (self.0 & Self::REOPEN) != 0
    }
}

/// File ID Both Directory Information structure.
///
/// Used when FileInformationClass is FileIdBothDirectoryInformation.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileIdBothDirectoryInformation {
    /// Offset to next entry (0 if last).
    pub next_entry_offset: u32,

    /// File index.
    pub file_index: u32,

    /// Creation time.
    pub creation_time: u64,

    /// Last access time.
    pub last_access_time: u64,

    /// Last write time.
    pub last_write_time: u64,

    /// Change time.
    pub change_time: u64,

    /// End of file (file size).
    pub end_of_file: u64,

    /// Allocation size.
    pub allocation_size: u64,

    /// File attributes.
    pub file_attributes: u32,

    /// File name length.
    pub file_name_length: u32,

    /// EA size.
    pub ea_size: u32,

    /// Short name length.
    pub short_name_length: u8,

    /// Reserved.
    pub reserved1: u8,

    /// Short name (24 bytes, null-terminated Unicode).
    pub short_name: [u8; 24],

    /// Reserved.
    pub reserved2: u16,

    /// File ID.
    pub file_id: u64,
    // File name follows (variable length Unicode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_query_directory_request_default() {
        let req = QueryDirectoryRequest::default();
        assert_eq!(req.structure_size, QUERY_DIRECTORY_REQUEST_SIZE);
    }

    #[test]
    fn test_query_directory_response_default() {
        let resp = QueryDirectoryResponse::default();
        assert_eq!(resp.structure_size, QUERY_DIRECTORY_RESPONSE_SIZE);
    }

    #[test]
    fn test_file_information_class() {
        assert_eq!(FileInformationClass::FileDirectoryInformation as u8, 1);
        assert_eq!(FileInformationClass::FileIdBothDirectoryInformation as u8, 37);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = QueryDirectoryRequest {
            structure_size: QUERY_DIRECTORY_REQUEST_SIZE,
            file_information_class: FileInformationClass::FileIdBothDirectoryInformation,
            flags: QueryDirectoryFlags::new(QueryDirectoryFlags::RESTART_SCANS),
            file_index: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            file_name_offset: 96,
            file_name_length: 2,
            output_buffer_length: 65536,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = QueryDirectoryRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert!(parsed.flags.restart_scans());
        assert_eq!(
            parsed.file_information_class,
            FileInformationClass::FileIdBothDirectoryInformation
        );
        assert_eq!(parsed.output_buffer_length, 65536);
    }

    #[test]
    fn test_query_directory_flags() {
        let flags = QueryDirectoryFlags::new(
            QueryDirectoryFlags::RESTART_SCANS | QueryDirectoryFlags::RETURN_SINGLE_ENTRY,
        );
        assert!(flags.restart_scans());
        assert!(flags.return_single_entry());
        assert!(!flags.index_specified());
        assert!(!flags.reopen());
    }
}
