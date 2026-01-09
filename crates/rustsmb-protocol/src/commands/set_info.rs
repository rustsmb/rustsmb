//! SMB2 SET_INFO command.
//!
//! Used to set file, directory, or volume information.
//! See MS-SMB2 Section 2.2.39 and 2.2.40.

use binrw::{BinRead, BinWrite};

/// SMB2 SET_INFO request structure size.
pub const SET_INFO_REQUEST_SIZE: u16 = 33;

/// SMB2 SET_INFO response structure size.
pub const SET_INFO_RESPONSE_SIZE: u16 = 2;

/// SMB2 SET_INFO Request.
///
/// See MS-SMB2 Section 2.2.39.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct SetInfoRequest {
    /// Structure size (must be 33).
    pub structure_size: u16,

    /// Info type.
    pub info_type: SetInfoType,

    /// File info class.
    pub file_info_class: u8,

    /// Buffer length.
    pub buffer_length: u32,

    /// Buffer offset from beginning of header.
    pub buffer_offset: u16,

    /// Reserved.
    pub reserved: u16,

    /// Additional information.
    pub additional_information: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
    // Buffer follows
}

impl Default for SetInfoRequest {
    fn default() -> Self {
        Self {
            structure_size: SET_INFO_REQUEST_SIZE,
            info_type: SetInfoType::File,
            file_info_class: 0,
            buffer_length: 0,
            buffer_offset: 0,
            reserved: 0,
            additional_information: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 SET_INFO Response.
///
/// See MS-SMB2 Section 2.2.40.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct SetInfoResponse {
    /// Structure size (must be 2).
    pub structure_size: u16,
}

impl Default for SetInfoResponse {
    fn default() -> Self {
        Self {
            structure_size: SET_INFO_RESPONSE_SIZE,
        }
    }
}

/// Info type for SET_INFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum SetInfoType {
    /// File information.
    #[default]
    File = 0x01,
    /// File system information.
    FileSystem = 0x02,
    /// Security information.
    Security = 0x03,
    /// Quota information.
    Quota = 0x04,
}

/// File information classes for SET_INFO (when InfoType is File).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetFileInfoClass {
    /// Basic information.
    FileBasicInformation = 4,
    /// Rename information.
    FileRenameInformation = 10,
    /// Link information.
    FileLinkInformation = 11,
    /// Disposition information.
    FileDispositionInformation = 13,
    /// Position information.
    FilePositionInformation = 14,
    /// Full EA information.
    FileFullEaInformation = 15,
    /// Mode information.
    FileModeInformation = 16,
    /// Allocation information.
    FileAllocationInformation = 19,
    /// End of file information.
    FileEndOfFileInformation = 20,
    /// Pipe information.
    FilePipeInformation = 23,
    /// Valid data length information.
    FileValidDataLengthInformation = 39,
    /// Short name information.
    FileShortNameInformation = 40,
}

impl SetFileInfoClass {
    /// Create from u8.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            4 => Self::FileBasicInformation,
            10 => Self::FileRenameInformation,
            11 => Self::FileLinkInformation,
            13 => Self::FileDispositionInformation,
            14 => Self::FilePositionInformation,
            15 => Self::FileFullEaInformation,
            16 => Self::FileModeInformation,
            19 => Self::FileAllocationInformation,
            20 => Self::FileEndOfFileInformation,
            23 => Self::FilePipeInformation,
            39 => Self::FileValidDataLengthInformation,
            40 => Self::FileShortNameInformation,
            _ => return None,
        })
    }
}

/// FILE_RENAME_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileRenameInformation {
    /// Replace if exists.
    pub replace_if_exists: u8,
    /// Reserved (7 bytes).
    pub reserved: [u8; 7],
    /// Root directory (for relative renames).
    pub root_directory: u64,
    /// File name length in bytes.
    pub file_name_length: u32,
    // File name follows (Unicode)
}

/// FILE_DISPOSITION_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileDispositionInformation {
    /// Delete pending.
    pub delete_pending: u8,
}

/// FILE_END_OF_FILE_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileEndOfFileInformation {
    /// End of file.
    pub end_of_file: u64,
}

/// FILE_ALLOCATION_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileAllocationInformation {
    /// Allocation size.
    pub allocation_size: u64,
}

/// FILE_POSITION_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FilePositionInformation {
    /// Current byte offset.
    pub current_byte_offset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_set_info_request_default() {
        let req = SetInfoRequest::default();
        assert_eq!(req.structure_size, SET_INFO_REQUEST_SIZE);
    }

    #[test]
    fn test_set_info_response_default() {
        let resp = SetInfoResponse::default();
        assert_eq!(resp.structure_size, SET_INFO_RESPONSE_SIZE);
    }

    #[test]
    fn test_set_info_type() {
        assert_eq!(SetInfoType::File as u8, 0x01);
        assert_eq!(SetInfoType::Security as u8, 0x03);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = SetInfoRequest {
            structure_size: SET_INFO_REQUEST_SIZE,
            info_type: SetInfoType::File,
            file_info_class: SetFileInfoClass::FileDispositionInformation as u8,
            buffer_length: 1,
            buffer_offset: 96,
            reserved: 0,
            additional_information: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = SetInfoRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.info_type, SetInfoType::File);
        assert_eq!(
            parsed.file_info_class,
            SetFileInfoClass::FileDispositionInformation as u8
        );
    }

    #[test]
    fn test_file_disposition_information() {
        let info = FileDispositionInformation { delete_pending: 1 };

        let mut buf = Vec::new();
        info.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = FileDispositionInformation::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.delete_pending, 1);
    }

    #[test]
    fn test_file_end_of_file_information() {
        let info = FileEndOfFileInformation {
            end_of_file: 1024 * 1024,
        };

        let mut buf = Vec::new();
        info.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = FileEndOfFileInformation::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.end_of_file, 1024 * 1024);
    }
}
