//! SMB2 QUERY_INFO command.
//!
//! Used to query file, directory, or volume information.
//! See MS-SMB2 Section 2.2.37 and 2.2.38.

use binrw::{BinRead, BinWrite};

/// SMB2 QUERY_INFO request structure size.
pub const QUERY_INFO_REQUEST_SIZE: u16 = 41;

/// SMB2 QUERY_INFO response structure size.
pub const QUERY_INFO_RESPONSE_SIZE: u16 = 9;

/// SMB2 QUERY_INFO Request.
///
/// See MS-SMB2 Section 2.2.37.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct QueryInfoRequest {
    /// Structure size (must be 41).
    pub structure_size: u16,

    /// Info type.
    pub info_type: InfoType,

    /// File info class.
    pub file_info_class: u8,

    /// Output buffer length.
    pub output_buffer_length: u32,

    /// Input buffer offset.
    pub input_buffer_offset: u16,

    /// Reserved.
    pub reserved: u16,

    /// Input buffer length.
    pub input_buffer_length: u32,

    /// Additional information.
    pub additional_information: AdditionalInformation,

    /// Flags.
    pub flags: QueryInfoFlags,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
    // Input buffer follows (for certain queries)
}

impl Default for QueryInfoRequest {
    fn default() -> Self {
        Self {
            structure_size: QUERY_INFO_REQUEST_SIZE,
            info_type: InfoType::File,
            file_info_class: 0,
            output_buffer_length: 0,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: AdditionalInformation(0),
            flags: QueryInfoFlags(0),
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 QUERY_INFO Response.
///
/// See MS-SMB2 Section 2.2.38.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct QueryInfoResponse {
    /// Structure size (must be 9).
    pub structure_size: u16,

    /// Output buffer offset from beginning of header.
    pub output_buffer_offset: u16,

    /// Output buffer length.
    pub output_buffer_length: u32,
    // Output buffer follows
}

impl Default for QueryInfoResponse {
    fn default() -> Self {
        Self {
            structure_size: QUERY_INFO_RESPONSE_SIZE,
            output_buffer_offset: 0,
            output_buffer_length: 0,
        }
    }
}

/// Info type for QUERY_INFO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum InfoType {
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

/// Additional information flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct AdditionalInformation(pub u32);

impl AdditionalInformation {
    /// Owner security information.
    pub const OWNER_SECURITY_INFORMATION: u32 = 0x00000001;
    /// Group security information.
    pub const GROUP_SECURITY_INFORMATION: u32 = 0x00000002;
    /// DACL security information.
    pub const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    /// SACL security information.
    pub const SACL_SECURITY_INFORMATION: u32 = 0x00000008;
    /// Label security information.
    pub const LABEL_SECURITY_INFORMATION: u32 = 0x00000010;
    /// Attribute security information.
    pub const ATTRIBUTE_SECURITY_INFORMATION: u32 = 0x00000020;
    /// Scope security information.
    pub const SCOPE_SECURITY_INFORMATION: u32 = 0x00000040;
    /// Backup security information.
    pub const BACKUP_SECURITY_INFORMATION: u32 = 0x00010000;

    /// Create new additional information.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

/// Query info flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct QueryInfoFlags(pub u32);

impl QueryInfoFlags {
    /// Restart scan.
    pub const RESTART_SCAN: u32 = 0x00000001;
    /// Return single entry.
    pub const RETURN_SINGLE_ENTRY: u32 = 0x00000002;
    /// Index specified.
    pub const INDEX_SPECIFIED: u32 = 0x00000004;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

/// File information classes for QUERY_INFO (when InfoType is File).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileInfoClass {
    /// Basic information.
    FileBasicInformation = 4,
    /// Standard information.
    FileStandardInformation = 5,
    /// Internal information.
    FileInternalInformation = 6,
    /// EA information.
    FileEaInformation = 7,
    /// Access information.
    FileAccessInformation = 8,
    /// Position information.
    FilePositionInformation = 14,
    /// Mode information.
    FileModeInformation = 16,
    /// Alignment information.
    FileAlignmentInformation = 17,
    /// All information.
    FileAllInformation = 18,
    /// Alternate name information.
    FileAlternateNameInformation = 21,
    /// Stream information.
    FileStreamInformation = 22,
    /// Compression information.
    FileCompressionInformation = 28,
    /// Network open information.
    FileNetworkOpenInformation = 34,
    /// Attribute tag information.
    FileAttributeTagInformation = 35,
    /// ID information (SMB 3.1.1).
    FileIdInformation = 59,
}

impl FileInfoClass {
    /// Create from u8.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            4 => Self::FileBasicInformation,
            5 => Self::FileStandardInformation,
            6 => Self::FileInternalInformation,
            7 => Self::FileEaInformation,
            8 => Self::FileAccessInformation,
            14 => Self::FilePositionInformation,
            16 => Self::FileModeInformation,
            17 => Self::FileAlignmentInformation,
            18 => Self::FileAllInformation,
            21 => Self::FileAlternateNameInformation,
            22 => Self::FileStreamInformation,
            28 => Self::FileCompressionInformation,
            34 => Self::FileNetworkOpenInformation,
            35 => Self::FileAttributeTagInformation,
            59 => Self::FileIdInformation,
            _ => return None,
        })
    }
}

/// File system information classes for QUERY_INFO (when InfoType is FileSystem).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FsInfoClass {
    /// Volume information.
    FileFsVolumeInformation = 1,
    /// Size information.
    FileFsSizeInformation = 3,
    /// Device information.
    FileFsDeviceInformation = 4,
    /// Attribute information.
    FileFsAttributeInformation = 5,
    /// Control information.
    FileFsControlInformation = 6,
    /// Full size information.
    FileFsFullSizeInformation = 7,
    /// Object ID information.
    FileFsObjectIdInformation = 8,
    /// Sector size information.
    FileFsSectorSizeInformation = 11,
}

impl FsInfoClass {
    /// Create from u8.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::FileFsVolumeInformation,
            3 => Self::FileFsSizeInformation,
            4 => Self::FileFsDeviceInformation,
            5 => Self::FileFsAttributeInformation,
            6 => Self::FileFsControlInformation,
            7 => Self::FileFsFullSizeInformation,
            8 => Self::FileFsObjectIdInformation,
            11 => Self::FileFsSectorSizeInformation,
            _ => return None,
        })
    }
}

/// FILE_BASIC_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileBasicInformation {
    /// Creation time.
    pub creation_time: u64,
    /// Last access time.
    pub last_access_time: u64,
    /// Last write time.
    pub last_write_time: u64,
    /// Change time.
    pub change_time: u64,
    /// File attributes.
    pub file_attributes: u32,
    /// Reserved.
    pub reserved: u32,
}

/// FILE_STANDARD_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileStandardInformation {
    /// Allocation size.
    pub allocation_size: u64,
    /// End of file.
    pub end_of_file: u64,
    /// Number of links.
    pub number_of_links: u32,
    /// Delete pending.
    pub delete_pending: u8,
    /// Directory.
    pub directory: u8,
    /// Reserved.
    pub reserved: u16,
}

/// FILE_NETWORK_OPEN_INFORMATION structure.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FileNetworkOpenInformation {
    /// Creation time.
    pub creation_time: u64,
    /// Last access time.
    pub last_access_time: u64,
    /// Last write time.
    pub last_write_time: u64,
    /// Change time.
    pub change_time: u64,
    /// Allocation size.
    pub allocation_size: u64,
    /// End of file.
    pub end_of_file: u64,
    /// File attributes.
    pub file_attributes: u32,
    /// Reserved.
    pub reserved: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_query_info_request_default() {
        let req = QueryInfoRequest::default();
        assert_eq!(req.structure_size, QUERY_INFO_REQUEST_SIZE);
    }

    #[test]
    fn test_query_info_response_default() {
        let resp = QueryInfoResponse::default();
        assert_eq!(resp.structure_size, QUERY_INFO_RESPONSE_SIZE);
    }

    #[test]
    fn test_info_type() {
        assert_eq!(InfoType::File as u8, 0x01);
        assert_eq!(InfoType::FileSystem as u8, 0x02);
        assert_eq!(InfoType::Security as u8, 0x03);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = QueryInfoRequest {
            structure_size: QUERY_INFO_REQUEST_SIZE,
            info_type: InfoType::File,
            file_info_class: FileInfoClass::FileBasicInformation as u8,
            output_buffer_length: 40,
            input_buffer_offset: 0,
            reserved: 0,
            input_buffer_length: 0,
            additional_information: AdditionalInformation(0),
            flags: QueryInfoFlags(0),
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = QueryInfoRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.info_type, InfoType::File);
        assert_eq!(
            parsed.file_info_class,
            FileInfoClass::FileBasicInformation as u8
        );
    }

    #[test]
    fn test_file_basic_information_roundtrip() {
        let info = FileBasicInformation {
            creation_time: 132000000000000000,
            last_access_time: 132000000000000000,
            last_write_time: 132000000000000000,
            change_time: 132000000000000000,
            file_attributes: 0x20,
            reserved: 0,
        };

        let mut buf = Vec::new();
        info.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = FileBasicInformation::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.creation_time, 132000000000000000);
        assert_eq!(parsed.file_attributes, 0x20);
    }
}
