//! SMB2 CLOSE command.
//!
//! Used to close a file handle.
//! See MS-SMB2 Section 2.2.15 and 2.2.16.

use binrw::{BinRead, BinWrite};

/// SMB2 CLOSE request structure size.
pub const CLOSE_REQUEST_SIZE: u16 = 24;

/// SMB2 CLOSE response structure size.
pub const CLOSE_RESPONSE_SIZE: u16 = 60;

/// SMB2 CLOSE Request.
///
/// See MS-SMB2 Section 2.2.15.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CloseRequest {
    /// Structure size (must be 24).
    pub structure_size: u16,

    /// Flags.
    pub flags: CloseFlags,

    /// Reserved (must be 0).
    pub reserved: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
}

impl Default for CloseRequest {
    fn default() -> Self {
        Self {
            structure_size: CLOSE_REQUEST_SIZE,
            flags: CloseFlags(0),
            reserved: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 CLOSE Response.
///
/// See MS-SMB2 Section 2.2.16.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CloseResponse {
    /// Structure size (must be 60).
    pub structure_size: u16,

    /// Flags.
    pub flags: CloseFlags,

    /// Reserved (must be 0).
    pub reserved: u32,

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

    /// End of file (file size).
    pub end_of_file: u64,

    /// File attributes.
    pub file_attributes: u32,
}

impl Default for CloseResponse {
    fn default() -> Self {
        Self {
            structure_size: CLOSE_RESPONSE_SIZE,
            flags: CloseFlags(0),
            reserved: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
        }
    }
}

/// Close flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct CloseFlags(pub u16);

impl CloseFlags {
    /// Return post-query attributes.
    pub const POSTQUERY_ATTRIB: u16 = 0x0001;

    /// Create new flags.
    #[inline]
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Check if post-query attributes requested.
    #[inline]
    pub fn postquery_attrib(self) -> bool {
        (self.0 & Self::POSTQUERY_ATTRIB) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_close_request_default() {
        let req = CloseRequest::default();
        assert_eq!(req.structure_size, CLOSE_REQUEST_SIZE);
    }

    #[test]
    fn test_close_response_default() {
        let resp = CloseResponse::default();
        assert_eq!(resp.structure_size, CLOSE_RESPONSE_SIZE);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = CloseRequest {
            structure_size: CLOSE_REQUEST_SIZE,
            flags: CloseFlags::new(CloseFlags::POSTQUERY_ATTRIB),
            reserved: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = CloseRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert!(parsed.flags.postquery_attrib());
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
        assert_eq!(parsed.file_id_volatile, 0x0FEDCBA987654321);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = CloseResponse {
            structure_size: CLOSE_RESPONSE_SIZE,
            flags: CloseFlags::new(CloseFlags::POSTQUERY_ATTRIB),
            reserved: 0,
            creation_time: 132000000000000000,
            last_access_time: 132000000000000000,
            last_write_time: 132000000000000000,
            change_time: 132000000000000000,
            allocation_size: 4096,
            end_of_file: 1024,
            file_attributes: 0x20,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = CloseResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert!(parsed.flags.postquery_attrib());
        assert_eq!(parsed.end_of_file, 1024);
    }
}
