//! SMB2 READ command.
//!
//! Used to read data from a file.
//! See MS-SMB2 Section 2.2.19 and 2.2.20.

use binrw::{BinRead, BinWrite};

/// SMB2 READ request structure size.
pub const READ_REQUEST_SIZE: u16 = 49;

/// SMB2 READ response structure size.
pub const READ_RESPONSE_SIZE: u16 = 17;

/// Maximum read size (8 MB default).
pub const MAX_READ_SIZE: u32 = 8 * 1024 * 1024;

/// SMB2 READ Request.
///
/// See MS-SMB2 Section 2.2.19.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct ReadRequest {
    /// Structure size (must be 49).
    pub structure_size: u16,

    /// Padding (recommended 0x50 for alignment).
    pub padding: u8,

    /// Flags (SMB 3.x only).
    pub flags: ReadFlags,

    /// Length of data to read.
    pub length: u32,

    /// Offset in file to read from.
    pub offset: u64,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Minimum count (for named pipes).
    pub minimum_count: u32,

    /// Channel (SMB 3.x only).
    pub channel: u32,

    /// Remaining bytes (for multi-credit reads).
    pub remaining_bytes: u32,

    /// Read channel info offset.
    pub read_channel_info_offset: u16,

    /// Read channel info length.
    pub read_channel_info_length: u16,
    // Buffer follows
}

impl Default for ReadRequest {
    fn default() -> Self {
        Self {
            structure_size: READ_REQUEST_SIZE,
            padding: 0x50,
            flags: ReadFlags(0),
            length: 0,
            offset: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
        }
    }
}

/// SMB2 READ Response.
///
/// See MS-SMB2 Section 2.2.20.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct ReadResponse {
    /// Structure size (must be 17).
    pub structure_size: u16,

    /// Data offset from beginning of header.
    pub data_offset: u8,

    /// Reserved.
    pub reserved: u8,

    /// Data length.
    pub data_length: u32,

    /// Data remaining (for multi-credit reads).
    pub data_remaining: u32,

    /// Flags (SMB 3.x only).
    pub flags: ReadResponseFlags,
    // Data follows
}

impl Default for ReadResponse {
    fn default() -> Self {
        Self {
            structure_size: READ_RESPONSE_SIZE,
            data_offset: 0,
            reserved: 0,
            data_length: 0,
            data_remaining: 0,
            flags: ReadResponseFlags(0),
        }
    }
}

/// Read request flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct ReadFlags(pub u8);

impl ReadFlags {
    /// Read unbuffered (SMB 3.0.2+).
    pub const READ_UNBUFFERED: u8 = 0x01;

    /// Create new flags.
    #[inline]
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Check if unbuffered read.
    #[inline]
    pub fn is_unbuffered(self) -> bool {
        (self.0 & Self::READ_UNBUFFERED) != 0
    }
}

/// Read response flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct ReadResponseFlags(pub u32);

impl ReadResponseFlags {
    /// RDMA transform (SMB 3.x).
    pub const RDMA_TRANSFORM: u32 = 0x00000001;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

/// Read channel (SMB 3.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReadChannel {
    /// No channel.
    None = 0,
    /// RDMA V1.
    RdmaV1 = 1,
    /// RDMA V1 Invalidate.
    RdmaV1Invalidate = 2,
}

impl ReadChannel {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::RdmaV1,
            2 => Self::RdmaV1Invalidate,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_request_default() {
        let req = ReadRequest::default();
        assert_eq!(req.structure_size, READ_REQUEST_SIZE);
        assert_eq!(req.padding, 0x50);
    }

    #[test]
    fn test_read_response_default() {
        let resp = ReadResponse::default();
        assert_eq!(resp.structure_size, READ_RESPONSE_SIZE);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = ReadRequest {
            structure_size: READ_REQUEST_SIZE,
            padding: 0x50,
            flags: ReadFlags::new(ReadFlags::READ_UNBUFFERED),
            length: 65536,
            offset: 0x1000,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = ReadRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert!(parsed.flags.is_unbuffered());
        assert_eq!(parsed.length, 65536);
        assert_eq!(parsed.offset, 0x1000);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = ReadResponse {
            structure_size: READ_RESPONSE_SIZE,
            data_offset: 0x50,
            reserved: 0,
            data_length: 1024,
            data_remaining: 0,
            flags: ReadResponseFlags(0),
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = ReadResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.data_offset, 0x50);
        assert_eq!(parsed.data_length, 1024);
    }
}
