//! SMB2 WRITE command.
//!
//! Used to write data to a file.
//! See MS-SMB2 Section 2.2.21 and 2.2.22.

use binrw::{BinRead, BinWrite};

/// SMB2 WRITE request structure size.
pub const WRITE_REQUEST_SIZE: u16 = 49;

/// SMB2 WRITE response structure size.
pub const WRITE_RESPONSE_SIZE: u16 = 17;

/// Maximum write size (8 MB default).
pub const MAX_WRITE_SIZE: u32 = 8 * 1024 * 1024;

/// SMB2 WRITE Request.
///
/// See MS-SMB2 Section 2.2.21.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct WriteRequest {
    /// Structure size (must be 49).
    pub structure_size: u16,

    /// Data offset from beginning of header.
    pub data_offset: u16,

    /// Data length.
    pub length: u32,

    /// Offset in file to write to.
    pub offset: u64,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Channel (SMB 3.x only).
    pub channel: u32,

    /// Remaining bytes (for multi-credit writes).
    pub remaining_bytes: u32,

    /// Write channel info offset.
    pub write_channel_info_offset: u16,

    /// Write channel info length.
    pub write_channel_info_length: u16,

    /// Flags.
    pub flags: WriteFlags,
    // Data follows
}

impl Default for WriteRequest {
    fn default() -> Self {
        Self {
            structure_size: WRITE_REQUEST_SIZE,
            data_offset: 0,
            length: 0,
            offset: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: WriteFlags(0),
        }
    }
}

/// SMB2 WRITE Response.
///
/// See MS-SMB2 Section 2.2.22.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct WriteResponse {
    /// Structure size (must be 17).
    pub structure_size: u16,

    /// Reserved.
    pub reserved: u16,

    /// Count of bytes written.
    pub count: u32,

    /// Remaining (for multi-credit writes).
    pub remaining: u32,

    /// Write channel info offset.
    pub write_channel_info_offset: u16,

    /// Write channel info length.
    pub write_channel_info_length: u16,
}

impl Default for WriteResponse {
    fn default() -> Self {
        Self {
            structure_size: WRITE_RESPONSE_SIZE,
            reserved: 0,
            count: 0,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        }
    }
}

/// Write flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct WriteFlags(pub u32);

impl WriteFlags {
    /// Write through.
    pub const WRITE_THROUGH: u32 = 0x00000001;
    /// Write unbuffered (SMB 3.0.2+).
    pub const WRITE_UNBUFFERED: u32 = 0x00000002;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if write through.
    #[inline]
    pub fn is_write_through(self) -> bool {
        (self.0 & Self::WRITE_THROUGH) != 0
    }

    /// Check if unbuffered write.
    #[inline]
    pub fn is_unbuffered(self) -> bool {
        (self.0 & Self::WRITE_UNBUFFERED) != 0
    }
}

/// Write channel (SMB 3.x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum WriteChannel {
    /// No channel.
    None = 0,
    /// RDMA V1.
    RdmaV1 = 1,
    /// RDMA V1 Invalidate.
    RdmaV1Invalidate = 2,
}

impl WriteChannel {
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
    fn test_write_request_default() {
        let req = WriteRequest::default();
        assert_eq!(req.structure_size, WRITE_REQUEST_SIZE);
    }

    #[test]
    fn test_write_response_default() {
        let resp = WriteResponse::default();
        assert_eq!(resp.structure_size, WRITE_RESPONSE_SIZE);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = WriteRequest {
            structure_size: WRITE_REQUEST_SIZE,
            data_offset: 0x70,
            length: 4096,
            offset: 0x2000,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: WriteFlags::new(WriteFlags::WRITE_THROUGH),
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = WriteRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert!(parsed.flags.is_write_through());
        assert_eq!(parsed.length, 4096);
        assert_eq!(parsed.offset, 0x2000);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = WriteResponse {
            structure_size: WRITE_RESPONSE_SIZE,
            reserved: 0,
            count: 4096,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = WriteResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.count, 4096);
    }

    #[test]
    fn test_write_flags() {
        let flags = WriteFlags::new(WriteFlags::WRITE_THROUGH | WriteFlags::WRITE_UNBUFFERED);
        assert!(flags.is_write_through());
        assert!(flags.is_unbuffered());
    }
}
