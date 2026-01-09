//! SMB2 FLUSH command.
//!
//! Used to flush cached data to persistent storage.
//! See MS-SMB2 Section 2.2.17 and 2.2.18.

use binrw::{BinRead, BinWrite};

/// SMB2 FLUSH request structure size.
pub const FLUSH_REQUEST_SIZE: u16 = 24;

/// SMB2 FLUSH response structure size.
pub const FLUSH_RESPONSE_SIZE: u16 = 4;

/// SMB2 FLUSH Request.
///
/// See MS-SMB2 Section 2.2.17.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FlushRequest {
    /// Structure size (must be 24).
    pub structure_size: u16,

    /// Reserved1 (must be 0).
    pub reserved1: u16,

    /// Reserved2 (must be 0).
    pub reserved2: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
}

impl Default for FlushRequest {
    fn default() -> Self {
        Self {
            structure_size: FLUSH_REQUEST_SIZE,
            reserved1: 0,
            reserved2: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 FLUSH Response.
///
/// See MS-SMB2 Section 2.2.18.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct FlushResponse {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for FlushResponse {
    fn default() -> Self {
        Self {
            structure_size: FLUSH_RESPONSE_SIZE,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_flush_request_roundtrip() {
        let req = FlushRequest {
            structure_size: FLUSH_REQUEST_SIZE,
            reserved1: 0,
            reserved2: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = FlushRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, FLUSH_REQUEST_SIZE);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
        assert_eq!(parsed.file_id_volatile, 0x0FEDCBA987654321);
    }

    #[test]
    fn test_flush_response_roundtrip() {
        let resp = FlushResponse::default();

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = FlushResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, FLUSH_RESPONSE_SIZE);
    }
}
