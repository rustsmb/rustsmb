//! SMB2 LOGOFF command.
//!
//! Used to terminate a session.
//! See MS-SMB2 Section 2.2.7 and 2.2.8.

use binrw::{BinRead, BinWrite};

/// SMB2 LOGOFF request structure size.
pub const LOGOFF_REQUEST_SIZE: u16 = 4;

/// SMB2 LOGOFF response structure size.
pub const LOGOFF_RESPONSE_SIZE: u16 = 4;

/// SMB2 LOGOFF Request.
///
/// See MS-SMB2 Section 2.2.7.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LogoffRequest {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for LogoffRequest {
    fn default() -> Self {
        Self {
            structure_size: LOGOFF_REQUEST_SIZE,
            reserved: 0,
        }
    }
}

/// SMB2 LOGOFF Response.
///
/// See MS-SMB2 Section 2.2.8.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LogoffResponse {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for LogoffResponse {
    fn default() -> Self {
        Self {
            structure_size: LOGOFF_RESPONSE_SIZE,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_logoff_request_roundtrip() {
        let req = LogoffRequest::default();

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = LogoffRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, LOGOFF_REQUEST_SIZE);
    }

    #[test]
    fn test_logoff_response_roundtrip() {
        let resp = LogoffResponse::default();

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = LogoffResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, LOGOFF_RESPONSE_SIZE);
    }
}
