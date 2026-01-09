//! SMB2 ECHO command.
//!
//! Used as a keep-alive mechanism.
//! See MS-SMB2 Section 2.2.28 and 2.2.29.

use binrw::{BinRead, BinWrite};

/// SMB2 ECHO request structure size.
pub const ECHO_REQUEST_SIZE: u16 = 4;

/// SMB2 ECHO response structure size.
pub const ECHO_RESPONSE_SIZE: u16 = 4;

/// SMB2 ECHO Request.
///
/// See MS-SMB2 Section 2.2.28.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct EchoRequest {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for EchoRequest {
    fn default() -> Self {
        Self {
            structure_size: ECHO_REQUEST_SIZE,
            reserved: 0,
        }
    }
}

/// SMB2 ECHO Response.
///
/// See MS-SMB2 Section 2.2.29.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct EchoResponse {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for EchoResponse {
    fn default() -> Self {
        Self {
            structure_size: ECHO_RESPONSE_SIZE,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_echo_request_roundtrip() {
        let req = EchoRequest::default();

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = EchoRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, ECHO_REQUEST_SIZE);
    }

    #[test]
    fn test_echo_response_roundtrip() {
        let resp = EchoResponse::default();

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = EchoResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, ECHO_RESPONSE_SIZE);
    }
}
