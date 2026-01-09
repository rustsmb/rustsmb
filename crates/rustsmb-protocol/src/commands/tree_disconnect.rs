//! SMB2 TREE_DISCONNECT command.
//!
//! Used to disconnect from a share.
//! See MS-SMB2 Section 2.2.11 and 2.2.12.

use binrw::{BinRead, BinWrite};

/// SMB2 TREE_DISCONNECT request structure size.
pub const TREE_DISCONNECT_REQUEST_SIZE: u16 = 4;

/// SMB2 TREE_DISCONNECT response structure size.
pub const TREE_DISCONNECT_RESPONSE_SIZE: u16 = 4;

/// SMB2 TREE_DISCONNECT Request.
///
/// See MS-SMB2 Section 2.2.11.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct TreeDisconnectRequest {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for TreeDisconnectRequest {
    fn default() -> Self {
        Self {
            structure_size: TREE_DISCONNECT_REQUEST_SIZE,
            reserved: 0,
        }
    }
}

/// SMB2 TREE_DISCONNECT Response.
///
/// See MS-SMB2 Section 2.2.12.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct TreeDisconnectResponse {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for TreeDisconnectResponse {
    fn default() -> Self {
        Self {
            structure_size: TREE_DISCONNECT_RESPONSE_SIZE,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_tree_disconnect_request_roundtrip() {
        let req = TreeDisconnectRequest::default();

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = TreeDisconnectRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, TREE_DISCONNECT_REQUEST_SIZE);
    }

    #[test]
    fn test_tree_disconnect_response_roundtrip() {
        let resp = TreeDisconnectResponse::default();

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = TreeDisconnectResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, TREE_DISCONNECT_RESPONSE_SIZE);
    }
}
