//! SMB2 CANCEL command.
//!
//! Used to cancel a pending request.
//! See MS-SMB2 Section 2.2.30.

use binrw::{BinRead, BinWrite};

/// SMB2 CANCEL request structure size.
pub const CANCEL_REQUEST_SIZE: u16 = 4;

/// SMB2 CANCEL Request.
///
/// See MS-SMB2 Section 2.2.30.
/// Note: There is no CANCEL response - the server simply acknowledges
/// by responding to the original request with STATUS_CANCELLED.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CancelRequest {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for CancelRequest {
    fn default() -> Self {
        Self {
            structure_size: CANCEL_REQUEST_SIZE,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_cancel_request_roundtrip() {
        let req = CancelRequest::default();

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), 4);

        let parsed = CancelRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, CANCEL_REQUEST_SIZE);
    }
}
