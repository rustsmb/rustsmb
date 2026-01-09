//! SMB2 LOCK command.
//!
//! Used to acquire or release byte-range locks on a file.
//! See MS-SMB2 Section 2.2.26 and 2.2.27.

use binrw::{BinRead, BinWrite};

/// SMB2 LOCK request structure size.
pub const LOCK_REQUEST_SIZE: u16 = 48;

/// SMB2 LOCK response structure size.
pub const LOCK_RESPONSE_SIZE: u16 = 4;

/// SMB2 LOCK Request.
///
/// See MS-SMB2 Section 2.2.26.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LockRequest {
    /// Structure size (must be 48).
    pub structure_size: u16,

    /// Lock count.
    pub lock_count: u16,

    /// Lock sequence (SMB 3.x).
    pub lock_sequence: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
    // Locks follow (array of LockElement)
}

impl Default for LockRequest {
    fn default() -> Self {
        Self {
            structure_size: LOCK_REQUEST_SIZE,
            lock_count: 0,
            lock_sequence: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 LOCK Response.
///
/// See MS-SMB2 Section 2.2.27.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LockResponse {
    /// Structure size (must be 4).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,
}

impl Default for LockResponse {
    fn default() -> Self {
        Self {
            structure_size: LOCK_RESPONSE_SIZE,
            reserved: 0,
        }
    }
}

/// Lock element in a LOCK request.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LockElement {
    /// Offset of the lock range.
    pub offset: u64,

    /// Length of the lock range.
    pub length: u64,

    /// Lock flags.
    pub flags: LockFlags,

    /// Reserved (must be 0).
    pub reserved: u32,
}

impl Default for LockElement {
    fn default() -> Self {
        Self {
            offset: 0,
            length: 0,
            flags: LockFlags(0),
            reserved: 0,
        }
    }
}

/// Lock flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct LockFlags(pub u32);

impl LockFlags {
    /// Shared lock (read lock).
    pub const SHARED_LOCK: u32 = 0x00000001;
    /// Exclusive lock (write lock).
    pub const EXCLUSIVE_LOCK: u32 = 0x00000002;
    /// Unlock.
    pub const UNLOCK: u32 = 0x00000004;
    /// Fail immediately if lock cannot be acquired.
    pub const FAIL_IMMEDIATELY: u32 = 0x00000010;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if shared lock.
    #[inline]
    pub fn is_shared(self) -> bool {
        (self.0 & Self::SHARED_LOCK) != 0
    }

    /// Check if exclusive lock.
    #[inline]
    pub fn is_exclusive(self) -> bool {
        (self.0 & Self::EXCLUSIVE_LOCK) != 0
    }

    /// Check if unlock.
    #[inline]
    pub fn is_unlock(self) -> bool {
        (self.0 & Self::UNLOCK) != 0
    }

    /// Check if fail immediately.
    #[inline]
    pub fn fail_immediately(self) -> bool {
        (self.0 & Self::FAIL_IMMEDIATELY) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_lock_request_default() {
        let req = LockRequest::default();
        assert_eq!(req.structure_size, LOCK_REQUEST_SIZE);
    }

    #[test]
    fn test_lock_response_default() {
        let resp = LockResponse::default();
        assert_eq!(resp.structure_size, LOCK_RESPONSE_SIZE);
    }

    #[test]
    fn test_lock_element_roundtrip() {
        let elem = LockElement {
            offset: 0x1000,
            length: 0x2000,
            flags: LockFlags::new(LockFlags::EXCLUSIVE_LOCK | LockFlags::FAIL_IMMEDIATELY),
            reserved: 0,
        };

        let mut buf = Vec::new();
        elem.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = LockElement::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.offset, 0x1000);
        assert_eq!(parsed.length, 0x2000);
        assert!(parsed.flags.is_exclusive());
        assert!(parsed.flags.fail_immediately());
        assert!(!parsed.flags.is_shared());
        assert!(!parsed.flags.is_unlock());
    }

    #[test]
    fn test_request_roundtrip() {
        let req = LockRequest {
            structure_size: LOCK_REQUEST_SIZE,
            lock_count: 2,
            lock_sequence: 1,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = LockRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.lock_count, 2);
        assert_eq!(parsed.lock_sequence, 1);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
    }
}
