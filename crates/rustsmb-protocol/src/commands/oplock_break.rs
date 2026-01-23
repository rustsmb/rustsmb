//! SMB2 OPLOCK_BREAK notification.
//!
//! Used to notify clients of oplock or lease breaks.
//! See MS-SMB2 Section 2.2.23, 2.2.24, 2.2.25.

use binrw::{BinRead, BinWrite};

/// SMB2 OPLOCK_BREAK notification structure size.
pub const OPLOCK_BREAK_NOTIFICATION_SIZE: u16 = 24;

/// SMB2 OPLOCK_BREAK acknowledgment request structure size.
pub const OPLOCK_BREAK_ACK_SIZE: u16 = 24;

/// SMB2 OPLOCK_BREAK response structure size.
pub const OPLOCK_BREAK_RESPONSE_SIZE: u16 = 24;

/// SMB2 LEASE_BREAK notification structure size.
pub const LEASE_BREAK_NOTIFICATION_SIZE: u16 = 44;

/// SMB2 LEASE_BREAK acknowledgment structure size.
pub const LEASE_BREAK_ACK_SIZE: u16 = 36;

/// SMB2 LEASE_BREAK response structure size.
pub const LEASE_BREAK_RESPONSE_SIZE: u16 = 36;

/// SMB2 Oplock Break Notification.
///
/// Sent by server to notify client of oplock break.
/// See MS-SMB2 Section 2.2.23.1.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct OplockBreakNotification {
    /// Structure size (must be 24).
    pub structure_size: u16,

    /// New oplock level.
    pub oplock_level: OplockLevel,

    /// Reserved.
    pub reserved: u8,

    /// Reserved2.
    pub reserved2: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
}

impl Default for OplockBreakNotification {
    fn default() -> Self {
        Self {
            structure_size: OPLOCK_BREAK_NOTIFICATION_SIZE,
            oplock_level: OplockLevel::None,
            reserved: 0,
            reserved2: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 Oplock Break Acknowledgment.
///
/// Sent by client to acknowledge oplock break.
/// See MS-SMB2 Section 2.2.24.1.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct OplockBreakAcknowledgment {
    /// Structure size (must be 24).
    pub structure_size: u16,

    /// Oplock level being acknowledged.
    pub oplock_level: OplockLevel,

    /// Reserved.
    pub reserved: u8,

    /// Reserved2.
    pub reserved2: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
}

impl Default for OplockBreakAcknowledgment {
    fn default() -> Self {
        Self {
            structure_size: OPLOCK_BREAK_ACK_SIZE,
            oplock_level: OplockLevel::None,
            reserved: 0,
            reserved2: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// SMB2 Oplock Break Response.
///
/// Server response to oplock break acknowledgment.
/// See MS-SMB2 Section 2.2.25.1.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct OplockBreakResponse {
    /// Structure size (must be 24).
    pub structure_size: u16,

    /// Oplock level.
    pub oplock_level: OplockLevel,

    /// Reserved.
    pub reserved: u8,

    /// Reserved2.
    pub reserved2: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,
}

impl Default for OplockBreakResponse {
    fn default() -> Self {
        Self {
            structure_size: OPLOCK_BREAK_RESPONSE_SIZE,
            oplock_level: OplockLevel::None,
            reserved: 0,
            reserved2: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
        }
    }
}

/// Oplock level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum OplockLevel {
    /// No oplock.
    #[default]
    None = 0x00,
    /// Level II oplock (shared read cache).
    LevelII = 0x01,
    /// Exclusive oplock.
    Exclusive = 0x08,
    /// Batch oplock.
    Batch = 0x09,
    /// Lease (SMB 2.1+).
    Lease = 0xFF,
}

/// SMB2 Lease Break Notification.
///
/// Sent by server to notify client of lease break.
/// See MS-SMB2 Section 2.2.23.2.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LeaseBreakNotification {
    /// Structure size (must be 44).
    pub structure_size: u16,

    /// New epoch (SMB 3.x).
    pub new_epoch: u16,

    /// Flags.
    pub flags: LeaseBreakFlags,

    /// Lease key.
    pub lease_key: [u8; 16],

    /// Current lease state.
    pub current_lease_state: LeaseState,

    /// New lease state.
    pub new_lease_state: LeaseState,

    /// Break reason (SMB 3.x).
    pub break_reason: u32,

    /// Access mask hint.
    pub access_mask_hint: u32,

    /// Share mask hint.
    pub share_mask_hint: u32,
}

impl Default for LeaseBreakNotification {
    fn default() -> Self {
        Self {
            structure_size: LEASE_BREAK_NOTIFICATION_SIZE,
            new_epoch: 0,
            flags: LeaseBreakFlags(0),
            lease_key: [0; 16],
            current_lease_state: LeaseState(0),
            new_lease_state: LeaseState(0),
            break_reason: 0,
            access_mask_hint: 0,
            share_mask_hint: 0,
        }
    }
}

/// SMB2 Lease Break Acknowledgment.
///
/// Sent by client to acknowledge lease break.
/// See MS-SMB2 Section 2.2.24.2.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LeaseBreakAcknowledgment {
    /// Structure size (must be 36).
    pub structure_size: u16,

    /// Reserved.
    pub reserved: u16,

    /// Flags.
    pub flags: u32,

    /// Lease key.
    pub lease_key: [u8; 16],

    /// Lease state being acknowledged.
    pub lease_state: LeaseState,

    /// Lease duration (must be 0).
    pub lease_duration: u64,
}

impl Default for LeaseBreakAcknowledgment {
    fn default() -> Self {
        Self {
            structure_size: LEASE_BREAK_ACK_SIZE,
            reserved: 0,
            flags: 0,
            lease_key: [0; 16],
            lease_state: LeaseState(0),
            lease_duration: 0,
        }
    }
}

/// SMB2 Lease Break Response.
///
/// Server response to lease break acknowledgment.
/// See MS-SMB2 Section 2.2.25.2.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct LeaseBreakResponse {
    /// Structure size (must be 36).
    pub structure_size: u16,

    /// Reserved.
    pub reserved: u16,

    /// Flags.
    pub flags: u32,

    /// Lease key.
    pub lease_key: [u8; 16],

    /// Lease state.
    pub lease_state: LeaseState,

    /// Lease duration (must be 0).
    pub lease_duration: u64,
}

impl Default for LeaseBreakResponse {
    fn default() -> Self {
        Self {
            structure_size: LEASE_BREAK_RESPONSE_SIZE,
            reserved: 0,
            flags: 0,
            lease_key: [0; 16],
            lease_state: LeaseState(0),
            lease_duration: 0,
        }
    }
}

/// Lease break flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct LeaseBreakFlags(pub u32);

impl LeaseBreakFlags {
    /// Acknowledgment required.
    pub const ACK_REQUIRED: u32 = 0x00000001;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if acknowledgment required.
    #[inline]
    pub fn ack_required(self) -> bool {
        (self.0 & Self::ACK_REQUIRED) != 0
    }
}

/// Lease state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct LeaseState(pub u32);

impl LeaseState {
    /// No lease.
    pub const NONE: u32 = 0x00;
    /// Read caching.
    pub const READ_CACHING: u32 = 0x01;
    /// Write caching.
    pub const WRITE_CACHING: u32 = 0x02;
    /// Handle caching.
    pub const HANDLE_CACHING: u32 = 0x04;

    /// Create new lease state.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if read caching.
    #[inline]
    pub fn has_read_caching(self) -> bool {
        (self.0 & Self::READ_CACHING) != 0
    }

    /// Check if handle caching.
    #[inline]
    pub fn has_handle_caching(self) -> bool {
        (self.0 & Self::HANDLE_CACHING) != 0
    }

    /// Check if write caching.
    #[inline]
    pub fn has_write_caching(self) -> bool {
        (self.0 & Self::WRITE_CACHING) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_oplock_break_notification_default() {
        let notif = OplockBreakNotification::default();
        assert_eq!(notif.structure_size, OPLOCK_BREAK_NOTIFICATION_SIZE);
    }

    #[test]
    fn test_oplock_break_ack_default() {
        let ack = OplockBreakAcknowledgment::default();
        assert_eq!(ack.structure_size, OPLOCK_BREAK_ACK_SIZE);
    }

    #[test]
    fn test_oplock_break_response_default() {
        let resp = OplockBreakResponse::default();
        assert_eq!(resp.structure_size, OPLOCK_BREAK_RESPONSE_SIZE);
    }

    #[test]
    fn test_lease_break_notification_default() {
        let notif = LeaseBreakNotification::default();
        assert_eq!(notif.structure_size, LEASE_BREAK_NOTIFICATION_SIZE);
    }

    #[test]
    fn test_oplock_level() {
        assert_eq!(OplockLevel::None as u8, 0x00);
        assert_eq!(OplockLevel::LevelII as u8, 0x01);
        assert_eq!(OplockLevel::Exclusive as u8, 0x08);
        assert_eq!(OplockLevel::Batch as u8, 0x09);
        assert_eq!(OplockLevel::Lease as u8, 0xFF);
    }

    #[test]
    fn test_lease_state() {
        let state = LeaseState::new(LeaseState::READ_CACHING | LeaseState::WRITE_CACHING);
        assert!(state.has_read_caching());
        assert!(state.has_write_caching());
        assert!(!state.has_handle_caching());
    }

    #[test]
    fn test_oplock_notification_roundtrip() {
        let notif = OplockBreakNotification {
            structure_size: OPLOCK_BREAK_NOTIFICATION_SIZE,
            oplock_level: OplockLevel::LevelII,
            reserved: 0,
            reserved2: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
        };

        let mut buf = Vec::new();
        notif.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = OplockBreakNotification::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.oplock_level, OplockLevel::LevelII);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
    }

    #[test]
    fn test_lease_break_notification_roundtrip() {
        let notif = LeaseBreakNotification {
            structure_size: LEASE_BREAK_NOTIFICATION_SIZE,
            new_epoch: 2,
            flags: LeaseBreakFlags::new(LeaseBreakFlags::ACK_REQUIRED),
            lease_key: [1; 16],
            current_lease_state: LeaseState::new(
                LeaseState::READ_CACHING | LeaseState::WRITE_CACHING | LeaseState::HANDLE_CACHING,
            ),
            new_lease_state: LeaseState::new(LeaseState::READ_CACHING),
            break_reason: 0,
            access_mask_hint: 0,
            share_mask_hint: 0,
        };

        let mut buf = Vec::new();
        notif.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = LeaseBreakNotification::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.new_epoch, 2);
        assert!(parsed.flags.ack_required());
        assert!(parsed.current_lease_state.has_read_caching());
        assert!(parsed.current_lease_state.has_write_caching());
        assert!(parsed.current_lease_state.has_handle_caching());
        assert!(parsed.new_lease_state.has_read_caching());
        assert!(!parsed.new_lease_state.has_write_caching());
    }
}
