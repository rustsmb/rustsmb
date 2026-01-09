//! SMB2 CREATE command.
//!
//! Used to create or open a file, directory, or named pipe.
//! See MS-SMB2 Section 2.2.13 and 2.2.14.

use binrw::{BinRead, BinWrite};

/// SMB2 CREATE request structure size.
pub const CREATE_REQUEST_SIZE: u16 = 57;

/// SMB2 CREATE response structure size.
pub const CREATE_RESPONSE_SIZE: u16 = 89;

/// SMB2 CREATE Request.
///
/// See MS-SMB2 Section 2.2.13.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CreateRequest {
    /// Structure size (must be 57).
    pub structure_size: u16,

    /// Security flags (must be 0).
    pub security_flags: u8,

    /// Requested oplock level.
    pub requested_oplock_level: OplockLevel,

    /// Impersonation level.
    pub impersonation_level: ImpersonationLevel,

    /// SMB2 create flags.
    pub smb_create_flags: u64,

    /// Reserved (must be 0).
    pub reserved: u64,

    /// Desired access mask.
    pub desired_access: u32,

    /// File attributes.
    pub file_attributes: u32,

    /// Share access flags.
    pub share_access: u32,

    /// Create disposition.
    pub create_disposition: u32,

    /// Create options.
    pub create_options: u32,

    /// Name offset from beginning of header.
    pub name_offset: u16,

    /// Name length in bytes.
    pub name_length: u16,

    /// Create contexts offset.
    pub create_contexts_offset: u32,

    /// Create contexts length.
    pub create_contexts_length: u32,
    // Name follows (Unicode string)
    // Create contexts follow
}

impl Default for CreateRequest {
    fn default() -> Self {
        Self {
            structure_size: CREATE_REQUEST_SIZE,
            security_flags: 0,
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0,
            file_attributes: 0,
            share_access: 0,
            create_disposition: 0,
            create_options: 0,
            name_offset: 0,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
        }
    }
}

/// SMB2 CREATE Response.
///
/// See MS-SMB2 Section 2.2.14.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CreateResponse {
    /// Structure size (must be 89).
    pub structure_size: u16,

    /// Oplock level granted.
    pub oplock_level: OplockLevel,

    /// Flags.
    pub flags: CreateResponseFlags,

    /// Create action.
    pub create_action: u32,

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

    /// Reserved2.
    pub reserved2: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Create contexts offset.
    pub create_contexts_offset: u32,

    /// Create contexts length.
    pub create_contexts_length: u32,
    // Create contexts follow
}

impl Default for CreateResponse {
    fn default() -> Self {
        Self {
            structure_size: CREATE_RESPONSE_SIZE,
            oplock_level: OplockLevel::None,
            flags: CreateResponseFlags(0),
            create_action: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
            reserved2: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
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
    /// Level II oplock.
    LevelII = 0x01,
    /// Exclusive oplock.
    Exclusive = 0x08,
    /// Batch oplock.
    Batch = 0x09,
    /// Lease.
    Lease = 0xFF,
}

/// Impersonation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u32)]
#[repr(u32)]
pub enum ImpersonationLevel {
    /// Anonymous.
    Anonymous = 0,
    /// Identification.
    Identification = 1,
    /// Impersonation.
    #[default]
    Impersonation = 2,
    /// Delegation.
    Delegation = 3,
}

/// Create response flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct CreateResponseFlags(pub u8);

impl CreateResponseFlags {
    /// Reparse point.
    pub const REPARSEPOINT: u8 = 0x01;

    /// Create new flags.
    #[inline]
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Check if reparse point.
    #[inline]
    pub fn is_reparse_point(self) -> bool {
        (self.0 & Self::REPARSEPOINT) != 0
    }
}

/// Create options flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CreateOptions(pub u32);

impl CreateOptions {
    /// Directory file.
    pub const DIRECTORY_FILE: u32 = 0x00000001;
    /// Write through.
    pub const WRITE_THROUGH: u32 = 0x00000002;
    /// Sequential only.
    pub const SEQUENTIAL_ONLY: u32 = 0x00000004;
    /// No intermediate buffering.
    pub const NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;
    /// Synchronous IO alert.
    pub const SYNCHRONOUS_IO_ALERT: u32 = 0x00000010;
    /// Synchronous IO non-alert.
    pub const SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
    /// Non-directory file.
    pub const NON_DIRECTORY_FILE: u32 = 0x00000040;
    /// Complete if oplocked.
    pub const COMPLETE_IF_OPLOCKED: u32 = 0x00000100;
    /// No EA knowledge.
    pub const NO_EA_KNOWLEDGE: u32 = 0x00000200;
    /// Random access.
    pub const RANDOM_ACCESS: u32 = 0x00000800;
    /// Delete on close.
    pub const DELETE_ON_CLOSE: u32 = 0x00001000;
    /// Open by file ID.
    pub const OPEN_BY_FILE_ID: u32 = 0x00002000;
    /// Open for backup intent.
    pub const OPEN_FOR_BACKUP_INTENT: u32 = 0x00004000;
    /// No compression.
    pub const NO_COMPRESSION: u32 = 0x00008000;
    /// Open remote instance.
    pub const OPEN_REMOTE_INSTANCE: u32 = 0x00000400;
    /// Open requiring oplock.
    pub const OPEN_REQUIRING_OPLOCK: u32 = 0x00010000;
    /// Disallow exclusive.
    pub const DISALLOW_EXCLUSIVE: u32 = 0x00020000;
    /// Reserve opfilter.
    pub const RESERVE_OPFILTER: u32 = 0x00100000;
    /// Open reparse point.
    pub const OPEN_REPARSE_POINT: u32 = 0x00200000;
    /// Open no recall.
    pub const OPEN_NO_RECALL: u32 = 0x00400000;
    /// Open for free space query.
    pub const OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x00800000;

    /// Create new options.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if directory file.
    #[inline]
    pub fn is_directory(self) -> bool {
        (self.0 & Self::DIRECTORY_FILE) != 0
    }

    /// Check if non-directory file.
    #[inline]
    pub fn is_non_directory(self) -> bool {
        (self.0 & Self::NON_DIRECTORY_FILE) != 0
    }

    /// Check if delete on close.
    #[inline]
    pub fn delete_on_close(self) -> bool {
        (self.0 & Self::DELETE_ON_CLOSE) != 0
    }
}

/// Create disposition values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum CreateDisposition {
    /// Supersede - if exists, supersede; if not, create.
    Supersede = 0,
    /// Open - if exists, open; if not, fail.
    Open = 1,
    /// Create - if exists, fail; if not, create.
    Create = 2,
    /// Open if - if exists, open; if not, create.
    #[default]
    OpenIf = 3,
    /// Overwrite - if exists, open and truncate; if not, fail.
    Overwrite = 4,
    /// Overwrite if - if exists, open and truncate; if not, create.
    OverwriteIf = 5,
}

impl CreateDisposition {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Supersede,
            1 => Self::Open,
            2 => Self::Create,
            3 => Self::OpenIf,
            4 => Self::Overwrite,
            5 => Self::OverwriteIf,
            _ => return None,
        })
    }
}

/// Create action values (response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateAction {
    /// File was superseded.
    Superseded = 0,
    /// Existing file was opened.
    Opened = 1,
    /// New file was created.
    Created = 2,
    /// Existing file was overwritten.
    Overwritten = 3,
}

impl CreateAction {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Superseded,
            1 => Self::Opened,
            2 => Self::Created,
            3 => Self::Overwritten,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_create_request_default() {
        let req = CreateRequest::default();
        assert_eq!(req.structure_size, CREATE_REQUEST_SIZE);
    }

    #[test]
    fn test_create_response_default() {
        let resp = CreateResponse::default();
        assert_eq!(resp.structure_size, CREATE_RESPONSE_SIZE);
    }

    #[test]
    fn test_oplock_level() {
        assert_eq!(OplockLevel::None as u8, 0x00);
        assert_eq!(OplockLevel::Exclusive as u8, 0x08);
        assert_eq!(OplockLevel::Lease as u8, 0xFF);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = CreateResponse {
            structure_size: CREATE_RESPONSE_SIZE,
            oplock_level: OplockLevel::Exclusive,
            flags: CreateResponseFlags(0),
            create_action: CreateAction::Created as u32,
            creation_time: 132000000000000000,
            last_access_time: 132000000000000000,
            last_write_time: 132000000000000000,
            change_time: 132000000000000000,
            allocation_size: 4096,
            end_of_file: 1024,
            file_attributes: 0x20, // Archive
            reserved2: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            create_contexts_offset: 0,
            create_contexts_length: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = CreateResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.oplock_level, OplockLevel::Exclusive);
        assert_eq!(parsed.create_action, CreateAction::Created as u32);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
        assert_eq!(parsed.file_id_volatile, 0x0FEDCBA987654321);
    }

    #[test]
    fn test_create_options() {
        let opts = CreateOptions::new(CreateOptions::DIRECTORY_FILE | CreateOptions::DELETE_ON_CLOSE);
        assert!(opts.is_directory());
        assert!(opts.delete_on_close());
        assert!(!opts.is_non_directory());
    }
}
