//! SMB2 IOCTL command.
//!
//! Used to send device control codes.
//! See MS-SMB2 Section 2.2.31 and 2.2.32.

use binrw::{BinRead, BinWrite};

/// SMB2 IOCTL request structure size.
pub const IOCTL_REQUEST_SIZE: u16 = 57;

/// SMB2 IOCTL response structure size.
pub const IOCTL_RESPONSE_SIZE: u16 = 49;

/// SMB2 IOCTL Request.
///
/// See MS-SMB2 Section 2.2.31.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct IoctlRequest {
    /// Structure size (must be 57).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,

    /// Control code.
    pub ctl_code: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Input offset from beginning of header.
    pub input_offset: u32,

    /// Input count.
    pub input_count: u32,

    /// Max input response.
    pub max_input_response: u32,

    /// Output offset from beginning of header.
    pub output_offset: u32,

    /// Output count.
    pub output_count: u32,

    /// Max output response.
    pub max_output_response: u32,

    /// Flags.
    pub flags: IoctlFlags,

    /// Reserved2 (must be 0).
    pub reserved2: u32,
    // Input buffer follows
}

impl Default for IoctlRequest {
    fn default() -> Self {
        Self {
            structure_size: IOCTL_REQUEST_SIZE,
            reserved: 0,
            ctl_code: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            input_offset: 0,
            input_count: 0,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 0,
            flags: IoctlFlags(0),
            reserved2: 0,
        }
    }
}

/// SMB2 IOCTL Response.
///
/// See MS-SMB2 Section 2.2.32.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct IoctlResponse {
    /// Structure size (must be 49).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,

    /// Control code.
    pub ctl_code: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Input offset from beginning of header.
    pub input_offset: u32,

    /// Input count.
    pub input_count: u32,

    /// Output offset from beginning of header.
    pub output_offset: u32,

    /// Output count.
    pub output_count: u32,

    /// Flags.
    pub flags: u32,

    /// Reserved2.
    pub reserved2: u32,
    // Output buffer follows
}

impl Default for IoctlResponse {
    fn default() -> Self {
        Self {
            structure_size: IOCTL_RESPONSE_SIZE,
            reserved: 0,
            ctl_code: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            input_offset: 0,
            input_count: 0,
            output_offset: 0,
            output_count: 0,
            flags: 0,
            reserved2: 0,
        }
    }
}

/// IOCTL flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct IoctlFlags(pub u32);

impl IoctlFlags {
    /// IOCTL is a FSCTL.
    pub const IS_FSCTL: u32 = 0x00000001;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if this is a FSCTL.
    #[inline]
    pub fn is_fsctl(self) -> bool {
        (self.0 & Self::IS_FSCTL) != 0
    }
}

/// Common FSCTL codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsctlCode {
    /// DFS get referrals.
    DfsGetReferrals = 0x00060194,
    /// Pipe peek.
    PipePeek = 0x0011400C,
    /// Pipe wait.
    PipeWait = 0x00110018,
    /// Pipe transceive.
    PipeTransceive = 0x0011C017,
    /// SRV request resume key.
    SrvRequestResumeKey = 0x00140078,
    /// SRV read hash.
    SrvReadHash = 0x001441BB,
    /// SRV copychunk.
    SrvCopychunk = 0x001440F2,
    /// SRV copychunk write.
    SrvCopychunkWrite = 0x001480F2,
    /// LMR request resiliency.
    LmrRequestResiliency = 0x001401D4,
    /// Query network interface info.
    QueryNetworkInterfaceInfo = 0x001401FC,
    /// Set reparse point.
    SetReparsePoint = 0x000900A4,
    /// Get reparse point.
    GetReparsePoint = 0x000900A8,
    /// Delete reparse point.
    DeleteReparsePoint = 0x000900AC,
    /// File level trim.
    FileLevelTrim = 0x00098208,
    /// Validate negotiate info.
    ValidateNegotiateInfo = 0x00140204,
}

impl FsctlCode {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0x00060194 => Self::DfsGetReferrals,
            0x0011400C => Self::PipePeek,
            0x00110018 => Self::PipeWait,
            0x0011C017 => Self::PipeTransceive,
            0x00140078 => Self::SrvRequestResumeKey,
            0x001441BB => Self::SrvReadHash,
            0x001440F2 => Self::SrvCopychunk,
            0x001480F2 => Self::SrvCopychunkWrite,
            0x001401D4 => Self::LmrRequestResiliency,
            0x001401FC => Self::QueryNetworkInterfaceInfo,
            0x000900A4 => Self::SetReparsePoint,
            0x000900A8 => Self::GetReparsePoint,
            0x000900AC => Self::DeleteReparsePoint,
            0x00098208 => Self::FileLevelTrim,
            0x00140204 => Self::ValidateNegotiateInfo,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ioctl_request_default() {
        let req = IoctlRequest::default();
        assert_eq!(req.structure_size, IOCTL_REQUEST_SIZE);
    }

    #[test]
    fn test_ioctl_response_default() {
        let resp = IoctlResponse::default();
        assert_eq!(resp.structure_size, IOCTL_RESPONSE_SIZE);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = IoctlRequest {
            structure_size: IOCTL_REQUEST_SIZE,
            reserved: 0,
            ctl_code: FsctlCode::PipeTransceive as u32,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            input_offset: 120,
            input_count: 64,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 4096,
            flags: IoctlFlags::new(IoctlFlags::IS_FSCTL),
            reserved2: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = IoctlRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.ctl_code, FsctlCode::PipeTransceive as u32);
        assert!(parsed.flags.is_fsctl());
        assert_eq!(parsed.max_output_response, 4096);
    }

    #[test]
    fn test_fsctl_codes() {
        assert_eq!(
            FsctlCode::from_u32(0x00140204),
            Some(FsctlCode::ValidateNegotiateInfo)
        );
        assert_eq!(FsctlCode::from_u32(0xFFFFFFFF), None);
    }
}
