//! SMB2 NEGOTIATE command.
//!
//! The NEGOTIATE command is used to negotiate the SMB2 protocol dialect.

use binrw::{BinRead, BinWrite};
use rustsmb_core::SmbDialect;

/// SMB2 NEGOTIATE request.
///
/// See MS-SMB2 Section 2.2.3.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct NegotiateRequest {
    /// Structure size (must be 36).
    pub structure_size: u16,

    /// Number of dialects in the dialect array.
    pub dialect_count: u16,

    /// Security mode flags.
    pub security_mode: SecurityMode,

    /// Reserved.
    pub reserved: u16,

    /// Capabilities.
    pub capabilities: Capabilities,

    /// Client GUID.
    pub client_guid: [u8; 16],

    /// Negotiate context offset (SMB 3.1.1).
    pub negotiate_context_offset: u32,

    /// Negotiate context count (SMB 3.1.1).
    pub negotiate_context_count: u16,

    /// Reserved2.
    pub reserved2: u16,
    // Dialects array follows (variable length)
    // Negotiate contexts follow (SMB 3.1.1)
}

impl Default for NegotiateRequest {
    fn default() -> Self {
        Self {
            structure_size: 36,
            dialect_count: 0,
            security_mode: SecurityMode::new(0),
            reserved: 0,
            capabilities: Capabilities::new(0),
            client_guid: [0; 16],
            negotiate_context_offset: 0,
            negotiate_context_count: 0,
            reserved2: 0,
        }
    }
}

/// SMB2 NEGOTIATE response.
///
/// See MS-SMB2 Section 2.2.4.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct NegotiateResponse {
    /// Structure size (must be 65).
    pub structure_size: u16,

    /// Security mode flags.
    pub security_mode: SecurityMode,

    /// Selected dialect.
    pub dialect_revision: u16,

    /// Negotiate context count (SMB 3.1.1).
    pub negotiate_context_count: u16,

    /// Server GUID.
    pub server_guid: [u8; 16],

    /// Server capabilities.
    pub capabilities: Capabilities,

    /// Maximum transact size.
    pub max_transact_size: u32,

    /// Maximum read size.
    pub max_read_size: u32,

    /// Maximum write size.
    pub max_write_size: u32,

    /// System time.
    pub system_time: u64,

    /// Server start time.
    pub server_start_time: u64,

    /// Security buffer offset.
    pub security_buffer_offset: u16,

    /// Security buffer length.
    pub security_buffer_length: u16,

    /// Negotiate context offset (SMB 3.1.1).
    pub negotiate_context_offset: u32,
    // Security buffer follows
    // Negotiate contexts follow (SMB 3.1.1)
}

impl Default for NegotiateResponse {
    fn default() -> Self {
        Self {
            structure_size: 65,
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            dialect_revision: SmbDialect::Smb311.revision(),
            negotiate_context_count: 0,
            server_guid: [0; 16],
            capabilities: Capabilities::new(0),
            max_transact_size: 8 * 1024 * 1024,
            max_read_size: 8 * 1024 * 1024,
            max_write_size: 8 * 1024 * 1024,
            system_time: 0,
            server_start_time: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            negotiate_context_offset: 0,
        }
    }
}

/// Security mode flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct SecurityMode(pub u16);

impl SecurityMode {
    /// Signing is enabled.
    pub const SIGNING_ENABLED: u16 = 0x0001;
    /// Signing is required.
    pub const SIGNING_REQUIRED: u16 = 0x0002;

    /// Create new security mode.
    #[inline]
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Check if signing is enabled.
    #[inline]
    pub fn signing_enabled(self) -> bool {
        (self.0 & Self::SIGNING_ENABLED) != 0
    }

    /// Check if signing is required.
    #[inline]
    pub fn signing_required(self) -> bool {
        (self.0 & Self::SIGNING_REQUIRED) != 0
    }
}

/// SMB2 capabilities flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct Capabilities(pub u32);

impl Capabilities {
    /// Distributed File System (DFS) support.
    pub const DFS: u32 = 0x00000001;
    /// Leasing support.
    pub const LEASING: u32 = 0x00000002;
    /// Large MTU support (implies multi-credit operations).
    pub const LARGE_MTU: u32 = 0x00000004;
    /// Multi-channel support (SMB 3.x only).
    /// Per MS-SMB2 2.2.4: SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x00000008
    pub const MULTI_CHANNEL: u32 = 0x00000008;
    /// Persistent handles.
    pub const PERSISTENT_HANDLES: u32 = 0x00000010;
    /// Directory leasing.
    pub const DIRECTORY_LEASING: u32 = 0x00000020;
    /// Encryption support.
    pub const ENCRYPTION: u32 = 0x00000040;

    /// Create new capabilities.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if DFS is supported.
    #[inline]
    pub fn supports_dfs(self) -> bool {
        (self.0 & Self::DFS) != 0
    }

    /// Check if leasing is supported.
    #[inline]
    pub fn supports_leasing(self) -> bool {
        (self.0 & Self::LEASING) != 0
    }

    /// Check if encryption is supported.
    #[inline]
    pub fn supports_encryption(self) -> bool {
        (self.0 & Self::ENCRYPTION) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_mode() {
        let mode =
            SecurityMode::new(SecurityMode::SIGNING_ENABLED | SecurityMode::SIGNING_REQUIRED);
        assert!(mode.signing_enabled());
        assert!(mode.signing_required());
    }

    #[test]
    fn test_capabilities() {
        let caps = Capabilities::new(Capabilities::LEASING | Capabilities::ENCRYPTION);
        assert!(!caps.supports_dfs());
        assert!(caps.supports_leasing());
        assert!(caps.supports_encryption());
    }
}
