//! SMB2 SESSION_SETUP command.
//!
//! Used to establish a session and authenticate the client.
//! See MS-SMB2 Section 2.2.5 and 2.2.6.

use binrw::{BinRead, BinWrite};

/// SMB2 SESSION_SETUP request structure size.
pub const SESSION_SETUP_REQUEST_SIZE: u16 = 25;

/// SMB2 SESSION_SETUP response structure size.
pub const SESSION_SETUP_RESPONSE_SIZE: u16 = 9;

/// SMB2 SESSION_SETUP Request.
///
/// See MS-SMB2 Section 2.2.5.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct SessionSetupRequest {
    /// Structure size (must be 25).
    pub structure_size: u16,

    /// Session binding request flags.
    pub flags: SessionSetupFlags,

    /// Security mode.
    pub security_mode: SessionSecurityMode,

    /// Capabilities.
    pub capabilities: SessionCapabilities,

    /// Channel (must be 0).
    pub channel: u32,

    /// Security buffer offset.
    pub security_buffer_offset: u16,

    /// Security buffer length.
    pub security_buffer_length: u16,

    /// Previous session ID (for re-authentication).
    pub previous_session_id: u64,
    // Security buffer follows (SPNEGO/NTLM token)
}

impl Default for SessionSetupRequest {
    fn default() -> Self {
        Self {
            structure_size: SESSION_SETUP_REQUEST_SIZE,
            flags: SessionSetupFlags(0),
            security_mode: SessionSecurityMode(0),
            capabilities: SessionCapabilities(0),
            channel: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            previous_session_id: 0,
        }
    }
}

/// SMB2 SESSION_SETUP Response.
///
/// See MS-SMB2 Section 2.2.6.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct SessionSetupResponse {
    /// Structure size (must be 9).
    pub structure_size: u16,

    /// Session flags.
    pub session_flags: SessionFlags,

    /// Security buffer offset.
    pub security_buffer_offset: u16,

    /// Security buffer length.
    pub security_buffer_length: u16,
    // Security buffer follows (SPNEGO/NTLM token)
}

impl Default for SessionSetupResponse {
    fn default() -> Self {
        Self {
            structure_size: SESSION_SETUP_RESPONSE_SIZE,
            session_flags: SessionFlags(0),
            security_buffer_offset: 0,
            security_buffer_length: 0,
        }
    }
}

/// Session setup request flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct SessionSetupFlags(pub u8);

impl SessionSetupFlags {
    /// Request to bind to an existing session.
    pub const SESSION_BINDING: u8 = 0x01;

    /// Create new flags.
    #[inline]
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Check if this is a session binding request.
    #[inline]
    pub fn is_binding(self) -> bool {
        (self.0 & Self::SESSION_BINDING) != 0
    }
}

/// Session security mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct SessionSecurityMode(pub u8);

impl SessionSecurityMode {
    /// Signing is enabled.
    pub const SIGNING_ENABLED: u8 = 0x01;
    /// Signing is required.
    pub const SIGNING_REQUIRED: u8 = 0x02;

    /// Create new security mode.
    #[inline]
    pub fn new(value: u8) -> Self {
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

/// Session capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct SessionCapabilities(pub u32);

impl SessionCapabilities {
    /// DFS capability.
    pub const GLOBAL_CAP_DFS: u32 = 0x00000001;
    /// Unused in SMB 3.x.
    pub const GLOBAL_CAP_UNUSED1: u32 = 0x00000002;
    /// Unused in SMB 3.x.
    pub const GLOBAL_CAP_UNUSED2: u32 = 0x00000004;
    /// Unused in SMB 3.x.
    pub const GLOBAL_CAP_UNUSED3: u32 = 0x00000008;

    /// Create new capabilities.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }
}

/// Session flags in response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct SessionFlags(pub u16);

impl SessionFlags {
    /// Session is guest.
    pub const IS_GUEST: u16 = 0x0001;
    /// Session is anonymous (null user).
    pub const IS_NULL: u16 = 0x0002;
    /// Session requires encryption.
    pub const ENCRYPT_DATA: u16 = 0x0004;

    /// Create new session flags.
    #[inline]
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Check if guest session.
    #[inline]
    pub fn is_guest(self) -> bool {
        (self.0 & Self::IS_GUEST) != 0
    }

    /// Check if null (anonymous) session.
    #[inline]
    pub fn is_null(self) -> bool {
        (self.0 & Self::IS_NULL) != 0
    }

    /// Check if encryption is required.
    #[inline]
    pub fn requires_encryption(self) -> bool {
        (self.0 & Self::ENCRYPT_DATA) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_session_setup_request_default() {
        let req = SessionSetupRequest::default();
        assert_eq!(req.structure_size, 25);
    }

    #[test]
    fn test_session_setup_response_default() {
        let resp = SessionSetupResponse::default();
        assert_eq!(resp.structure_size, 9);
    }

    #[test]
    fn test_session_flags() {
        let flags = SessionFlags::new(SessionFlags::IS_GUEST | SessionFlags::ENCRYPT_DATA);
        assert!(flags.is_guest());
        assert!(!flags.is_null());
        assert!(flags.requires_encryption());
    }

    #[test]
    fn test_request_roundtrip() {
        let req = SessionSetupRequest {
            structure_size: 25,
            flags: SessionSetupFlags::new(SessionSetupFlags::SESSION_BINDING),
            security_mode: SessionSecurityMode::new(SessionSecurityMode::SIGNING_REQUIRED),
            capabilities: SessionCapabilities::new(SessionCapabilities::GLOBAL_CAP_DFS),
            channel: 0,
            security_buffer_offset: 88,
            security_buffer_length: 74,
            previous_session_id: 0x123456789ABCDEF0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = SessionSetupRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 25);
        assert!(parsed.flags.is_binding());
        assert!(parsed.security_mode.signing_required());
        assert_eq!(parsed.previous_session_id, 0x123456789ABCDEF0);
    }
}
