//! SMB2 TREE_CONNECT command.
//!
//! Used to connect to a share.
//! See MS-SMB2 Section 2.2.9 and 2.2.10.

use binrw::{BinRead, BinWrite};

/// SMB2 TREE_CONNECT request structure size.
pub const TREE_CONNECT_REQUEST_SIZE: u16 = 9;

/// SMB2 TREE_CONNECT response structure size.
pub const TREE_CONNECT_RESPONSE_SIZE: u16 = 16;

/// SMB2 TREE_CONNECT Request.
///
/// See MS-SMB2 Section 2.2.9.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct TreeConnectRequest {
    /// Structure size (must be 9).
    pub structure_size: u16,

    /// Flags (SMB 3.1.1+).
    pub flags: TreeConnectFlags,

    /// Path offset from beginning of header.
    pub path_offset: u16,

    /// Path length in bytes.
    pub path_length: u16,
    // Path follows (Unicode string, e.g., "\\server\share")
}

impl Default for TreeConnectRequest {
    fn default() -> Self {
        Self {
            structure_size: TREE_CONNECT_REQUEST_SIZE,
            flags: TreeConnectFlags(0),
            path_offset: 0,
            path_length: 0,
        }
    }
}

/// SMB2 TREE_CONNECT Response.
///
/// See MS-SMB2 Section 2.2.10.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct TreeConnectResponse {
    /// Structure size (must be 16).
    pub structure_size: u16,

    /// Share type.
    pub share_type: ShareType,

    /// Reserved.
    pub reserved: u8,

    /// Share flags.
    pub share_flags: ShareFlags,

    /// Capabilities.
    pub capabilities: ShareCapabilities,

    /// Maximal access rights.
    pub maximal_access: u32,
}

impl Default for TreeConnectResponse {
    fn default() -> Self {
        Self {
            structure_size: TREE_CONNECT_RESPONSE_SIZE,
            share_type: ShareType::Disk,
            reserved: 0,
            share_flags: ShareFlags(0),
            capabilities: ShareCapabilities(0),
            maximal_access: 0,
        }
    }
}

/// Tree connect flags (SMB 3.1.1+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct TreeConnectFlags(pub u16);

impl TreeConnectFlags {
    /// Cluster reconnect.
    pub const CLUSTER_RECONNECT: u16 = 0x0001;
    /// Redirect to owner.
    pub const REDIRECT_TO_OWNER: u16 = 0x0002;
    /// Extension present.
    pub const EXTENSION_PRESENT: u16 = 0x0004;

    /// Create new flags.
    #[inline]
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Check if cluster reconnect.
    #[inline]
    pub fn is_cluster_reconnect(self) -> bool {
        (self.0 & Self::CLUSTER_RECONNECT) != 0
    }
}

/// Share type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum ShareType {
    /// Disk share.
    #[default]
    Disk = 0x01,
    /// Named pipe share.
    Pipe = 0x02,
    /// Print share.
    Print = 0x03,
}

/// Share flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct ShareFlags(pub u32);

impl ShareFlags {
    /// Manual caching.
    pub const MANUAL_CACHING: u32 = 0x00000000;
    /// Auto caching.
    pub const AUTO_CACHING: u32 = 0x00000010;
    /// VDO caching.
    pub const VDO_CACHING: u32 = 0x00000020;
    /// No caching.
    pub const NO_CACHING: u32 = 0x00000030;
    /// DFS.
    pub const DFS: u32 = 0x00000001;
    /// DFS root.
    pub const DFS_ROOT: u32 = 0x00000002;
    /// Restrict exclusive opens.
    pub const RESTRICT_EXCLUSIVE_OPENS: u32 = 0x00000100;
    /// Force shared delete.
    pub const FORCE_SHARED_DELETE: u32 = 0x00000200;
    /// Allow namespace caching.
    pub const ALLOW_NAMESPACE_CACHING: u32 = 0x00000400;
    /// Access based directory enum.
    pub const ACCESS_BASED_DIRECTORY_ENUM: u32 = 0x00000800;
    /// Force level II oplock.
    pub const FORCE_LEVELII_OPLOCK: u32 = 0x00001000;
    /// Enable hash v1.
    pub const ENABLE_HASH_V1: u32 = 0x00002000;
    /// Enable hash v2.
    pub const ENABLE_HASH_V2: u32 = 0x00004000;
    /// Encrypt data.
    pub const ENCRYPT_DATA: u32 = 0x00008000;
    /// Identity remoting.
    pub const IDENTITY_REMOTING: u32 = 0x00040000;
    /// Compress data.
    pub const COMPRESS_DATA: u32 = 0x00100000;
    /// Isolated transport.
    pub const ISOLATED_TRANSPORT: u32 = 0x00200000;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if DFS share.
    #[inline]
    pub fn is_dfs(self) -> bool {
        (self.0 & Self::DFS) != 0
    }

    /// Check if encryption required.
    #[inline]
    pub fn requires_encryption(self) -> bool {
        (self.0 & Self::ENCRYPT_DATA) != 0
    }
}

/// Share capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct ShareCapabilities(pub u32);

impl ShareCapabilities {
    /// DFS available.
    pub const DFS: u32 = 0x00000008;
    /// Continuous availability.
    pub const CONTINUOUS_AVAILABILITY: u32 = 0x00000010;
    /// Scale out.
    pub const SCALEOUT: u32 = 0x00000020;
    /// Cluster.
    pub const CLUSTER: u32 = 0x00000040;
    /// Asymmetric.
    pub const ASYMMETRIC: u32 = 0x00000080;
    /// Redirect to owner.
    pub const REDIRECT_TO_OWNER: u32 = 0x00000100;

    /// Create new capabilities.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if DFS supported.
    #[inline]
    pub fn supports_dfs(self) -> bool {
        (self.0 & Self::DFS) != 0
    }

    /// Check if continuously available.
    #[inline]
    pub fn is_continuously_available(self) -> bool {
        (self.0 & Self::CONTINUOUS_AVAILABILITY) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_tree_connect_request_default() {
        let req = TreeConnectRequest::default();
        assert_eq!(req.structure_size, TREE_CONNECT_REQUEST_SIZE);
    }

    #[test]
    fn test_tree_connect_response_default() {
        let resp = TreeConnectResponse::default();
        assert_eq!(resp.structure_size, TREE_CONNECT_RESPONSE_SIZE);
    }

    #[test]
    fn test_share_type() {
        assert_eq!(ShareType::Disk as u8, 0x01);
        assert_eq!(ShareType::Pipe as u8, 0x02);
        assert_eq!(ShareType::Print as u8, 0x03);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = TreeConnectResponse {
            structure_size: TREE_CONNECT_RESPONSE_SIZE,
            share_type: ShareType::Disk,
            reserved: 0,
            share_flags: ShareFlags::new(ShareFlags::ENCRYPT_DATA | ShareFlags::DFS),
            capabilities: ShareCapabilities::new(ShareCapabilities::CONTINUOUS_AVAILABILITY),
            maximal_access: 0x001F01FF,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = TreeConnectResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.share_type, ShareType::Disk);
        assert!(parsed.share_flags.requires_encryption());
        assert!(parsed.share_flags.is_dfs());
        assert!(parsed.capabilities.is_continuously_available());
        assert_eq!(parsed.maximal_access, 0x001F01FF);
    }
}
