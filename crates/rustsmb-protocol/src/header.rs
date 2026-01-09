//! SMB2 packet header parsing.
//!
//! The SMB2 header is a 64-byte fixed structure that appears at the start
//! of every SMB2 message.

use binrw::{binrw, BinRead, BinWrite};

/// SMB2 protocol magic bytes (0xFE 'S' 'M' 'B').
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// SMB2 header size in bytes.
pub const SMB2_HEADER_SIZE: usize = 64;

/// SMB2 packet header (64 bytes).
///
/// See MS-SMB2 Section 2.2.1.
#[binrw]
#[brw(little, magic = b"\xFESMB")]
#[derive(Debug, Clone)]
pub struct Smb2Header {
    /// Structure size (must be 64).
    pub structure_size: u16,

    /// Credit charge for this operation.
    pub credit_charge: u16,

    /// NT_STATUS code (for responses) or channel sequence (for requests).
    pub status: u32,

    /// Command code.
    pub command: Smb2Command,

    /// Credits requested (request) or granted (response).
    pub credits: u16,

    /// Flags.
    pub flags: Smb2Flags,

    /// Offset to next command in compound request (0 if last).
    pub next_command: u32,

    /// Message ID for request/response matching.
    pub message_id: u64,

    /// Reserved (async ID for async responses).
    pub async_id: u32,

    /// Tree ID.
    pub tree_id: u32,

    /// Session ID.
    pub session_id: u64,

    /// Message signature (16 bytes).
    pub signature: [u8; 16],
}

impl Default for Smb2Header {
    fn default() -> Self {
        Self {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::Negotiate,
            credits: 0,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 0,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        }
    }
}

/// SMB2 command codes.
///
/// See MS-SMB2 Section 2.2.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BinRead, BinWrite)]
#[brw(repr = u16)]
#[repr(u16)]
pub enum Smb2Command {
    /// SMB2 NEGOTIATE.
    Negotiate = 0x0000,
    /// SMB2 SESSION_SETUP.
    SessionSetup = 0x0001,
    /// SMB2 LOGOFF.
    Logoff = 0x0002,
    /// SMB2 TREE_CONNECT.
    TreeConnect = 0x0003,
    /// SMB2 TREE_DISCONNECT.
    TreeDisconnect = 0x0004,
    /// SMB2 CREATE.
    Create = 0x0005,
    /// SMB2 CLOSE.
    Close = 0x0006,
    /// SMB2 FLUSH.
    Flush = 0x0007,
    /// SMB2 READ.
    Read = 0x0008,
    /// SMB2 WRITE.
    Write = 0x0009,
    /// SMB2 LOCK.
    Lock = 0x000A,
    /// SMB2 IOCTL.
    Ioctl = 0x000B,
    /// SMB2 CANCEL.
    Cancel = 0x000C,
    /// SMB2 ECHO.
    Echo = 0x000D,
    /// SMB2 QUERY_DIRECTORY.
    QueryDirectory = 0x000E,
    /// SMB2 CHANGE_NOTIFY.
    ChangeNotify = 0x000F,
    /// SMB2 QUERY_INFO.
    QueryInfo = 0x0010,
    /// SMB2 SET_INFO.
    SetInfo = 0x0011,
    /// SMB2 OPLOCK_BREAK.
    OplockBreak = 0x0012,
}

impl Smb2Command {
    /// Returns true if this command requires a valid session ID.
    pub fn requires_session(self) -> bool {
        !matches!(self, Self::Negotiate | Self::Echo)
    }

    /// Returns true if this command requires a valid tree ID.
    pub fn requires_tree(self) -> bool {
        matches!(
            self,
            Self::Create
                | Self::Close
                | Self::Flush
                | Self::Read
                | Self::Write
                | Self::Lock
                | Self::Ioctl
                | Self::QueryDirectory
                | Self::ChangeNotify
                | Self::QueryInfo
                | Self::SetInfo
                | Self::OplockBreak
        )
    }
}

/// SMB2 header flags.
///
/// See MS-SMB2 Section 2.2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct Smb2Flags(pub u32);

impl Smb2Flags {
    /// Response flag (set by server).
    pub const SERVER_TO_REDIR: u32 = 0x00000001;
    /// Async command.
    pub const ASYNC_COMMAND: u32 = 0x00000002;
    /// Related operations (compound).
    pub const RELATED_OPERATIONS: u32 = 0x00000004;
    /// Message is signed.
    pub const SIGNED: u32 = 0x00000008;
    /// Priority mask.
    pub const PRIORITY_MASK: u32 = 0x00000070;
    /// DFS operation.
    pub const DFS_OPERATIONS: u32 = 0x10000000;
    /// Replay operation.
    pub const REPLAY_OPERATION: u32 = 0x20000000;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if this is a response.
    #[inline]
    pub fn is_response(self) -> bool {
        (self.0 & Self::SERVER_TO_REDIR) != 0
    }

    /// Check if this is an async command.
    #[inline]
    pub fn is_async(self) -> bool {
        (self.0 & Self::ASYNC_COMMAND) != 0
    }

    /// Check if message is signed.
    #[inline]
    pub fn is_signed(self) -> bool {
        (self.0 & Self::SIGNED) != 0
    }

    /// Check if this is a related operation.
    #[inline]
    pub fn is_related(self) -> bool {
        (self.0 & Self::RELATED_OPERATIONS) != 0
    }

    /// Set response flag.
    #[inline]
    pub fn set_response(&mut self) {
        self.0 |= Self::SERVER_TO_REDIR;
    }

    /// Set signed flag.
    #[inline]
    pub fn set_signed(&mut self) {
        self.0 |= Self::SIGNED;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_header_size() {
        assert_eq!(SMB2_HEADER_SIZE, 64);
    }

    #[test]
    fn test_command_requires_session() {
        assert!(!Smb2Command::Negotiate.requires_session());
        assert!(!Smb2Command::Echo.requires_session());
        assert!(Smb2Command::SessionSetup.requires_session());
        assert!(Smb2Command::Create.requires_session());
    }

    #[test]
    fn test_command_requires_tree() {
        assert!(!Smb2Command::Negotiate.requires_tree());
        assert!(!Smb2Command::SessionSetup.requires_tree());
        assert!(Smb2Command::Create.requires_tree());
        assert!(Smb2Command::Read.requires_tree());
    }

    #[test]
    fn test_flags() {
        let mut flags = Smb2Flags::new(0);
        assert!(!flags.is_response());
        assert!(!flags.is_signed());

        flags.set_response();
        assert!(flags.is_response());

        flags.set_signed();
        assert!(flags.is_signed());
    }

    #[test]
    fn test_header_roundtrip() {
        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 1,
            status: 0,
            command: Smb2Command::Negotiate,
            credits: 126,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 0,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        let mut buf = Vec::new();
        header.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), SMB2_HEADER_SIZE);
        assert_eq!(&buf[0..4], &SMB2_MAGIC);

        let parsed = Smb2Header::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.command, Smb2Command::Negotiate);
        assert_eq!(parsed.credits, 126);
    }
}
