//! Minimal SMB2 client for HA/failover testing.
//!
//! This client supports:
//! - NEGOTIATE (SMB 2.1/3.0)
//! - SESSION_SETUP (anonymous/guest, session binding)
//! - TREE_CONNECT
//! - CREATE/READ/WRITE/CLOSE
//!
//! Unlike smbclient, this client can:
//! - Keep session state across connections
//! - Perform session binding to resume on another server

#![allow(dead_code)] // Some structs/methods are for future tests

use binrw::{BinRead, BinWrite};
use rustsmb_protocol::{
    negotiate::{Capabilities, NegotiateRequest, NegotiateResponse, SecurityMode},
    session_setup::{SessionSetupFlags, SessionSetupRequest},
    tree_connect::{TreeConnectFlags, TreeConnectRequest},
    Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE,
};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Errors from the test client.
#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Protocol(String),
    Status(u32),
    NotConnected,
    NoSession,
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        ClientError::Io(e)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "I/O error: {}", e),
            ClientError::Protocol(s) => write!(f, "Protocol error: {}", s),
            ClientError::Status(s) => write!(f, "Server returned error status: {:#010x}", s),
            ClientError::NotConnected => write!(f, "Not connected"),
            ClientError::NoSession => write!(f, "Session not established"),
        }
    }
}

impl std::error::Error for ClientError {}

/// File handle for read/write operations.
#[derive(Debug, Clone)]
pub struct FileHandle {
    pub persistent_id: u64,
    pub volatile_id: u64,
}

/// Minimal SMB2 test client.
pub struct TestClient {
    stream: Option<TcpStream>,
    addr: String,
    pub session_id: u64,
    pub tree_id: u32,
    message_id: u64,
    pub dialect: u16,
}

impl TestClient {
    /// Create a new disconnected client.
    pub fn new() -> Self {
        Self {
            stream: None,
            addr: String::new(),
            session_id: 0,
            tree_id: 0,
            message_id: 0,
            dialect: 0,
        }
    }

    /// Connect to an SMB server.
    pub async fn connect(&mut self, addr: &str) -> Result<(), ClientError> {
        let stream = TcpStream::connect(addr).await?;
        self.stream = Some(stream);
        self.addr = addr.to_string();
        self.message_id = 0;
        Ok(())
    }

    /// Disconnect but keep session state for rebinding.
    pub fn disconnect(&mut self) {
        self.stream = None;
        // Keep session_id, tree_id for rebinding
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Reconnect to a different server (for failover testing).
    pub async fn reconnect(&mut self, addr: &str) -> Result<(), ClientError> {
        self.disconnect();
        self.connect(addr).await?;
        // Message ID should restart for new connection
        self.message_id = 0;
        Ok(())
    }

    /// Negotiate SMB2/3 protocol.
    pub async fn negotiate(&mut self) -> Result<u16, ClientError> {
        // Build negotiate request
        let dialects: Vec<u16> = vec![0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
        let msg_id = self.next_message_id();

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::Negotiate,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: msg_id,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        let request = NegotiateRequest {
            structure_size: 36,
            dialect_count: dialects.len() as u16,
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            reserved: 0,
            capabilities: Capabilities::new(Capabilities::LARGE_MTU),
            client_guid: [0; 16],
            negotiate_context_offset: 0,
            negotiate_context_count: 0,
            reserved2: 0,
        };

        // Serialize
        let mut body = Vec::new();
        request.write(&mut Cursor::new(&mut body)).map_err(|e| {
            ClientError::Protocol(format!("Failed to serialize negotiate request: {}", e))
        })?;

        // Add dialects
        for dialect in &dialects {
            body.extend_from_slice(&dialect.to_le_bytes());
        }

        // Send request
        self.send_message(&header, &body).await?;

        // Receive response
        let (resp_header, resp_body) = self.recv_message().await?;

        if resp_header.status != 0 {
            return Err(ClientError::Status(resp_header.status));
        }

        // Parse response
        let response = NegotiateResponse::read(&mut Cursor::new(&resp_body)).map_err(|e| {
            ClientError::Protocol(format!("Failed to parse negotiate response: {}", e))
        })?;

        self.dialect = response.dialect_revision;
        Ok(response.dialect_revision)
    }

    /// Perform session setup (anonymous/guest authentication).
    pub async fn session_setup(&mut self) -> Result<u64, ClientError> {
        let msg_id = self.next_message_id();

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::SessionSetup,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: msg_id,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        // Empty security buffer for anonymous auth
        let request = SessionSetupRequest {
            structure_size: 25,
            flags: SessionSetupFlags::new(0),
            security_mode: rustsmb_protocol::session_setup::SessionSecurityMode::new(0),
            capabilities: rustsmb_protocol::session_setup::SessionCapabilities::new(0),
            channel: 0,
            security_buffer_offset: 88, // After header (64) + fixed request (24)
            security_buffer_length: 0,
            previous_session_id: 0,
        };

        let mut body = Vec::new();
        request.write(&mut Cursor::new(&mut body)).map_err(|e| {
            ClientError::Protocol(format!("Failed to serialize session_setup request: {}", e))
        })?;

        self.send_message(&header, &body).await?;

        let (resp_header, _resp_body) = self.recv_message().await?;

        if resp_header.status != 0 {
            return Err(ClientError::Status(resp_header.status));
        }

        self.session_id = resp_header.session_id;
        Ok(self.session_id)
    }

    /// Bind to an existing session on a new connection (for HA failover).
    pub async fn session_bind(&mut self, previous_session_id: u64) -> Result<(), ClientError> {
        let msg_id = self.next_message_id();

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::SessionSetup,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: msg_id,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        // Session binding request
        let request = SessionSetupRequest {
            structure_size: 25,
            flags: SessionSetupFlags::new(SessionSetupFlags::SESSION_BINDING),
            security_mode: rustsmb_protocol::session_setup::SessionSecurityMode::new(0),
            capabilities: rustsmb_protocol::session_setup::SessionCapabilities::new(0),
            channel: 0,
            security_buffer_offset: 88,
            security_buffer_length: 0,
            previous_session_id,
        };

        let mut body = Vec::new();
        request.write(&mut Cursor::new(&mut body)).map_err(|e| {
            ClientError::Protocol(format!("Failed to serialize session_bind request: {}", e))
        })?;

        self.send_message(&header, &body).await?;

        let (resp_header, _resp_body) = self.recv_message().await?;

        if resp_header.status != 0 {
            return Err(ClientError::Status(resp_header.status));
        }

        // Session bound successfully
        self.session_id = previous_session_id;
        Ok(())
    }

    /// Connect to a share (tree connect).
    pub async fn tree_connect(&mut self, share: &str) -> Result<u32, ClientError> {
        if self.session_id == 0 {
            return Err(ClientError::NoSession);
        }

        // Format path as UNC: \\server\share
        let path = format!("\\\\127.0.0.1\\{}", share);
        let path_utf16: Vec<u16> = path.encode_utf16().collect();
        let path_bytes: Vec<u8> = path_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();

        let msg_id = self.next_message_id();

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::TreeConnect,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: msg_id,
            async_id: 0,
            tree_id: 0,
            session_id: self.session_id,
            signature: [0; 16],
        };

        let request = TreeConnectRequest {
            structure_size: 9,
            flags: TreeConnectFlags(0),
            path_offset: 72, // After header (64) + fixed request (8)
            path_length: path_bytes.len() as u16,
        };

        let mut body = Vec::new();
        request.write(&mut Cursor::new(&mut body)).map_err(|e| {
            ClientError::Protocol(format!("Failed to serialize tree_connect request: {}", e))
        })?;
        body.extend_from_slice(&path_bytes);

        self.send_message(&header, &body).await?;

        let (resp_header, _resp_body) = self.recv_message().await?;

        if resp_header.status != 0 {
            return Err(ClientError::Status(resp_header.status));
        }

        self.tree_id = resp_header.tree_id;
        Ok(self.tree_id)
    }

    /// Send an ECHO request (keepalive).
    pub async fn echo(&mut self) -> Result<(), ClientError> {
        let msg_id = self.next_message_id();

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::Echo,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: msg_id,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        // Echo request body: just structure_size (4) + reserved (0)
        let body = vec![4, 0, 0, 0];

        self.send_message(&header, &body).await?;

        let (resp_header, _) = self.recv_message().await?;

        if resp_header.status != 0 {
            return Err(ClientError::Status(resp_header.status));
        }

        Ok(())
    }

    // Helper: Get next message ID
    fn next_message_id(&mut self) -> u64 {
        let id = self.message_id;
        self.message_id += 1;
        id
    }

    // Helper: Send SMB2 message
    async fn send_message(&mut self, header: &Smb2Header, body: &[u8]) -> Result<(), ClientError> {
        let stream = self.stream.as_mut().ok_or(ClientError::NotConnected)?;

        let mut msg = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());

        // Serialize header
        header
            .write(&mut Cursor::new(&mut msg))
            .map_err(|e| ClientError::Protocol(format!("Failed to serialize header: {}", e)))?;

        // Append body
        msg.extend_from_slice(body);

        // NetBIOS header (4 bytes: 0x00 + 3-byte length)
        let len = msg.len();
        let nb_header = [0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8];

        stream.write_all(&nb_header).await?;
        stream.write_all(&msg).await?;
        stream.flush().await?;

        Ok(())
    }

    // Helper: Receive SMB2 message
    async fn recv_message(&mut self) -> Result<(Smb2Header, Vec<u8>), ClientError> {
        let stream = self.stream.as_mut().ok_or(ClientError::NotConnected)?;

        // Read NetBIOS header
        let mut nb_header = [0u8; 4];
        stream.read_exact(&mut nb_header).await?;

        let len = ((nb_header[1] as usize) << 16)
            | ((nb_header[2] as usize) << 8)
            | (nb_header[3] as usize);

        // Read SMB2 message
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;

        // Parse header
        let header = Smb2Header::read(&mut Cursor::new(&msg))
            .map_err(|e| ClientError::Protocol(format!("Failed to parse header: {}", e)))?;

        // Body is everything after header
        let body = if msg.len() > SMB2_HEADER_SIZE {
            msg[SMB2_HEADER_SIZE..].to_vec()
        } else {
            Vec::new()
        };

        Ok((header, body))
    }
}

impl Default for TestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new() {
        let client = TestClient::new();
        assert!(!client.is_connected());
        assert_eq!(client.session_id, 0);
    }
}
