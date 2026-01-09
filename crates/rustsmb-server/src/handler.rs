//! Connection handler for SMB clients.
//!
//! Handles reading SMB messages from the socket, parsing headers,
//! dispatching to command handlers, and sending responses.

use crate::{ServerConfig, ShareManager};
use binrw::{BinRead, BinWrite};
use bytes::{Buf, BytesMut};
use rustsmb_auth::{AuthContext, AuthResult, DynAuthProvider};
use rustsmb_core::{NtStatus, SmbDialect};
use rustsmb_protocol::{Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE, SMB2_MAGIC};
use rustsmb_session::{Connection, SessionManager};
use rustsmb_state::{HandleState, SessionState, TreeState};
use rustsmb_vfs::FileType;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, trace, warn};

/// Global connection ID counter.
static CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Context for handling a connection.
pub struct ConnectionHandler<S> {
    /// The underlying socket/stream.
    stream: S,
    /// Read buffer.
    read_buf: BytesMut,
    /// Connection state.
    connection: Connection,
    /// Server configuration.
    config: Arc<ServerConfig>,
    /// Session manager.
    session_manager: Arc<SessionManager>,
    /// Auth provider.
    auth_provider: DynAuthProvider,
    /// Share manager.
    shares: Arc<ShareManager>,
    /// Authentication context (for multi-round auth).
    auth_context: AuthContext,
}

impl<S> ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new connection handler.
    pub fn new(
        stream: S,
        peer_addr: SocketAddr,
        config: Arc<ServerConfig>,
        session_manager: Arc<SessionManager>,
        auth_provider: DynAuthProvider,
        shares: Arc<ShareManager>,
    ) -> Self {
        let conn_id = CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let connection = Connection::new(conn_id, peer_addr);

        Self {
            stream,
            read_buf: BytesMut::with_capacity(64 * 1024),
            connection,
            config,
            session_manager,
            auth_provider,
            shares,
            auth_context: AuthContext::default(),
        }
    }

    /// Run the connection handler loop.
    pub async fn run(&mut self) -> Result<(), HandlerError> {
        info!(
            conn_id = self.connection.id,
            peer = %self.connection.peer_addr,
            "New connection"
        );

        loop {
            // Read the next message
            let message = match self.read_message().await {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    debug!(conn_id = self.connection.id, "Connection closed by client");
                    break;
                }
                Err(e) => {
                    error!(conn_id = self.connection.id, error = %e, "Error reading message");
                    return Err(e);
                }
            };

            // Process the message
            let response = match self.process_message(&message).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(conn_id = self.connection.id, error = %e, "Error processing message");
                    // Build error response
                    self.build_error_response(&message, e.status())?
                }
            };

            // Skip empty responses (e.g., CANCEL)
            if response.is_empty() {
                continue;
            }

            // Send response
            if let Err(e) = self.send_response(&response).await {
                error!(conn_id = self.connection.id, error = %e, "Error sending response");
                return Err(e);
            }

            // Check if we should disconnect
            if self.connection.is_disconnecting() {
                debug!(conn_id = self.connection.id, "Connection disconnecting");
                break;
            }
        }

        info!(conn_id = self.connection.id, "Connection closed");
        Ok(())
    }

    /// Read the next SMB message from the socket.
    async fn read_message(&mut self) -> Result<Option<Vec<u8>>, HandlerError> {
        // SMB messages are prefixed with a 4-byte NetBIOS header containing the length
        loop {
            // Try to parse a complete message from the buffer
            if self.read_buf.len() >= 4 {
                // NetBIOS session message: 1 byte type (0x00) + 3 bytes length
                let len = ((self.read_buf[1] as usize) << 16)
                    | ((self.read_buf[2] as usize) << 8)
                    | (self.read_buf[3] as usize);

                if self.read_buf.len() >= 4 + len {
                    // We have a complete message
                    self.read_buf.advance(4); // Skip NetBIOS header
                    let message = self.read_buf.split_to(len).to_vec();
                    return Ok(Some(message));
                }
            }

            // Need more data
            let n = self.stream.read_buf(&mut self.read_buf).await?;
            if n == 0 {
                if self.read_buf.is_empty() {
                    return Ok(None);
                }
                return Err(HandlerError::Protocol("Incomplete message".into()));
            }
        }
    }

    /// Process an SMB message and generate a response.
    async fn process_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandlerError> {
        // Check minimum size
        if message.len() < SMB2_HEADER_SIZE {
            return Err(HandlerError::Protocol("Message too small".into()));
        }

        // Check magic
        if message[0..4] != SMB2_MAGIC {
            return Err(HandlerError::Protocol("Invalid SMB2 magic".into()));
        }

        // Parse header
        let header = Smb2Header::read(&mut Cursor::new(message))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse header: {}", e)))?;

        trace!(
            conn_id = self.connection.id,
            command = ?header.command,
            message_id = header.message_id,
            session_id = header.session_id,
            "Processing message"
        );

        // Update connection activity
        self.connection.touch();

        // Dispatch to command handler
        let body = &message[SMB2_HEADER_SIZE..];
        self.dispatch_command(&header, body).await
    }

    /// Dispatch to the appropriate command handler.
    async fn dispatch_command(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        match header.command {
            Smb2Command::Negotiate => self.handle_negotiate(header, body).await,
            Smb2Command::SessionSetup => self.handle_session_setup(header, body).await,
            Smb2Command::Logoff => self.handle_logoff(header, body).await,
            Smb2Command::TreeConnect => self.handle_tree_connect(header, body).await,
            Smb2Command::TreeDisconnect => self.handle_tree_disconnect(header, body).await,
            Smb2Command::Create => self.handle_create(header, body).await,
            Smb2Command::Close => self.handle_close(header, body).await,
            Smb2Command::Flush => self.handle_flush(header, body).await,
            Smb2Command::Read => self.handle_read(header, body).await,
            Smb2Command::Write => self.handle_write(header, body).await,
            Smb2Command::Lock => self.handle_lock(header, body).await,
            Smb2Command::Ioctl => self.handle_ioctl(header, body).await,
            Smb2Command::Cancel => self.handle_cancel(header, body).await,
            Smb2Command::Echo => self.handle_echo(header, body).await,
            Smb2Command::QueryDirectory => self.handle_query_directory(header, body).await,
            Smb2Command::ChangeNotify => self.handle_change_notify(header, body).await,
            Smb2Command::QueryInfo => self.handle_query_info(header, body).await,
            Smb2Command::SetInfo => self.handle_set_info(header, body).await,
            Smb2Command::OplockBreak => self.handle_oplock_break(header, body).await,
        }
    }

    /// Send a response message.
    async fn send_response(&mut self, response: &[u8]) -> Result<(), HandlerError> {
        // Add NetBIOS header (4 bytes: 0x00 + 3-byte length)
        let len = response.len();
        let nb_header = [0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8];

        self.stream.write_all(&nb_header).await?;
        self.stream.write_all(response).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Build an error response.
    fn build_error_response(
        &self,
        request: &[u8],
        status: NtStatus,
    ) -> Result<Vec<u8>, HandlerError> {
        // Parse request header to get command and message ID
        let req_header = Smb2Header::read(&mut Cursor::new(request))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse header: {}", e)))?;

        let resp_header = Smb2Header {
            structure_size: 64,
            credit_charge: req_header.credit_charge,
            status: status.code(),
            command: req_header.command,
            credits: 1,
            flags: Smb2Flags(Smb2Flags::SERVER_TO_REDIR),
            next_command: 0,
            message_id: req_header.message_id,
            async_id: 0,
            tree_id: req_header.tree_id,
            session_id: req_header.session_id,
            signature: [0; 16],
        };

        // Build response with error response body (9 bytes)
        let mut response = Vec::with_capacity(SMB2_HEADER_SIZE + 9);
        resp_header
            .write(&mut Cursor::new(&mut response))
            .map_err(|e| HandlerError::Protocol(format!("Failed to write header: {}", e)))?;

        // Error response body: StructureSize (2) + ErrorContextCount (1) + Reserved (1) +
        // ByteCount (4) + ErrorData (variable, 0 for now)
        response.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        response.push(0); // ErrorContextCount
        response.push(0); // Reserved
        response.extend_from_slice(&0u32.to_le_bytes()); // ByteCount
        response.push(0); // ErrorData (1 byte minimum)

        Ok(response)
    }

    /// Build a response header.
    fn build_response_header(&self, request: &Smb2Header, status: NtStatus) -> Smb2Header {
        Smb2Header {
            structure_size: 64,
            credit_charge: request.credit_charge,
            status: status.code(),
            command: request.command,
            credits: self.connection.grant_credits(request.credits, false),
            flags: Smb2Flags(Smb2Flags::SERVER_TO_REDIR),
            next_command: 0,
            message_id: request.message_id,
            async_id: 0,
            tree_id: request.tree_id,
            session_id: request.session_id,
            signature: [0; 16],
        }
    }
}

// Command handlers
impl<S> ConnectionHandler<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn handle_negotiate(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::negotiate::{
            Capabilities, NegotiateRequest, NegotiateResponse, SecurityMode,
        };

        debug!(conn_id = self.connection.id, "NEGOTIATE request");

        // Parse request (fixed 36-byte structure)
        let request = NegotiateRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse negotiate: {}", e)))?;

        // Parse dialects from after the fixed structure
        let dialect_count = request.dialect_count as usize;
        let dialects_offset = 36; // Size of NegotiateRequest
        let mut dialects = Vec::with_capacity(dialect_count);

        for i in 0..dialect_count {
            let offset = dialects_offset + i * 2;
            if offset + 2 <= body.len() {
                let dialect = u16::from_le_bytes([body[offset], body[offset + 1]]);
                dialects.push(dialect);
            }
        }

        // Select best dialect
        let dialect = self.select_dialect(&dialects);
        let dialect_value = dialect.map(|d| d.revision()).unwrap_or(0xFFFF);

        if dialect.is_none() {
            return Err(HandlerError::Status(NtStatus::NotSupported));
        }

        let selected_dialect = dialect.unwrap();
        self.connection.negotiate(selected_dialect);

        // Build capabilities
        let mut caps_value = Capabilities::LARGE_MTU;
        if selected_dialect >= SmbDialect::Smb300 {
            caps_value |= Capabilities::ENCRYPTION;
        }

        // Build response
        let resp_header = self.build_response_header(header, NtStatus::Success);

        let response = NegotiateResponse {
            structure_size: 65,
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            dialect_revision: dialect_value,
            negotiate_context_count: 0,
            server_guid: self.config.server_guid,
            capabilities: Capabilities::new(caps_value),
            max_transact_size: self.connection.max_transact_size,
            max_read_size: self.connection.max_read_size,
            max_write_size: self.connection.max_write_size,
            system_time: current_filetime(),
            server_start_time: 0,
            security_buffer_offset: 128,
            security_buffer_length: 0,
            negotiate_context_offset: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_session_setup(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::session_setup::{
            SessionFlags, SessionSetupRequest, SessionSetupResponse,
        };

        debug!(conn_id = self.connection.id, "SESSION_SETUP request");

        // Parse request (fixed 25-byte structure)
        let request = SessionSetupRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse session_setup: {}", e)))?;

        // Parse security buffer from after the fixed structure
        let sec_offset = request.security_buffer_offset as usize;
        let sec_len = request.security_buffer_length as usize;

        // The offset is from the start of the SMB2 message (including header)
        // In our case, body starts after the header, so we need to adjust
        let body_offset = sec_offset.saturating_sub(SMB2_HEADER_SIZE);
        let security_buffer = if body_offset + sec_len <= body.len() {
            &body[body_offset..body_offset + sec_len]
        } else if sec_len <= body.len() {
            // Try from start of body if offset math doesn't work
            &body[..sec_len.min(body.len())]
        } else {
            &[]
        };

        // Perform authentication
        let auth_result = self
            .auth_provider
            .authenticate(&mut self.auth_context, security_buffer)
            .await
            .map_err(|e| HandlerError::Auth(e.to_string()))?;

        match auth_result {
            AuthResult::Success { user, session_key } => {
                // Generate session ID
                let session_id = self
                    .session_manager
                    .next_session_id()
                    .await
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;

                // Create session state
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let session = SessionState {
                    session_id,
                    user_id: user.username.clone(),
                    domain: user.domain.clone(),
                    session_key,
                    dialect: self.connection.dialect.unwrap_or(SmbDialect::Smb202),
                    signing_required: self.connection.signing_required,
                    encryption_required: self.connection.encryption_required,
                    is_guest: user.is_guest,
                    created_at: now,
                    last_access: now,
                    expires_at: now + 3600, // 1 hour
                };

                self.session_manager
                    .create_session(session)
                    .await
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;

                self.connection.add_session(session_id);

                info!(
                    conn_id = self.connection.id,
                    session_id,
                    user = %user.username,
                    "Session established"
                );

                let mut resp_header = self.build_response_header(header, NtStatus::Success);
                resp_header.session_id = session_id;

                let mut session_flags = 0u16;
                if user.is_guest {
                    session_flags |= SessionFlags::IS_GUEST;
                }
                if user.is_anonymous {
                    session_flags |= SessionFlags::IS_NULL;
                }

                let response = SessionSetupResponse {
                    structure_size: 9,
                    session_flags: SessionFlags::new(session_flags),
                    security_buffer_offset: 72,
                    security_buffer_length: 0,
                };

                self.serialize_response(&resp_header, &response)
            }
            AuthResult::Continue { response_token } => {
                // More rounds needed
                let resp_header =
                    self.build_response_header(header, NtStatus::MoreProcessingRequired);

                let response = SessionSetupResponse {
                    structure_size: 9,
                    session_flags: SessionFlags::new(0),
                    security_buffer_offset: 72,
                    security_buffer_length: response_token.len() as u16,
                };

                // Serialize header and body, then append security buffer
                let mut result = self.serialize_response(&resp_header, &response)?;
                result.extend_from_slice(&response_token);
                Ok(result)
            }
            AuthResult::Failure { reason } => {
                warn!(
                    conn_id = self.connection.id,
                    error = %reason,
                    "Authentication failed"
                );
                Err(HandlerError::Status(NtStatus::LogonFailure))
            }
        }
    }

    async fn handle_logoff(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::logoff::LogoffResponse;

        debug!(
            conn_id = self.connection.id,
            session_id = header.session_id,
            "LOGOFF request"
        );

        // Remove session
        self.connection.remove_session(header.session_id);
        let _ = self.session_manager.delete_session(header.session_id).await;

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = LogoffResponse {
            structure_size: 4,
            reserved: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_tree_connect(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::tree_connect::{
            ShareCapabilities, ShareFlags, ShareType, TreeConnectRequest, TreeConnectResponse,
        };

        debug!(conn_id = self.connection.id, "TREE_CONNECT request");

        // Parse request
        let request = TreeConnectRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse tree_connect: {}", e)))?;

        // Parse path from after the fixed structure
        let path_offset = request.path_offset as usize;
        let path_len = request.path_length as usize;

        let body_offset = path_offset.saturating_sub(SMB2_HEADER_SIZE);
        let path_bytes = if body_offset + path_len <= body.len() {
            &body[body_offset..body_offset + path_len]
        } else {
            &[]
        };

        // Decode UTF-16LE path
        let path = decode_utf16le(path_bytes);

        // Extract share name from path (\\server\share)
        let share_name = extract_share_name(&path);

        // Check if share exists
        let share_config = self.shares.get_share_config(&share_name).ok_or_else(|| {
            warn!(conn_id = self.connection.id, share = %share_name, "Share not found");
            HandlerError::Status(NtStatus::BadNetworkName)
        })?;

        // Generate tree ID
        let tree_id = self
            .session_manager
            .next_tree_id(header.session_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Create tree state
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let tree = TreeState {
            tree_id,
            session_id: header.session_id,
            share_name: share_name.clone(),
            share_path: share_config.path.clone(),
            access_flags: 0x001F01FF, // Full access
            is_dfs: false,
            created_at: now,
        };

        self.session_manager
            .create_tree(tree)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        info!(
            conn_id = self.connection.id,
            session_id = header.session_id,
            tree_id,
            share = %share_name,
            "Tree connected"
        );

        let mut resp_header = self.build_response_header(header, NtStatus::Success);
        resp_header.tree_id = tree_id;

        let response = TreeConnectResponse {
            structure_size: 16,
            share_type: ShareType::Disk,
            reserved: 0,
            share_flags: ShareFlags(0),
            capabilities: ShareCapabilities(0),
            maximal_access: 0x001F01FF, // Full access
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_tree_disconnect(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::tree_disconnect::TreeDisconnectResponse;

        debug!(
            conn_id = self.connection.id,
            tree_id = header.tree_id,
            "TREE_DISCONNECT request"
        );

        let _ = self
            .session_manager
            .delete_tree(header.session_id, header.tree_id)
            .await;

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = TreeDisconnectResponse {
            structure_size: 4,
            reserved: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_create(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::create::{
            CreateRequest, CreateResponse, CreateResponseFlags, OplockLevel,
        };

        debug!(conn_id = self.connection.id, "CREATE request");

        // Parse request
        let request = CreateRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse create: {}", e)))?;

        // Parse filename from after the fixed structure
        let name_offset = request.name_offset as usize;
        let name_len = request.name_length as usize;

        let body_offset = name_offset.saturating_sub(SMB2_HEADER_SIZE);
        let name_bytes = if body_offset + name_len <= body.len() {
            &body[body_offset..body_offset + name_len]
        } else {
            &[]
        };

        let filename = decode_utf16le(name_bytes);

        // Get share backend
        let tree = self
            .session_manager
            .get_tree(header.session_id, header.tree_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        let backend = self
            .shares
            .get_share(&tree.share_name)
            .ok_or(HandlerError::Status(NtStatus::BadNetworkName))?;

        // Open/create file
        let open_flags = rustsmb_vfs::OpenFlags::new(
            rustsmb_vfs::OpenFlags::READ | rustsmb_vfs::OpenFlags::WRITE,
        );
        let _file_handle = backend
            .open(&filename, open_flags, 0o644)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        // Generate handle IDs
        let handle_id = self
            .session_manager
            .next_handle_id()
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Create handle state
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let handle = HandleState {
            persistent_id: handle_id,
            volatile_id: handle_id,
            tree_id: header.tree_id,
            session_id: header.session_id,
            path: filename.clone(),
            access_mask: request.desired_access,
            share_access: request.share_access,
            create_options: request.create_options,
            is_durable: false,
            is_persistent: false,
            created_at: now,
            last_access: now,
        };

        self.session_manager
            .create_handle(handle)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        debug!(
            conn_id = self.connection.id,
            handle_id,
            path = %filename,
            "File opened"
        );

        let resp_header = self.build_response_header(header, NtStatus::Success);

        // Split handle_id into two u64 values for the response
        let file_id_persistent = handle_id as u64;
        let file_id_volatile = (handle_id >> 64) as u64;

        let response = CreateResponse {
            structure_size: 89,
            oplock_level: OplockLevel::None,
            flags: CreateResponseFlags(0),
            create_action: 1, // Opened
            creation_time: current_filetime(),
            last_access_time: current_filetime(),
            last_write_time: current_filetime(),
            change_time: current_filetime(),
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0x80, // Normal
            reserved2: 0,
            file_id_persistent,
            file_id_volatile,
            create_contexts_offset: 0,
            create_contexts_length: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_close(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::close::{CloseFlags, CloseRequest, CloseResponse};

        debug!(conn_id = self.connection.id, "CLOSE request");

        let request = CloseRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse close: {}", e)))?;

        // Reconstruct handle ID from file_id
        let handle_id =
            (request.file_id_volatile as u128) << 64 | request.file_id_persistent as u128;

        // Delete handle
        let _ = self.session_manager.delete_handle(handle_id).await;

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = CloseResponse {
            structure_size: 60,
            flags: CloseFlags(0),
            reserved: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_flush(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::flush::FlushResponse;

        debug!(conn_id = self.connection.id, "FLUSH request");

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = FlushResponse {
            structure_size: 4,
            reserved: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_read(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::read::{ReadRequest, ReadResponse, ReadResponseFlags};

        debug!(conn_id = self.connection.id, "READ request");

        let request = ReadRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse read: {}", e)))?;

        // Reconstruct handle ID
        let handle_id =
            (request.file_id_volatile as u128) << 64 | request.file_id_persistent as u128;

        // Get handle info
        let handle = self
            .session_manager
            .get_handle(handle_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidHandle))?;

        // Get tree and backend
        let tree = self
            .session_manager
            .get_tree(header.session_id, handle.tree_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        let backend = self
            .shares
            .get_share(&tree.share_name)
            .ok_or(HandlerError::Status(NtStatus::BadNetworkName))?;

        // Re-open file for reading (stateless approach)
        let open_flags = rustsmb_vfs::OpenFlags::new(rustsmb_vfs::OpenFlags::READ);
        let file_handle = backend
            .open(&handle.path, open_flags, 0o644)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        // Read data
        let data = backend
            .read(&file_handle, request.offset, request.length)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        let resp_header = self.build_response_header(header, NtStatus::Success);

        // Build response header first
        let response = ReadResponse {
            structure_size: 17,
            data_offset: 80,
            reserved: 0,
            data_length: data.len() as u32,
            data_remaining: 0,
            flags: ReadResponseFlags(0),
        };

        // Serialize header and response body
        let mut result = self.serialize_response(&resp_header, &response)?;
        // Append read data
        result.extend_from_slice(&data);

        Ok(result)
    }

    async fn handle_write(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::write::{WriteRequest, WriteResponse};

        debug!(conn_id = self.connection.id, "WRITE request");

        let request = WriteRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse write: {}", e)))?;

        // Reconstruct handle ID
        let handle_id =
            (request.file_id_volatile as u128) << 64 | request.file_id_persistent as u128;

        // Get handle info
        let handle = self
            .session_manager
            .get_handle(handle_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidHandle))?;

        // Get tree and backend
        let tree = self
            .session_manager
            .get_tree(header.session_id, handle.tree_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        let backend = self
            .shares
            .get_share(&tree.share_name)
            .ok_or(HandlerError::Status(NtStatus::BadNetworkName))?;

        // Re-open file for writing (stateless approach)
        let open_flags = rustsmb_vfs::OpenFlags::new(rustsmb_vfs::OpenFlags::WRITE);
        let file_handle = backend
            .open(&handle.path, open_flags, 0o644)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        // Parse write data from body
        let data_offset = request.data_offset as usize;
        let data_len = request.length as usize;
        let body_offset = data_offset.saturating_sub(SMB2_HEADER_SIZE);
        let data = if body_offset + data_len <= body.len() {
            &body[body_offset..body_offset + data_len]
        } else {
            &[]
        };

        // Write data
        let bytes_written = backend
            .write(&file_handle, request.offset, data)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = WriteResponse {
            structure_size: 17,
            reserved: 0,
            count: bytes_written,
            remaining: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_lock(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::lock::LockResponse;

        debug!(conn_id = self.connection.id, "LOCK request");

        // Simplified: just acknowledge
        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = LockResponse {
            structure_size: 4,
            reserved: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_ioctl(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        debug!(conn_id = self.connection.id, "IOCTL request");
        // Most IOCTLs are not supported
        let _ = header;
        Err(HandlerError::Status(NtStatus::NotSupported))
    }

    async fn handle_cancel(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        debug!(
            conn_id = self.connection.id,
            message_id = header.message_id,
            "CANCEL request"
        );

        // Cancel any pending async operations
        self.connection
            .async_requests
            .cancel_by_message_id(header.message_id);

        // CANCEL has no response
        Ok(Vec::new())
    }

    async fn handle_echo(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::echo::EchoResponse;

        debug!(conn_id = self.connection.id, "ECHO request");

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = EchoResponse {
            structure_size: 4,
            reserved: 0,
        };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_query_directory(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::query_directory::{QueryDirectoryRequest, QueryDirectoryResponse};

        debug!(conn_id = self.connection.id, "QUERY_DIRECTORY request");

        let request = QueryDirectoryRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse query_dir: {}", e)))?;

        // Reconstruct handle ID
        let handle_id =
            (request.file_id_volatile as u128) << 64 | request.file_id_persistent as u128;

        // Get handle info
        let handle = self
            .session_manager
            .get_handle(handle_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidHandle))?;

        // Get backend
        let tree = self
            .session_manager
            .get_tree(header.session_id, handle.tree_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        let backend = self
            .shares
            .get_share(&tree.share_name)
            .ok_or(HandlerError::Status(NtStatus::BadNetworkName))?;

        // Read directory
        let entries = backend
            .readdir(&handle.path)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        // Build output buffer (simplified FileBothDirectoryInformation)
        let output_buffer = build_directory_info(&entries);

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = QueryDirectoryResponse {
            structure_size: 9,
            output_buffer_offset: 72,
            output_buffer_length: output_buffer.len() as u32,
        };

        // Serialize header and response, then append output buffer
        let mut result = self.serialize_response(&resp_header, &response)?;
        result.extend_from_slice(&output_buffer);

        Ok(result)
    }

    async fn handle_change_notify(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        debug!(conn_id = self.connection.id, "CHANGE_NOTIFY request");
        // Change notify is typically async - simplified to not supported
        let _ = header;
        Err(HandlerError::Status(NtStatus::NotSupported))
    }

    async fn handle_query_info(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::query_info::{QueryInfoRequest, QueryInfoResponse};

        debug!(conn_id = self.connection.id, "QUERY_INFO request");

        let request = QueryInfoRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse query_info: {}", e)))?;

        // Reconstruct handle ID
        let handle_id =
            (request.file_id_volatile as u128) << 64 | request.file_id_persistent as u128;

        // Get handle info
        let handle = self
            .session_manager
            .get_handle(handle_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidHandle))?;

        // Get backend
        let tree = self
            .session_manager
            .get_tree(header.session_id, handle.tree_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        let backend = self
            .shares
            .get_share(&tree.share_name)
            .ok_or(HandlerError::Status(NtStatus::BadNetworkName))?;

        // Get file info
        let metadata = backend
            .stat(&handle.path)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        // Build response based on info type
        let output_buffer = build_file_info(&metadata, request.file_info_class);

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = QueryInfoResponse {
            structure_size: 9,
            output_buffer_offset: 72,
            output_buffer_length: output_buffer.len() as u32,
        };

        // Serialize header and response, then append output buffer
        let mut result = self.serialize_response(&resp_header, &response)?;
        result.extend_from_slice(&output_buffer);

        Ok(result)
    }

    async fn handle_set_info(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::set_info::SetInfoResponse;

        debug!(conn_id = self.connection.id, "SET_INFO request");

        // Simplified: acknowledge without actually setting
        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = SetInfoResponse { structure_size: 2 };

        self.serialize_response(&resp_header, &response)
    }

    async fn handle_oplock_break(
        &mut self,
        header: &Smb2Header,
        _body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        debug!(conn_id = self.connection.id, "OPLOCK_BREAK request");
        // Oplocks not fully supported
        let _ = header;
        Err(HandlerError::Status(NtStatus::NotSupported))
    }

    /// Select the best dialect from the client's list.
    fn select_dialect(&self, client_dialects: &[u16]) -> Option<SmbDialect> {
        // Prefer newer dialects
        let server_dialects = [
            (0x0311, SmbDialect::Smb311),
            (0x0302, SmbDialect::Smb302),
            (0x0300, SmbDialect::Smb300),
            (0x0210, SmbDialect::Smb210),
            (0x0202, SmbDialect::Smb202),
        ];

        for (value, dialect) in server_dialects {
            if client_dialects.contains(&value) {
                return Some(dialect);
            }
        }
        None
    }

    /// Serialize a response with header and body.
    fn serialize_response<T: BinWrite + binrw::meta::WriteEndian>(
        &self,
        header: &Smb2Header,
        body: &T,
    ) -> Result<Vec<u8>, HandlerError>
    where
        for<'a> T::Args<'a>: Default,
    {
        let mut buf = Vec::with_capacity(256);

        header
            .write(&mut Cursor::new(&mut buf))
            .map_err(|e| HandlerError::Protocol(format!("Failed to write header: {}", e)))?;

        body.write(&mut Cursor::new(&mut buf))
            .map_err(|e| HandlerError::Protocol(format!("Failed to write body: {}", e)))?;

        Ok(buf)
    }
}

/// Handler error types.
#[derive(Debug)]
pub enum HandlerError {
    /// I/O error.
    Io(std::io::Error),
    /// Protocol error.
    Protocol(String),
    /// Authentication error.
    Auth(String),
    /// VFS error.
    Vfs(String),
    /// Internal error.
    Internal(String),
    /// Status code error.
    Status(NtStatus),
}

impl HandlerError {
    /// Get the NT_STATUS for this error.
    pub fn status(&self) -> NtStatus {
        match self {
            Self::Io(_) => NtStatus::InternalError,
            Self::Protocol(_) => NtStatus::InvalidParameter,
            Self::Auth(_) => NtStatus::LogonFailure,
            Self::Vfs(_) => NtStatus::ObjectNameNotFound,
            Self::Internal(_) => NtStatus::InternalError,
            Self::Status(s) => *s,
        }
    }
}

impl From<std::io::Error> for HandlerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Protocol(e) => write!(f, "Protocol error: {}", e),
            Self::Auth(e) => write!(f, "Auth error: {}", e),
            Self::Vfs(e) => write!(f, "VFS error: {}", e),
            Self::Internal(e) => write!(f, "Internal error: {}", e),
            Self::Status(s) => write!(f, "Status: {:?}", s),
        }
    }
}

impl std::error::Error for HandlerError {}

/// Get current time as Windows FILETIME (100-nanosecond intervals since 1601).
fn current_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Windows epoch is Jan 1, 1601; Unix epoch is Jan 1, 1970
    // Difference is 11644473600 seconds
    const EPOCH_DIFF: u64 = 11644473600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() + EPOCH_DIFF) * TICKS_PER_SEC + d.subsec_nanos() as u64 / 100)
        .unwrap_or(0)
}

/// Extract share name from UNC path (\\server\share).
fn extract_share_name(path: &str) -> String {
    let path = path.trim_start_matches('\\');
    if let Some(idx) = path.find('\\') {
        let after_server = &path[idx + 1..];
        if let Some(end) = after_server.find('\\') {
            after_server[..end].to_string()
        } else {
            after_server.to_string()
        }
    } else {
        path.to_string()
    }
}

/// Decode UTF-16LE bytes to a string.
fn decode_utf16le(bytes: &[u8]) -> String {
    let u16_vec: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&u16_vec)
}

/// Build directory info buffer from entries.
fn build_directory_info(entries: &[rustsmb_vfs::DirEntry]) -> Vec<u8> {
    let mut buf = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        let name_bytes: Vec<u16> = entry.name.encode_utf16().collect();
        let name_len = name_bytes.len() * 2;

        // FileBothDirectoryInformation structure
        let entry_size = 94 + name_len; // Fixed fields + name
        let next_offset = if i < entries.len() - 1 {
            // Align to 8 bytes
            (entry_size + 7) & !7
        } else {
            0
        };

        buf.extend_from_slice(&(next_offset as u32).to_le_bytes()); // NextEntryOffset
        buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // CreationTime
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastAccessTime
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastWriteTime
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // ChangeTime
        buf.extend_from_slice(&entry.metadata.size.to_le_bytes()); // EndOfFile
        buf.extend_from_slice(&entry.metadata.size.to_le_bytes()); // AllocationSize

        let is_dir = entry.metadata.file_type == FileType::Directory;
        let attrs = if is_dir { 0x10u32 } else { 0x80u32 }; // Directory or Normal
        buf.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
        buf.extend_from_slice(&(name_len as u32).to_le_bytes()); // FileNameLength
        buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
        buf.push(0); // ShortNameLength
        buf.push(0); // Reserved
        buf.extend_from_slice(&[0u8; 24]); // ShortName (12 UTF-16 chars)

        // FileName
        for c in name_bytes {
            buf.extend_from_slice(&c.to_le_bytes());
        }

        // Padding to 8-byte alignment
        if next_offset > 0 {
            let padding = next_offset - entry_size;
            buf.extend(std::iter::repeat(0u8).take(padding));
        }
    }

    buf
}

/// Build file info buffer from metadata.
fn build_file_info(metadata: &rustsmb_vfs::Metadata, info_class: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    let is_dir = metadata.file_type == FileType::Directory;

    match info_class {
        // FileBasicInformation
        4 => {
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // CreationTime
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastAccessTime
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastWriteTime
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // ChangeTime
            let attrs = if is_dir { 0x10u32 } else { 0x80u32 };
            buf.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
            buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        }
        // FileStandardInformation
        5 => {
            buf.extend_from_slice(&metadata.size.to_le_bytes()); // AllocationSize
            buf.extend_from_slice(&metadata.size.to_le_bytes()); // EndOfFile
            buf.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
            buf.push(0); // DeletePending
            buf.push(if is_dir { 1 } else { 0 }); // Directory
            buf.extend_from_slice(&[0u8; 2]); // Reserved
        }
        // FileAllInformation (combination)
        18 => {
            // Basic info
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            let attrs = if is_dir { 0x10u32 } else { 0x80u32 };
            buf.extend_from_slice(&attrs.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            // Standard info
            buf.extend_from_slice(&metadata.size.to_le_bytes());
            buf.extend_from_slice(&metadata.size.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes());
            buf.push(0);
            buf.push(if is_dir { 1 } else { 0 });
            buf.extend_from_slice(&[0u8; 2]);
            // Internal, EA, Access, Position info...
            buf.extend_from_slice(&[0u8; 48]);
        }
        _ => {
            // Unknown info class - return minimal data
            buf.extend_from_slice(&[0u8; 8]);
        }
    }

    buf
}
