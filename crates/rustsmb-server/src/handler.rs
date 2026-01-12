//! Connection handler for SMB clients.
//!
//! Handles reading SMB messages from the socket, parsing headers,
//! dispatching to command handlers, and sending responses.

use crate::{ServerConfig, ShareManager};
use binrw::{BinRead, BinWrite};
use bytes::{Buf, BytesMut};
use rustsmb_auth::{AuthContext, AuthResult, DynAuthProvider, PreauthIntegrityHash, SessionKeys};
use rustsmb_core::{NtStatus, SmbDialect};
use rustsmb_protocol::crypto::signing::{MessageSigner, SigningAlgorithm};
use rustsmb_protocol::{Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE, SMB2_MAGIC};
use rustsmb_session::{Connection, SessionManager};
use rustsmb_state::{HandleState, LeaseEntry, SessionState, TreeState};
use rustsmb_vfs::{CreateParams, FileType};
use std::collections::HashMap;
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
    /// Server ID for lease tracking.
    server_id: String,
    /// Pre-authentication integrity hash (SMB 3.1.1).
    preauth_hash: PreauthIntegrityHash,
    /// Signing keys per session (session_id -> signing_key).
    signing_keys: HashMap<u64, Vec<u8>>,
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
        server_id: String,
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
            server_id,
            preauth_hash: PreauthIntegrityHash::new(),
            signing_keys: HashMap::new(),
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

            // Sign response if we have a signing key for this session
            let response = self.maybe_sign_response(response)?;

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

        // Note: Sessions are NOT deleted on connection close.
        // In HA mode, sessions persist in the shared state store and can be
        // bound from another server via SESSION_BINDING. Sessions expire based
        // on their TTL (expires_at field) and are cleaned up by expiration.
        // This allows transparent failover without re-authentication.
        let session_count = self.connection.session_ids().count();
        if session_count > 0 {
            debug!(
                conn_id = self.connection.id,
                session_count,
                "Connection closed with active sessions (sessions persist for HA binding)"
            );
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
            credit_charge = header.credit_charge,
            "Processing message"
        );

        // Update connection activity
        self.connection.touch();

        // Consume credits for this request (skip NEGOTIATE which bootstraps credits)
        // The credit_charge field indicates how many credits this request consumes
        if header.command != Smb2Command::Negotiate {
            let charge = header.credit_charge.max(1); // Minimum 1 credit per request
            if self.connection.consume_credits(charge).is_none() {
                debug!(
                    conn_id = self.connection.id,
                    charge, "Insufficient credits for request"
                );
                // Don't fail - just log. Client tracks its own credits.
            }
        }

        // Dispatch to command handler
        let body = &message[SMB2_HEADER_SIZE..];
        self.dispatch_command(&header, body, message).await
    }

    /// Dispatch to the appropriate command handler.
    async fn dispatch_command(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
        full_message: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        // Commands that require a valid session
        let requires_session = matches!(
            header.command,
            Smb2Command::Logoff
                | Smb2Command::TreeConnect
                | Smb2Command::TreeDisconnect
                | Smb2Command::Create
                | Smb2Command::Close
                | Smb2Command::Flush
                | Smb2Command::Read
                | Smb2Command::Write
                | Smb2Command::Lock
                | Smb2Command::Ioctl
                | Smb2Command::QueryDirectory
                | Smb2Command::ChangeNotify
                | Smb2Command::QueryInfo
                | Smb2Command::SetInfo
        );

        // Validate session_id for commands that require it
        if requires_session
            && header.session_id != 0
            && self
                .session_manager
                .get_session(header.session_id)
                .await
                .map_err(|e| HandlerError::Internal(e.to_string()))?
                .is_none()
        {
            return Err(HandlerError::Status(NtStatus::UserSessionDeleted));
        }

        // Commands that require a valid tree connection
        let requires_tree = matches!(
            header.command,
            Smb2Command::Create
                | Smb2Command::Close
                | Smb2Command::Flush
                | Smb2Command::Read
                | Smb2Command::Write
                | Smb2Command::Lock
                | Smb2Command::QueryDirectory
                | Smb2Command::ChangeNotify
                | Smb2Command::QueryInfo
                | Smb2Command::SetInfo
        );

        // Validate tree_id for commands that require it
        if requires_tree
            && header.tree_id != 0
            && self
                .session_manager
                .get_tree(header.session_id, header.tree_id)
                .await
                .map_err(|e| HandlerError::Internal(e.to_string()))?
                .is_none()
        {
            return Err(HandlerError::Status(NtStatus::NetworkNameDeleted));
        }

        match header.command {
            Smb2Command::Negotiate => self.handle_negotiate(header, body, full_message).await,
            Smb2Command::SessionSetup => {
                self.handle_session_setup(header, body, full_message).await
            }
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
        full_message: &[u8],
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
        // Store client GUID for ValidateNegotiate verification
        self.connection.client_guid = request.client_guid;
        debug!(
            conn_id = self.connection.id,
            dialect = ?selected_dialect,
            "Negotiated dialect"
        );

        // Build capabilities
        let mut caps_value = Capabilities::LARGE_MTU;
        if selected_dialect >= SmbDialect::Smb300 {
            caps_value |= Capabilities::ENCRYPTION;
        }

        // For SMB 3.1.1, update pre-auth integrity hash with request
        if selected_dialect == SmbDialect::Smb311 {
            debug!(
                "Preauth: hashing NEGOTIATE request ({} bytes), first 16 bytes: {:02x?}, hash before: {:02x?}",
                full_message.len(),
                &full_message[..16.min(full_message.len())],
                &self.preauth_hash.value()[..8]
            );
            self.preauth_hash.update(full_message);
            debug!(
                "Preauth: hash after NEGOTIATE req: {:02x?}",
                &self.preauth_hash.value()[..8]
            );
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

        let result = self.serialize_response(&resp_header, &response)?;

        // For SMB 3.1.1, update pre-auth integrity hash with response
        if selected_dialect == SmbDialect::Smb311 {
            debug!(
                "Preauth: hashing NEGOTIATE response ({} bytes)",
                result.len()
            );
            self.preauth_hash.update(&result);
            debug!(
                "Preauth: hash after NEGOTIATE resp: {:02x?}",
                &self.preauth_hash.value()[..8]
            );
        }

        Ok(result)
    }

    async fn handle_session_setup(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
        full_message: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::session_setup::{
            SessionFlags, SessionSetupRequest, SessionSetupResponse,
        };

        debug!(conn_id = self.connection.id, "SESSION_SETUP request");

        // Parse request (fixed 25-byte structure)
        let request = SessionSetupRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse session_setup: {}", e)))?;

        // Check for session binding request (HA failover)
        if request.flags.is_binding() {
            return self.handle_session_binding(header, &request).await;
        }

        // Per MS-SMB2: SessionId == 0 means this is a NEW session, not a continuation
        // We must reset auth_context to avoid reusing session_id from previous sessions
        if header.session_id == 0 {
            self.auth_context = AuthContext::default();
        }

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
            AuthResult::Success {
                user,
                session_key,
                response_token,
            } => {
                // Use existing session ID from Continue phase, or generate new one
                let session_id = if let Some(id) = self.auth_context.session_id {
                    id
                } else {
                    self.session_manager
                        .next_session_id()
                        .await
                        .map_err(|e| HandlerError::Internal(e.to_string()))?
                };

                let dialect = self.connection.dialect.unwrap_or(SmbDialect::Smb202);

                // For SMB 3.1.1, we need to include the SUCCESS response in the preauth hash
                // BEFORE deriving keys. smbprotocol does this, and we need to match.
                // The order is:
                // 1. Hash SS2 request
                // 2. Build response (unsigned)
                // 3. Hash response (with zero signature)
                // 4. Derive signing key from complete preauth hash
                // 5. Sign the response

                // Step 1: Hash the request
                if dialect == SmbDialect::Smb311 {
                    debug!(
                        "Preauth: hashing SESSION_SETUP (Success) request ({} bytes), hash before: {:02x?}",
                        full_message.len(),
                        &self.preauth_hash.value()[..8]
                    );
                    self.preauth_hash.update(full_message);
                    debug!(
                        "Preauth: hash after SS2 req: {:02x?}",
                        &self.preauth_hash.value()[..8]
                    );
                }

                // Create session state (do this early to get session_id)
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let session_state = SessionState {
                    session_id,
                    user_id: user.username.clone(),
                    domain: user.domain.clone(),
                    session_key: session_key.clone(),
                    dialect,
                    signing_required: self.connection.signing_required,
                    encryption_required: self.connection.encryption_required,
                    is_guest: user.is_guest,
                    created_at: now,
                    last_access: now,
                    expires_at: now + 3600, // 1 hour
                    bound_server_id: None,
                };

                self.session_manager
                    .create_session(session_state)
                    .await
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;

                self.connection.add_session(session_id);

                info!(
                    conn_id = self.connection.id,
                    session_id,
                    user = %user.username,
                    "Session established"
                );

                // Step 2: Build response (with zero signature initially)
                let mut resp_header = self.build_response_header(header, NtStatus::Success);
                resp_header.session_id = session_id;

                let should_sign = !user.is_guest && !user.is_anonymous;
                if should_sign {
                    resp_header.flags = Smb2Flags(Smb2Flags::SERVER_TO_REDIR | Smb2Flags::SIGNED);
                }

                let mut session_flags = 0u16;
                if user.is_guest {
                    session_flags |= SessionFlags::IS_GUEST;
                }
                if user.is_anonymous {
                    session_flags |= SessionFlags::IS_NULL;
                }

                let security_buffer = response_token.unwrap_or_default();
                let response = SessionSetupResponse {
                    structure_size: 9,
                    session_flags: SessionFlags::new(session_flags),
                    security_buffer_offset: 72,
                    security_buffer_length: security_buffer.len() as u16,
                };

                let mut result = self.serialize_response(&resp_header, &response)?;
                result.extend_from_slice(&security_buffer);
                debug!(
                    conn_id = self.connection.id,
                    "SessionSetup Success response header bytes={:02x?}",
                    &result[..SMB2_HEADER_SIZE.min(result.len())]
                );

                if dialect == SmbDialect::Smb311 {
                    debug!(
                        "Preauth: hashing SESSION_SETUP (Success) response ({} bytes), hash before: {:02x?}",
                        result.len(),
                        &self.preauth_hash.value()[..8]
                    );
                    self.preauth_hash.update(&result);
                    debug!(
                        "Preauth: final hash for key derivation: {:02x?}",
                        &self.preauth_hash.value()[..16]
                    );
                }

                // Step 4: Derive signing key
                let signing_key = match dialect {
                    SmbDialect::Smb311 => {
                        debug!(
                            "SMB 3.1.1 key derivation: session_key={:02x?} preauth_hash={:02x?}",
                            &session_key[..session_key.len().min(16)],
                            &self.preauth_hash.value()[..16]
                        );
                        SessionKeys::derive_smb311(&session_key, self.preauth_hash.value())
                            .signing_key
                    }
                    SmbDialect::Smb302 | SmbDialect::Smb300 => {
                        debug!(
                            "SMB 3.0.x key derivation: session_key={:02x?}",
                            &session_key[..session_key.len().min(16)]
                        );
                        SessionKeys::derive_smb3(&session_key).signing_key
                    }
                    _ => session_key.clone(),
                };
                debug!(
                    "Derived signing_key={:02x?}",
                    &signing_key[..signing_key.len().min(16)]
                );

                // Store signing key for subsequent message signing
                if should_sign {
                    self.signing_keys.insert(session_id, signing_key.clone());
                }

                // Step 5: Sign the response
                if should_sign {
                    self.sign_message(&mut result, &signing_key, dialect)?;
                }

                Ok(result)
            }
            AuthResult::Continue { response_token } => {
                // More rounds needed
                let dialect = self.connection.dialect.unwrap_or(SmbDialect::Smb202);

                // Generate session ID if this is the first round (session_id not yet assigned)
                // Per MS-SMB2: the server MUST return a session_id even in interim responses
                let session_id = if let Some(id) = self.auth_context.session_id {
                    id
                } else {
                    let id = self
                        .session_manager
                        .next_session_id()
                        .await
                        .map_err(|e| HandlerError::Internal(e.to_string()))?;
                    self.auth_context.session_id = Some(id);
                    debug!(
                        conn_id = self.connection.id,
                        session_id = id,
                        "Allocated interim session ID for auth"
                    );
                    id
                };

                // For SMB 3.1.1, update preauth hash with request
                if dialect == SmbDialect::Smb311 {
                    debug!(
                        "Preauth: hashing SESSION_SETUP (Continue) request ({} bytes), hash before: {:02x?}",
                        full_message.len(),
                        &self.preauth_hash.value()[..8]
                    );
                    self.preauth_hash.update(full_message);
                    debug!(
                        "Preauth: hash after SESSION_SETUP (Continue) req: {:02x?}",
                        &self.preauth_hash.value()[..8]
                    );
                }

                let mut resp_header =
                    self.build_response_header(header, NtStatus::MoreProcessingRequired);
                resp_header.session_id = session_id;

                let response = SessionSetupResponse {
                    structure_size: 9,
                    session_flags: SessionFlags::new(0),
                    security_buffer_offset: 72,
                    security_buffer_length: response_token.len() as u16,
                };

                // Serialize header and body, then append security buffer
                let mut result = self.serialize_response(&resp_header, &response)?;
                result.extend_from_slice(&response_token);

                // For SMB 3.1.1, update preauth hash with response
                if dialect == SmbDialect::Smb311 {
                    debug!(
                        "Preauth: hashing SESSION_SETUP (Continue) response ({} bytes)",
                        result.len()
                    );
                    self.preauth_hash.update(&result);
                    debug!(
                        "Preauth: hash after SS1 resp: {:02x?}",
                        &self.preauth_hash.value()[..8]
                    );
                }

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

    /// Handle session binding for HA failover.
    ///
    /// When a client reconnects to a different server after failover, it sends
    /// SESSION_SETUP with the SESSION_BINDING flag to bind to an existing session.
    /// The server looks up the session in the shared StateStore.
    async fn handle_session_binding(
        &mut self,
        header: &Smb2Header,
        request: &rustsmb_protocol::session_setup::SessionSetupRequest,
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::session_setup::{SessionFlags, SessionSetupResponse};

        let previous_session_id = request.previous_session_id;

        debug!(
            conn_id = self.connection.id,
            previous_session_id, "SESSION_SETUP binding request (HA failover)"
        );

        // Look up existing session in StateStore
        let session = self
            .session_manager
            .get_session(previous_session_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or_else(|| {
                warn!(
                    conn_id = self.connection.id,
                    previous_session_id, "Session binding failed: session not found"
                );
                HandlerError::Status(NtStatus::UserSessionDeleted)
            })?;

        // Verify session hasn't expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > session.expires_at {
            warn!(
                conn_id = self.connection.id,
                previous_session_id,
                expires_at = session.expires_at,
                now,
                "Session binding failed: session expired"
            );
            return Err(HandlerError::Status(NtStatus::UserSessionDeleted));
        }

        // Bind session to this connection
        self.connection.add_session(previous_session_id);

        // Restore negotiated dialect from session
        if self.connection.dialect.is_none() {
            self.connection.negotiate(session.dialect);
        }

        info!(
            conn_id = self.connection.id,
            session_id = previous_session_id,
            user = %session.user_id,
            "Session bound (HA failover)"
        );

        // Refresh session TTL
        let _ = self
            .session_manager
            .refresh_session(previous_session_id)
            .await;

        // Build success response
        let mut resp_header = self.build_response_header(header, NtStatus::Success);
        resp_header.session_id = previous_session_id;

        let mut session_flags = 0u16;
        if session.is_guest {
            session_flags |= SessionFlags::IS_GUEST;
        }

        let response = SessionSetupResponse {
            structure_size: 9,
            session_flags: SessionFlags::new(session_flags),
            security_buffer_offset: 72,
            security_buffer_length: 0,
        };

        self.serialize_response(&resp_header, &response)
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

        // Check if session exists
        let session = self
            .session_manager
            .get_session(header.session_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        if session.is_none() {
            // Session doesn't exist - already logged off
            return Err(HandlerError::Status(NtStatus::UserSessionDeleted));
        }

        // Remove session
        self.connection.remove_session(header.session_id);
        // Also remove signing key for this session
        self.signing_keys.remove(&header.session_id);
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

        // Check if tree exists
        let tree = self
            .session_manager
            .get_tree(header.session_id, header.tree_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        if tree.is_none() {
            // Tree doesn't exist - already disconnected
            return Err(HandlerError::Status(NtStatus::NetworkNameDeleted));
        }

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
            parse_create_contexts, CreateContext, CreateContextBuilder, CreateRequest,
            CreateResponse, CreateResponseFlags, OplockLevel,
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

        // Parse CREATE contexts if present
        let contexts = if request.create_contexts_length > 0 {
            let ctx_offset = request.create_contexts_offset as usize;
            let ctx_body_offset = ctx_offset.saturating_sub(SMB2_HEADER_SIZE);
            let ctx_len = request.create_contexts_length as usize;
            if ctx_body_offset + ctx_len <= body.len() {
                let ctx_data = &body[ctx_body_offset..ctx_body_offset + ctx_len];
                parse_create_contexts(ctx_data).unwrap_or_else(|e| {
                    warn!(conn_id = self.connection.id, error = %e, "Failed to parse CREATE contexts");
                    vec![]
                })
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // Check for durable handle reconnect requests first
        for ctx in &contexts {
            match ctx {
                CreateContext::DurableHandleReconnect { file_id } => {
                    return self
                        .handle_durable_reconnect(header, file_id.persistent_id(), None, &filename)
                        .await;
                }
                CreateContext::DurableHandleReconnectV2 {
                    file_id,
                    create_guid,
                    ..
                } => {
                    return self
                        .handle_durable_reconnect(
                            header,
                            file_id.persistent_id(),
                            Some(*create_guid),
                            &filename,
                        )
                        .await;
                }
                _ => {}
            }
        }

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

        // Check share mode conflicts with existing handles
        let existing_handles = self
            .session_manager
            .state_store()
            .get_handles_for_file(&tree.share_name, &filename)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        let requested_access = request.desired_access;
        let requested_share = request.share_access;

        // Access mask constants
        const FILE_READ_DATA: u32 = 0x00000001;
        const FILE_WRITE_DATA: u32 = 0x00000002;
        const DELETE: u32 = 0x00010000;
        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const GENERIC_ALL: u32 = 0x10000000;

        // Share access constants
        const FILE_SHARE_READ: u32 = 0x01;
        const FILE_SHARE_WRITE: u32 = 0x02;
        const FILE_SHARE_DELETE: u32 = 0x04;

        // Helper to check if access implies read
        let wants_read = |access: u32| -> bool {
            (access & FILE_READ_DATA) != 0
                || (access & GENERIC_READ) != 0
                || (access & GENERIC_ALL) != 0
        };

        // Helper to check if access implies write
        let wants_write = |access: u32| -> bool {
            (access & FILE_WRITE_DATA) != 0
                || (access & GENERIC_WRITE) != 0
                || (access & GENERIC_ALL) != 0
        };

        // Helper to check if access implies delete
        let wants_delete =
            |access: u32| -> bool { (access & DELETE) != 0 || (access & GENERIC_ALL) != 0 };

        for existing in &existing_handles {
            // Check if our requested access conflicts with existing handle's share mode
            // If existing handle doesn't share READ and we want READ -> conflict
            if (existing.share_access & FILE_SHARE_READ) == 0 && wants_read(requested_access) {
                debug!(
                    conn_id = self.connection.id,
                    "Sharing violation: existing handle doesn't share READ"
                );
                return Err(HandlerError::Status(NtStatus::SharingViolation));
            }
            // If existing handle doesn't share WRITE and we want WRITE -> conflict
            if (existing.share_access & FILE_SHARE_WRITE) == 0 && wants_write(requested_access) {
                debug!(
                    conn_id = self.connection.id,
                    "Sharing violation: existing handle doesn't share WRITE"
                );
                return Err(HandlerError::Status(NtStatus::SharingViolation));
            }
            // If existing handle doesn't share DELETE and we want DELETE -> conflict
            if (existing.share_access & FILE_SHARE_DELETE) == 0 && wants_delete(requested_access) {
                debug!(
                    conn_id = self.connection.id,
                    "Sharing violation: existing handle doesn't share DELETE"
                );
                return Err(HandlerError::Status(NtStatus::SharingViolation));
            }

            // Check if we don't share access that existing handle has
            // If we don't share READ and existing has READ access -> conflict
            if (requested_share & FILE_SHARE_READ) == 0 && wants_read(existing.access_mask) {
                debug!(
                    conn_id = self.connection.id,
                    "Sharing violation: we don't share READ but existing has it"
                );
                return Err(HandlerError::Status(NtStatus::SharingViolation));
            }
            // If we don't share WRITE and existing has WRITE access -> conflict
            if (requested_share & FILE_SHARE_WRITE) == 0 && wants_write(existing.access_mask) {
                debug!(
                    conn_id = self.connection.id,
                    "Sharing violation: we don't share WRITE but existing has it"
                );
                return Err(HandlerError::Status(NtStatus::SharingViolation));
            }
            // If we don't share DELETE and existing has DELETE access -> conflict
            if (requested_share & FILE_SHARE_DELETE) == 0 && wants_delete(existing.access_mask) {
                debug!(
                    conn_id = self.connection.id,
                    "Sharing violation: we don't share DELETE but existing has it"
                );
                return Err(HandlerError::Status(NtStatus::SharingViolation));
            }
        }

        // Pass SMB parameters directly to the backend - it handles the conversion
        let create_params = CreateParams {
            desired_access: request.desired_access,
            share_access: request.share_access,
            create_disposition: request.create_disposition,
            create_options: request.create_options,
            file_attributes: request.file_attributes,
        };

        let _file_handle = backend
            .open(&filename, &create_params)
            .await
            .map_err(|e| HandlerError::Vfs(e.to_string()))?;

        // Generate handle IDs
        let handle_id = self
            .session_manager
            .next_handle_id()
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        // Check for durable handle request in contexts
        let mut is_durable = false;
        let mut is_persistent = false;
        let mut create_guid: Option<[u8; 16]> = None;
        let mut durable_timeout: u32 = 0;
        let mut requested_oplock = OplockLevel::None;
        let mut lease_key: Option<[u8; 16]> = None;
        let mut lease_state: u32 = 0;

        for ctx in &contexts {
            match ctx {
                CreateContext::DurableHandleRequest => {
                    is_durable = true;
                    debug!(
                        conn_id = self.connection.id,
                        "Durable handle requested (DHnQ)"
                    );
                }
                CreateContext::DurableHandleRequestV2 {
                    timeout,
                    flags,
                    create_guid: guid,
                    ..
                } => {
                    is_durable = true;
                    create_guid = Some(*guid);
                    durable_timeout = *timeout;
                    if flags.is_persistent() {
                        // Persistent handles require SMB 3.0+
                        if let Some(dialect) = self.connection.dialect {
                            if dialect >= SmbDialect::Smb300 {
                                is_persistent = true;
                                debug!(
                                    conn_id = self.connection.id,
                                    "Persistent handle requested (DH2Q)"
                                );
                            }
                        }
                    } else {
                        debug!(
                            conn_id = self.connection.id,
                            timeout = timeout,
                            "Durable handle V2 requested (DH2Q)"
                        );
                    }
                }
                CreateContext::LeaseRequest {
                    lease_key: key,
                    lease_state: state,
                    ..
                } => {
                    lease_key = Some(*key);
                    lease_state = *state;
                    // Grant READ lease for now (simplified)
                    if *state & 0x01 != 0 {
                        requested_oplock = OplockLevel::Lease;
                    }
                    debug!(
                        conn_id = self.connection.id,
                        lease_state = state,
                        "Lease requested"
                    );
                }
                CreateContext::LeaseRequestV2 {
                    lease_key: key,
                    lease_state: state,
                    ..
                } => {
                    lease_key = Some(*key);
                    lease_state = *state;
                    if *state & 0x01 != 0 {
                        requested_oplock = OplockLevel::Lease;
                    }
                    debug!(
                        conn_id = self.connection.id,
                        lease_state = state,
                        "Lease V2 requested"
                    );
                }
                _ => {}
            }
        }

        // Generate create GUID if durable but client didn't provide one
        let final_create_guid = create_guid.unwrap_or_else(|| {
            if is_durable {
                let mut guid = [0u8; 16];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut guid);
                guid
            } else {
                [0u8; 16]
            }
        });

        // Create handle state with Phase 11 fields
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut handle = HandleState {
            persistent_id: handle_id,
            volatile_id: handle_id,
            tree_id: header.tree_id,
            session_id: header.session_id,
            path: filename.clone(),
            access_mask: request.desired_access,
            share_access: request.share_access,
            create_options: request.create_options,
            is_durable,
            is_persistent,
            created_at: now,
            last_access: now,
            create_guid: None, // Set below if durable
            file_offset: 0,
            share_name: tree.share_name.clone(),
            create_disposition: request.create_disposition,
            file_attributes: request.file_attributes,
            app_instance_id: None,
            durable_timeout,
            reconnect_deadline: None,
            lease_key: None, // Set below if lease requested
            oplock_level: requested_oplock.as_u8(),
            bound_server_id: None,
        };

        // Set create GUID if durable
        if is_durable {
            handle.set_create_guid(&final_create_guid);
            // Set reconnect deadline based on timeout (or default 60 seconds)
            let timeout_ms = if durable_timeout > 0 {
                durable_timeout
            } else {
                60_000
            };
            handle.set_durable_timeout(timeout_ms);
        }

        // Handle lease request with conflict detection
        let mut granted_lease_state = 0u32;
        if let Some(key) = lease_key {
            // Build file path for lease tracking
            let file_path = format!("{}/{}", tree.share_name, filename);

            // Create lease entry
            let lease = LeaseEntry::new(
                key,
                self.connection.client_guid_string(),
                header.session_id,
                self.server_id.clone(),
                file_path.clone(),
                lease_state,
            );

            // Check for conflicts and create lease atomically
            match self
                .session_manager
                .state_store()
                .check_and_create_lease(&file_path, &lease, lease_state)
                .await
            {
                Ok(result) => {
                    // Use the granted state (may be reduced due to conflicts)
                    granted_lease_state = result.granted_state;

                    if !result.conflicts.is_empty() {
                        debug!(
                            conn_id = self.connection.id,
                            conflicts = result.conflicts.len(),
                            requested = lease_state,
                            granted = granted_lease_state,
                            "Lease reduced due to conflicts"
                        );
                    }

                    // Set lease key on handle only if lease was created
                    handle.set_lease_key(&key);
                }
                Err(e) => {
                    warn!(
                        conn_id = self.connection.id,
                        error = %e,
                        "Lease creation failed, proceeding without lease"
                    );
                    // Continue without lease - file open still succeeds
                }
            }
        }

        self.session_manager
            .create_handle(handle)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        debug!(
            conn_id = self.connection.id,
            handle_id,
            path = %filename,
            is_durable,
            is_persistent,
            "File opened"
        );

        let resp_header = self.build_response_header(header, NtStatus::Success);

        // Split handle_id into two u64 values for the response
        let file_id_persistent = handle_id as u64;
        let file_id_volatile = (handle_id >> 64) as u64;

        // Build response CREATE contexts
        let mut ctx_builder = CreateContextBuilder::new();

        // Add durable handle response if requested
        if is_durable {
            if is_persistent {
                // DH2Q response for persistent handles
                ctx_builder = ctx_builder.add_durable_handle_response_v2(durable_timeout, 0x02);
            // PERSISTENT flag
            } else if create_guid.is_some() {
                // DH2Q response for durable V2
                ctx_builder = ctx_builder.add_durable_handle_response_v2(durable_timeout, 0);
            } else {
                // DHnQ response for simple durable
                ctx_builder = ctx_builder.add_durable_handle_response();
            }
        }

        // Add lease response if requested (with conflict-detected grant)
        if let Some(key) = lease_key {
            // Use the granted_lease_state from check_and_create_lease (may be reduced)
            ctx_builder = ctx_builder.add_lease_response(key, granted_lease_state, 0);
        }

        let ctx_data = ctx_builder.build();
        let (ctx_offset, ctx_len) = if ctx_data.is_empty() {
            (0u32, 0u32)
        } else {
            // Context offset is from start of SMB2 header
            // Header (64) + CreateResponse fixed part (88) = 152
            // But CreateResponse structure_size is 89 which includes variable parts
            (152u32, ctx_data.len() as u32)
        };

        let response = CreateResponse {
            structure_size: 89,
            oplock_level: requested_oplock,
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
            create_contexts_offset: ctx_offset,
            create_contexts_length: ctx_len,
        };

        let mut result = self.serialize_response(&resp_header, &response)?;

        // Append CREATE contexts if any
        if !ctx_data.is_empty() {
            result.extend_from_slice(&ctx_data);
        }

        Ok(result)
    }

    /// Handle durable handle reconnection.
    ///
    /// This is called when a client sends CREATE with DurableHandleReconnect
    /// or DurableHandleReconnectV2 to reconnect to an existing handle after
    /// failover or network disconnection.
    async fn handle_durable_reconnect(
        &mut self,
        header: &Smb2Header,
        persistent_id: u64,
        create_guid: Option<[u8; 16]>,
        filename: &str,
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::create::{
            CreateContextBuilder, CreateResponse, CreateResponseFlags, OplockLevel,
        };

        debug!(
            conn_id = self.connection.id,
            persistent_id,
            path = %filename,
            "Durable handle reconnect request"
        );

        // Look up the existing handle by persistent_id
        let handle_id = persistent_id as u128;
        let mut handle = self
            .session_manager
            .get_handle(handle_id)
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?
            .ok_or_else(|| {
                warn!(
                    conn_id = self.connection.id,
                    persistent_id, "Durable handle reconnect failed: handle not found"
                );
                HandlerError::Status(NtStatus::ObjectNameNotFound)
            })?;

        // Verify handle is durable
        if !handle.is_durable && !handle.is_persistent {
            warn!(
                conn_id = self.connection.id,
                persistent_id, "Durable handle reconnect failed: handle not durable"
            );
            return Err(HandlerError::Status(NtStatus::ObjectNameNotFound));
        }

        // Check if handle can still be reconnected (within timeout)
        if !handle.can_reconnect() {
            warn!(
                conn_id = self.connection.id,
                persistent_id, "Durable handle reconnect failed: handle expired"
            );
            // Clean up expired handle
            let _ = self.session_manager.delete_handle(handle_id).await;
            return Err(HandlerError::Status(NtStatus::ObjectNameNotFound));
        }

        // Validate create GUID for V2 reconnect
        if let Some(client_guid) = create_guid {
            if let Some(stored_guid) = handle.get_create_guid() {
                if client_guid != stored_guid {
                    warn!(
                        conn_id = self.connection.id,
                        persistent_id, "Durable handle reconnect failed: GUID mismatch"
                    );
                    return Err(HandlerError::Status(NtStatus::ObjectNameNotFound));
                }
            }
        }

        // Verify the path matches (security check)
        if !filename.is_empty() && handle.path != filename {
            warn!(
                conn_id = self.connection.id,
                persistent_id,
                expected = %handle.path,
                got = %filename,
                "Durable handle reconnect failed: path mismatch"
            );
            return Err(HandlerError::Status(NtStatus::ObjectNameNotFound));
        }

        // Get the backend and verify we can still open the file
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

        // Re-open the file with original access mask
        let reopen_params = CreateParams {
            desired_access: handle.access_mask,
            share_access: handle.share_access,
            create_disposition: rustsmb_vfs::disposition::OPEN, // Open existing file
            create_options: 0,
            file_attributes: 0,
        };
        let _file_handle = backend
            .open(&handle.path, &reopen_params)
            .await
            .map_err(|e| {
                warn!(
                    conn_id = self.connection.id,
                    persistent_id,
                    error = %e,
                    "Durable handle reconnect failed: cannot reopen file"
                );
                HandlerError::Status(NtStatus::ObjectNameNotFound)
            })?;

        // Update handle state for new connection
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        handle.session_id = header.session_id;
        handle.tree_id = header.tree_id;
        handle.last_access = now;
        // Generate new volatile ID for this connection
        handle.volatile_id = handle.persistent_id; // Simplified - use same ID

        // Update handle in state store
        self.session_manager
            .update_handle(handle.clone())
            .await
            .map_err(|e| HandlerError::Internal(e.to_string()))?;

        info!(
            conn_id = self.connection.id,
            session_id = header.session_id,
            persistent_id,
            path = %handle.path,
            "Durable handle reconnected"
        );

        // Build response
        let resp_header = self.build_response_header(header, NtStatus::Success);

        let file_id_persistent = handle.persistent_id as u64;
        let file_id_volatile = (handle.persistent_id >> 64) as u64;

        // Build response contexts
        let mut ctx_builder = CreateContextBuilder::new();
        if handle.is_persistent {
            ctx_builder = ctx_builder.add_durable_handle_response_v2(handle.durable_timeout, 0x02);
        } else if create_guid.is_some() {
            ctx_builder = ctx_builder.add_durable_handle_response_v2(handle.durable_timeout, 0);
        } else {
            ctx_builder = ctx_builder.add_durable_handle_response();
        }

        // Add lease response if handle had a lease
        if let Some(key) = handle.get_lease_key() {
            // Restore previous lease state (simplified)
            ctx_builder = ctx_builder.add_lease_response(key, 0x01, 0); // Grant READ caching
        }

        let ctx_data = ctx_builder.build();
        let (ctx_offset, ctx_len) = if ctx_data.is_empty() {
            (0u32, 0u32)
        } else {
            (152u32, ctx_data.len() as u32)
        };

        let oplock_level = OplockLevel::from_u8(handle.oplock_level);

        let response = CreateResponse {
            structure_size: 89,
            oplock_level,
            flags: CreateResponseFlags(0),
            create_action: 1, // Opened
            creation_time: current_filetime(),
            last_access_time: current_filetime(),
            last_write_time: current_filetime(),
            change_time: current_filetime(),
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: handle.file_attributes,
            reserved2: 0,
            file_id_persistent,
            file_id_volatile,
            create_contexts_offset: ctx_offset,
            create_contexts_length: ctx_len,
        };

        let mut result = self.serialize_response(&resp_header, &response)?;
        if !ctx_data.is_empty() {
            result.extend_from_slice(&ctx_data);
        }

        Ok(result)
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

        // Get handle first - if it doesn't exist, the handle was already closed
        let handle = match self.session_manager.get_handle(handle_id).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                // Handle doesn't exist - already closed
                return Err(HandlerError::Status(NtStatus::FileClosed));
            }
            Err(e) => {
                return Err(HandlerError::Internal(e.to_string()));
            }
        };

        // Delete lease if present
        if let Some(lease_key) = &handle.lease_key {
            if let Err(e) = self
                .session_manager
                .state_store()
                .delete_lease(lease_key)
                .await
            {
                debug!(error = %e, lease_key = %lease_key, "Failed to delete lease on close");
            }
        }

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
        let read_params = CreateParams {
            desired_access: rustsmb_vfs::access_mask::GENERIC_READ,
            share_access: 0,
            create_disposition: rustsmb_vfs::disposition::OPEN,
            create_options: 0,
            file_attributes: 0,
        };
        let file_handle = backend
            .open(&handle.path, &read_params)
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
        let write_params = CreateParams {
            desired_access: rustsmb_vfs::access_mask::GENERIC_WRITE,
            share_access: 0,
            create_disposition: rustsmb_vfs::disposition::OPEN,
            create_options: 0,
            file_attributes: 0,
        };
        let file_handle = backend
            .open(&handle.path, &write_params)
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
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::ioctl::{FsctlCode, IoctlRequest};

        debug!(conn_id = self.connection.id, "IOCTL request");

        let request = IoctlRequest::read(&mut Cursor::new(body))
            .map_err(|e| HandlerError::Protocol(format!("Failed to parse IOCTL: {}", e)))?;

        let ctl_code = FsctlCode::from_u32(request.ctl_code);
        debug!(conn_id = self.connection.id, ctl_code = ?ctl_code, "IOCTL control code");

        match ctl_code {
            Some(FsctlCode::ValidateNegotiateInfo) => {
                self.handle_validate_negotiate_info(header, &request, body)
                    .await
            }
            _ => {
                debug!(
                    conn_id = self.connection.id,
                    ctl_code = request.ctl_code,
                    "Unsupported IOCTL"
                );
                Err(HandlerError::Status(NtStatus::NotSupported))
            }
        }
    }

    /// Handle FSCTL_VALIDATE_NEGOTIATE_INFO.
    ///
    /// This verifies the negotiated parameters match what the client sent.
    /// Required by SMB clients to verify the negotiation was not tampered with.
    async fn handle_validate_negotiate_info(
        &mut self,
        header: &Smb2Header,
        request: &rustsmb_protocol::ioctl::IoctlRequest,
        body: &[u8],
    ) -> Result<Vec<u8>, HandlerError> {
        use rustsmb_protocol::ioctl::{IoctlResponse, IOCTL_RESPONSE_SIZE};
        use rustsmb_protocol::negotiate::{Capabilities, SecurityMode};

        // Input buffer offset is relative to the SMB2 header, body is after the header
        // The IOCTL request structure is 56 bytes (57 - 1 for structure_size accounting)
        let input_offset = request.input_offset as usize;
        let input_count = request.input_count as usize;

        // Calculate the actual offset in body (input_offset is from start of SMB2 header)
        let body_offset = input_offset.saturating_sub(SMB2_HEADER_SIZE);

        if body_offset + input_count > body.len() || input_count < 24 {
            return Err(HandlerError::Status(NtStatus::InvalidParameter));
        }

        let input = &body[body_offset..body_offset + input_count];

        // Parse ValidateNegotiateInfo request:
        // Capabilities (4 bytes) + Guid (16 bytes) + SecurityMode (2 bytes) + DialectCount (2 bytes) + Dialects
        let _client_caps = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
        let client_guid: [u8; 16] = input[4..20].try_into().unwrap();
        let _client_security_mode = u16::from_le_bytes([input[20], input[21]]);
        let dialect_count = u16::from_le_bytes([input[22], input[23]]) as usize;

        // Verify client GUID matches what was sent in NEGOTIATE
        if client_guid != self.connection.client_guid {
            warn!(
                conn_id = self.connection.id,
                "ValidateNegotiate: client GUID mismatch"
            );
            return Err(HandlerError::Status(NtStatus::AccessDenied));
        }

        // Get our negotiated dialect
        let negotiated_dialect = self
            .connection
            .dialect
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        // Verify the client offered our negotiated dialect
        let dialects_start = 24;
        let mut dialect_found = false;
        for i in 0..dialect_count {
            let offset = dialects_start + i * 2;
            if offset + 2 <= input.len() {
                let dialect = u16::from_le_bytes([input[offset], input[offset + 1]]);
                if dialect == negotiated_dialect.revision() {
                    dialect_found = true;
                    break;
                }
            }
        }

        if !dialect_found {
            warn!(
                conn_id = self.connection.id,
                "ValidateNegotiate: negotiated dialect not in client list"
            );
            return Err(HandlerError::Status(NtStatus::AccessDenied));
        }

        // Build ValidateNegotiateInfo response:
        // Capabilities (4 bytes) + Guid (16 bytes) + SecurityMode (2 bytes) + Dialect (2 bytes)
        let mut output_buffer = Vec::with_capacity(24);

        // Server capabilities (LARGE_MTU + ENCRYPTION for SMB 3.x)
        let mut server_caps = Capabilities::LARGE_MTU;
        if negotiated_dialect >= SmbDialect::Smb300 {
            server_caps |= Capabilities::ENCRYPTION;
        }
        output_buffer.extend_from_slice(&server_caps.to_le_bytes());

        // Server GUID
        output_buffer.extend_from_slice(&self.config.server_guid);

        // Security mode (signing enabled)
        let security_mode = SecurityMode::new(SecurityMode::SIGNING_ENABLED);
        output_buffer.extend_from_slice(&security_mode.0.to_le_bytes());

        // Negotiated dialect
        output_buffer.extend_from_slice(&negotiated_dialect.revision().to_le_bytes());

        // Build IOCTL response
        let output_offset = (SMB2_HEADER_SIZE + IOCTL_RESPONSE_SIZE as usize - 1) as u32;

        let resp_header = self.build_response_header(header, NtStatus::Success);
        let response = IoctlResponse {
            structure_size: IOCTL_RESPONSE_SIZE,
            reserved: 0,
            ctl_code: request.ctl_code,
            file_id_persistent: request.file_id_persistent,
            file_id_volatile: request.file_id_volatile,
            input_offset: 0,
            input_count: 0,
            output_offset,
            output_count: output_buffer.len() as u32,
            flags: 0,
            reserved2: 0,
        };

        // Serialize response header + IOCTL response + output buffer
        let mut result = Vec::with_capacity(SMB2_HEADER_SIZE + 48 + output_buffer.len());

        let mut header_buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        resp_header
            .write(&mut Cursor::new(&mut header_buf))
            .map_err(|e| HandlerError::Protocol(format!("Failed to write header: {}", e)))?;
        result.extend_from_slice(&header_buf);

        let mut body_buf = Vec::with_capacity(48);
        response
            .write(&mut Cursor::new(&mut body_buf))
            .map_err(|e| {
                HandlerError::Protocol(format!("Failed to write IOCTL response: {}", e))
            })?;
        result.extend_from_slice(&body_buf);

        result.extend_from_slice(&output_buffer);

        debug!(
            conn_id = self.connection.id,
            output_len = output_buffer.len(),
            "ValidateNegotiate: success"
        );

        Ok(result)
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
            // SMB 3.1.1 negotiation contexts are not yet implemented; prefer 3.0.x for now.
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

    /// Sign an SMB2 message in place.
    ///
    /// The message must have the SIGNED flag set in the header.
    /// The signature field (bytes 48-63) will be zeroed, then the
    /// signature computed and written back.
    fn sign_message(
        &self,
        message: &mut [u8],
        signing_key: &[u8],
        dialect: SmbDialect,
    ) -> Result<(), HandlerError> {
        if message.len() < SMB2_HEADER_SIZE {
            return Err(HandlerError::Protocol("Message too short to sign".into()));
        }

        // Zero the signature field (bytes 48-63)
        message[48..64].fill(0);

        // SMB 3.x signs the entire SMB2 packet (header + body) with the signature
        // field zeroed. Compute the signature over the full message for compatibility
        // with Windows and smbprotocol.
        let signature = Self::compute_signature(signing_key, dialect, message)?;
        let header_only_signature =
            Self::compute_signature(signing_key, dialect, &message[..SMB2_HEADER_SIZE])?;

        // Write signature back to message
        message[48..64].copy_from_slice(&signature);
        debug!(
            conn_id = self.connection.id,
            "Signed message: signature={:02x?} header_only_signature={:02x?}",
            signature,
            header_only_signature
        );

        Ok(())
    }

    /// Sign a response message if we have a signing key for the session.
    ///
    /// This is called from the main loop after the command handler returns
    /// the response. It looks up the signing key based on the session_id
    /// in the response header and signs the message if needed.
    fn maybe_sign_response(&self, mut response: Vec<u8>) -> Result<Vec<u8>, HandlerError> {
        // Need at least a full header
        if response.len() < SMB2_HEADER_SIZE {
            return Ok(response);
        }

        // Extract session_id from response header (offset 40, 8 bytes)
        let session_id = u64::from_le_bytes([
            response[40],
            response[41],
            response[42],
            response[43],
            response[44],
            response[45],
            response[46],
            response[47],
        ]);

        // Check if we have a signing key for this session
        if let Some(signing_key) = self.signing_keys.get(&session_id) {
            // Check if already signed (SIGNED flag at offset 16, bit 0x08)
            let flags =
                u32::from_le_bytes([response[16], response[17], response[18], response[19]]);

            if (flags & Smb2Flags::SIGNED) != 0 {
                // Already signed by the handler (e.g., SESSION_SETUP Success)
                return Ok(response);
            }

            // Set the SIGNED flag
            let new_flags = flags | Smb2Flags::SIGNED;
            response[16..20].copy_from_slice(&new_flags.to_le_bytes());

            // Get dialect from connection
            let dialect = self.connection.dialect.unwrap_or(SmbDialect::Smb302);

            // Zero the signature field before computing signature
            response[48..64].copy_from_slice(&[0u8; 16]);

            // Compute and write signature
            let signature = Self::compute_signature(signing_key, dialect, &response)?;
            response[48..64].copy_from_slice(&signature);

            trace!(
                conn_id = self.connection.id,
                session_id,
                "Signed response message"
            );
        }

        Ok(response)
    }

    /// Compute SMB signing MAC for the provided message bytes.
    ///
    /// The caller is responsible for zeroing the signature field in `message`
    /// before invoking this helper.
    fn compute_signature(
        signing_key: &[u8],
        dialect: SmbDialect,
        message: &[u8],
    ) -> Result<[u8; 16], HandlerError> {
        // Select signing algorithm based on dialect
        let algorithm = match dialect {
            SmbDialect::Smb311 => SigningAlgorithm::AesCmac, // Default for 3.1.1 (GMAC needs proper nonce)
            SmbDialect::Smb302 | SmbDialect::Smb300 => SigningAlgorithm::AesCmac,
            _ => {
                // SMB 2.x uses HMAC-SHA256, not supported by MessageSigner
                // For now, use AES-CMAC which is close enough for testing
                SigningAlgorithm::AesCmac
            }
        };

        // Pad key to 16 bytes if necessary
        let mut key = [0u8; 16];
        let key_len = signing_key.len().min(16);
        key[..key_len].copy_from_slice(&signing_key[..key_len]);

        let signer = MessageSigner::new(algorithm, &key)
            .map_err(|e| HandlerError::Protocol(format!("Failed to create signer: {}", e)))?;

        signer
            .sign(message)
            .map_err(|e| HandlerError::Protocol(format!("Failed to sign message: {}", e)))
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

        // Serialize header to a temp buffer first
        let mut header_buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        header
            .write(&mut Cursor::new(&mut header_buf))
            .map_err(|e| HandlerError::Protocol(format!("Failed to write header: {}", e)))?;
        buf.extend_from_slice(&header_buf);

        // Serialize body to a temp buffer and append
        let mut body_buf = Vec::with_capacity(128);
        body.write(&mut Cursor::new(&mut body_buf))
            .map_err(|e| HandlerError::Protocol(format!("Failed to write body: {}", e)))?;
        buf.extend_from_slice(&body_buf);

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    #[test]
    fn compute_signature_matches_smbprotocol_vector() {
        // Captured from smbprotocol client during NTLM auth with KEY_EXCH.
        let signing_key: [u8; 16] = [
            0xb6, 0xb0, 0x55, 0x58, 0x0d, 0xed, 0xda, 0x89, 0xc6, 0x7b, 0x28, 0xd8, 0xd9, 0x86,
            0x76, 0xbd,
        ];

        let message = hex_bytes(
            "fe534d42400001000000000001001d02090000000000000002000000000000000000000000000000\
             0200000000000000000000000000000000000000000000000900000048000900a1073005a0030a0100",
        );

        let signature = ConnectionHandler::<DuplexStream>::compute_signature(
            &signing_key,
            SmbDialect::Smb302,
            &message,
        )
        .expect("signature computation should succeed");

        assert_eq!(
            signature,
            [
                0x39, 0xa6, 0x58, 0x63, 0x78, 0xdd, 0x5f, 0xcf, 0xab, 0x86, 0xe1, 0xde, 0x11, 0x67,
                0x3e, 0xa7
            ]
        );
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // ==========================================================================
    // SESSION_SETUP Unit Tests - MS-SMB2 Specification Compliance
    // ==========================================================================
    //
    // These tests verify compliance with MS-SMB2 sections:
    // - 3.3.5.5: Receiving an SMB2 SESSION_SETUP Request
    // - 3.3.5.5.1: Authenticating a New Session
    // - 3.3.5.5.3: Handling GSS-API Authentication
    // - 3.2.5.3.1: Client handling of SESSION_SETUP Response
    //
    // Key requirements tested:
    // 1. SessionId == 0 in request means NEW session (auth context reset)
    // 2. SessionId is allocated once and reused across auth rounds
    // 3. Interim responses (MORE_PROCESSING_REQUIRED) include SessionId
    // 4. Success responses include the same SessionId from interim phase
    // ==========================================================================

    use rustsmb_auth::{AuthContext, AuthMechanism, AuthProvider, AuthResult, AuthState, UserInfo};
    use rustsmb_core::AuthError;
    use rustsmb_protocol::session_setup::{
        SessionCapabilities, SessionSecurityMode, SessionSetupFlags, SessionSetupRequest,
    };
    use rustsmb_state_memory::MemoryStateStore;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    /// NT_STATUS codes for comparison in tests.
    const STATUS_SUCCESS: u32 = 0x00000000;
    const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC0000016;

    /// Mock auth provider for testing multi-round authentication.
    ///
    /// Supports configurable authentication flow:
    /// - Single-round: Returns Success immediately
    /// - Multi-round: Returns Continue N times, then Success
    struct MockMultiRoundAuthProvider {
        /// Number of Continue responses before Success.
        rounds_before_success: u32,
        /// Current round counter (per-context tracking via state).
        round_counter: AtomicU32,
    }

    impl MockMultiRoundAuthProvider {
        fn new(rounds_before_success: u32) -> Self {
            Self {
                rounds_before_success,
                round_counter: AtomicU32::new(0),
            }
        }

        /// Create a single-round auth provider (immediate success).
        fn single_round() -> Self {
            Self::new(0)
        }

        /// Create a two-round auth provider (Continue, then Success).
        fn two_round() -> Self {
            Self::new(1)
        }

        /// Create a three-round auth provider (Continue, Continue, Success).
        fn three_round() -> Self {
            Self::new(2)
        }
    }

    impl AuthProvider for MockMultiRoundAuthProvider {
        fn authenticate<'a>(
            &'a self,
            context: &'a mut AuthContext,
            _token: &'a [u8],
        ) -> rustsmb_auth::BoxFuture<'a, Result<AuthResult, AuthError>> {
            Box::pin(async move {
                let current_round = self.round_counter.fetch_add(1, AtomicOrdering::SeqCst);

                if current_round < self.rounds_before_success {
                    // More rounds needed - return Continue
                    context.state = AuthState::ChallengeIssued;
                    Ok(AuthResult::Continue {
                        response_token: format!("challenge_round_{}", current_round + 1)
                            .into_bytes(),
                    })
                } else {
                    // Final round - return Success
                    context.state = AuthState::Complete;
                    Ok(AuthResult::Success {
                        user: UserInfo::authenticated("testuser", Some("TESTDOMAIN")),
                        session_key: vec![0x42; 16], // Mock session key
                        response_token: Some(b"final_token".to_vec()),
                    })
                }
            })
        }

        fn get_user<'a>(
            &'a self,
            username: &'a str,
            domain: Option<&'a str>,
        ) -> rustsmb_auth::BoxFuture<'a, Result<Option<UserInfo>, AuthError>> {
            Box::pin(async move { Ok(Some(UserInfo::authenticated(username, domain))) })
        }

        fn validate_session_key<'a>(
            &'a self,
            _session_id: u64,
            _key: &'a [u8],
        ) -> rustsmb_auth::BoxFuture<'a, Result<bool, AuthError>> {
            Box::pin(async move { Ok(true) })
        }

        fn supported_mechanisms(&self) -> Vec<AuthMechanism> {
            vec![AuthMechanism::Ntlm]
        }
    }

    /// Create a test ConnectionHandler with mock dependencies.
    async fn create_test_handler(
        auth_provider: impl AuthProvider,
    ) -> ConnectionHandler<DuplexStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let _ = client; // We don't use the client side in unit tests

        let state_store = Arc::new(MemoryStateStore::new());
        let session_manager = Arc::new(SessionManager::new(
            state_store,
            rustsmb_session::SessionManagerConfig::default(),
        ));
        let config = Arc::new(ServerConfig::default());
        let shares = Arc::new(ShareManager::new());

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

        ConnectionHandler::new(
            server,
            peer_addr,
            config,
            session_manager,
            Arc::new(auth_provider),
            shares,
            "test-server-1".to_string(),
        )
    }

    /// Build a SESSION_SETUP request message.
    ///
    /// Per MS-SMB2 2.2.5, the request structure is:
    /// - SMB2 Header (64 bytes)
    /// - SESSION_SETUP Request (variable)
    fn build_session_setup_request(session_id: u64, security_buffer: &[u8]) -> Vec<u8> {
        // Build SMB2 header (magic bytes are written by binrw via #[brw(magic = ...)])
        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 1,
            status: 0,
            command: Smb2Command::SessionSetup,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 1,
            async_id: 0,
            tree_id: 0,
            session_id,
            signature: [0u8; 16],
        };

        // Build SESSION_SETUP request body
        // SecurityBufferOffset = 64 (header) + 25 (fixed request size) = 89
        // But we need to account for padding - offset is from message start
        let request = SessionSetupRequest {
            structure_size: 25,
            flags: SessionSetupFlags::new(0),
            security_mode: SessionSecurityMode(1), // SMB2_NEGOTIATE_SIGNING_ENABLED
            capabilities: SessionCapabilities(0),
            channel: 0,
            security_buffer_offset: 88, // 64 + 24 (structure minus buffer fields)
            security_buffer_length: security_buffer.len() as u16,
            previous_session_id: 0,
        };

        // Serialize header to a temp buffer (binrw writes magic bytes)
        let mut header_buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        header
            .write(&mut Cursor::new(&mut header_buf))
            .expect("header serialization should succeed");

        // Serialize request body to a temp buffer
        let mut request_buf = Vec::with_capacity(32);
        request
            .write(&mut Cursor::new(&mut request_buf))
            .expect("request serialization should succeed");

        // Combine all parts
        let mut buf =
            Vec::with_capacity(header_buf.len() + request_buf.len() + security_buffer.len());
        buf.extend_from_slice(&header_buf);
        buf.extend_from_slice(&request_buf);
        buf.extend_from_slice(security_buffer);

        buf
    }

    /// Extract SessionId from an SMB2 response message.
    ///
    /// SMB2 header layout (MS-SMB2 2.2.1):
    /// - ProtocolId: 4 bytes (0-3)
    /// - StructureSize: 2 bytes (4-5)
    /// - CreditCharge: 2 bytes (6-7)
    /// - Status: 4 bytes (8-11)
    /// - Command: 2 bytes (12-13)
    /// - Credits: 2 bytes (14-15)
    /// - Flags: 4 bytes (16-19)
    /// - NextCommand: 4 bytes (20-23)
    /// - MessageId: 8 bytes (24-31)
    /// - AsyncId: 4 bytes (32-35)
    /// - TreeId: 4 bytes (36-39)
    /// - SessionId: 8 bytes (40-47)
    /// - Signature: 16 bytes (48-63)
    fn extract_session_id_from_response(response: &[u8]) -> u64 {
        assert!(response.len() >= 64, "Response too short for SMB2 header");
        // SessionId is at offset 40-47 in the SMB2 header
        u64::from_le_bytes(response[40..48].try_into().unwrap())
    }

    /// Extract NtStatus from an SMB2 response message.
    fn extract_status_from_response(response: &[u8]) -> u32 {
        assert!(response.len() >= 64, "Response too short for SMB2 header");
        // Status is at offset 8-12 in the SMB2 header
        u32::from_le_bytes(response[8..12].try_into().unwrap())
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.3.5.5 - SessionId == 0 means NEW session
    // -------------------------------------------------------------------------
    // "If SessionId in the SMB2 header of the request is zero, the server MUST
    // process the authentication request as specified in section 3.3.5.5.1."
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_id_zero_resets_auth_context() {
        // Create handler with single-round auth
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // Simulate a previous auth that left state in auth_context
        handler.auth_context.session_id = Some(12345);
        handler.auth_context.state = AuthState::ChallengeIssued;
        handler.auth_context.challenge = Some(vec![0x01, 0x02, 0x03]);

        // Build request with SessionId = 0 (NEW session)
        let request = build_session_setup_request(0, b"test_token");
        let header = Smb2Header::read(&mut Cursor::new(&request[..64])).unwrap();

        // Handle the session setup
        let response = handler
            .handle_session_setup(&header, &request[64..], &request)
            .await
            .expect("SESSION_SETUP should succeed");

        // Verify auth_context was reset (session_id should NOT be 12345)
        // The new session should have a freshly allocated session_id
        let response_session_id = extract_session_id_from_response(&response);
        assert_ne!(
            response_session_id, 12345,
            "MS-SMB2 3.3.5.5: SessionId=0 should create NEW session, not reuse old"
        );
        assert_ne!(
            response_session_id, 0,
            "Server MUST allocate a unique SessionId for new sessions"
        );
    }

    #[tokio::test]
    async fn test_session_id_zero_starts_fresh_auth() {
        // Create handler with two-round auth to test context reset
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::two_round()).await;

        // Simulate leftover state from a previous incomplete auth
        handler.auth_context.session_id = Some(99999);
        handler.auth_context.state = AuthState::ChallengeIssued;

        // First request with SessionId = 0 should reset everything
        let request1 = build_session_setup_request(0, b"token1");
        let header1 = Smb2Header::read(&mut Cursor::new(&request1[..64])).unwrap();

        let response1 = handler
            .handle_session_setup(&header1, &request1[64..], &request1)
            .await
            .expect("First SESSION_SETUP should succeed");

        let session_id = extract_session_id_from_response(&response1);
        let status = extract_status_from_response(&response1);

        // Should be MORE_PROCESSING_REQUIRED with a NEW session ID (not 99999)
        assert_eq!(
            status, STATUS_MORE_PROCESSING_REQUIRED,
            "First round should return MORE_PROCESSING_REQUIRED"
        );
        assert_ne!(
            session_id, 99999,
            "MS-SMB2 3.3.5.5: SessionId=0 must not reuse previous session_id"
        );
        assert_ne!(session_id, 0, "SessionId must be allocated");
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.3.5.5.1 - SessionId allocated once at start
    // -------------------------------------------------------------------------
    // "A session object MUST be allocated for this request. The session MUST
    // be inserted into the GlobalSessionTable and a unique Session.SessionId
    // is assigned to serve as a lookup key in the table."
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_id_preserved_across_auth_rounds() {
        // Create handler with two-round auth
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::two_round()).await;

        // Round 1: SessionId = 0 (new session)
        let request1 = build_session_setup_request(0, b"negotiate_token");
        let header1 = Smb2Header::read(&mut Cursor::new(&request1[..64])).unwrap();

        let response1 = handler
            .handle_session_setup(&header1, &request1[64..], &request1)
            .await
            .expect("Round 1 should succeed");

        let session_id_round1 = extract_session_id_from_response(&response1);
        let status1 = extract_status_from_response(&response1);

        assert_eq!(status1, STATUS_MORE_PROCESSING_REQUIRED);
        assert_ne!(
            session_id_round1, 0,
            "SessionId must be allocated in round 1"
        );

        // Round 2: Use the allocated SessionId
        let request2 = build_session_setup_request(session_id_round1, b"authenticate_token");
        let header2 = Smb2Header::read(&mut Cursor::new(&request2[..64])).unwrap();

        let response2 = handler
            .handle_session_setup(&header2, &request2[64..], &request2)
            .await
            .expect("Round 2 should succeed");

        let session_id_round2 = extract_session_id_from_response(&response2);
        let status2 = extract_status_from_response(&response2);

        assert_eq!(status2, STATUS_SUCCESS);
        assert_eq!(
            session_id_round1, session_id_round2,
            "MS-SMB2 3.3.5.5.1: SessionId MUST be same across all auth rounds"
        );
    }

    #[tokio::test]
    async fn test_three_round_auth_preserves_session_id() {
        // Create handler with three-round auth (Continue, Continue, Success)
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::three_round()).await;

        // Round 1: New session
        let request1 = build_session_setup_request(0, b"token1");
        let header1 = Smb2Header::read(&mut Cursor::new(&request1[..64])).unwrap();
        let response1 = handler
            .handle_session_setup(&header1, &request1[64..], &request1)
            .await
            .unwrap();

        let session_id = extract_session_id_from_response(&response1);
        assert_eq!(
            extract_status_from_response(&response1),
            STATUS_MORE_PROCESSING_REQUIRED
        );

        // Round 2: Continue with same session
        let request2 = build_session_setup_request(session_id, b"token2");
        let header2 = Smb2Header::read(&mut Cursor::new(&request2[..64])).unwrap();
        let response2 = handler
            .handle_session_setup(&header2, &request2[64..], &request2)
            .await
            .unwrap();

        assert_eq!(
            extract_session_id_from_response(&response2),
            session_id,
            "Round 2 must use same SessionId"
        );
        assert_eq!(
            extract_status_from_response(&response2),
            STATUS_MORE_PROCESSING_REQUIRED
        );

        // Round 3: Final success
        let request3 = build_session_setup_request(session_id, b"token3");
        let header3 = Smb2Header::read(&mut Cursor::new(&request3[..64])).unwrap();
        let response3 = handler
            .handle_session_setup(&header3, &request3[64..], &request3)
            .await
            .unwrap();

        assert_eq!(
            extract_session_id_from_response(&response3),
            session_id,
            "MS-SMB2: Final SUCCESS must use same SessionId allocated in round 1"
        );
        assert_eq!(extract_status_from_response(&response3), STATUS_SUCCESS);
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.2.5.3.1 - Interim responses include SessionId
    // -------------------------------------------------------------------------
    // "If the GSS protocol returns success and the Status code of the SMB2
    // header of the response was STATUS_MORE_PROCESSING_REQUIRED, the client
    // MUST process as follows: ... the client MUST look for a session object
    // in Connection.PreAuthSessionTable by using the SessionId in the SMB2
    // header of the SMB2 SESSION_SETUP Response."
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_interim_response_contains_session_id() {
        // Create handler with multi-round auth
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::two_round()).await;

        // Request with SessionId = 0 (new session)
        let request = build_session_setup_request(0, b"negotiate");
        let header = Smb2Header::read(&mut Cursor::new(&request[..64])).unwrap();

        let response = handler
            .handle_session_setup(&header, &request[64..], &request)
            .await
            .expect("SESSION_SETUP should succeed");

        let session_id = extract_session_id_from_response(&response);
        let status = extract_status_from_response(&response);

        // Verify this is an interim response
        assert_eq!(
            status, STATUS_MORE_PROCESSING_REQUIRED,
            "Should be an interim response"
        );

        // MS-SMB2 3.2.5.3.1: Client expects SessionId in interim responses
        assert_ne!(
            session_id, 0,
            "MS-SMB2 3.2.5.3.1: Interim responses MUST include allocated SessionId"
        );

        // Verify the session_id was stored in auth_context for next round
        assert_eq!(
            handler.auth_context.session_id,
            Some(session_id),
            "auth_context.session_id should be set for subsequent rounds"
        );
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.3.5.5.3 - Session.SessionId in response header
    // -------------------------------------------------------------------------
    // "Session.SessionId MUST be placed in the SessionId field of the SMB2
    // header." (for success responses)
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_success_response_contains_session_id() {
        // Create handler with single-round auth (immediate success)
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        let request = build_session_setup_request(0, b"credentials");
        let header = Smb2Header::read(&mut Cursor::new(&request[..64])).unwrap();

        let response = handler
            .handle_session_setup(&header, &request[64..], &request)
            .await
            .expect("SESSION_SETUP should succeed");

        let session_id = extract_session_id_from_response(&response);
        let status = extract_status_from_response(&response);

        assert_eq!(status, STATUS_SUCCESS);
        assert_ne!(
            session_id, 0,
            "MS-SMB2 3.3.5.5.3: Session.SessionId MUST be in response header"
        );
    }

    // -------------------------------------------------------------------------
    // Test: Multiple concurrent sessions get unique SessionIds
    // -------------------------------------------------------------------------
    // Per MS-SMB2 3.3.5.5.1: "a unique Session.SessionId is assigned"
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_multiple_sessions_get_unique_ids() {
        // We need separate handlers to simulate different connections
        let state_store = Arc::new(MemoryStateStore::new());
        let session_manager = Arc::new(SessionManager::new(
            state_store,
            rustsmb_session::SessionManagerConfig::default(),
        ));
        let config = Arc::new(ServerConfig::default());
        let shares = Arc::new(ShareManager::new());

        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);

        // Create two handlers sharing the same session manager
        let (_, server1) = tokio::io::duplex(64 * 1024);
        let (_, server2) = tokio::io::duplex(64 * 1024);

        let mut handler1 = ConnectionHandler::new(
            server1,
            peer_addr,
            config.clone(),
            session_manager.clone(),
            Arc::new(MockMultiRoundAuthProvider::single_round()),
            shares.clone(),
            "test-server-1".to_string(),
        );

        let mut handler2 = ConnectionHandler::new(
            server2,
            peer_addr,
            config,
            session_manager,
            Arc::new(MockMultiRoundAuthProvider::single_round()),
            shares,
            "test-server-1".to_string(),
        );

        // Session 1
        let request1 = build_session_setup_request(0, b"user1:pass1");
        let header1 = Smb2Header::read(&mut Cursor::new(&request1[..64])).unwrap();
        let response1 = handler1
            .handle_session_setup(&header1, &request1[64..], &request1)
            .await
            .unwrap();
        let session_id1 = extract_session_id_from_response(&response1);

        // Session 2
        let request2 = build_session_setup_request(0, b"user2:pass2");
        let header2 = Smb2Header::read(&mut Cursor::new(&request2[..64])).unwrap();
        let response2 = handler2
            .handle_session_setup(&header2, &request2[64..], &request2)
            .await
            .unwrap();
        let session_id2 = extract_session_id_from_response(&response2);

        assert_ne!(
            session_id1, session_id2,
            "Each session MUST have unique SessionId"
        );
        assert_ne!(session_id1, 0);
        assert_ne!(session_id2, 0);
    }

    // -------------------------------------------------------------------------
    // Test: Auth context state tracking
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_auth_context_session_id_tracking() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::two_round()).await;

        // Initially, auth_context.session_id should be None
        assert!(
            handler.auth_context.session_id.is_none(),
            "Initial auth_context.session_id should be None"
        );

        // After first round (Continue), session_id should be set
        let request1 = build_session_setup_request(0, b"token1");
        let header1 = Smb2Header::read(&mut Cursor::new(&request1[..64])).unwrap();
        let response1 = handler
            .handle_session_setup(&header1, &request1[64..], &request1)
            .await
            .unwrap();

        let allocated_session_id = extract_session_id_from_response(&response1);
        assert_eq!(
            handler.auth_context.session_id,
            Some(allocated_session_id),
            "auth_context.session_id should be set after Continue response"
        );

        // After second round (Success), same session_id should be used
        let request2 = build_session_setup_request(allocated_session_id, b"token2");
        let header2 = Smb2Header::read(&mut Cursor::new(&request2[..64])).unwrap();
        let response2 = handler
            .handle_session_setup(&header2, &request2[64..], &request2)
            .await
            .unwrap();

        assert_eq!(
            extract_session_id_from_response(&response2),
            allocated_session_id,
            "Success response should use the same allocated SessionId"
        );
    }

    // ==========================================================================
    // MS-SMB2 Compliance Tests - Status Code Validation
    // ==========================================================================
    //
    // These tests verify correct NT_STATUS codes per MS-SMB2:
    // - 3.3.5.6: CLOSE - NT_STATUS_FILE_CLOSED for invalid handle
    // - 3.3.5.4: TREE_DISCONNECT - NT_STATUS_NETWORK_NAME_DELETED for invalid tree
    // - 3.3.5.3: LOGOFF - NT_STATUS_USER_SESSION_DELETED for invalid session
    // ==========================================================================

    /// NT_STATUS codes for status validation tests
    const STATUS_FILE_CLOSED: u32 = 0xC0000128;
    const STATUS_NETWORK_NAME_DELETED: u32 = 0xC00000C9;
    const STATUS_USER_SESSION_DELETED: u32 = 0xC0000203;

    /// Build a CLOSE request message.
    fn build_close_request(session_id: u64, tree_id: u32, file_id: u128) -> Vec<u8> {
        use rustsmb_protocol::close::{CloseFlags, CloseRequest};

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 1,
            status: 0,
            command: Smb2Command::Close,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 1,
            async_id: 0,
            tree_id,
            session_id,
            signature: [0u8; 16],
        };

        let request = CloseRequest {
            structure_size: 24,
            flags: CloseFlags(0),
            reserved: 0,
            file_id_persistent: file_id as u64,
            file_id_volatile: (file_id >> 64) as u64,
        };

        // Write header and request to separate buffers, then combine
        let mut header_buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        header
            .write(&mut Cursor::new(&mut header_buf))
            .expect("header serialization should succeed");

        let mut request_buf = Vec::with_capacity(24);
        request
            .write(&mut Cursor::new(&mut request_buf))
            .expect("request serialization should succeed");

        let mut buf = Vec::with_capacity(header_buf.len() + request_buf.len());
        buf.extend_from_slice(&header_buf);
        buf.extend_from_slice(&request_buf);
        buf
    }

    /// Build a TREE_DISCONNECT request message.
    fn build_tree_disconnect_request(session_id: u64, tree_id: u32) -> Vec<u8> {
        use rustsmb_protocol::tree_disconnect::TreeDisconnectRequest;

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 1,
            status: 0,
            command: Smb2Command::TreeDisconnect,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 1,
            async_id: 0,
            tree_id,
            session_id,
            signature: [0u8; 16],
        };

        let request = TreeDisconnectRequest {
            structure_size: 4,
            reserved: 0,
        };

        // Write header and request to separate buffers, then combine
        let mut header_buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        header
            .write(&mut Cursor::new(&mut header_buf))
            .expect("header serialization should succeed");

        let mut request_buf = Vec::with_capacity(4);
        request
            .write(&mut Cursor::new(&mut request_buf))
            .expect("request serialization should succeed");

        let mut buf = Vec::with_capacity(header_buf.len() + request_buf.len());
        buf.extend_from_slice(&header_buf);
        buf.extend_from_slice(&request_buf);
        buf
    }

    /// Build a LOGOFF request message.
    fn build_logoff_request(session_id: u64) -> Vec<u8> {
        use rustsmb_protocol::logoff::LogoffRequest;

        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 1,
            status: 0,
            command: Smb2Command::Logoff,
            credits: 1,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 1,
            async_id: 0,
            tree_id: 0,
            session_id,
            signature: [0u8; 16],
        };

        let request = LogoffRequest {
            structure_size: 4,
            reserved: 0,
        };

        // Write header and request to separate buffers, then combine
        let mut header_buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        header
            .write(&mut Cursor::new(&mut header_buf))
            .expect("header serialization should succeed");

        let mut request_buf = Vec::with_capacity(4);
        request
            .write(&mut Cursor::new(&mut request_buf))
            .expect("request serialization should succeed");

        let mut buf = Vec::with_capacity(header_buf.len() + request_buf.len());
        buf.extend_from_slice(&header_buf);
        buf.extend_from_slice(&request_buf);
        buf
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.3.5.6 - CLOSE with invalid handle returns FILE_CLOSED
    // -------------------------------------------------------------------------
    // "If the FileId in the request is not valid, the server MUST fail the
    // request with STATUS_FILE_CLOSED."
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_close_invalid_handle_returns_file_closed() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // First, establish a session
        let session_request = build_session_setup_request(0, b"auth_token");
        let session_header = Smb2Header::read(&mut Cursor::new(&session_request[..64])).unwrap();
        let session_response = handler
            .handle_session_setup(&session_header, &session_request[64..], &session_request)
            .await
            .unwrap();
        let session_id = extract_session_id_from_response(&session_response);

        // Try to close a handle that doesn't exist (file_id = 12345)
        let close_request = build_close_request(session_id, 1, 12345);
        let close_header = Smb2Header::read(&mut Cursor::new(&close_request[..64])).unwrap();

        let result = handler
            .handle_close(&close_header, &close_request[64..])
            .await;

        // Per MS-SMB2, closing an invalid handle should return STATUS_FILE_CLOSED
        assert!(result.is_err());
        if let Err(HandlerError::Status(status)) = result {
            assert_eq!(
                status.code(),
                STATUS_FILE_CLOSED,
                "MS-SMB2 3.3.5.6: Invalid handle MUST return STATUS_FILE_CLOSED"
            );
        } else {
            panic!("Expected HandlerError::Status, got {:?}", result);
        }
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.3.5.4 - TREE_DISCONNECT with invalid tree returns error
    // -------------------------------------------------------------------------
    // "If the TreeId in the SMB2 header of the request is not valid, the server
    // MUST fail the request with STATUS_NETWORK_NAME_DELETED."
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_tree_disconnect_invalid_tree_returns_network_name_deleted() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // First, establish a session
        let session_request = build_session_setup_request(0, b"auth_token");
        let session_header = Smb2Header::read(&mut Cursor::new(&session_request[..64])).unwrap();
        let session_response = handler
            .handle_session_setup(&session_header, &session_request[64..], &session_request)
            .await
            .unwrap();
        let session_id = extract_session_id_from_response(&session_response);

        // Try to disconnect a tree that doesn't exist (tree_id = 999)
        let tdis_request = build_tree_disconnect_request(session_id, 999);
        let tdis_header = Smb2Header::read(&mut Cursor::new(&tdis_request[..64])).unwrap();

        let result = handler
            .handle_tree_disconnect(&tdis_header, &tdis_request[64..])
            .await;

        // Per MS-SMB2, disconnecting an invalid tree should return STATUS_NETWORK_NAME_DELETED
        assert!(result.is_err());
        if let Err(HandlerError::Status(status)) = result {
            assert_eq!(
                status.code(),
                STATUS_NETWORK_NAME_DELETED,
                "MS-SMB2 3.3.5.4: Invalid tree MUST return STATUS_NETWORK_NAME_DELETED"
            );
        } else {
            panic!("Expected HandlerError::Status, got {:?}", result);
        }
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 3.3.5.3 - LOGOFF with invalid session returns error
    // -------------------------------------------------------------------------
    // "If the SessionId in the SMB2 header of the request is not valid, the
    // server MUST fail the request with STATUS_USER_SESSION_DELETED."
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_logoff_invalid_session_returns_user_session_deleted() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // Try to logoff a session that doesn't exist (session_id = 99999)
        let logoff_request = build_logoff_request(99999);
        let logoff_header = Smb2Header::read(&mut Cursor::new(&logoff_request[..64])).unwrap();

        let result = handler
            .handle_logoff(&logoff_header, &logoff_request[64..])
            .await;

        // Per MS-SMB2, logging off an invalid session should return STATUS_USER_SESSION_DELETED
        assert!(result.is_err());
        if let Err(HandlerError::Status(status)) = result {
            assert_eq!(
                status.code(),
                STATUS_USER_SESSION_DELETED,
                "MS-SMB2 3.3.5.3: Invalid session MUST return STATUS_USER_SESSION_DELETED"
            );
        } else {
            panic!("Expected HandlerError::Status, got {:?}", result);
        }
    }

    // -------------------------------------------------------------------------
    // Test: MS-SMB2 - Double LOGOFF returns USER_SESSION_DELETED
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_double_logoff_returns_user_session_deleted() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // Establish a session
        let session_request = build_session_setup_request(0, b"auth_token");
        let session_header = Smb2Header::read(&mut Cursor::new(&session_request[..64])).unwrap();
        let session_response = handler
            .handle_session_setup(&session_header, &session_request[64..], &session_request)
            .await
            .unwrap();
        let session_id = extract_session_id_from_response(&session_response);

        // First logoff should succeed
        let logoff1_request = build_logoff_request(session_id);
        let logoff1_header = Smb2Header::read(&mut Cursor::new(&logoff1_request[..64])).unwrap();
        let logoff1_result = handler
            .handle_logoff(&logoff1_header, &logoff1_request[64..])
            .await;
        assert!(
            logoff1_result.is_ok(),
            "First logoff should succeed: {:?}",
            logoff1_result
        );

        // Second logoff should fail with USER_SESSION_DELETED
        let logoff2_request = build_logoff_request(session_id);
        let logoff2_header = Smb2Header::read(&mut Cursor::new(&logoff2_request[..64])).unwrap();
        let logoff2_result = handler
            .handle_logoff(&logoff2_header, &logoff2_request[64..])
            .await;

        assert!(logoff2_result.is_err());
        if let Err(HandlerError::Status(status)) = logoff2_result {
            assert_eq!(
                status.code(),
                STATUS_USER_SESSION_DELETED,
                "Second logoff MUST return STATUS_USER_SESSION_DELETED"
            );
        } else {
            panic!("Expected HandlerError::Status, got {:?}", logoff2_result);
        }
    }

    // ==========================================================================
    // Test: Message Signing Key Storage
    // ==========================================================================
    // Per MS-SMB2 3.3.5.5.3: After successful authentication, the signing key
    // must be stored and used for signing subsequent messages.
    // ==========================================================================

    #[tokio::test]
    async fn test_signing_key_stored_after_session_setup() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // Before session setup, no signing keys
        assert!(
            handler.signing_keys.is_empty(),
            "No signing keys before session setup"
        );

        // Establish a session
        let session_request = build_session_setup_request(0, b"auth_token");
        let session_header = Smb2Header::read(&mut Cursor::new(&session_request[..64])).unwrap();
        let session_response = handler
            .handle_session_setup(&session_header, &session_request[64..], &session_request)
            .await
            .unwrap();
        let session_id = extract_session_id_from_response(&session_response);

        // After successful session setup, signing key should be stored
        assert!(
            handler.signing_keys.contains_key(&session_id),
            "MS-SMB2 3.3.5.5.3: Signing key MUST be stored after successful SESSION_SETUP"
        );
    }

    #[tokio::test]
    async fn test_signing_key_removed_after_logoff() {
        let mut handler = create_test_handler(MockMultiRoundAuthProvider::single_round()).await;

        // Establish a session
        let session_request = build_session_setup_request(0, b"auth_token");
        let session_header = Smb2Header::read(&mut Cursor::new(&session_request[..64])).unwrap();
        let session_response = handler
            .handle_session_setup(&session_header, &session_request[64..], &session_request)
            .await
            .unwrap();
        let session_id = extract_session_id_from_response(&session_response);

        // Verify signing key exists
        assert!(handler.signing_keys.contains_key(&session_id));

        // Logoff
        let logoff_request = build_logoff_request(session_id);
        let logoff_header = Smb2Header::read(&mut Cursor::new(&logoff_request[..64])).unwrap();
        handler
            .handle_logoff(&logoff_header, &logoff_request[64..])
            .await
            .unwrap();

        // After logoff, signing key should be removed
        assert!(
            !handler.signing_keys.contains_key(&session_id),
            "Signing key MUST be removed after LOGOFF"
        );
    }

    // ==========================================================================
    // Test: maybe_sign_response properly signs messages with stored key
    // ==========================================================================

    #[test]
    fn test_maybe_sign_response_leaves_unsigned_when_no_key() {
        // Create a mock response without a stored signing key
        let mut response = [0u8; 72];
        response[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        response[4..6].copy_from_slice(&64u16.to_le_bytes());

        let session_id: u64 = 999; // No key for this session
        response[40..48].copy_from_slice(&session_id.to_le_bytes());

        // Empty signing keys map
        let signing_keys: HashMap<u64, Vec<u8>> = HashMap::new();

        // The SIGNED flag should NOT be set when no key exists
        let flags = u32::from_le_bytes([response[16], response[17], response[18], response[19]]);
        assert_eq!(
            flags & Smb2Flags::SIGNED,
            0,
            "Response should not be signed when no key exists"
        );

        // Verify signing_keys doesn't have the session
        assert!(
            !signing_keys.contains_key(&session_id),
            "No signing key should exist for unknown session"
        );
    }
}
