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
    /// Server ID for lease tracking.
    server_id: String,
    /// Pre-authentication integrity hash (SMB 3.1.1).
    preauth_hash: PreauthIntegrityHash,
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

        // Clean up all sessions for this connection
        let session_ids: Vec<u64> = self.connection.session_ids().copied().collect();
        if !session_ids.is_empty() {
            debug!(
                conn_id = self.connection.id,
                session_count = session_ids.len(),
                "Cleaning up sessions on connection close"
            );
            for session_id in session_ids {
                let _ = self.session_manager.delete_session(session_id).await;
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
                // Generate session ID
                let session_id = self
                    .session_manager
                    .next_session_id()
                    .await
                    .map_err(|e| HandlerError::Internal(e.to_string()))?;

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

                // Step 5: Sign the response
                if should_sign {
                    self.sign_message(&mut result, &signing_key, dialect)?;
                }

                Ok(result)
            }
            AuthResult::Continue { response_token } => {
                // More rounds needed
                let dialect = self.connection.dialect.unwrap_or(SmbDialect::Smb202);

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
            parse_create_contexts, CreateContext, CreateContextBuilder, CreateDisposition,
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

        // Convert SMB CreateDisposition to VFS OpenFlags
        let disposition = CreateDisposition::from_u32(request.create_disposition)
            .ok_or(HandlerError::Status(NtStatus::InvalidParameter))?;

        let open_flags_value = match disposition {
            CreateDisposition::Create => {
                // Create new file, fail if exists
                rustsmb_vfs::OpenFlags::READ
                    | rustsmb_vfs::OpenFlags::WRITE
                    | rustsmb_vfs::OpenFlags::CREATE
                    | rustsmb_vfs::OpenFlags::EXCL
            }
            CreateDisposition::Open => {
                // Open existing file, fail if not exists
                rustsmb_vfs::OpenFlags::READ | rustsmb_vfs::OpenFlags::WRITE
            }
            CreateDisposition::OpenIf => {
                // Open if exists, create if not
                rustsmb_vfs::OpenFlags::READ
                    | rustsmb_vfs::OpenFlags::WRITE
                    | rustsmb_vfs::OpenFlags::CREATE
            }
            CreateDisposition::Overwrite => {
                // Open and truncate, fail if not exists
                rustsmb_vfs::OpenFlags::READ
                    | rustsmb_vfs::OpenFlags::WRITE
                    | rustsmb_vfs::OpenFlags::TRUNC
            }
            CreateDisposition::OverwriteIf => {
                // Open and truncate if exists, create if not
                rustsmb_vfs::OpenFlags::READ
                    | rustsmb_vfs::OpenFlags::WRITE
                    | rustsmb_vfs::OpenFlags::CREATE
                    | rustsmb_vfs::OpenFlags::TRUNC
            }
            CreateDisposition::Supersede => {
                // Similar to overwrite but also creates
                rustsmb_vfs::OpenFlags::READ
                    | rustsmb_vfs::OpenFlags::WRITE
                    | rustsmb_vfs::OpenFlags::CREATE
                    | rustsmb_vfs::OpenFlags::TRUNC
            }
        };
        let open_flags = rustsmb_vfs::OpenFlags::new(open_flags_value);

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
        let open_flags = rustsmb_vfs::OpenFlags::new(
            rustsmb_vfs::OpenFlags::READ | rustsmb_vfs::OpenFlags::WRITE,
        );
        let _file_handle = backend
            .open(&handle.path, open_flags, 0o644)
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

        // Get handle first to check for lease
        if let Ok(Some(handle)) = self.session_manager.get_handle(handle_id).await {
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
