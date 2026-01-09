//! NTLM authentication provider.

use super::crypto::{generate_challenge, nt_hash, ntowf_v2, verify_ntlmv2_response};
use super::messages::{AuthenticateMessage, ChallengeMessage, NegotiateMessage};
use super::{build_target_info, current_filetime, NtlmFlags};
use crate::{AuthContext, AuthMechanism, AuthProvider, AuthResult, AuthState, BoxFuture, UserInfo};
use rustsmb_core::AuthError;
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, warn};

/// Pending challenge data for NTLM authentication.
type PendingChallengeData = ([u8; 8], Vec<u8>, u64);

/// NTLM authentication provider.
///
/// Implements NTLMv2 authentication.
pub struct NtlmAuthProvider {
    /// User database: username -> (nt_hash, UserInfo).
    users: RwLock<HashMap<String, ([u8; 16], UserInfo)>>,
    /// Server name (NetBIOS).
    server_name: String,
    /// Domain name (NetBIOS).
    domain_name: String,
    /// DNS server name.
    dns_server: String,
    /// DNS domain name.
    dns_domain: String,
    /// Allow anonymous connections.
    allow_anonymous: bool,
    /// Pending challenges: session_id -> (challenge, target_info, timestamp).
    pending_challenges: RwLock<HashMap<u64, PendingChallengeData>>,
    /// Next session ID counter.
    next_session: RwLock<u64>,
}

impl NtlmAuthProvider {
    /// Create a new NTLM provider.
    pub fn new(server_name: &str, domain_name: &str) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            server_name: server_name.to_string(),
            domain_name: domain_name.to_string(),
            dns_server: format!("{}.local", server_name.to_lowercase()),
            dns_domain: format!("{}.local", domain_name.to_lowercase()),
            allow_anonymous: false,
            pending_challenges: RwLock::new(HashMap::new()),
            next_session: RwLock::new(1),
        }
    }

    /// Set DNS names.
    pub fn with_dns(mut self, dns_server: &str, dns_domain: &str) -> Self {
        self.dns_server = dns_server.to_string();
        self.dns_domain = dns_domain.to_string();
        self
    }

    /// Allow anonymous connections.
    pub fn with_anonymous(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Add a user with password.
    pub fn add_user(&self, username: &str, password: &str, is_admin: bool) {
        let nt = nt_hash(password);
        let mut user_info = UserInfo::authenticated(username, Some(&self.domain_name));
        user_info.is_admin = is_admin;

        let mut users = self.users.write().unwrap();
        users.insert(username.to_uppercase(), (nt, user_info));
    }

    /// Add a user with pre-computed NT hash.
    pub fn add_user_hash(&self, username: &str, nt_hash: [u8; 16], is_admin: bool) {
        let mut user_info = UserInfo::authenticated(username, Some(&self.domain_name));
        user_info.is_admin = is_admin;

        let mut users = self.users.write().unwrap();
        users.insert(username.to_uppercase(), (nt_hash, user_info));
    }

    /// Get temporary session ID for challenge tracking.
    fn get_temp_session_id(&self) -> u64 {
        let mut next = self.next_session.write().unwrap();
        let id = *next;
        *next = next.wrapping_add(1);
        id
    }

    /// Process NEGOTIATE message.
    fn process_negotiate(
        &self,
        context: &mut AuthContext,
        msg: &NegotiateMessage,
    ) -> Result<AuthResult, AuthError> {
        debug!("Processing NTLM negotiate from {:?}", msg.workstation);

        // Generate challenge
        let server_challenge = generate_challenge();
        let timestamp = current_filetime();

        // Build target info
        let target_info = build_target_info(
            &self.domain_name,
            &self.server_name,
            &self.dns_domain,
            &self.dns_server,
            timestamp,
        );

        // Negotiate flags
        let mut flags = NtlmFlags::server_default();
        // Honor client's unicode/oem preference
        if msg.flags.has(NtlmFlags::NEGOTIATE_UNICODE) {
            flags.set(NtlmFlags::NEGOTIATE_UNICODE);
        }

        // Build challenge message
        let challenge = ChallengeMessage::new(
            &self.server_name,
            server_challenge,
            target_info.clone(),
            flags,
        );

        // Store challenge for validation
        let session_id = context
            .session_id
            .unwrap_or_else(|| self.get_temp_session_id());
        {
            let mut pending = self.pending_challenges.write().unwrap();
            pending.insert(session_id, (server_challenge, target_info, timestamp));
        }

        context.session_id = Some(session_id);
        context.challenge = Some(server_challenge.to_vec());
        context.state = AuthState::ChallengeIssued;

        Ok(AuthResult::Continue {
            response_token: challenge.build(),
        })
    }

    /// Process AUTHENTICATE message.
    fn process_authenticate(
        &self,
        context: &mut AuthContext,
        msg: &AuthenticateMessage,
    ) -> Result<AuthResult, AuthError> {
        debug!(
            "Processing NTLM authenticate for user: {} domain: {}",
            msg.user_name, msg.domain_name
        );

        // Check for anonymous
        if msg.is_anonymous() {
            if self.allow_anonymous {
                context.state = AuthState::Complete;
                return Ok(AuthResult::Success {
                    user: UserInfo {
                        id: "anonymous".to_string(),
                        username: "anonymous".to_string(),
                        is_guest: true,
                        ..Default::default()
                    },
                    session_key: vec![0; 16],
                });
            } else {
                context.state = AuthState::Failed;
                return Err(AuthError::InvalidCredentials);
            }
        }

        // Get stored challenge
        let session_id = context
            .session_id
            .ok_or(AuthError::Failed("No session ID in context".to_string()))?;

        let (server_challenge, _target_info, _timestamp) = {
            let pending = self.pending_challenges.read().unwrap();
            pending
                .get(&session_id)
                .cloned()
                .ok_or(AuthError::Failed("No pending challenge".to_string()))?
        };

        // Look up user
        let username_upper = msg.user_name.to_uppercase();
        let (nt, user_info) = {
            let users = self.users.read().unwrap();
            users
                .get(&username_upper)
                .cloned()
                .ok_or(AuthError::InvalidCredentials)?
        };

        // Compute NTOWFv2
        let domain = if msg.domain_name.is_empty() {
            &self.domain_name
        } else {
            &msg.domain_name
        };
        let ntowf = ntowf_v2(&nt, &msg.user_name, domain);

        // Verify NTLMv2 response
        let session_key = verify_ntlmv2_response(&ntowf, &server_challenge, &msg.nt_response)
            .ok_or_else(|| {
                warn!("NTLMv2 verification failed for user {}", msg.user_name);
                AuthError::InvalidCredentials
            })?;

        // Clean up pending challenge
        {
            let mut pending = self.pending_challenges.write().unwrap();
            pending.remove(&session_id);
        }

        context.state = AuthState::Complete;
        debug!("NTLM authentication successful for {}", msg.user_name);

        Ok(AuthResult::Success {
            user: user_info,
            session_key: session_key.to_vec(),
        })
    }
}

impl AuthProvider for NtlmAuthProvider {
    fn authenticate<'a>(
        &'a self,
        context: &'a mut AuthContext,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<AuthResult, AuthError>> {
        Box::pin(async move {
            if token.len() < 12 {
                return Err(AuthError::Failed("Token too short".to_string()));
            }

            // Determine message type
            let msg_type = u32::from_le_bytes([token[8], token[9], token[10], token[11]]);

            match msg_type {
                1 => {
                    // NEGOTIATE
                    let msg = NegotiateMessage::parse(token)
                        .ok_or(AuthError::Failed("Invalid NEGOTIATE message".to_string()))?;
                    self.process_negotiate(context, &msg)
                }
                3 => {
                    // AUTHENTICATE
                    let msg = AuthenticateMessage::parse(token).ok_or(AuthError::Failed(
                        "Invalid AUTHENTICATE message".to_string(),
                    ))?;
                    self.process_authenticate(context, &msg)
                }
                _ => Err(AuthError::Failed(format!(
                    "Unexpected NTLM message type: {}",
                    msg_type
                ))),
            }
        })
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        _domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<UserInfo>, AuthError>> {
        Box::pin(async move {
            let users = self.users.read().unwrap();
            Ok(users
                .get(&username.to_uppercase())
                .map(|(_, info)| info.clone()))
        })
    }

    fn validate_session_key<'a>(
        &'a self,
        _session_id: u64,
        _key: &'a [u8],
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        Box::pin(async move {
            // NTLMv2 session keys are derived deterministically
            // Full validation would require storing keys
            Ok(true)
        })
    }

    fn supported_mechanisms(&self) -> Vec<AuthMechanism> {
        vec![AuthMechanism::NtlmV2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ntlm_challenge_response() {
        let provider = NtlmAuthProvider::new("SERVER", "DOMAIN");
        provider.add_user("testuser", "testpass", false);

        let mut context = AuthContext::default();

        // Build negotiate message
        let negotiate = NegotiateMessage::default();
        let negotiate_bytes = negotiate.build();

        // Process negotiate
        let result = provider
            .authenticate(&mut context, &negotiate_bytes)
            .await
            .unwrap();

        // Should get challenge
        let challenge_bytes = match result {
            AuthResult::Continue { response_token } => response_token,
            _ => panic!("Expected Continue with challenge"),
        };

        assert!(context.session_id.is_some());
        assert!(matches!(context.state, AuthState::ChallengeIssued));

        // Parse challenge
        let challenge = ChallengeMessage::parse(&challenge_bytes).unwrap();
        assert_eq!(challenge.target_name, "SERVER");
    }

    #[tokio::test]
    async fn test_ntlm_full_auth() {
        use super::super::crypto::{compute_ntlmv2_response, nt_hash, ntowf_v2};

        let provider = NtlmAuthProvider::new("SERVER", "DOMAIN");
        provider.add_user("testuser", "testpass", false);

        let mut context = AuthContext::default();

        // Step 1: Negotiate
        let negotiate = NegotiateMessage::default();
        let result = provider
            .authenticate(&mut context, &negotiate.build())
            .await
            .unwrap();

        let challenge_bytes = match result {
            AuthResult::Continue { response_token } => response_token,
            _ => panic!("Expected challenge"),
        };

        let challenge = ChallengeMessage::parse(&challenge_bytes).unwrap();

        // Step 2: Build authenticate message
        let password = "testpass";
        let username = "testuser";
        let domain = "DOMAIN";

        let nt = nt_hash(password);
        let ntowf = ntowf_v2(&nt, username, domain);

        let client_challenge = super::super::crypto::generate_challenge();
        let timestamp = current_filetime();

        let (nt_response, _) = compute_ntlmv2_response(
            &ntowf,
            &challenge.server_challenge,
            &client_challenge,
            timestamp,
            &challenge.target_info,
        );

        // Build authenticate message manually (simplified)
        let auth_msg = build_authenticate_message(username, domain, &nt_response, challenge.flags);

        // Step 3: Authenticate
        let result = provider
            .authenticate(&mut context, &auth_msg)
            .await
            .unwrap();

        match result {
            AuthResult::Success { user, session_key } => {
                assert_eq!(user.username, "testuser");
                assert_eq!(session_key.len(), 16);
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_ntlm_wrong_password() {
        use super::super::crypto::{compute_ntlmv2_response, nt_hash, ntowf_v2};

        let provider = NtlmAuthProvider::new("SERVER", "DOMAIN");
        provider.add_user("testuser", "testpass", false);

        let mut context = AuthContext::default();

        // Negotiate
        let negotiate = NegotiateMessage::default();
        let result = provider
            .authenticate(&mut context, &negotiate.build())
            .await
            .unwrap();

        let challenge_bytes = match result {
            AuthResult::Continue { response_token } => response_token,
            _ => panic!("Expected challenge"),
        };

        let challenge = ChallengeMessage::parse(&challenge_bytes).unwrap();

        // Build authenticate with wrong password
        let password = "wrongpass";
        let username = "testuser";
        let domain = "DOMAIN";

        let nt = nt_hash(password);
        let ntowf = ntowf_v2(&nt, username, domain);

        let client_challenge = super::super::crypto::generate_challenge();
        let timestamp = current_filetime();

        let (nt_response, _) = compute_ntlmv2_response(
            &ntowf,
            &challenge.server_challenge,
            &client_challenge,
            timestamp,
            &challenge.target_info,
        );

        let auth_msg = build_authenticate_message(username, domain, &nt_response, challenge.flags);

        // Should fail
        let result = provider.authenticate(&mut context, &auth_msg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ntlm_anonymous() {
        let provider = NtlmAuthProvider::new("SERVER", "DOMAIN").with_anonymous();

        let mut context = AuthContext::default();

        // Negotiate
        let negotiate = NegotiateMessage::default();
        let result = provider
            .authenticate(&mut context, &negotiate.build())
            .await
            .unwrap();

        let challenge_bytes = match result {
            AuthResult::Continue { response_token } => response_token,
            _ => panic!("Expected challenge"),
        };

        let challenge = ChallengeMessage::parse(&challenge_bytes).unwrap();

        // Build anonymous authenticate
        let auth_msg = build_authenticate_message("", "", &[], challenge.flags);

        let result = provider
            .authenticate(&mut context, &auth_msg)
            .await
            .unwrap();
        match result {
            AuthResult::Success { user, .. } => {
                assert!(user.is_guest);
                assert_eq!(user.username, "anonymous");
            }
            _ => panic!("Expected success"),
        }
    }

    /// Helper to build authenticate message for tests.
    fn build_authenticate_message(
        username: &str,
        domain: &str,
        nt_response: &[u8],
        flags: NtlmFlags,
    ) -> Vec<u8> {
        use super::super::NTLM_SIGNATURE;

        // Encode strings
        let domain_bytes: Vec<u8> = domain
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let user_bytes: Vec<u8> = username
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let ws_bytes: Vec<u8> = "WORKSTATION"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // Calculate offsets (base header is 88 bytes)
        let base_offset = 88;
        let lm_offset = base_offset;
        let lm_len = 0;
        let nt_offset = lm_offset + lm_len;
        let nt_len = nt_response.len();
        let domain_offset = nt_offset + nt_len;
        let domain_len = domain_bytes.len();
        let user_offset = domain_offset + domain_len;
        let user_len = user_bytes.len();
        let ws_offset = user_offset + user_len;
        let ws_len = ws_bytes.len();
        let esk_offset = ws_offset + ws_len;
        let esk_len = 0;

        let mut buf = Vec::with_capacity(base_offset + nt_len + domain_len + user_len + ws_len);

        // Header
        buf.extend_from_slice(NTLM_SIGNATURE);
        buf.extend_from_slice(&3u32.to_le_bytes()); // Type 3

        // LM response buffer
        buf.extend_from_slice(&(lm_len as u16).to_le_bytes());
        buf.extend_from_slice(&(lm_len as u16).to_le_bytes());
        buf.extend_from_slice(&(lm_offset as u32).to_le_bytes());

        // NT response buffer
        buf.extend_from_slice(&(nt_len as u16).to_le_bytes());
        buf.extend_from_slice(&(nt_len as u16).to_le_bytes());
        buf.extend_from_slice(&(nt_offset as u32).to_le_bytes());

        // Domain buffer
        buf.extend_from_slice(&(domain_len as u16).to_le_bytes());
        buf.extend_from_slice(&(domain_len as u16).to_le_bytes());
        buf.extend_from_slice(&(domain_offset as u32).to_le_bytes());

        // User buffer
        buf.extend_from_slice(&(user_len as u16).to_le_bytes());
        buf.extend_from_slice(&(user_len as u16).to_le_bytes());
        buf.extend_from_slice(&(user_offset as u32).to_le_bytes());

        // Workstation buffer
        buf.extend_from_slice(&(ws_len as u16).to_le_bytes());
        buf.extend_from_slice(&(ws_len as u16).to_le_bytes());
        buf.extend_from_slice(&(ws_offset as u32).to_le_bytes());

        // Encrypted session key buffer
        buf.extend_from_slice(&(esk_len as u16).to_le_bytes());
        buf.extend_from_slice(&(esk_len as u16).to_le_bytes());
        buf.extend_from_slice(&(esk_offset as u32).to_le_bytes());

        // Flags
        buf.extend_from_slice(&flags.0.to_le_bytes());

        // Version
        buf.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]); // Windows 10

        // MIC (zeros)
        buf.extend_from_slice(&[0u8; 16]);

        // Payload
        buf.extend_from_slice(nt_response);
        buf.extend_from_slice(&domain_bytes);
        buf.extend_from_slice(&user_bytes);
        buf.extend_from_slice(&ws_bytes);

        buf
    }
}
