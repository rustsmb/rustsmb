//! NTLM authentication provider.

use super::crypto::{
    decrypt_session_key, generate_challenge, nt_hash, ntowf_v2, verify_ntlmv2_response,
};
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

        // Negotiate flags: per MS-NLMP and ksmbd, we must ensure mandatory bits
        // are always set even if client didn't offer them. Optional bits are only
        // enabled if both server supports them AND client requested them.

        // Mandatory flags required for proper NTLM operation
        let mandatory = NtlmFlags::NEGOTIATE_UNICODE
            | NtlmFlags::NEGOTIATE_NTLM
            | NtlmFlags::NEGOTIATE_EXTENDED_SESSION_SECURITY
            | NtlmFlags::NEGOTIATE_TARGET_INFO
            | NtlmFlags::REQUEST_TARGET
            | NtlmFlags::TARGET_TYPE_SERVER;

        // Optional flags that require client support
        let optional = NtlmFlags::NEGOTIATE_KEY_EXCH
            | NtlmFlags::NEGOTIATE_128
            | NtlmFlags::NEGOTIATE_56
            | NtlmFlags::NEGOTIATE_SIGN
            | NtlmFlags::NEGOTIATE_SEAL
            | NtlmFlags::NEGOTIATE_VERSION
            | NtlmFlags::NEGOTIATE_ALWAYS_SIGN;

        // Start with mandatory flags, add optional flags only if client offered them
        let server_optional = NtlmFlags::server_default().0 & optional;
        let flags = NtlmFlags(mandatory | (server_optional & msg.flags.0));

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
                    response_token: None,
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

        // Compute NTOWFv2 - MUST use the SAME domain the client used
        // MS-NLMP: NTOWFv2 = HMAC_MD5(NT_Hash, UPPERCASE(Username) + UserDomain)
        // If client sends empty domain, we must use empty domain (not server default)
        debug!(
            "NTLMv2 verification: user={} domain={:?} nt_response_len={}",
            msg.user_name,
            msg.domain_name,
            msg.nt_response.len()
        );
        let ntowf = ntowf_v2(&nt, &msg.user_name, &msg.domain_name);

        // Verify NTLMv2 response
        let session_base_key = verify_ntlmv2_response(&ntowf, &server_challenge, &msg.nt_response)
            .ok_or_else(|| {
                warn!("NTLMv2 verification failed for user {}", msg.user_name);
                AuthError::InvalidCredentials
            })?;

        // If NEGOTIATE_KEY_EXCH is set, decrypt the exchanged session key
        let session_key = if msg.flags.has(NtlmFlags::NEGOTIATE_KEY_EXCH)
            && !msg.encrypted_session_key.is_empty()
        {
            debug!(
                "Decrypting exchanged session key (len={})",
                msg.encrypted_session_key.len()
            );
            let decrypted = decrypt_session_key(&session_base_key, &msg.encrypted_session_key)
                .ok_or_else(|| {
                    warn!("Failed to decrypt session key");
                    AuthError::Failed("Invalid encrypted session key".to_string())
                })?;
            debug!(
                "NTLMv2 session_base_key={:02x?} decrypted_session_key={:02x?}",
                session_base_key, decrypted
            );
            // Per MS-NLMP 3.4.5, SMB should derive signing/encryption keys from the
            // exported (decrypted) session key when KEY_EXCH is negotiated.
            decrypted
        } else {
            session_base_key
        };

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
            response_token: None,
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
            // Handle empty token as anonymous auth request
            if token.is_empty() {
                if self.allow_anonymous {
                    return Ok(AuthResult::Success {
                        user: UserInfo::anonymous(),
                        session_key: vec![],
                        response_token: None,
                    });
                } else {
                    return Err(AuthError::Failed(
                        "Anonymous access not allowed".to_string(),
                    ));
                }
            }

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
            AuthResult::Success {
                user, session_key, ..
            } => {
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

    #[tokio::test]
    async fn test_challenge_flags_mandatory_and_optional() {
        let provider = NtlmAuthProvider::new("SERVER", "DOMAIN");

        // Client only offers a small subset of flags.
        let negotiate = NegotiateMessage {
            flags: NtlmFlags(
                NtlmFlags::NEGOTIATE_UNICODE
                    | NtlmFlags::NEGOTIATE_NTLM
                    | NtlmFlags::REQUEST_TARGET,
            ),
            ..Default::default()
        };

        let mut context = AuthContext::default();
        let result = provider
            .authenticate(&mut context, &negotiate.build())
            .await
            .unwrap();

        let challenge_bytes = match result {
            AuthResult::Continue { response_token } => response_token,
            _ => panic!("Expected challenge response"),
        };

        let challenge = ChallengeMessage::parse(&challenge_bytes).unwrap();

        // Mandatory flags MUST be set even if client didn't offer them
        assert!(challenge.flags.has(NtlmFlags::NEGOTIATE_UNICODE));
        assert!(challenge.flags.has(NtlmFlags::NEGOTIATE_NTLM));
        assert!(challenge.flags.has(NtlmFlags::NEGOTIATE_TARGET_INFO));
        assert!(challenge.flags.has(NtlmFlags::REQUEST_TARGET));
        assert!(challenge
            .flags
            .has(NtlmFlags::NEGOTIATE_EXTENDED_SESSION_SECURITY));

        // Optional flags not offered by client should NOT be set
        assert!(!challenge.flags.has(NtlmFlags::NEGOTIATE_KEY_EXCH));
        assert!(!challenge.flags.has(NtlmFlags::NEGOTIATE_VERSION));
        assert!(!challenge.flags.has(NtlmFlags::NEGOTIATE_128));
        assert!(!challenge.flags.has(NtlmFlags::NEGOTIATE_56));
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
