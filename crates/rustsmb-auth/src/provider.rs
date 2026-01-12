//! Authentication provider trait.
//!
//! This module defines the core authentication traits and types used
//! throughout RustSMB.
//!
//! # Session Types
//!
//! SMB supports several session types:
//!
//! - **Authenticated**: Normal user session with full credentials
//! - **Guest**: Limited access session (NTLM_NEGOTIATE_FLAG_ANONYMOUS not set)
//! - **Anonymous**: Null session with minimal access (NTLM_NEGOTIATE_FLAG_ANONYMOUS set)
//!
//! # Authentication Flow
//!
//! ```text
//! Client                    Server
//!   |                         |
//!   |---(1) Negotiate-------->|
//!   |<--(2) Challenge---------|
//!   |---(3) Authenticate----->|
//!   |<--(4) Success/Failure---|
//!   |                         |
//! ```

use rustsmb_core::AuthError;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// Type alias for boxed async results.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Authentication provider trait.
///
/// Implementations provide different authentication mechanisms.
pub trait AuthProvider: Send + Sync + 'static {
    /// Authenticate a user with a security token.
    fn authenticate<'a>(
        &'a self,
        context: &'a mut AuthContext,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<AuthResult, AuthError>>;

    /// Get user information.
    fn get_user<'a>(
        &'a self,
        username: &'a str,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<UserInfo>, AuthError>>;

    /// Validate a session key.
    fn validate_session_key<'a>(
        &'a self,
        session_id: u64,
        key: &'a [u8],
    ) -> BoxFuture<'a, Result<bool, AuthError>>;

    /// Get supported authentication mechanisms.
    fn supported_mechanisms(&self) -> Vec<AuthMechanism>;

    /// Check if guest sessions are allowed.
    fn allows_guest(&self) -> bool {
        false
    }

    /// Check if anonymous sessions are allowed.
    fn allows_anonymous(&self) -> bool {
        false
    }

    /// Get guest user info (if guest is allowed).
    fn guest_user(&self) -> Option<UserInfo> {
        if self.allows_guest() {
            Some(UserInfo::guest())
        } else {
            None
        }
    }

    /// Get anonymous user info (if anonymous is allowed).
    fn anonymous_user(&self) -> Option<UserInfo> {
        if self.allows_anonymous() {
            Some(UserInfo::anonymous())
        } else {
            None
        }
    }
}

/// Authentication context for multi-round authentication.
#[derive(Debug, Default)]
pub struct AuthContext {
    /// Session ID (if assigned).
    pub session_id: Option<u64>,
    /// Authentication state.
    pub state: AuthState,
    /// Challenge data (for NTLM).
    pub challenge: Option<Vec<u8>>,
    /// Server name.
    pub server_name: String,
    /// Whether anonymous authentication was requested.
    pub anonymous_requested: bool,
    /// Pre-auth integrity hash (SMB 3.1.1).
    pub preauth_hash: Option<Vec<u8>>,
    /// Whether client is using raw mechanism (not SPNEGO-wrapped).
    pub raw_mechanism: bool,
}

/// Authentication state.
#[derive(Debug, Clone, Default)]
pub enum AuthState {
    /// Initial state.
    #[default]
    Initial,
    /// Waiting for response to challenge.
    ChallengeIssued,
    /// Authentication complete.
    Complete,
    /// Guest session established.
    Guest,
    /// Anonymous session established.
    Anonymous,
    /// Authentication failed.
    Failed,
}

/// Result of an authentication attempt.
#[derive(Debug)]
pub enum AuthResult {
    /// Authentication successful.
    Success {
        user: UserInfo,
        session_key: Vec<u8>,
        /// Optional final response token (e.g., SPNEGO AcceptCompleted).
        response_token: Option<Vec<u8>>,
    },
    /// More data needed, send response token.
    Continue { response_token: Vec<u8> },
    /// Authentication failed.
    Failure { reason: AuthError },
}

/// Session type for access control decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionType {
    /// Fully authenticated user session.
    Authenticated,
    /// Guest session (limited access).
    Guest,
    /// Anonymous/null session (minimal access).
    Anonymous,
}

impl Default for SessionType {
    fn default() -> Self {
        Self::Authenticated
    }
}

/// User information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID/SID.
    pub id: String,
    /// Username.
    pub username: String,
    /// Domain.
    pub domain: Option<String>,
    /// Display name.
    pub display_name: Option<String>,
    /// Is administrator.
    pub is_admin: bool,
    /// Is guest.
    pub is_guest: bool,
    /// Is anonymous (null session).
    pub is_anonymous: bool,
    /// Group memberships.
    pub groups: Vec<String>,
    /// Session type.
    pub session_type: SessionType,
}

impl UserInfo {
    /// Create a guest user.
    pub fn guest() -> Self {
        Self {
            id: "S-1-5-21-0-0-0-501".to_string(), // Well-known Guest SID suffix
            username: "Guest".to_string(),
            domain: None,
            display_name: Some("Guest".to_string()),
            is_admin: false,
            is_guest: true,
            is_anonymous: false,
            groups: vec!["Guests".to_string()],
            session_type: SessionType::Guest,
        }
    }

    /// Create an anonymous user.
    pub fn anonymous() -> Self {
        Self {
            id: "S-1-5-7".to_string(), // Well-known Anonymous SID
            username: "ANONYMOUS LOGON".to_string(),
            domain: None,
            display_name: Some("Anonymous".to_string()),
            is_admin: false,
            is_guest: false,
            is_anonymous: true,
            groups: Vec::new(),
            session_type: SessionType::Anonymous,
        }
    }

    /// Check if this user has minimal access rights.
    pub fn is_restricted(&self) -> bool {
        self.is_guest || self.is_anonymous
    }

    /// Create a new authenticated user.
    pub fn authenticated(username: &str, domain: Option<&str>) -> Self {
        Self {
            id: format!("{}\\{}", domain.unwrap_or("LOCAL"), username),
            username: username.to_string(),
            domain: domain.map(String::from),
            display_name: Some(username.to_string()),
            is_admin: false,
            is_guest: false,
            is_anonymous: false,
            groups: Vec::new(),
            session_type: SessionType::Authenticated,
        }
    }
}

/// Authentication mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    /// NTLM authentication.
    Ntlm,
    /// NTLMv2 authentication.
    NtlmV2,
    /// Kerberos authentication.
    Kerberos,
    /// Simple password authentication.
    Simple,
    /// Anonymous authentication.
    Anonymous,
}

/// Dynamic dispatch wrapper for auth providers.
pub type DynAuthProvider = std::sync::Arc<dyn AuthProvider>;

/// Anonymous/guest authentication provider.
///
/// Provides authentication for anonymous and guest sessions.
/// Used when no credentials are provided or when explicitly
/// requesting anonymous access.
#[derive(Debug, Clone)]
pub struct AnonymousAuthProvider {
    /// Allow anonymous (null) sessions.
    allow_anonymous: bool,
    /// Allow guest sessions.
    allow_guest: bool,
    /// Default to guest when authentication fails.
    fallback_to_guest: bool,
}

impl AnonymousAuthProvider {
    /// Create a provider that only allows anonymous sessions.
    pub fn anonymous_only() -> Self {
        Self {
            allow_anonymous: true,
            allow_guest: false,
            fallback_to_guest: false,
        }
    }

    /// Create a provider that only allows guest sessions.
    pub fn guest_only() -> Self {
        Self {
            allow_anonymous: false,
            allow_guest: true,
            fallback_to_guest: false,
        }
    }

    /// Create a provider that allows both anonymous and guest.
    pub fn allow_both() -> Self {
        Self {
            allow_anonymous: true,
            allow_guest: true,
            fallback_to_guest: false,
        }
    }

    /// Enable fallback to guest on authentication failure.
    pub fn with_guest_fallback(mut self) -> Self {
        self.fallback_to_guest = true;
        self
    }

    /// Check if this request is for anonymous access.
    fn is_anonymous_request(&self, token: &[u8]) -> bool {
        // Empty token or anonymous NTLM flag
        token.is_empty()
    }
}

impl Default for AnonymousAuthProvider {
    fn default() -> Self {
        Self::guest_only()
    }
}

impl AuthProvider for AnonymousAuthProvider {
    fn authenticate<'a>(
        &'a self,
        context: &'a mut AuthContext,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<AuthResult, AuthError>> {
        Box::pin(async move {
            if self.is_anonymous_request(token) && self.allow_anonymous {
                context.state = AuthState::Anonymous;
                return Ok(AuthResult::Success {
                    user: UserInfo::anonymous(),
                    session_key: vec![0; 16], // Null session key
                    response_token: None,
                });
            }

            if self.allow_guest {
                context.state = AuthState::Guest;
                return Ok(AuthResult::Success {
                    user: UserInfo::guest(),
                    session_key: vec![0; 16], // Guest session key
                    response_token: None,
                });
            }

            Err(AuthError::Failed(
                "Anonymous/guest access not allowed".to_string(),
            ))
        })
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        _domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<UserInfo>, AuthError>> {
        Box::pin(async move {
            match username.to_lowercase().as_str() {
                "" | "anonymous" | "anonymous logon" if self.allow_anonymous => {
                    Ok(Some(UserInfo::anonymous()))
                }
                "guest" if self.allow_guest => Ok(Some(UserInfo::guest())),
                _ => Ok(None),
            }
        })
    }

    fn validate_session_key<'a>(
        &'a self,
        _session_id: u64,
        key: &'a [u8],
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        Box::pin(async move {
            // Anonymous/guest sessions use null keys
            Ok(key.iter().all(|&b| b == 0))
        })
    }

    fn supported_mechanisms(&self) -> Vec<AuthMechanism> {
        vec![AuthMechanism::Anonymous]
    }

    fn allows_guest(&self) -> bool {
        self.allow_guest
    }

    fn allows_anonymous(&self) -> bool {
        self.allow_anonymous
    }
}

/// Composite authentication provider.
///
/// Chains multiple providers together, trying each in order.
pub struct CompositeAuthProvider {
    providers: Vec<DynAuthProvider>,
    fallback: Option<DynAuthProvider>,
}

impl CompositeAuthProvider {
    /// Create a new composite provider.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            fallback: None,
        }
    }

    /// Add a provider to the chain.
    pub fn with_provider(mut self, provider: DynAuthProvider) -> Self {
        self.providers.push(provider);
        self
    }

    /// Set a fallback provider (e.g., guest).
    pub fn with_fallback(mut self, provider: DynAuthProvider) -> Self {
        self.fallback = Some(provider);
        self
    }
}

impl Default for CompositeAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for CompositeAuthProvider {
    fn authenticate<'a>(
        &'a self,
        context: &'a mut AuthContext,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<AuthResult, AuthError>> {
        Box::pin(async move {
            // Try each provider in order
            for provider in &self.providers {
                match provider.authenticate(context, token).await {
                    Ok(result) => return Ok(result),
                    Err(AuthError::InvalidCredentials) => continue,
                    Err(e) => return Err(e),
                }
            }

            // Try fallback if configured
            if let Some(ref fallback) = self.fallback {
                return fallback.authenticate(context, token).await;
            }

            Err(AuthError::InvalidCredentials)
        })
    }

    fn get_user<'a>(
        &'a self,
        username: &'a str,
        domain: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<UserInfo>, AuthError>> {
        Box::pin(async move {
            for provider in &self.providers {
                if let Some(user) = provider.get_user(username, domain).await? {
                    return Ok(Some(user));
                }
            }
            Ok(None)
        })
    }

    fn validate_session_key<'a>(
        &'a self,
        session_id: u64,
        key: &'a [u8],
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        Box::pin(async move {
            for provider in &self.providers {
                if provider.validate_session_key(session_id, key).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    fn supported_mechanisms(&self) -> Vec<AuthMechanism> {
        self.providers
            .iter()
            .flat_map(|p| p.supported_mechanisms())
            .collect()
    }

    fn allows_guest(&self) -> bool {
        self.providers.iter().any(|p| p.allows_guest())
            || self.fallback.as_ref().is_some_and(|f| f.allows_guest())
    }

    fn allows_anonymous(&self) -> bool {
        self.providers.iter().any(|p| p.allows_anonymous())
            || self.fallback.as_ref().is_some_and(|f| f.allows_anonymous())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_info_guest() {
        let user = UserInfo::guest();
        assert!(user.is_guest);
        assert!(!user.is_anonymous);
        assert!(user.is_restricted());
        assert_eq!(user.session_type, SessionType::Guest);
    }

    #[test]
    fn test_user_info_anonymous() {
        let user = UserInfo::anonymous();
        assert!(!user.is_guest);
        assert!(user.is_anonymous);
        assert!(user.is_restricted());
        assert_eq!(user.session_type, SessionType::Anonymous);
    }

    #[test]
    fn test_user_info_authenticated() {
        let user = UserInfo::authenticated("testuser", Some("DOMAIN"));
        assert!(!user.is_guest);
        assert!(!user.is_anonymous);
        assert!(!user.is_restricted());
        assert_eq!(user.session_type, SessionType::Authenticated);
    }

    #[tokio::test]
    async fn test_anonymous_provider() {
        let provider = AnonymousAuthProvider::anonymous_only();
        let mut context = AuthContext::default();

        let result = provider.authenticate(&mut context, &[]).await.unwrap();
        match result {
            AuthResult::Success { user, .. } => {
                assert!(user.is_anonymous);
            }
            _ => panic!("Expected anonymous success"),
        }
    }

    #[tokio::test]
    async fn test_guest_provider() {
        let provider = AnonymousAuthProvider::guest_only();
        let mut context = AuthContext::default();

        // Non-empty token triggers guest
        let result = provider.authenticate(&mut context, b"x").await.unwrap();
        match result {
            AuthResult::Success { user, .. } => {
                assert!(user.is_guest);
            }
            _ => panic!("Expected guest success"),
        }
    }

    #[test]
    fn test_auth_state() {
        let state = AuthState::default();
        assert!(matches!(state, AuthState::Initial));
    }
}
