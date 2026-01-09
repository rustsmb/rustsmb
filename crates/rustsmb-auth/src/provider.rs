//! Authentication provider trait.

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
    },
    /// More data needed, send response token.
    Continue { response_token: Vec<u8> },
    /// Authentication failed.
    Failure { reason: AuthError },
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
    /// Group memberships.
    pub groups: Vec<String>,
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
}

/// Dynamic dispatch wrapper for auth providers.
pub type DynAuthProvider = std::sync::Arc<dyn AuthProvider>;
