//! Simple password authentication provider.
//!
//! This provider uses a simple username/password map for authentication.
//! Suitable for testing and simple deployments.

use crate::{
    AuthContext, AuthMechanism, AuthProvider, AuthResult, AuthState, BoxFuture, UserInfo,
};
use rustsmb_core::AuthError;
use std::collections::HashMap;
use std::sync::RwLock;

/// Simple password authentication provider.
pub struct SimpleAuthProvider {
    /// Username -> (password, UserInfo) map.
    users: RwLock<HashMap<String, (String, UserInfo)>>,
    /// Allow guest access.
    allow_guest: bool,
}

impl SimpleAuthProvider {
    /// Create a new simple auth provider.
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            allow_guest: false,
        }
    }

    /// Enable guest access.
    pub fn with_guest(mut self) -> Self {
        self.allow_guest = true;
        self
    }

    /// Add a user.
    pub fn add_user(&self, username: &str, password: &str, is_admin: bool) {
        let user_info = UserInfo {
            id: username.to_string(),
            username: username.to_string(),
            domain: None,
            display_name: Some(username.to_string()),
            is_admin,
            is_guest: false,
            groups: Vec::new(),
        };
        let mut users = self.users.write().unwrap();
        users.insert(username.to_string(), (password.to_string(), user_info));
    }

    /// Validate username and password.
    fn validate(&self, username: &str, password: &str) -> Option<UserInfo> {
        let users = self.users.read().unwrap();
        users.get(username).and_then(|(stored_pass, info)| {
            if stored_pass == password {
                Some(info.clone())
            } else {
                None
            }
        })
    }
}

impl Default for SimpleAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthProvider for SimpleAuthProvider {
    fn authenticate<'a>(
        &'a self,
        context: &'a mut AuthContext,
        token: &'a [u8],
    ) -> BoxFuture<'a, Result<AuthResult, AuthError>> {
        Box::pin(async move {
            // Simple auth: token is "username:password"
            let token_str = std::str::from_utf8(token).map_err(|_| AuthError::InvalidCredentials)?;

            let parts: Vec<&str> = token_str.splitn(2, ':').collect();
            if parts.len() != 2 {
                // Check for guest
                if self.allow_guest && (token_str.is_empty() || token_str == "guest") {
                    context.state = AuthState::Complete;
                    return Ok(AuthResult::Success {
                        user: UserInfo {
                            id: "guest".to_string(),
                            username: "guest".to_string(),
                            is_guest: true,
                            ..Default::default()
                        },
                        session_key: vec![0; 16],
                    });
                }
                return Err(AuthError::InvalidCredentials);
            }

            let username = parts[0];
            let password = parts[1];

            match self.validate(username, password) {
                Some(user) => {
                    context.state = AuthState::Complete;
                    // Generate a simple session key
                    let session_key = {
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};
                        let mut hasher = DefaultHasher::new();
                        username.hash(&mut hasher);
                        password.hash(&mut hasher);
                        let hash = hasher.finish();
                        hash.to_le_bytes().repeat(2)
                    };
                    Ok(AuthResult::Success { user, session_key })
                }
                None => {
                    context.state = AuthState::Failed;
                    Err(AuthError::InvalidCredentials)
                }
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
            Ok(users.get(username).map(|(_, info)| info.clone()))
        })
    }

    fn validate_session_key<'a>(
        &'a self,
        _session_id: u64,
        _key: &'a [u8],
    ) -> BoxFuture<'a, Result<bool, AuthError>> {
        Box::pin(async move {
            // Simple implementation: always valid
            Ok(true)
        })
    }

    fn supported_mechanisms(&self) -> Vec<AuthMechanism> {
        vec![AuthMechanism::Simple]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_auth_success() {
        let provider = SimpleAuthProvider::new();
        provider.add_user("testuser", "testpass", false);

        let mut context = AuthContext::default();
        let result = provider
            .authenticate(&mut context, b"testuser:testpass")
            .await
            .unwrap();

        match result {
            AuthResult::Success { user, .. } => {
                assert_eq!(user.username, "testuser");
            }
            _ => panic!("Expected success"),
        }
    }

    #[tokio::test]
    async fn test_simple_auth_failure() {
        let provider = SimpleAuthProvider::new();
        provider.add_user("testuser", "testpass", false);

        let mut context = AuthContext::default();
        let result = provider
            .authenticate(&mut context, b"testuser:wrongpass")
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_guest_auth() {
        let provider = SimpleAuthProvider::new().with_guest();

        let mut context = AuthContext::default();
        let result = provider.authenticate(&mut context, b"").await.unwrap();

        match result {
            AuthResult::Success { user, .. } => {
                assert!(user.is_guest);
            }
            _ => panic!("Expected guest success"),
        }
    }
}
