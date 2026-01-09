//! Main server implementation.

use crate::{ServerConfig, ShareManager};
use rustsmb_auth::DynAuthProvider;
use rustsmb_session::SessionManager;
use rustsmb_state::DynStateStore;
use std::sync::Arc;
use tracing::info;

/// SMB Server.
pub struct SmbServer {
    /// Server configuration.
    config: ServerConfig,
    /// Session manager.
    session_manager: Arc<SessionManager>,
    /// Authentication provider.
    auth_provider: DynAuthProvider,
    /// Share manager.
    shares: Arc<ShareManager>,
}

impl SmbServer {
    /// Create a new SMB server.
    pub fn new(
        config: ServerConfig,
        state_store: DynStateStore,
        auth_provider: DynAuthProvider,
    ) -> Self {
        let session_manager = Arc::new(SessionManager::with_defaults(state_store));

        Self {
            config,
            session_manager,
            auth_provider,
            shares: Arc::new(ShareManager::new()),
        }
    }

    /// Get the share manager.
    pub fn shares(&self) -> &Arc<ShareManager> {
        &self.shares
    }

    /// Get the session manager.
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    /// Get the auth provider.
    pub fn auth_provider(&self) -> &DynAuthProvider {
        &self.auth_provider
    }

    /// Run the server.
    ///
    /// This starts listening for connections and handling SMB requests.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting SMB server on {}", self.config.listen_addr);

        // TODO: Implement in Phase 6
        // - Create TCP listener
        // - Accept connections
        // - Spawn handler tasks
        // - Handle graceful shutdown

        todo!("Server implementation pending - Phase 6")
    }
}
