//! Server configuration.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Enable TLS.
    pub tls_enabled: bool,
    /// TLS certificate path.
    pub tls_cert: Option<PathBuf>,
    /// TLS key path.
    pub tls_key: Option<PathBuf>,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Worker thread count.
    pub worker_threads: usize,
    /// Session configuration.
    pub session: SessionConfig,
    /// Server name.
    pub server_name: String,
    /// Server GUID.
    pub server_guid: [u8; 16],
}

/// Session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session timeout.
    pub timeout: Duration,
    /// Maximum sessions per connection.
    pub max_sessions_per_connection: usize,
    /// Require signing.
    pub require_signing: bool,
    /// Require encryption.
    pub require_encryption: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:445".parse().unwrap(),
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            max_connections: 1000,
            worker_threads: 4,
            session: SessionConfig::default(),
            server_name: "RUSTSMB".to_string(),
            server_guid: [0; 16],
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3600),
            max_sessions_per_connection: 16,
            require_signing: false,
            require_encryption: false,
        }
    }
}
