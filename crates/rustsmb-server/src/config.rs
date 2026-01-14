//! Server configuration.
//!
//! Supports loading from TOML configuration files.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Listen address.
    #[serde(with = "socket_addr_serde")]
    pub listen_addr: SocketAddr,
    /// Enable TLS.
    pub tls_enabled: bool,
    /// TLS certificate path.
    pub tls_cert: Option<PathBuf>,
    /// TLS key path.
    pub tls_key: Option<PathBuf>,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Worker thread count (0 = auto).
    pub worker_threads: usize,
    /// Session configuration.
    pub session: SessionConfig,
    /// Server name (NetBIOS name, max 15 chars).
    pub server_name: String,
    /// Server GUID (auto-generated if empty).
    #[serde(with = "guid_serde")]
    pub server_guid: [u8; 16],
    /// Enable SMB 3.x encryption.
    pub enable_encryption: bool,
    /// Enable SMB signing.
    pub enable_signing: bool,
    /// Require signing for all connections.
    pub require_signing: bool,
    /// Supported SMB dialects.
    pub dialects: Vec<String>,
    /// Coordination configuration (for multi-server deployments).
    pub coordination: CoordinationConfig,
    /// Server-side copy configuration (FSCTL_SRV_COPYCHUNK).
    pub server_side_copy: ServerSideCopyConfig,
}

/// Session configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Session timeout in seconds.
    #[serde(with = "duration_secs_serde")]
    pub timeout: Duration,
    /// Maximum sessions per connection.
    pub max_sessions_per_connection: usize,
    /// Require signing.
    pub require_signing: bool,
    /// Require encryption.
    pub require_encryption: bool,
    /// Idle timeout in seconds.
    #[serde(with = "duration_secs_serde")]
    pub idle_timeout: Duration,
}

/// Server-side copy configuration (FSCTL_SRV_COPYCHUNK).
///
/// Per MS-SMB2 2.2.32.1, when a COPYCHUNK request exceeds server limits,
/// the server returns STATUS_INVALID_PARAMETER with a response containing
/// these limits so the client can adjust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSideCopyConfig {
    /// Maximum size of a single chunk in bytes.
    /// Default: 1MB (1,048,576 bytes).
    pub max_chunk_size: u32,
    /// Maximum total data size per COPYCHUNK request in bytes.
    /// Default: 16MB (16,777,216 bytes).
    pub max_data_size: u32,
    /// Maximum number of chunks per COPYCHUNK request.
    /// Default: 256.
    pub max_number_of_chunks: u32,
}

impl Default for ServerSideCopyConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 1_048_576, // 1MB
            max_data_size: 16_777_216, // 16MB
            max_number_of_chunks: 256,
        }
    }
}

/// Coordination configuration for multi-server deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoordinationConfig {
    /// Enable coordination (requires coordinator backend).
    pub enabled: bool,
    /// This server's unique ID (auto-generated if empty).
    pub server_id: String,
    /// External coordinator endpoint (e.g., "http://coordinator:9000").
    /// If set, uses gRPC client to connect to external coordinator service.
    /// If empty, uses embedded Raft coordinator (raft_addr must be set).
    pub coordinator_endpoint: String,
    /// Address for Raft peer communication (only used if coordinator_endpoint is empty).
    pub raft_addr: String,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval_secs: u64,
    /// Heartbeat timeout in seconds (server considered dead after this).
    pub heartbeat_timeout_secs: u64,
    /// Local cache configuration.
    pub cache: CacheLayerConfig,
}

impl Default for CoordinationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_id: String::new(),
            coordinator_endpoint: String::new(),
            raft_addr: "127.0.0.1:8080".to_string(),
            heartbeat_interval_secs: 5,
            heartbeat_timeout_secs: 15,
            cache: CacheLayerConfig::default(),
        }
    }
}

impl CoordinationConfig {
    /// Check if using external coordinator (gRPC client) vs embedded Raft.
    pub fn use_external_coordinator(&self) -> bool {
        !self.coordinator_endpoint.is_empty()
    }
}

/// Local cache layer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheLayerConfig {
    /// Maximum cached sessions.
    pub max_sessions: usize,
    /// Maximum cached handles.
    pub max_handles: usize,
    /// Maximum cached tree connections.
    pub max_trees: usize,
    /// Default cache entry TTL in seconds.
    pub default_ttl_secs: u64,
}

impl Default for CacheLayerConfig {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_handles: 1_000_000,
            max_trees: 50_000,
            default_ttl_secs: 300,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:445".parse().unwrap(),
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            max_connections: 1000,
            worker_threads: 0,
            session: SessionConfig::default(),
            server_name: "RUSTSMB".to_string(),
            server_guid: [0; 16],
            enable_encryption: true,
            enable_signing: true,
            require_signing: false,
            dialects: vec![
                "SMB 3.1.1".to_string(),
                "SMB 3.0.2".to_string(),
                "SMB 3.0".to_string(),
                "SMB 2.1".to_string(),
                "SMB 2.0.2".to_string(),
            ],
            coordination: CoordinationConfig::default(),
            server_side_copy: ServerSideCopyConfig::default(),
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
            idle_timeout: Duration::from_secs(900),
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string.
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Generate a random server GUID if not set.
    pub fn ensure_guid(&mut self) {
        if self.server_guid == [0; 16] {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut self.server_guid);
        }
    }

    /// Get the effective worker thread count.
    pub fn effective_worker_threads(&self) -> usize {
        if self.worker_threads == 0 {
            num_cpus()
        } else {
            self.worker_threads
        }
    }
}

/// Configuration error.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// I/O error.
    Io(String),
    /// Parse error.
    Parse(String),
    /// Validation error.
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Parse(e) => write!(f, "Parse error: {}", e),
            Self::Validation(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Get the number of available CPUs.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

/// Serde helper for SocketAddr.
mod socket_addr_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::net::SocketAddr;

    pub fn serialize<S: Serializer>(addr: &SocketAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SocketAddr, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Serde helper for Duration as seconds.
mod duration_secs_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Serde helper for GUID as hex string.
mod guid_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(guid: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write;
        let hex = guid.iter().fold(String::with_capacity(32), |mut acc, b| {
            let _ = write!(acc, "{:02x}", b);
            acc
        });
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() {
            return Ok([0; 16]);
        }
        if s.len() != 32 {
            return Err(serde::de::Error::custom("GUID must be 32 hex characters"));
        }
        let mut guid = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(serde::de::Error::custom)?;
            guid[i] = u8::from_str_radix(hex_str, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.listen_addr.port(), 445);
        assert!(!config.tls_enabled);
        assert_eq!(config.max_connections, 1000);
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
            listen_addr = "127.0.0.1:8445"
            max_connections = 500
            server_name = "TEST"

            [session]
            timeout = 7200
            max_sessions_per_connection = 8
        "#;

        let config = ServerConfig::from_toml(toml).unwrap();
        assert_eq!(config.listen_addr.port(), 8445);
        assert_eq!(config.max_connections, 500);
        assert_eq!(config.server_name, "TEST");
        assert_eq!(config.session.timeout, Duration::from_secs(7200));
        assert_eq!(config.session.max_sessions_per_connection, 8);
    }

    #[test]
    fn test_ensure_guid() {
        let mut config = ServerConfig::default();
        assert_eq!(config.server_guid, [0; 16]);
        config.ensure_guid();
        assert_ne!(config.server_guid, [0; 16]);
    }
}
