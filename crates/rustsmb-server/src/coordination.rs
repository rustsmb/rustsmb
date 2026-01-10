//! Server coordination for multi-server deployments.
//!
//! This module provides coordination support for running multiple RustSMB
//! servers with shared state. It handles:
//!
//! - Server registration and heartbeats
//! - Cache invalidation on server failure or epoch changes
//! - Graceful shutdown with cluster leave
//!
//! # Coordination Modes
//!
//! Two coordination modes are supported:
//!
//! 1. **External Coordinator** (recommended for production):
//!    Connect to a separate coordinator service via gRPC.
//!    Set `coordinator_endpoint` in config.
//!
//! 2. **Embedded Raft** (for development/testing):
//!    Each server runs its own Raft node.
//!    Leave `coordinator_endpoint` empty and set `raft_addr`.

use crate::config::CoordinationConfig;
use rustsmb_coord_raft::{CoordinatorConfig, RaftCoordinator};
use rustsmb_coordinator_client::CoordinatorClient;
use rustsmb_state::{coordination::CoordinationBackend, DynStateStore, ServerRegistration};
use rustsmb_state_cached::{CacheConfig, CachedStateStore};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

/// Coordinator backend - either external gRPC client or embedded Raft.
enum CoordinatorBackendImpl {
    /// External coordinator service via gRPC.
    External(Arc<CoordinatorClient>),
    /// Embedded Raft coordinator (for dev/testing).
    Embedded(Arc<RaftCoordinator>),
}

impl CoordinatorBackendImpl {
    /// Get the coordination backend trait object.
    fn as_backend(&self) -> Arc<dyn CoordinationBackend> {
        match self {
            Self::External(client) => client.clone(),
            Self::Embedded(raft) => raft.clone(),
        }
    }
}

/// Server coordination layer.
///
/// Manages the connection to the coordinator and handles cache invalidation.
pub struct ServerCoordination {
    /// The coordinator backend (external or embedded).
    coordinator: CoordinatorBackendImpl,
    /// The cached state store.
    cached_store: Arc<CachedStateStore>,
    /// Server registration info.
    registration: ServerRegistration,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
    /// Heartbeat interval.
    heartbeat_interval: Duration,
    /// Whether using external coordinator.
    using_external: bool,
}

/// Convert a string server ID to a u64 node ID for Raft.
fn string_to_node_id(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    // Ensure non-zero (Raft requires node_id > 0)
    let hash = hasher.finish();
    if hash == 0 {
        1
    } else {
        hash
    }
}

impl ServerCoordination {
    /// Create a new server coordination layer.
    pub fn new(
        config: &CoordinationConfig,
        server_name: &str,
        listen_port: u16,
        bulk_store: DynStateStore,
    ) -> Self {
        // Generate server ID if not provided
        let server_id = if config.server_id.is_empty() {
            format!("{}-{}", server_name, uuid::Uuid::new_v4())
        } else {
            config.server_id.clone()
        };

        // Create cache config
        let cache_config = CacheConfig {
            max_sessions: config.cache.max_sessions,
            max_handles: config.cache.max_handles,
            max_trees: config.cache.max_trees,
            default_ttl: Duration::from_secs(config.cache.default_ttl_secs),
        };

        // Create the appropriate coordinator backend
        let (coordinator, using_external) = if config.use_external_coordinator() {
            // External coordinator via gRPC - will be connected in start()
            // For now, create a placeholder that will be replaced
            // This is a sync function, so we can't connect here
            let coord_config = CoordinatorConfig {
                node_id: string_to_node_id(&server_id),
                node_addr: config.raft_addr.clone(),
                heartbeat_timeout_secs: config.heartbeat_timeout_secs,
                heartbeat_check_interval_secs: config.heartbeat_interval_secs,
                raft_tick_interval_ms: 100,
                election_tick: 10,
                heartbeat_tick: 3,
            };
            let raft = Arc::new(
                RaftCoordinator::new(coord_config).expect("Failed to create Raft coordinator"),
            );
            // We'll replace this with the gRPC client in start()
            (CoordinatorBackendImpl::Embedded(raft), true)
        } else {
            // Embedded Raft coordinator
            let node_id = string_to_node_id(&server_id);
            let coord_config = CoordinatorConfig {
                node_id,
                node_addr: config.raft_addr.clone(),
                heartbeat_timeout_secs: config.heartbeat_timeout_secs,
                heartbeat_check_interval_secs: config.heartbeat_interval_secs,
                raft_tick_interval_ms: 100,
                election_tick: 10,
                heartbeat_tick: 3,
            };
            let raft = Arc::new(
                RaftCoordinator::new(coord_config).expect("Failed to create Raft coordinator"),
            );
            (CoordinatorBackendImpl::Embedded(raft), false)
        };

        // Create cached state store with coordinator for epoch-based invalidation
        let cached_store = Arc::new(CachedStateStore::new(
            bulk_store,
            cache_config,
            Some(coordinator.as_backend()),
        ));

        // Create server registration
        let registration =
            ServerRegistration::new(&server_id, server_name, listen_port, &config.raft_addr);

        Self {
            coordinator,
            cached_store,
            registration,
            shutdown: Arc::new(AtomicBool::new(false)),
            heartbeat_interval: Duration::from_secs(config.heartbeat_interval_secs),
            using_external,
        }
    }

    /// Create with external coordinator (async version for gRPC connection).
    pub async fn new_with_external_coordinator(
        config: &CoordinationConfig,
        server_name: &str,
        listen_port: u16,
        bulk_store: DynStateStore,
    ) -> Result<Self, CoordinationError> {
        if !config.use_external_coordinator() {
            return Err(CoordinationError::Backend(
                "coordinator_endpoint not set".to_string(),
            ));
        }

        // Generate server ID if not provided
        let server_id = if config.server_id.is_empty() {
            format!("{}-{}", server_name, uuid::Uuid::new_v4())
        } else {
            config.server_id.clone()
        };

        // Connect to external coordinator
        info!(
            endpoint = %config.coordinator_endpoint,
            "Connecting to external coordinator"
        );

        let client = CoordinatorClient::connect(&config.coordinator_endpoint)
            .await
            .map_err(|e| CoordinationError::Backend(e.to_string()))?;

        let client = Arc::new(client);
        let coordinator = CoordinatorBackendImpl::External(client);

        // Create cache config
        let cache_config = CacheConfig {
            max_sessions: config.cache.max_sessions,
            max_handles: config.cache.max_handles,
            max_trees: config.cache.max_trees,
            default_ttl: Duration::from_secs(config.cache.default_ttl_secs),
        };

        // Create cached state store with coordinator for epoch-based invalidation
        let cached_store = Arc::new(CachedStateStore::new(
            bulk_store,
            cache_config,
            Some(coordinator.as_backend()),
        ));

        // Create server registration
        let registration =
            ServerRegistration::new(&server_id, server_name, listen_port, &config.raft_addr);

        Ok(Self {
            coordinator,
            cached_store,
            registration,
            shutdown: Arc::new(AtomicBool::new(false)),
            heartbeat_interval: Duration::from_secs(config.heartbeat_interval_secs),
            using_external: true,
        })
    }

    /// Get the cached state store for use by the server.
    pub fn state_store(&self) -> DynStateStore {
        self.cached_store.clone()
    }

    /// Get the coordinator backend.
    pub fn coordinator(&self) -> Arc<dyn CoordinationBackend> {
        self.coordinator.as_backend()
    }

    /// Get the server ID.
    pub fn server_id(&self) -> &str {
        &self.registration.server_id
    }

    /// Check if using external coordinator.
    pub fn is_external(&self) -> bool {
        self.using_external
    }

    /// Start the coordination tasks.
    ///
    /// This registers the server, starts heartbeat task, and subscribes to events.
    /// Call this after creating the server but before accepting connections.
    pub async fn start(&self) -> Result<(), CoordinationError> {
        // Register with the cluster
        self.coordinator
            .as_backend()
            .register_server(&self.registration)
            .await
            .map_err(|e| CoordinationError::Registration(e.to_string()))?;

        info!(
            server_id = %self.registration.server_id,
            external = self.using_external,
            "Registered with coordination cluster"
        );

        // Start background tasks based on coordinator type
        match &self.coordinator {
            CoordinatorBackendImpl::External(client) => {
                // Start subscription handler for external coordinator
                let client = Arc::clone(client);
                client.start_subscriptions();
            }
            CoordinatorBackendImpl::Embedded(raft) => {
                // Start the heartbeat monitor on the embedded coordinator
                raft.start_heartbeat_monitor();
            }
        }

        // Spawn heartbeat task
        self.spawn_heartbeat_task();

        // Spawn epoch change listener
        self.spawn_epoch_listener();

        // Spawn server failure listener
        self.spawn_failure_listener();

        Ok(())
    }

    /// Stop the coordination tasks and leave the cluster.
    pub async fn stop(&self) {
        info!(
            server_id = %self.registration.server_id,
            "Stopping coordination"
        );

        // Signal shutdown
        self.shutdown.store(true, Ordering::Release);

        // Stop coordinator-specific tasks
        match &self.coordinator {
            CoordinatorBackendImpl::External(_) => {
                // External coordinator cleanup handled by leave_cluster
            }
            CoordinatorBackendImpl::Embedded(raft) => {
                // Stop the embedded coordinator
                raft.stop();
            }
        }

        // Leave the cluster gracefully
        if let Err(e) = self.coordinator.as_backend().leave_cluster().await {
            warn!(error = %e, "Error leaving cluster");
        }

        info!("Coordination stopped");
    }

    /// Spawn the heartbeat task.
    fn spawn_heartbeat_task(&self) {
        let coordinator = self.coordinator.as_backend();
        let server_id = self.registration.server_id.clone();
        let interval = self.heartbeat_interval;
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            debug!(server_id = %server_id, "Starting heartbeat task");

            while !shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(interval).await;

                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                if let Err(e) = coordinator.heartbeat(&server_id).await {
                    warn!(
                        server_id = %server_id,
                        error = %e,
                        "Failed to send heartbeat"
                    );
                } else {
                    debug!(server_id = %server_id, "Heartbeat sent");
                }
            }

            debug!(server_id = %server_id, "Heartbeat task stopped");
        });
    }

    /// Spawn the epoch change listener.
    fn spawn_epoch_listener(&self) {
        let coordinator = self.coordinator.as_backend();
        let cached_store = self.cached_store.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            debug!("Starting epoch change listener");

            let mut stream = coordinator.subscribe_epoch_changes().await;

            while let Some(new_epoch) = stream.next().await {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                info!(epoch = new_epoch, "Epoch changed - invalidating cache");
                cached_store.set_epoch(new_epoch);
                cached_store.invalidate_all();
            }

            debug!("Epoch change listener stopped");
        });
    }

    /// Spawn the server failure listener.
    fn spawn_failure_listener(&self) {
        let coordinator = self.coordinator.as_backend();
        let cached_store = self.cached_store.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            debug!("Starting server failure listener");

            let mut stream = coordinator.subscribe_server_failures().await;

            while let Some(failed_server_id) = stream.next().await {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                warn!(
                    failed_server = %failed_server_id,
                    "Server failure detected - invalidating all caches"
                );

                // Invalidate all caches on any server failure
                // This ensures strong consistency (CP)
                cached_store.invalidate_all();
            }

            debug!("Server failure listener stopped");
        });
    }

    /// Get cache statistics.
    pub async fn cache_stats(&self) -> rustsmb_state_cached::CacheStats {
        self.cached_store.stats().await
    }
}

/// Coordination error.
#[derive(Debug)]
pub enum CoordinationError {
    /// Failed to register with cluster.
    Registration(String),
    /// Failed to send heartbeat.
    Heartbeat(String),
    /// Coordination backend error.
    Backend(String),
}

impl std::fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration(e) => write!(f, "Registration error: {}", e),
            Self::Heartbeat(e) => write!(f, "Heartbeat error: {}", e),
            Self::Backend(e) => write!(f, "Backend error: {}", e),
        }
    }
}

impl std::error::Error for CoordinationError {}

/// Generate a simple UUID-like string (without external crate).
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> String {
            use rand::RngCore;
            let mut bytes = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut bytes);
            format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5],
                bytes[6], bytes[7],
                bytes[8], bytes[9],
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_state_memory::MemoryStateStore;

    #[tokio::test]
    async fn test_coordination_creation() {
        let config = CoordinationConfig::default();
        let bulk_store = MemoryStateStore::new_arc();

        let coord = ServerCoordination::new(&config, "TEST", 445, bulk_store);

        // Server ID should be auto-generated
        assert!(coord.server_id().starts_with("TEST-"));
        assert!(!coord.is_external());
    }

    #[tokio::test]
    async fn test_coordination_start_stop() {
        let config = CoordinationConfig::default();
        let bulk_store = MemoryStateStore::new_arc();

        let coord = ServerCoordination::new(&config, "TEST", 445, bulk_store);

        // Start coordination
        coord.start().await.unwrap();

        // Give tasks time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop coordination
        coord.stop().await;
    }

    #[tokio::test]
    async fn test_state_store_access() {
        let config = CoordinationConfig::default();
        let bulk_store = MemoryStateStore::new_arc();

        let coord = ServerCoordination::new(&config, "TEST", 445, bulk_store);

        // Get the cached state store
        let store = coord.state_store();

        // Should be able to generate IDs
        let session_id = store.next_session_id().await.unwrap();
        assert!(session_id > 0);
    }

    #[test]
    fn test_external_coordinator_config() {
        let mut config = CoordinationConfig::default();
        assert!(!config.use_external_coordinator());

        config.coordinator_endpoint = "http://coordinator:9000".to_string();
        assert!(config.use_external_coordinator());
    }
}
