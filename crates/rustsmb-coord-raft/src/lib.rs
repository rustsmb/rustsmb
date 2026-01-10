//! Raft-based coordination backend using tikv/raft-rs.
//!
//! This crate provides `RaftCoordinator`, an implementation of the
//! `CoordinationBackend` trait using the tikv/raft-rs library for
//! distributed consensus.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │        RaftCoordinator              │
//! │  ┌───────────────────────────────┐  │
//! │  │   raft::RawNode<MemStorage>   │  │  ← Raft consensus
//! │  └───────────────────────────────┘  │
//! │  ┌───────────────────────────────┐  │
//! │  │      CoordinationState        │  │  ← Application state
//! │  │  - cache_epoch                │  │
//! │  │  - servers                    │  │
//! │  │  - leases                     │  │
//! │  │  - locks                      │  │
//! │  └───────────────────────────────┘  │
//! │  ┌───────────────────────────────┐  │
//! │  │     Broadcast Channels        │  │  ← For subscriptions
//! │  └───────────────────────────────┘  │
//! │  ┌───────────────────────────────┐  │
//! │  │   Heartbeat Monitor Task      │  │  ← Detects server failures
//! │  └───────────────────────────────┘  │
//! │  ┌───────────────────────────────┐  │
//! │  │     Raft Tick Task            │  │  ← Drives Raft state machine
//! │  └───────────────────────────────┘  │
//! └─────────────────────────────────────┘
//! ```
//!
//! # Server Failure Detection
//!
//! The coordinator monitors server heartbeats and detects failures when a
//! server hasn't sent a heartbeat within the configured timeout (default 15s).
//!
//! When a server failure is detected:
//! 1. Server is unregistered from membership
//! 2. Cache epoch is incremented (triggers cache invalidation on all nodes)
//! 3. Server failure event is broadcast to subscribers
//! 4. Server's locks and leases are cleaned up
//!
//! # Multi-Node Support
//!
//! This implementation uses tikv/raft-rs for distributed consensus. In single-node
//! mode, it operates as a standalone coordinator. For multi-node deployments,
//! additional transport layer implementation is needed.

pub mod state;
pub mod types;

pub use state::{CoordRequest, CoordResponse, CoordStateMachine, CoordinationState};
pub use types::{ClusterMembership, CoordNode, CoordSnapshotData, NodeId};

use raft::storage::MemStorage;
use raft::{Config as RaftConfig, RawNode};
use rustsmb_core::CoordError;
use rustsmb_state::{
    BoxFuture, CoordinationBackend, EpochStream, ServerFailureStream, ServerRegistration,
};
use slog::{o, Drain, Logger};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

/// Configuration for RaftCoordinator.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// This node's ID.
    pub node_id: NodeId,
    /// This node's address.
    pub node_addr: String,
    /// Server heartbeat timeout in seconds.
    /// If a server doesn't send a heartbeat within this time, it's considered failed.
    pub heartbeat_timeout_secs: u64,
    /// How often to check for stale heartbeats in seconds.
    pub heartbeat_check_interval_secs: u64,
    /// Raft tick interval in milliseconds.
    pub raft_tick_interval_ms: u64,
    /// Raft election tick count.
    pub election_tick: usize,
    /// Raft heartbeat tick count.
    pub heartbeat_tick: usize,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            node_id: 1,
            node_addr: "127.0.0.1:8080".to_string(),
            heartbeat_timeout_secs: 15,
            heartbeat_check_interval_secs: 5,
            raft_tick_interval_ms: 100,
            election_tick: 10,
            heartbeat_tick: 3,
        }
    }
}

/// Proposal to be applied to the Raft state machine.
#[derive(Debug)]
struct Proposal {
    /// The request to apply.
    request: CoordRequest,
    /// Channel to send the response.
    response_tx: tokio::sync::oneshot::Sender<CoordResponse>,
}

/// Raft-based coordinator that implements CoordinationBackend.
///
/// This provides distributed coordination for SMB servers using the
/// tikv/raft-rs consensus library.
///
/// # Note (Phase 13)
///
/// This crate is being deprecated. The coordinator is now a separate service
/// (`rustsmb-coordinator`). SMB servers use `rustsmb-coordinator-client` to
/// communicate with the coordinator over gRPC.
pub struct RaftCoordinator {
    /// The coordination state machine.
    state_machine: Arc<CoordStateMachine>,
    /// The Raft node (protected by mutex for single-threaded access).
    raft_node: Arc<Mutex<RawNode<MemStorage>>>,
    /// Epoch change broadcast channel.
    epoch_tx: broadcast::Sender<u64>,
    /// Server failure broadcast channel.
    failure_tx: broadcast::Sender<String>,
    /// Configuration.
    config: CoordinatorConfig,
    /// Shutdown flag for background tasks.
    shutdown: Arc<AtomicBool>,
    /// Pending proposals waiting to be applied.
    proposals: Arc<Mutex<Vec<Proposal>>>,
    /// Next proposal ID.
    next_proposal_id: Arc<AtomicU64>,
    /// Pending proposal responses (proposal_id -> response channel).
    pending_responses:
        Arc<RwLock<std::collections::HashMap<u64, tokio::sync::oneshot::Sender<CoordResponse>>>>,
}

impl RaftCoordinator {
    /// Create a new Raft coordinator.
    pub fn new(config: CoordinatorConfig) -> Result<Self, CoordError> {
        let state_machine = Arc::new(CoordStateMachine::new());

        // Create slog logger for raft-rs
        let decorator = slog_stdlog::StdLog;
        let drain = std::sync::Mutex::new(decorator).fuse();
        let logger = Logger::root(drain, o!("tag" => "raft"));

        // Create Raft configuration
        let raft_config = RaftConfig {
            id: config.node_id,
            election_tick: config.election_tick,
            heartbeat_tick: config.heartbeat_tick,
            applied: 0,
            max_size_per_msg: 1024 * 1024,
            max_inflight_msgs: 256,
            ..Default::default()
        };

        // Validate configuration
        raft_config
            .validate()
            .map_err(|e| CoordError::Internal(format!("Invalid Raft config: {}", e)))?;

        // Create in-memory storage and initialize with a single-node cluster
        let storage = MemStorage::new_with_conf_state((vec![config.node_id], vec![]));

        // Create the Raft node
        let raft_node = RawNode::new(&raft_config, storage, &logger)
            .map_err(|e| CoordError::Internal(format!("Failed to create Raft node: {}", e)))?;

        let (epoch_tx, _) = broadcast::channel(16);
        let (failure_tx, _) = broadcast::channel(16);

        info!(node_id = config.node_id, "Created Raft coordinator");

        Ok(Self {
            state_machine,
            raft_node: Arc::new(Mutex::new(raft_node)),
            epoch_tx,
            failure_tx,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            proposals: Arc::new(Mutex::new(Vec::new())),
            next_proposal_id: Arc::new(AtomicU64::new(1)),
            pending_responses: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Result<Self, CoordError> {
        Self::new(CoordinatorConfig::default())
    }

    /// Start the Raft tick task.
    ///
    /// This spawns a background task that periodically ticks the Raft
    /// state machine to drive elections and heartbeats.
    pub fn start_raft_tick(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let coordinator = Arc::clone(self);
        let interval = Duration::from_millis(coordinator.config.raft_tick_interval_ms);

        tokio::spawn(async move {
            info!(
                interval_ms = coordinator.config.raft_tick_interval_ms,
                "Starting Raft tick task"
            );

            while !coordinator.shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(interval).await;

                if coordinator.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Tick the Raft state machine and process ready state
                coordinator.tick_and_process().await;
            }

            info!("Raft tick task stopped");
        })
    }

    /// Start the heartbeat monitoring task.
    ///
    /// This spawns a background task that periodically checks for servers
    /// with stale heartbeats and handles their failure.
    pub fn start_heartbeat_monitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let coordinator = Arc::clone(self);
        let interval = Duration::from_secs(coordinator.config.heartbeat_check_interval_secs);

        tokio::spawn(async move {
            info!(
                interval_secs = coordinator.config.heartbeat_check_interval_secs,
                timeout_secs = coordinator.config.heartbeat_timeout_secs,
                "Starting heartbeat monitor"
            );

            while !coordinator.shutdown.load(Ordering::Relaxed) {
                tokio::time::sleep(interval).await;

                if coordinator.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                coordinator.check_heartbeats().await;
            }

            info!("Heartbeat monitor stopped");
        })
    }

    /// Stop all background tasks.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Tick the Raft state machine and process ready state.
    async fn tick_and_process(&self) {
        let mut raft_node = self.raft_node.lock().await;

        // Tick the Raft state machine
        raft_node.tick();

        // Process any pending proposals
        let proposals = {
            let mut proposals = self.proposals.lock().await;
            std::mem::take(&mut *proposals)
        };

        for proposal in proposals {
            let proposal_id = self.next_proposal_id.fetch_add(1, Ordering::SeqCst);
            let data = serde_json::to_vec(&proposal.request).unwrap_or_default();

            // Store the response channel
            {
                let mut pending = self.pending_responses.write().await;
                pending.insert(proposal_id, proposal.response_tx);
            }

            // Propose to Raft
            if let Err(e) = raft_node.propose(vec![], data) {
                warn!(error = %e, "Failed to propose to Raft");
                // Send error response
                let mut pending = self.pending_responses.write().await;
                if let Some(tx) = pending.remove(&proposal_id) {
                    let _ = tx.send(CoordResponse::Error(format!("Raft proposal failed: {}", e)));
                }
            }
        }

        // Check if there's ready state to process
        if !raft_node.has_ready() {
            return;
        }

        let mut ready = raft_node.ready();

        // Process committed entries
        let committed_entries = ready.take_committed_entries();
        for entry in committed_entries {
            if entry.data.is_empty() {
                // Empty entry (e.g., leader election)
                continue;
            }

            // Deserialize and apply the request
            if let Ok(request) = serde_json::from_slice::<CoordRequest>(&entry.data) {
                let response = self.state_machine.apply(request).await;

                // For now, we track responses by entry index
                // In a real implementation, you'd want better proposal tracking
                let mut pending = self.pending_responses.write().await;
                // Try to find and send response (simplified - uses index as ID)
                if let Some(tx) = pending.remove(&entry.index) {
                    let _ = tx.send(response);
                }
            }
        }

        // Apply snapshot if present
        if !ready.snapshot().is_empty() {
            let snapshot = ready.snapshot();
            if let Ok(snapshot_data) = CoordSnapshotData::from_bytes(&snapshot.data) {
                let mut state = self.state_machine.state_mut().await;
                *state = snapshot_data.state;
            }
        }

        // Advance the Raft node
        let light_rd = raft_node.advance(ready);

        // Process messages to send (in a real implementation, send to other nodes)
        // For single-node, we can skip this

        // Advance the light ready
        raft_node.advance_apply();

        drop(light_rd);
    }

    /// Check for stale heartbeats and handle server failures.
    async fn check_heartbeats(&self) {
        let now = current_timestamp();
        let threshold = now.saturating_sub(self.config.heartbeat_timeout_secs);

        let stale_servers = self.read_state(|s| s.get_stale_servers(threshold)).await;

        for server_id in stale_servers {
            warn!(server_id = %server_id, "Server heartbeat timeout - marking as failed");
            if let Err(e) = self.handle_server_failure(&server_id).await {
                warn!(server_id = %server_id, error = %e, "Error handling server failure");
            }
        }
    }

    /// Handle a server failure.
    ///
    /// This is called when a server's heartbeat times out. It:
    /// 1. Unregisters the server (which also increments epoch)
    /// 2. Broadcasts the failure event and epoch change
    ///
    /// Note: Leases and locks are stored in StateStore (Redis), not in the
    /// coordinator. Cleanup of server-specific leases/locks is handled by
    /// the StateStore implementation.
    pub async fn handle_server_failure(&self, server_id: &str) -> Result<(), CoordError> {
        info!(server_id = %server_id, "Handling server failure");

        // Unregister the server (this increments epoch)
        let response = self
            .apply(CoordRequest::UnregisterServer(server_id.to_string()))
            .await;

        let new_epoch = match response {
            CoordResponse::Epoch(e) => e,
            _ => {
                // Server might already be unregistered
                self.read_state(|s| s.epoch()).await
            }
        };

        // Broadcast the failure and epoch change
        self.broadcast_server_failure(server_id.to_string());
        self.broadcast_epoch(new_epoch);

        info!(
            server_id = %server_id,
            new_epoch = new_epoch,
            "Server failure handled, epoch incremented"
        );

        Ok(())
    }

    /// Update a server's heartbeat timestamp.
    pub async fn update_heartbeat(&self, server_id: &str) -> Result<(), CoordError> {
        let timestamp = current_timestamp();
        let request = CoordRequest::UpdateHeartbeat {
            server_id: server_id.to_string(),
            timestamp,
        };
        self.apply(request).await;
        debug!(server_id = %server_id, timestamp = timestamp, "Heartbeat updated");
        Ok(())
    }

    /// Apply a request to the state machine.
    ///
    /// In single-node mode, this applies directly. In multi-node mode,
    /// this would go through Raft consensus.
    async fn apply(&self, request: CoordRequest) -> CoordResponse {
        // For single-node mode, apply directly to state machine
        // In multi-node mode, this would propose through Raft
        self.state_machine.apply(request).await
    }

    /// Propose a request through Raft consensus.
    ///
    /// This is used for multi-node deployments where requests need
    /// to go through consensus before being applied.
    #[allow(dead_code)]
    async fn propose(&self, request: CoordRequest) -> CoordResponse {
        let (tx, rx) = tokio::sync::oneshot::channel();

        {
            let mut proposals = self.proposals.lock().await;
            proposals.push(Proposal {
                request,
                response_tx: tx,
            });
        }

        // Wait for response (with timeout)
        match tokio::time::timeout(Duration::from_secs(5), rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => CoordResponse::Error("Proposal channel closed".to_string()),
            Err(_) => CoordResponse::Error("Proposal timeout".to_string()),
        }
    }

    /// Read state directly.
    async fn read_state<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&CoordinationState) -> T,
    {
        let state = self.state_machine.state().await;
        f(&state)
    }

    /// Get the state machine (for advanced operations).
    pub fn state_machine(&self) -> &Arc<CoordStateMachine> {
        &self.state_machine
    }

    /// Get the configuration.
    pub fn config(&self) -> &CoordinatorConfig {
        &self.config
    }

    /// Broadcast an epoch change.
    pub fn broadcast_epoch(&self, epoch: u64) {
        let _ = self.epoch_tx.send(epoch);
    }

    /// Broadcast a server failure.
    pub fn broadcast_server_failure(&self, server_id: String) {
        let _ = self.failure_tx.send(server_id);
    }

    /// Check if this node is the Raft leader.
    pub async fn is_leader(&self) -> bool {
        let raft_node = self.raft_node.lock().await;
        raft_node.raft.state == raft::StateRole::Leader
    }

    /// Get the current Raft leader ID.
    pub async fn leader_id(&self) -> Option<NodeId> {
        let raft_node = self.raft_node.lock().await;
        let leader = raft_node.raft.leader_id;
        if leader == 0 {
            None
        } else {
            Some(leader)
        }
    }
}

impl Drop for RaftCoordinator {
    fn drop(&mut self) {
        self.stop();
    }
}

impl CoordinationBackend for RaftCoordinator {
    fn register_server<'a>(
        &'a self,
        registration: &'a ServerRegistration,
    ) -> BoxFuture<'a, Result<(), CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::RegisterServer(registration.clone());
            self.apply(request).await;
            debug!(server_id = %registration.server_id, "Server registered");
            Ok(())
        })
    }

    fn heartbeat(&self, server_id: &str) -> BoxFuture<'_, Result<(), CoordError>> {
        let server_id = server_id.to_string();
        Box::pin(async move { self.update_heartbeat(&server_id).await })
    }

    fn leave_cluster(&self) -> BoxFuture<'_, Result<(), CoordError>> {
        Box::pin(async move {
            info!("Leaving cluster");
            Ok(())
        })
    }

    fn get_servers(&self) -> BoxFuture<'_, Result<Vec<ServerRegistration>, CoordError>> {
        Box::pin(async move { Ok(self.read_state(|s| s.get_servers()).await) })
    }

    fn subscribe_server_failures(&self) -> BoxFuture<'_, ServerFailureStream> {
        Box::pin(async move {
            let rx = self.failure_tx.subscribe();
            let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|r| r.ok());
            Box::pin(stream) as ServerFailureStream
        })
    }

    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>> {
        Box::pin(async move { Ok(self.read_state(|s| s.epoch()).await) })
    }

    fn subscribe_epoch_changes(&self) -> BoxFuture<'_, EpochStream> {
        Box::pin(async move {
            let rx = self.epoch_tx.subscribe();
            let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|r| r.ok());
            Box::pin(stream) as EpochStream
        })
    }

    fn increment_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::IncrementEpoch;
            let response = self.apply(request).await;
            match response {
                CoordResponse::Epoch(e) => {
                    self.broadcast_epoch(e);
                    Ok(e)
                }
                _ => {
                    let epoch = self.read_state(|s| s.epoch()).await;
                    Ok(epoch)
                }
            }
        })
    }
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// Re-export InMemoryCoordinator as an alias for backward compatibility
pub type InMemoryCoordinator = RaftCoordinator;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_basic() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // Test epoch
        let epoch = coordinator.get_epoch().await.unwrap();
        assert_eq!(epoch, 1);

        // Register a server
        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        coordinator.register_server(&server).await.unwrap();

        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_id, "srv1");
    }

    #[tokio::test]
    async fn test_heartbeat_via_trait() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // Register a server
        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        coordinator.register_server(&server).await.unwrap();

        // Use trait method for heartbeat
        coordinator.heartbeat("srv1").await.unwrap();

        // Server should still be registered
        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
    }

    #[tokio::test]
    async fn test_increment_epoch() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // Initial epoch
        let epoch = coordinator.get_epoch().await.unwrap();
        assert_eq!(epoch, 1);

        // Increment epoch
        let new_epoch = coordinator.increment_epoch().await.unwrap();
        assert_eq!(new_epoch, 2);

        // Verify epoch persisted
        let epoch = coordinator.get_epoch().await.unwrap();
        assert_eq!(epoch, 2);
    }

    #[tokio::test]
    async fn test_server_failure_handling() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // Register a server
        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        coordinator.register_server(&server).await.unwrap();

        // Initial epoch
        let initial_epoch = coordinator.get_epoch().await.unwrap();
        assert_eq!(initial_epoch, 1);

        // Handle server failure
        coordinator.handle_server_failure("srv1").await.unwrap();

        // Server should be unregistered
        let servers = coordinator.get_servers().await.unwrap();
        assert!(servers.is_empty());

        // Epoch should be incremented
        let new_epoch = coordinator.get_epoch().await.unwrap();
        assert_eq!(new_epoch, 2);
    }

    #[tokio::test]
    async fn test_stale_server_detection() {
        let config = CoordinatorConfig {
            heartbeat_timeout_secs: 1, // 1 second timeout for testing
            heartbeat_check_interval_secs: 1,
            ..Default::default()
        };
        let coordinator = Arc::new(RaftCoordinator::new(config).unwrap());

        // Register a server with old timestamp (will be immediately stale)
        let mut server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        // Set heartbeat to a very old time
        server.last_heartbeat = 0;

        coordinator.register_server(&server).await.unwrap();

        // Check heartbeats - should detect srv1 as stale
        coordinator.check_heartbeats().await;

        // Server should be unregistered
        let servers = coordinator.get_servers().await.unwrap();
        assert!(servers.is_empty());
    }

    #[tokio::test]
    async fn test_heartbeat_keeps_server_alive() {
        let config = CoordinatorConfig {
            heartbeat_timeout_secs: 1,
            heartbeat_check_interval_secs: 1,
            ..Default::default()
        };
        let coordinator = Arc::new(RaftCoordinator::new(config).unwrap());

        // Register a server
        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        coordinator.register_server(&server).await.unwrap();

        // Update heartbeat to current time
        coordinator.update_heartbeat("srv1").await.unwrap();

        // Check heartbeats - should NOT detect srv1 as stale
        coordinator.check_heartbeats().await;

        // Server should still be registered
        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
    }

    #[tokio::test]
    async fn test_failure_broadcast() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // Subscribe to failures before registering
        let mut failure_rx = coordinator.failure_tx.subscribe();
        let mut epoch_rx = coordinator.epoch_tx.subscribe();

        // Register a server
        let server = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        coordinator.register_server(&server).await.unwrap();

        // Handle server failure
        coordinator.handle_server_failure("srv1").await.unwrap();

        // Should receive failure broadcast
        let failed_server = failure_rx.try_recv().unwrap();
        assert_eq!(failed_server, "srv1");

        // Should receive epoch broadcast
        let new_epoch = epoch_rx.try_recv().unwrap();
        assert_eq!(new_epoch, 2);
    }

    #[tokio::test]
    async fn test_raft_leader_status() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // In single-node mode, this node should become leader after some ticks
        // For now, just verify the API works
        let _is_leader = coordinator.is_leader().await;
        let _leader_id = coordinator.leader_id().await;
    }

    #[tokio::test]
    async fn test_multiple_servers() {
        let coordinator = RaftCoordinator::with_defaults().unwrap();

        // Register two servers
        let server1 = ServerRegistration::new("srv1", "localhost", 445, "127.0.0.1:9000");
        let server2 = ServerRegistration::new("srv2", "localhost", 446, "127.0.0.1:9001");
        coordinator.register_server(&server1).await.unwrap();
        coordinator.register_server(&server2).await.unwrap();

        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 2);

        // Handle failure of srv1
        coordinator.handle_server_failure("srv1").await.unwrap();

        // srv2 should still be registered
        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_id, "srv2");
    }
}
