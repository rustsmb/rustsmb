//! In-memory coordination backend.
//!
//! This crate provides `InMemoryCoordinator`, an implementation of the
//! `CoordinationBackend` trait using a single-node in-memory state machine.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │     InMemoryCoordinator         │
//! │  ┌───────────────────────────┐  │
//! │  │    CoordStateMachine      │  │  ← Our application state
//! │  │  ┌─────────────────────┐  │  │
//! │  │  │ CoordinationState   │  │  │
//! │  │  │ - cache_epoch       │  │  │
//! │  │  │ - servers           │  │  │
//! │  │  │ - leases            │  │  │
//! │  │  │ - locks             │  │  │
//! │  │  └─────────────────────┘  │  │
//! │  └───────────────────────────┘  │
//! │  ┌───────────────────────────┐  │
//! │  │   Broadcast Channels     │  │  ← For subscriptions
//! │  └───────────────────────────┘  │
//! │  ┌───────────────────────────┐  │
//! │  │  Heartbeat Monitor Task  │  │  ← Detects server failures
//! │  └───────────────────────────┘  │
//! └─────────────────────────────────┘
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
//! # Future: Multi-Node Raft
//!
//! This implementation can be upgraded to multi-node Raft when openraft
//! stabilizes with edition 2024 support. The state machine and request/response
//! types are designed to be Raft-compatible.

pub mod state;

pub use state::{CoordRequest, CoordResponse, CoordStateMachine, CoordinationState};

use rustsmb_core::CoordError;
use rustsmb_state::{
    BoxFuture, CoordinationBackend, DistributedLock, EpochStream, LeaseBreakRequest,
    LeaseBreakStream, LeaseConflictResult, LeaseEntry, ServerFailureStream, ServerRegistration,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

/// Configuration for InMemoryCoordinator.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// This node's ID.
    pub node_id: String,
    /// This node's address.
    pub node_addr: String,
    /// Server heartbeat timeout in seconds.
    /// If a server doesn't send a heartbeat within this time, it's considered failed.
    pub heartbeat_timeout_secs: u64,
    /// How often to check for stale heartbeats in seconds.
    pub heartbeat_check_interval_secs: u64,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".to_string(),
            node_addr: "127.0.0.1:8080".to_string(),
            heartbeat_timeout_secs: 15,
            heartbeat_check_interval_secs: 5,
        }
    }
}

/// In-memory coordinator that implements CoordinationBackend.
///
/// This provides a single-node coordination layer for SMB servers.
/// For multi-node deployments, this can be upgraded to use Raft.
pub struct InMemoryCoordinator {
    /// The state machine.
    state_machine: Arc<CoordStateMachine>,
    /// Epoch change broadcast channel.
    epoch_tx: broadcast::Sender<u64>,
    /// Server failure broadcast channel.
    failure_tx: broadcast::Sender<String>,
    /// Lease break broadcast channel.
    lease_break_tx: broadcast::Sender<LeaseBreakRequest>,
    /// Configuration.
    config: CoordinatorConfig,
    /// Shutdown flag for the heartbeat monitor.
    shutdown: Arc<AtomicBool>,
}

impl InMemoryCoordinator {
    /// Create a new in-memory coordinator.
    pub fn new(config: CoordinatorConfig) -> Self {
        let state_machine = Arc::new(CoordStateMachine::new());

        let (epoch_tx, _) = broadcast::channel(16);
        let (failure_tx, _) = broadcast::channel(16);
        let (lease_break_tx, _) = broadcast::channel(64);

        info!(node_id = %config.node_id, "Created in-memory coordinator");

        Self {
            state_machine,
            epoch_tx,
            failure_tx,
            lease_break_tx,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CoordinatorConfig::default())
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

    /// Stop the heartbeat monitor.
    pub fn stop_heartbeat_monitor(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
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
    /// 2. Broadcasts the failure event
    /// 3. Cleans up the server's locks and leases
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

        // Clean up the server's locks
        self.apply(CoordRequest::ReleaseLocksForServer(server_id.to_string()))
            .await;

        // Clean up the server's leases
        self.apply(CoordRequest::ReleaseLeasesForServer(server_id.to_string()))
            .await;

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
    async fn apply(&self, request: CoordRequest) -> CoordResponse {
        self.state_machine.apply(request).await
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
}

impl Drop for InMemoryCoordinator {
    fn drop(&mut self) {
        self.stop_heartbeat_monitor();
    }
}

impl CoordinationBackend for InMemoryCoordinator {
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

    fn create_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::CreateLease(lease.clone());
            match self.apply(request).await {
                CoordResponse::Ok => Ok(()),
                CoordResponse::Error(e) => Err(CoordError::Conflict(e)),
                _ => Err(CoordError::Internal("Unexpected response".to_string())),
            }
        })
    }

    fn get_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<Option<LeaseEntry>, CoordError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move { Ok(self.read_state(|s| s.get_lease(&lease_key).cloned()).await) })
    }

    fn update_lease<'a>(&'a self, lease: &'a LeaseEntry) -> BoxFuture<'a, Result<(), CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::UpdateLease(lease.clone());
            self.apply(request).await;
            Ok(())
        })
    }

    fn delete_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<(), CoordError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move {
            let request = CoordRequest::DeleteLease(lease_key);
            self.apply(request).await;
            Ok(())
        })
    }

    fn request_lease_break<'a>(
        &'a self,
        lease_key: &'a str,
        new_state: u32,
    ) -> BoxFuture<'a, Result<(), CoordError>> {
        let lease_key = lease_key.to_string();
        Box::pin(async move {
            // Get the current lease
            let lease = self
                .read_state(|s| s.get_lease(&lease_key).cloned())
                .await
                .ok_or(CoordError::LeaseNotFound)?;

            // Broadcast lease break request
            let break_request = LeaseBreakRequest {
                lease_key: lease_key.clone(),
                current_state: lease.lease_state,
                new_state,
                target_server_id: lease.server_id.clone(),
            };

            let _ = self.lease_break_tx.send(break_request);
            Ok(())
        })
    }

    fn subscribe_lease_breaks(&self, _server_id: &str) -> BoxFuture<'_, LeaseBreakStream> {
        Box::pin(async move {
            let rx = self.lease_break_tx.subscribe();
            let stream = tokio_stream::wrappers::BroadcastStream::new(rx).filter_map(|r| r.ok());
            Box::pin(stream) as LeaseBreakStream
        })
    }

    fn get_leases_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<LeaseEntry>, CoordError>> {
        let file_path = file_path.to_string();
        Box::pin(async move {
            let request = CoordRequest::GetLeasesForFile(file_path);
            match self.apply(request).await {
                CoordResponse::Leases(leases) => Ok(leases),
                _ => Err(CoordError::Internal("Unexpected response".to_string())),
            }
        })
    }

    fn check_lease_conflict<'a>(
        &'a self,
        file_path: &'a str,
        requestor_lease_key: Option<&'a str>,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseConflictResult, CoordError>> {
        let file_path = file_path.to_string();
        let requestor_lease_key = requestor_lease_key.map(|s| s.to_string());
        Box::pin(async move {
            let request = CoordRequest::CheckLeaseConflict {
                file_path,
                requestor_lease_key,
                requested_state,
            };
            match self.apply(request).await {
                CoordResponse::LeaseConflict(result) => Ok(result),
                _ => Err(CoordError::Internal("Unexpected response".to_string())),
            }
        })
    }

    fn acquire_lock<'a>(
        &'a self,
        lock: &'a DistributedLock,
    ) -> BoxFuture<'a, Result<bool, CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::AcquireLock(lock.clone());
            match self.apply(request).await {
                CoordResponse::LockGranted(granted) => Ok(granted),
                _ => Err(CoordError::Internal("Unexpected response".to_string())),
            }
        })
    }

    fn release_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::ReleaseLock(lock_id);
            self.apply(request).await;
            Ok(())
        })
    }

    fn get_locks_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<DistributedLock>, CoordError>> {
        let file_path = file_path.to_string();
        Box::pin(async move { Ok(self.read_state(|s| s.get_locks_for_file(&file_path)).await) })
    }

    fn release_locks_for_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::ReleaseLocksForSession(session_id);
            self.apply(request).await;
            Ok(())
        })
    }

    fn release_locks_for_handle(&self, handle_id: u128) -> BoxFuture<'_, Result<(), CoordError>> {
        Box::pin(async move {
            let request = CoordRequest::ReleaseLocksForHandle(handle_id);
            self.apply(request).await;
            Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_basic() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Test epoch
        let epoch = coordinator.get_epoch().await.unwrap();
        assert_eq!(epoch, 1);

        // Register a server
        let server = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
        coordinator.register_server(&server).await.unwrap();

        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_id, "srv1");
    }

    #[tokio::test]
    async fn test_lease_operations() {
        let coordinator = InMemoryCoordinator::with_defaults();

        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );

        coordinator.create_lease(&lease).await.unwrap();

        let retrieved = coordinator.get_lease(&lease.lease_key).await.unwrap();
        assert!(retrieved.is_some());

        coordinator.delete_lease(&lease.lease_key).await.unwrap();
        let retrieved = coordinator.get_lease(&lease.lease_key).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_lock_operations() {
        let coordinator = InMemoryCoordinator::with_defaults();

        let lock = DistributedLock::new(
            0,
            100,
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            0,
            100,
            true,
        );

        let granted = coordinator.acquire_lock(&lock).await.unwrap();
        assert!(granted);

        let locks = coordinator.get_locks_for_file("/file.txt").await.unwrap();
        assert_eq!(locks.len(), 1);

        // Conflicting lock should fail
        let lock2 = DistributedLock::new(
            0,
            200,
            2,
            "srv2".to_string(),
            "/file.txt".to_string(),
            50,
            100,
            true,
        );
        let granted = coordinator.acquire_lock(&lock2).await.unwrap();
        assert!(!granted);
    }

    #[tokio::test]
    async fn test_lease_conflict() {
        let coordinator = InMemoryCoordinator::with_defaults();

        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );

        // First create should succeed
        coordinator.create_lease(&lease).await.unwrap();

        // Second create should fail
        let result = coordinator.create_lease(&lease).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_lock_cleanup() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Create locks for two sessions
        let lock1 = DistributedLock::new(
            0,
            100,
            1, // session 1
            "srv1".to_string(),
            "/a.txt".to_string(),
            0,
            100,
            true,
        );
        let lock2 = DistributedLock::new(
            0,
            100,
            2, // session 2
            "srv1".to_string(),
            "/b.txt".to_string(),
            0,
            100,
            true,
        );

        coordinator.acquire_lock(&lock1).await.unwrap();
        coordinator.acquire_lock(&lock2).await.unwrap();

        // Release all locks for session 1
        coordinator.release_locks_for_session(1).await.unwrap();

        // Session 1 lock should be gone
        let locks = coordinator.get_locks_for_file("/a.txt").await.unwrap();
        assert!(locks.is_empty());

        // Session 2 lock should remain
        let locks = coordinator.get_locks_for_file("/b.txt").await.unwrap();
        assert_eq!(locks.len(), 1);
    }

    #[tokio::test]
    async fn test_heartbeat_update() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Register a server
        let server = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
        coordinator.register_server(&server).await.unwrap();

        // Update heartbeat
        coordinator.update_heartbeat("srv1").await.unwrap();

        // Server should still be registered
        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
    }

    #[tokio::test]
    async fn test_server_failure_handling() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Register a server
        let server = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
        coordinator.register_server(&server).await.unwrap();

        // Create a lock for the server
        let lock = DistributedLock::new(
            0,
            100,
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            0,
            100,
            true,
        );
        coordinator.acquire_lock(&lock).await.unwrap();

        // Create a lease for the server
        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        coordinator.create_lease(&lease).await.unwrap();

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

        // Lock should be released
        let locks = coordinator.get_locks_for_file("/file.txt").await.unwrap();
        assert!(locks.is_empty());

        // Lease should be released
        let lease = coordinator.get_lease(&lease.lease_key).await.unwrap();
        assert!(lease.is_none());
    }

    #[tokio::test]
    async fn test_server_cleanup_by_server_id() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Register two servers
        let server1 = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
        let server2 = ServerRegistration::new(
            "srv2".to_string(),
            "localhost".to_string(),
            446,
            "127.0.0.1:9001".to_string(),
        );
        coordinator.register_server(&server1).await.unwrap();
        coordinator.register_server(&server2).await.unwrap();

        // Create locks for both servers
        let lock1 = DistributedLock::new(
            0,
            100,
            1,
            "srv1".to_string(),
            "/a.txt".to_string(),
            0,
            100,
            true,
        );
        let lock2 = DistributedLock::new(
            0,
            100,
            2,
            "srv2".to_string(),
            "/b.txt".to_string(),
            0,
            100,
            true,
        );
        coordinator.acquire_lock(&lock1).await.unwrap();
        coordinator.acquire_lock(&lock2).await.unwrap();

        // Create leases for both servers
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/a.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        let lease2 = LeaseEntry::new(
            [2u8; 16],
            "client2".to_string(),
            2,
            "srv2".to_string(),
            "/b.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        coordinator.create_lease(&lease1).await.unwrap();
        coordinator.create_lease(&lease2).await.unwrap();

        // Handle failure of srv1
        coordinator.handle_server_failure("srv1").await.unwrap();

        // srv1 locks and leases should be gone
        assert!(coordinator
            .get_locks_for_file("/a.txt")
            .await
            .unwrap()
            .is_empty());
        assert!(coordinator
            .get_lease(&lease1.lease_key)
            .await
            .unwrap()
            .is_none());

        // srv2 locks and leases should remain
        assert_eq!(
            coordinator
                .get_locks_for_file("/b.txt")
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(coordinator
            .get_lease(&lease2.lease_key)
            .await
            .unwrap()
            .is_some());

        // srv2 should still be registered
        let servers = coordinator.get_servers().await.unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].server_id, "srv2");
    }

    #[tokio::test]
    async fn test_stale_server_detection() {
        let config = CoordinatorConfig {
            heartbeat_timeout_secs: 1, // 1 second timeout for testing
            heartbeat_check_interval_secs: 1,
            ..Default::default()
        };
        let coordinator = Arc::new(InMemoryCoordinator::new(config));

        // Register a server with old timestamp (will be immediately stale)
        let mut server = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
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
        let coordinator = Arc::new(InMemoryCoordinator::new(config));

        // Register a server
        let server = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
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
        let coordinator = InMemoryCoordinator::with_defaults();

        // Subscribe to failures before registering
        let mut failure_rx = coordinator.failure_tx.subscribe();
        let mut epoch_rx = coordinator.epoch_tx.subscribe();

        // Register a server
        let server = ServerRegistration::new(
            "srv1".to_string(),
            "localhost".to_string(),
            445,
            "127.0.0.1:9000".to_string(),
        );
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
    async fn test_get_leases_for_file() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Create leases for different files
        let lease1 = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        let lease2 = LeaseEntry::new(
            [2u8; 16],
            "client2".to_string(),
            2,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        let lease3 = LeaseEntry::new(
            [3u8; 16],
            "client3".to_string(),
            3,
            "srv1".to_string(),
            "/other.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );

        coordinator.create_lease(&lease1).await.unwrap();
        coordinator.create_lease(&lease2).await.unwrap();
        coordinator.create_lease(&lease3).await.unwrap();

        // Get leases for file.txt
        let leases = coordinator.get_leases_for_file("/file.txt").await.unwrap();
        assert_eq!(leases.len(), 2);

        // Get leases for other.txt
        let leases = coordinator.get_leases_for_file("/other.txt").await.unwrap();
        assert_eq!(leases.len(), 1);
    }

    #[tokio::test]
    async fn test_check_lease_conflict() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Create a lease with write caching
        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::WRITE_CACHING,
        );
        coordinator.create_lease(&lease).await.unwrap();

        // Check conflict for another client requesting read
        let result = coordinator
            .check_lease_conflict("/file.txt", None, LeaseEntry::READ_CACHING)
            .await
            .unwrap();

        assert!(!result.can_grant);
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.granted_state, 0);
    }

    #[tokio::test]
    async fn test_check_lease_no_conflict() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Create a lease with read caching
        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING,
        );
        coordinator.create_lease(&lease).await.unwrap();

        // Check conflict for another client also requesting read - no conflict
        let result = coordinator
            .check_lease_conflict("/file.txt", None, LeaseEntry::READ_CACHING)
            .await
            .unwrap();

        assert!(result.can_grant);
        assert!(result.conflicts.is_empty());
    }

    #[tokio::test]
    async fn test_check_lease_conflict_excludes_self() {
        let coordinator = InMemoryCoordinator::with_defaults();

        // Create a lease with full caching
        let lease = LeaseEntry::new(
            [1u8; 16],
            "client1".to_string(),
            1,
            "srv1".to_string(),
            "/file.txt".to_string(),
            LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
        );
        coordinator.create_lease(&lease).await.unwrap();

        // Check conflict for the same lease key - should not conflict with itself
        let result = coordinator
            .check_lease_conflict(
                "/file.txt",
                Some(&lease.lease_key),
                LeaseEntry::READ_CACHING | LeaseEntry::WRITE_CACHING,
            )
            .await
            .unwrap();

        assert!(result.can_grant);
        assert!(result.conflicts.is_empty());
    }
}
