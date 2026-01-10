//! gRPC client implementation for the coordinator service.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustsmb_coordinator_proto::{
    CoordinatorServiceClient, GetEpochRequest, GetServersRequest, HeartbeatRequest,
    IncrementEpochRequest, LeaveClusterRequest, RegisterServerRequest,
    ServerRegistration as ProtoServerRegistration, SubscribeEpochChangesRequest,
};
use rustsmb_core::CoordError;
use rustsmb_state::{
    BoxFuture, CoordinationBackend, EpochStream, ServerFailureStream, ServerRegistration,
};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

/// Error type for coordinator client operations.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorClientError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("Transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("Not connected")]
    NotConnected,

    #[error("Stream closed")]
    StreamClosed,
}

impl From<CoordinatorClientError> for CoordError {
    fn from(e: CoordinatorClientError) -> Self {
        CoordError::Internal(e.to_string())
    }
}

/// Configuration for the coordinator client.
#[derive(Debug, Clone)]
pub struct CoordinatorClientConfig {
    /// Coordinator endpoint (e.g., "http://coordinator:9000").
    pub endpoint: String,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Retry count for failed operations.
    pub retry_count: u32,
    /// Delay between retries.
    pub retry_delay: Duration,
}

impl Default for CoordinatorClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:9000".to_string(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            retry_count: 3,
            retry_delay: Duration::from_millis(500),
        }
    }
}

/// gRPC client for the coordinator service.
///
/// Implements `CoordinationBackend` for use with `CachedStateStore`.
pub struct CoordinatorClient {
    /// gRPC client.
    client: CoordinatorServiceClient<Channel>,
    /// Configuration (stored for retry logic).
    #[allow(dead_code)]
    config: CoordinatorClientConfig,
    /// Server ID for this client (set after registration).
    server_id: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Cached epoch value.
    cached_epoch: AtomicU64,
    /// Broadcast channel for epoch changes.
    epoch_tx: broadcast::Sender<u64>,
    /// Broadcast channel for server failures.
    failure_tx: broadcast::Sender<String>,
    /// Whether the client is connected and registered.
    connected: AtomicBool,
}

impl CoordinatorClient {
    /// Connect to the coordinator service.
    pub async fn connect(endpoint: &str) -> Result<Self, CoordinatorClientError> {
        Self::connect_with_config(CoordinatorClientConfig {
            endpoint: endpoint.to_string(),
            ..Default::default()
        })
        .await
    }

    /// Connect with custom configuration.
    pub async fn connect_with_config(
        config: CoordinatorClientConfig,
    ) -> Result<Self, CoordinatorClientError> {
        info!(endpoint = %config.endpoint, "Connecting to coordinator");

        let channel = Channel::from_shared(config.endpoint.clone())
            .map_err(|e| CoordinatorClientError::ConnectionFailed(e.to_string()))?
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .connect()
            .await?;

        let client = CoordinatorServiceClient::new(channel);

        let (epoch_tx, _) = broadcast::channel(16);
        let (failure_tx, _) = broadcast::channel(16);

        Ok(Self {
            client,
            config,
            server_id: Arc::new(tokio::sync::RwLock::new(None)),
            cached_epoch: AtomicU64::new(0),
            epoch_tx,
            failure_tx,
            connected: AtomicBool::new(true),
        })
    }

    /// Get the server ID (if registered).
    pub async fn server_id(&self) -> Option<String> {
        self.server_id.read().await.clone()
    }

    /// Start background tasks for streaming subscriptions.
    pub fn start_subscriptions(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let client = Arc::clone(self);
        tokio::spawn(async move {
            // Run epoch subscription
            if let Err(e) = client.run_epoch_subscription().await {
                error!(error = %e, "Epoch subscription failed");
            }
        })
    }

    /// Run the epoch change subscription loop.
    async fn run_epoch_subscription(&self) -> Result<(), CoordinatorClientError> {
        let server_id = self.server_id.read().await.clone().unwrap_or_default();

        let request = SubscribeEpochChangesRequest {
            client_id: server_id,
        };

        let mut stream = self
            .client
            .clone()
            .subscribe_epoch_changes(request)
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            match result {
                Ok(event) => {
                    let new_epoch = event.new_epoch;
                    debug!(epoch = new_epoch, reason = %event.reason, "Received epoch change");

                    self.cached_epoch.store(new_epoch, Ordering::Release);
                    let _ = self.epoch_tx.send(new_epoch);
                }
                Err(e) => {
                    warn!(error = %e, "Epoch subscription error");
                    return Err(CoordinatorClientError::Grpc(e));
                }
            }
        }

        Ok(())
    }
}

impl CoordinationBackend for CoordinatorClient {
    fn register_server<'a>(
        &'a self,
        registration: &'a ServerRegistration,
    ) -> BoxFuture<'a, Result<(), CoordError>> {
        Box::pin(async move {
            let proto_reg = ProtoServerRegistration {
                server_id: registration.server_id.clone(),
                hostname: registration.hostname.clone(),
                port: registration.port as u32,
                registered_at: registration.registered_at,
                last_heartbeat: registration.last_heartbeat,
                active_sessions: registration.active_sessions,
                active_handles: registration.active_handles,
            };

            let request = RegisterServerRequest {
                registration: Some(proto_reg),
            };

            let response = self
                .client
                .clone()
                .register_server(request)
                .await
                .map_err(CoordinatorClientError::from)?
                .into_inner();

            // Store the server ID and epoch
            *self.server_id.write().await = Some(registration.server_id.clone());
            self.cached_epoch
                .store(response.current_epoch, Ordering::Release);

            info!(
                server_id = %registration.server_id,
                epoch = response.current_epoch,
                cluster_size = response.cluster_size,
                "Registered with coordinator"
            );

            Ok(())
        })
    }

    fn heartbeat(&self, server_id: &str) -> BoxFuture<'_, Result<(), CoordError>> {
        let server_id = server_id.to_string();
        Box::pin(async move {
            let request = HeartbeatRequest {
                server_id,
                active_sessions: 0, // TODO: get actual counts
                active_handles: 0,
            };

            let response = self
                .client
                .clone()
                .heartbeat(request)
                .await
                .map_err(CoordinatorClientError::from)?
                .into_inner();

            // Check if epoch changed
            let current = self.cached_epoch.load(Ordering::Acquire);
            if response.current_epoch != current {
                debug!(
                    old_epoch = current,
                    new_epoch = response.current_epoch,
                    "Epoch changed during heartbeat"
                );
                self.cached_epoch
                    .store(response.current_epoch, Ordering::Release);
                let _ = self.epoch_tx.send(response.current_epoch);
            }

            Ok(())
        })
    }

    fn leave_cluster(&self) -> BoxFuture<'_, Result<(), CoordError>> {
        Box::pin(async move {
            let server_id = self
                .server_id
                .read()
                .await
                .clone()
                .ok_or(CoordError::Internal("Not registered".to_string()))?;

            let request = LeaveClusterRequest { server_id };

            self.client
                .clone()
                .leave_cluster(request)
                .await
                .map_err(CoordinatorClientError::from)?;

            *self.server_id.write().await = None;
            self.connected.store(false, Ordering::Release);

            info!("Left coordinator cluster");

            Ok(())
        })
    }

    fn get_servers(&self) -> BoxFuture<'_, Result<Vec<ServerRegistration>, CoordError>> {
        Box::pin(async move {
            let response = self
                .client
                .clone()
                .get_servers(GetServersRequest {})
                .await
                .map_err(CoordinatorClientError::from)?
                .into_inner();

            let servers = response
                .servers
                .into_iter()
                .map(|s| ServerRegistration {
                    server_id: s.server_id,
                    hostname: s.hostname,
                    port: s.port as u16,
                    raft_addr: String::new(), // Not used in gRPC client
                    registered_at: s.registered_at,
                    last_heartbeat: s.last_heartbeat,
                    active_sessions: s.active_sessions,
                    active_handles: s.active_handles,
                })
                .collect();

            Ok(servers)
        })
    }

    fn subscribe_server_failures(&self) -> BoxFuture<'_, ServerFailureStream> {
        Box::pin(async move {
            let rx = self.failure_tx.subscribe();
            let stream = BroadcastStream::new(rx).filter_map(|r| r.ok());
            Box::pin(stream) as ServerFailureStream
        })
    }

    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>> {
        Box::pin(async move {
            // Return cached value if we have one
            let cached = self.cached_epoch.load(Ordering::Acquire);
            if cached > 0 {
                return Ok(cached);
            }

            // Otherwise fetch from coordinator
            let response = self
                .client
                .clone()
                .get_epoch(GetEpochRequest {})
                .await
                .map_err(CoordinatorClientError::from)?
                .into_inner();

            self.cached_epoch.store(response.epoch, Ordering::Release);

            Ok(response.epoch)
        })
    }

    fn subscribe_epoch_changes(&self) -> BoxFuture<'_, EpochStream> {
        Box::pin(async move {
            let rx = self.epoch_tx.subscribe();
            let stream = BroadcastStream::new(rx).filter_map(|r| r.ok());
            Box::pin(stream) as EpochStream
        })
    }

    fn increment_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>> {
        Box::pin(async move {
            let request = IncrementEpochRequest {
                reason: "manual".to_string(),
            };

            let response = self
                .client
                .clone()
                .increment_epoch(request)
                .await
                .map_err(CoordinatorClientError::from)?
                .into_inner();

            self.cached_epoch
                .store(response.new_epoch, Ordering::Release);
            let _ = self.epoch_tx.send(response.new_epoch);

            Ok(response.new_epoch)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = CoordinatorClientConfig::default();
        assert_eq!(config.endpoint, "http://localhost:9000");
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.retry_count, 3);
    }
}
