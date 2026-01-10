//! gRPC service implementation for the coordinator.
//!
//! This module implements the `CoordinatorService` gRPC trait.

use crate::config::CoordinatorConfig;
use crate::state::{CoordRequest, CoordResponse, CoordinationState};
use anyhow::Result;
use rustsmb_coordinator_proto::{
    CoordinatorService, CoordinatorServiceServer, EpochChangeEvent, GetClusterStatusRequest,
    GetClusterStatusResponse, GetEpochRequest, GetEpochResponse, GetServersRequest,
    GetServersResponse, HeartbeatRequest, HeartbeatResponse, IncrementEpochRequest,
    IncrementEpochResponse, LeaveClusterRequest, LeaveClusterResponse, RegisterServerRequest,
    RegisterServerResponse, ServerFailureEvent, ServerRegistration, SubscribeEpochChangesRequest,
    SubscribeServerFailuresRequest,
};
use rustsmb_state::ServerRegistration as StateServerRegistration;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

/// The coordinator service implementation.
pub struct CoordinatorServiceImpl {
    /// The replicated state.
    state: Arc<RwLock<CoordinationState>>,
    /// Configuration.
    config: CoordinatorConfig,
    /// Epoch change broadcast channel.
    epoch_tx: broadcast::Sender<EpochChangeEvent>,
    /// Server failure broadcast channel.
    failure_tx: broadcast::Sender<ServerFailureEvent>,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl CoordinatorServiceImpl {
    /// Create a new coordinator service.
    pub fn new(config: CoordinatorConfig) -> Self {
        let (epoch_tx, _) = broadcast::channel(64);
        let (failure_tx, _) = broadcast::channel(64);

        Self {
            state: Arc::new(RwLock::new(CoordinationState::new())),
            config,
            epoch_tx,
            failure_tx,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the heartbeat monitor task.
    pub fn start_heartbeat_monitor(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let service = Arc::clone(self);
        let timeout = service.config.heartbeat_timeout_secs;

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(5);

            while !service.shutdown.load(Ordering::Acquire) {
                tokio::time::sleep(check_interval).await;

                // Check for stale servers
                let stale_servers = {
                    let state = service.state.read().await;
                    state.get_stale_servers(timeout)
                };

                // Handle failures
                for server_id in stale_servers {
                    warn!(server_id = %server_id, "Server heartbeat timeout, removing");

                    let new_epoch = {
                        let mut state = service.state.write().await;
                        let response =
                            state.apply(CoordRequest::UnregisterServer(server_id.clone()));
                        match response {
                            CoordResponse::Epoch(e) => e,
                            _ => state.get_epoch(),
                        }
                    };

                    // Broadcast failure
                    let _ = service.failure_tx.send(ServerFailureEvent {
                        failed_server_id: server_id.clone(),
                        new_epoch,
                        timestamp: current_timestamp(),
                    });

                    // Broadcast epoch change
                    let _ = service.epoch_tx.send(EpochChangeEvent {
                        new_epoch,
                        reason: format!("server_failure:{}", server_id),
                        timestamp: current_timestamp(),
                    });
                }
            }
        })
    }

    /// Shutdown the service.
    #[allow(dead_code)]
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

#[tonic::async_trait]
impl CoordinatorService for CoordinatorServiceImpl {
    async fn register_server(
        &self,
        request: Request<RegisterServerRequest>,
    ) -> Result<Response<RegisterServerResponse>, Status> {
        let req = request.into_inner();
        let proto_reg = req
            .registration
            .ok_or_else(|| Status::invalid_argument("Missing registration"))?;

        let registration = StateServerRegistration {
            server_id: proto_reg.server_id.clone(),
            hostname: proto_reg.hostname,
            port: proto_reg.port as u16,
            raft_addr: String::new(),
            registered_at: proto_reg.registered_at,
            last_heartbeat: proto_reg.last_heartbeat,
            active_sessions: proto_reg.active_sessions,
            active_handles: proto_reg.active_handles,
        };

        let (epoch, cluster_size) = {
            let mut state = self.state.write().await;
            let response = state.apply(CoordRequest::RegisterServer(registration));
            let epoch = match response {
                CoordResponse::Epoch(e) => e,
                _ => state.get_epoch(),
            };
            let size = state.servers.len() as u32;
            (epoch, size)
        };

        info!(
            server_id = %proto_reg.server_id,
            epoch = epoch,
            cluster_size = cluster_size,
            "Server registered"
        );

        Ok(Response::new(RegisterServerResponse {
            current_epoch: epoch,
            cluster_size,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();

        let epoch = {
            let mut state = self.state.write().await;
            let response = state.apply(CoordRequest::UpdateHeartbeat {
                server_id: req.server_id.clone(),
                timestamp: current_timestamp(),
                active_sessions: req.active_sessions,
                active_handles: req.active_handles,
            });
            match response {
                CoordResponse::Error(e) => {
                    return Err(Status::not_found(e));
                }
                _ => state.get_epoch(),
            }
        };

        debug!(server_id = %req.server_id, epoch = epoch, "Heartbeat received");

        Ok(Response::new(HeartbeatResponse {
            current_epoch: epoch,
        }))
    }

    async fn leave_cluster(
        &self,
        request: Request<LeaveClusterRequest>,
    ) -> Result<Response<LeaveClusterResponse>, Status> {
        let req = request.into_inner();

        let new_epoch = {
            let mut state = self.state.write().await;
            let response = state.apply(CoordRequest::UnregisterServer(req.server_id.clone()));
            match response {
                CoordResponse::Epoch(e) => e,
                _ => state.get_epoch(),
            }
        };

        info!(server_id = %req.server_id, new_epoch = new_epoch, "Server left cluster");

        // Broadcast epoch change
        let _ = self.epoch_tx.send(EpochChangeEvent {
            new_epoch,
            reason: format!("server_leave:{}", req.server_id),
            timestamp: current_timestamp(),
        });

        Ok(Response::new(LeaveClusterResponse {}))
    }

    async fn get_servers(
        &self,
        _request: Request<GetServersRequest>,
    ) -> Result<Response<GetServersResponse>, Status> {
        let servers = {
            let state = self.state.read().await;
            state
                .get_servers()
                .into_iter()
                .map(|s| ServerRegistration {
                    server_id: s.server_id,
                    hostname: s.hostname,
                    port: s.port as u32,
                    registered_at: s.registered_at,
                    last_heartbeat: s.last_heartbeat,
                    active_sessions: s.active_sessions,
                    active_handles: s.active_handles,
                })
                .collect()
        };

        Ok(Response::new(GetServersResponse { servers }))
    }

    async fn get_epoch(
        &self,
        _request: Request<GetEpochRequest>,
    ) -> Result<Response<GetEpochResponse>, Status> {
        let epoch = self.state.read().await.get_epoch();
        Ok(Response::new(GetEpochResponse { epoch }))
    }

    type SubscribeEpochChangesStream =
        Pin<Box<dyn Stream<Item = Result<EpochChangeEvent, Status>> + Send>>;

    async fn subscribe_epoch_changes(
        &self,
        request: Request<SubscribeEpochChangesRequest>,
    ) -> Result<Response<Self::SubscribeEpochChangesStream>, Status> {
        let client_id = request.into_inner().client_id;
        info!(client_id = %client_id, "Client subscribed to epoch changes");

        let rx = self.epoch_tx.subscribe();
        let stream =
            BroadcastStream::new(rx).map(|r| r.map_err(|e| Status::internal(e.to_string())));

        Ok(Response::new(Box::pin(stream)))
    }

    type SubscribeServerFailuresStream =
        Pin<Box<dyn Stream<Item = Result<ServerFailureEvent, Status>> + Send>>;

    async fn subscribe_server_failures(
        &self,
        request: Request<SubscribeServerFailuresRequest>,
    ) -> Result<Response<Self::SubscribeServerFailuresStream>, Status> {
        let client_id = request.into_inner().client_id;
        info!(client_id = %client_id, "Client subscribed to server failures");

        let rx = self.failure_tx.subscribe();
        let stream =
            BroadcastStream::new(rx).map(|r| r.map_err(|e| Status::internal(e.to_string())));

        Ok(Response::new(Box::pin(stream)))
    }

    async fn increment_epoch(
        &self,
        request: Request<IncrementEpochRequest>,
    ) -> Result<Response<IncrementEpochResponse>, Status> {
        let reason = request.into_inner().reason;

        let new_epoch = {
            let mut state = self.state.write().await;
            let response = state.apply(CoordRequest::IncrementEpoch {
                reason: reason.clone(),
            });
            match response {
                CoordResponse::Epoch(e) => e,
                _ => state.get_epoch(),
            }
        };

        info!(new_epoch = new_epoch, reason = %reason, "Epoch incremented");

        // Broadcast epoch change
        let _ = self.epoch_tx.send(EpochChangeEvent {
            new_epoch,
            reason,
            timestamp: current_timestamp(),
        });

        Ok(Response::new(IncrementEpochResponse { new_epoch }))
    }

    async fn get_cluster_status(
        &self,
        _request: Request<GetClusterStatusRequest>,
    ) -> Result<Response<GetClusterStatusResponse>, Status> {
        let state = self.state.read().await;

        let servers: Vec<ServerRegistration> = state
            .get_servers()
            .into_iter()
            .map(|s| ServerRegistration {
                server_id: s.server_id,
                hostname: s.hostname,
                port: s.port as u32,
                registered_at: s.registered_at,
                last_heartbeat: s.last_heartbeat,
                active_sessions: s.active_sessions,
                active_handles: s.active_handles,
            })
            .collect();

        Ok(Response::new(GetClusterStatusResponse {
            epoch: state.get_epoch(),
            server_count: servers.len() as u32,
            servers,
            leader_id: String::new(), // TODO: implement Raft leader tracking
            is_leader: true,          // TODO: implement Raft leader tracking
            raft_term: 0,             // TODO: implement Raft term tracking
        }))
    }
}

/// Run the coordinator service.
pub async fn run(config: CoordinatorConfig) -> Result<()> {
    let addr = config.listen_addr.parse()?;

    let service = Arc::new(CoordinatorServiceImpl::new(config));

    // Start heartbeat monitor
    let _monitor_handle = service.start_heartbeat_monitor();

    info!(addr = %addr, "Starting gRPC server");

    tonic::transport::Server::builder()
        .add_service(CoordinatorServiceServer::from_arc(service))
        .serve(addr)
        .await?;

    Ok(())
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_creation() {
        let config = CoordinatorConfig::default();
        let service = CoordinatorServiceImpl::new(config);

        let state = service.state.read().await;
        assert_eq!(state.get_epoch(), 1);
        assert!(state.servers.is_empty());
    }
}
