//! gRPC/Protobuf definitions for the RustSMB coordinator service.
//!
//! This crate contains the generated Rust code from the `coordinator.proto` file,
//! which defines the gRPC service for cluster coordination.
//!
//! The coordinator service handles:
//! - Server membership (register, heartbeat, leave)
//! - Cache epoch management
//! - Server failure notifications
//!
//! It does NOT handle file leases or locks - those are managed by the StateStore (Redis).

/// Generated protobuf/gRPC code.
pub mod coordinator {
    tonic::include_proto!("rustsmb.coordinator.v1");
}

// Re-export commonly used types for convenience.
pub use coordinator::coordinator_service_client::CoordinatorServiceClient;
pub use coordinator::coordinator_service_server::{CoordinatorService, CoordinatorServiceServer};
pub use coordinator::{
    EpochChangeEvent, GetClusterStatusRequest, GetClusterStatusResponse, GetEpochRequest,
    GetEpochResponse, GetServersRequest, GetServersResponse, HeartbeatRequest, HeartbeatResponse,
    IncrementEpochRequest, IncrementEpochResponse, LeaveClusterRequest, LeaveClusterResponse,
    RegisterServerRequest, RegisterServerResponse, ServerFailureEvent, ServerRegistration,
    SubscribeEpochChangesRequest, SubscribeServerFailuresRequest,
};
