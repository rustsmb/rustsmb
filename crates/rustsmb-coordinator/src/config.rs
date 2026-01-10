//! Configuration for the coordinator service.

use serde::{Deserialize, Serialize};

/// Configuration for a coordinator node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    /// Raft node ID (must be unique in the cluster).
    pub node_id: u64,

    /// Address to listen on for gRPC connections (e.g., "0.0.0.0:9000").
    pub listen_addr: String,

    /// List of peer addresses (e.g., ["node2:9000", "node3:9000"]).
    pub peers: Vec<String>,

    /// Timeout in seconds before marking a server as failed.
    pub heartbeat_timeout_secs: u64,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            node_id: 1,
            listen_addr: "0.0.0.0:9000".to_string(),
            peers: vec![],
            heartbeat_timeout_secs: 15,
        }
    }
}
