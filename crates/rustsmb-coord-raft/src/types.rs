//! Type definitions for the Raft coordination backend using tikv/raft-rs.
//!
//! This module defines types compatible with raft-rs.

use crate::state::CoordinationState;
use serde::{Deserialize, Serialize};

/// Node ID type for Raft cluster members.
pub type NodeId = u64;

/// Information about a Raft node in the cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct CoordNode {
    /// The unique node ID.
    pub id: NodeId,
    /// Raft communication address (e.g., "127.0.0.1:9000").
    pub raft_addr: String,
    /// SMB server address for client connections (e.g., "127.0.0.1:445").
    pub smb_addr: String,
}

impl CoordNode {
    /// Create a new CoordNode.
    pub fn new(id: NodeId, raft_addr: String, smb_addr: String) -> Self {
        Self {
            id,
            raft_addr,
            smb_addr,
        }
    }
}

impl std::fmt::Display for CoordNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Node(id={}, raft={})", self.id, self.raft_addr)
    }
}

/// Snapshot data containing the complete coordination state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordSnapshotData {
    /// The coordination state at the time of snapshot.
    pub state: CoordinationState,
}

impl CoordSnapshotData {
    /// Create a new snapshot from the current state.
    pub fn new(state: CoordinationState) -> Self {
        Self { state }
    }

    /// Serialize to bytes for network transfer.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

impl Default for CoordSnapshotData {
    fn default() -> Self {
        Self {
            state: CoordinationState::new(),
        }
    }
}

/// Cluster membership information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterMembership {
    /// Current cluster members (node_id -> node info).
    pub nodes: std::collections::HashMap<NodeId, CoordNode>,
    /// Leader node ID (if known).
    pub leader_id: Option<NodeId>,
}

impl ClusterMembership {
    /// Create a new empty membership.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node to the cluster.
    pub fn add_node(&mut self, node: CoordNode) {
        self.nodes.insert(node.id, node);
    }

    /// Remove a node from the cluster.
    pub fn remove_node(&mut self, node_id: NodeId) -> Option<CoordNode> {
        self.nodes.remove(&node_id)
    }

    /// Get all node IDs.
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::CoordinationState;

    #[test]
    fn test_coord_node_creation() {
        let node = CoordNode::new(1, "127.0.0.1:9000".to_string(), "127.0.0.1:445".to_string());
        assert_eq!(node.id, 1);
        assert_eq!(node.raft_addr, "127.0.0.1:9000");
        assert_eq!(node.smb_addr, "127.0.0.1:445");
    }

    #[test]
    fn test_coord_node_display() {
        let node = CoordNode::new(1, "127.0.0.1:9000".to_string(), "127.0.0.1:445".to_string());
        let display = format!("{}", node);
        assert!(display.contains("id=1"));
        assert!(display.contains("raft=127.0.0.1:9000"));
    }

    #[test]
    fn test_coord_node_serialization() {
        let node = CoordNode::new(1, "127.0.0.1:9000".to_string(), "127.0.0.1:445".to_string());
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: CoordNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, deserialized);
    }

    #[test]
    fn test_snapshot_data_serialization() {
        let state = CoordinationState::new();
        let snapshot = CoordSnapshotData::new(state);

        let bytes = snapshot.to_bytes().unwrap();
        let restored = CoordSnapshotData::from_bytes(&bytes).unwrap();

        assert_eq!(snapshot.state.epoch(), restored.state.epoch());
    }

    #[test]
    fn test_cluster_membership() {
        let mut membership = ClusterMembership::new();

        let node1 = CoordNode::new(1, "127.0.0.1:9000".to_string(), "127.0.0.1:445".to_string());
        let node2 = CoordNode::new(2, "127.0.0.1:9001".to_string(), "127.0.0.1:446".to_string());

        membership.add_node(node1);
        membership.add_node(node2);

        assert_eq!(membership.nodes.len(), 2);
        assert!(membership.node_ids().contains(&1));
        assert!(membership.node_ids().contains(&2));

        membership.remove_node(1);
        assert_eq!(membership.nodes.len(), 1);
        assert!(!membership.node_ids().contains(&1));
    }
}
