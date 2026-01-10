//! Coordinator state machine (Raft replicated).
//!
//! This is a simplified state machine that only manages:
//! - Server membership (registration, heartbeats)
//! - Cache epoch
//!
//! Leases and locks are NOT stored here - they are in Redis (StateStore).

use rustsmb_state::ServerRegistration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Commands that can be applied to the state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordRequest {
    /// Register a new server.
    RegisterServer(ServerRegistration),
    /// Unregister a server (on failure or graceful leave).
    UnregisterServer(String),
    /// Update a server's heartbeat timestamp.
    UpdateHeartbeat {
        server_id: String,
        timestamp: u64,
        active_sessions: u64,
        active_handles: u64,
    },
    /// Increment the cache epoch.
    IncrementEpoch { reason: String },
}

/// Responses from the state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordResponse {
    /// Operation succeeded.
    Ok,
    /// Operation succeeded with epoch value.
    Epoch(u64),
    /// Operation succeeded with server list.
    Servers(Vec<ServerRegistration>),
    /// Error occurred.
    Error(String),
}

/// The replicated state managed by Raft.
///
/// This is intentionally minimal - only server membership and epoch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoordinationState {
    /// Global cache epoch (incremented on server failure).
    pub cache_epoch: u64,

    /// Active server registrations.
    pub servers: HashMap<String, ServerRegistration>,
}

impl CoordinationState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            cache_epoch: 1,
            servers: HashMap::new(),
        }
    }

    /// Apply a request to the state machine.
    pub fn apply(&mut self, request: CoordRequest) -> CoordResponse {
        match request {
            CoordRequest::RegisterServer(mut registration) => {
                let now = current_timestamp();
                registration.registered_at = now;
                registration.last_heartbeat = now;

                let server_id = registration.server_id.clone();
                self.servers.insert(server_id, registration);

                CoordResponse::Epoch(self.cache_epoch)
            }

            CoordRequest::UnregisterServer(server_id) => {
                self.servers.remove(&server_id);
                // Increment epoch when a server is unregistered (failure)
                self.cache_epoch += 1;
                CoordResponse::Epoch(self.cache_epoch)
            }

            CoordRequest::UpdateHeartbeat {
                server_id,
                timestamp,
                active_sessions,
                active_handles,
            } => {
                if let Some(server) = self.servers.get_mut(&server_id) {
                    server.last_heartbeat = timestamp;
                    server.active_sessions = active_sessions;
                    server.active_handles = active_handles;
                    CoordResponse::Ok
                } else {
                    CoordResponse::Error(format!("Server not found: {}", server_id))
                }
            }

            CoordRequest::IncrementEpoch { reason: _ } => {
                self.cache_epoch += 1;
                CoordResponse::Epoch(self.cache_epoch)
            }
        }
    }

    /// Get all registered servers.
    pub fn get_servers(&self) -> Vec<ServerRegistration> {
        self.servers.values().cloned().collect()
    }

    /// Get a specific server.
    #[allow(dead_code)]
    pub fn get_server(&self, server_id: &str) -> Option<&ServerRegistration> {
        self.servers.get(server_id)
    }

    /// Get the current epoch.
    pub fn get_epoch(&self) -> u64 {
        self.cache_epoch
    }

    /// Find servers with stale heartbeats.
    pub fn get_stale_servers(&self, timeout_secs: u64) -> Vec<String> {
        let now = current_timestamp();
        let cutoff = now.saturating_sub(timeout_secs);

        self.servers
            .iter()
            .filter(|(_, server)| server.last_heartbeat < cutoff)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Serialize state to bytes (for Raft snapshots).
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize state from bytes.
    #[allow(dead_code)]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_server() {
        let mut state = CoordinationState::new();

        let registration = ServerRegistration::new("server1", "localhost", 445, "");
        let response = state.apply(CoordRequest::RegisterServer(registration));

        assert!(matches!(response, CoordResponse::Epoch(1)));
        assert_eq!(state.servers.len(), 1);
        assert!(state.servers.contains_key("server1"));
    }

    #[test]
    fn test_unregister_increments_epoch() {
        let mut state = CoordinationState::new();

        // Register a server
        let registration = ServerRegistration::new("server1", "localhost", 445, "");
        state.apply(CoordRequest::RegisterServer(registration));

        // Unregister it
        let response = state.apply(CoordRequest::UnregisterServer("server1".to_string()));

        // Epoch should increment
        assert!(matches!(response, CoordResponse::Epoch(2)));
        assert!(state.servers.is_empty());
    }

    #[test]
    fn test_heartbeat_update() {
        let mut state = CoordinationState::new();

        // Register a server
        let registration = ServerRegistration::new("server1", "localhost", 445, "");
        state.apply(CoordRequest::RegisterServer(registration));

        // Update heartbeat
        let response = state.apply(CoordRequest::UpdateHeartbeat {
            server_id: "server1".to_string(),
            timestamp: 12345,
            active_sessions: 10,
            active_handles: 100,
        });

        assert!(matches!(response, CoordResponse::Ok));
        let server = state.get_server("server1").unwrap();
        assert_eq!(server.last_heartbeat, 12345);
        assert_eq!(server.active_sessions, 10);
        assert_eq!(server.active_handles, 100);
    }

    #[test]
    fn test_stale_server_detection() {
        let mut state = CoordinationState::new();

        // Register a server with old heartbeat
        let mut registration = ServerRegistration::new("server1", "localhost", 445, "");
        registration.last_heartbeat = 1000; // Very old
        state.servers.insert("server1".to_string(), registration);

        // Register a server with fresh heartbeat
        let registration2 = ServerRegistration::new("server2", "localhost", 446, "");
        state.apply(CoordRequest::RegisterServer(registration2));

        // Find stale servers (timeout 15 seconds)
        let stale = state.get_stale_servers(15);

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], "server1");
    }

    #[test]
    fn test_serialization() {
        let mut state = CoordinationState::new();
        let registration = ServerRegistration::new("server1", "localhost", 445, "");
        state.apply(CoordRequest::RegisterServer(registration));
        state.apply(CoordRequest::IncrementEpoch {
            reason: "test".to_string(),
        });

        let bytes = state.to_bytes();
        let restored = CoordinationState::from_bytes(&bytes).unwrap();

        assert_eq!(restored.cache_epoch, state.cache_epoch);
        assert_eq!(restored.servers.len(), state.servers.len());
    }
}
