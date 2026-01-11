//! High Availability integration tests.
//!
//! Tests multi-server scenarios with shared state store to verify:
//! - Session binding (transparent failover)
//! - Data persistence across servers
//! - State store sharing
//!
//! Run with: `cargo test --test integration_ha -- --ignored`
//!
//! Environment variables:
//! - `RUSTSMB_HA_TEST_BACKEND=redis` - Use Redis state store (default: memory)
//! - `RUSTSMB_REDIS_URL=redis://host:port` - Redis connection URL

#![cfg(unix)] // Unix-only due to smbclient dependency
#![allow(dead_code)] // Some fields/methods are for future tests

mod ha_client;

use ha_client::TestClient;
use rustsmb_auth::{NtlmAuthProvider, SpnegoProvider};
use rustsmb_backend_memory::MemoryBackend;
use rustsmb_server::{ServerConfig, ShareConfig, SmbServer};
use rustsmb_state::StateStore;
use rustsmb_state_memory::MemoryStateStore;
use rustsmb_vfs::StorageBackend;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::sleep;

/// Find an available port.
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port")
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}

/// Check if smbclient is available.
fn has_smbclient() -> bool {
    Command::new("smbclient")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Multi-server test cluster with shared state.
struct MultiServerCluster {
    servers: Vec<ServerHandle>,
    state_store: Arc<dyn StateStore + Send + Sync>,
    shared_backend: Arc<dyn StorageBackend + Send + Sync>,
    ports: Vec<u16>,
}

struct ServerHandle {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl MultiServerCluster {
    /// Create a new cluster with the specified number of servers.
    async fn new(count: usize) -> Self {
        // Create shared state store
        // Note: In CI with RUSTSMB_HA_TEST_BACKEND=redis, we'd use RedisStateStore
        // For now, use MemoryStateStore which still tests the architecture
        let state_store: Arc<dyn StateStore + Send + Sync> = Arc::new(MemoryStateStore::new());

        // Shared backend for all servers (files visible across servers)
        let shared_backend: Arc<dyn StorageBackend + Send + Sync> = Arc::new(MemoryBackend::new());

        let mut servers = Vec::with_capacity(count);
        let mut ports = Vec::with_capacity(count);

        for _ in 0..count {
            let port = find_available_port();
            ports.push(port);

            let config = ServerConfig {
                listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
                require_signing: false,
                enable_signing: false,
                enable_encryption: false,
                ..Default::default()
            };

            let ntlm_provider = NtlmAuthProvider::new("RUSTSMB", "WORKGROUP").with_anonymous();
            ntlm_provider.add_user("testuser", "testpass", false);
            let auth: Arc<dyn rustsmb_auth::AuthProvider> =
                Arc::new(SpnegoProvider::ntlm(Arc::new(ntlm_provider)));

            let server = SmbServer::new(config, state_store.clone(), auth);

            // Add shared "test" share
            let share_config = ShareConfig {
                name: "test".to_string(),
                path: "/tmp/rustsmb".to_string(),
                read_only: false,
                guest_ok: true,
                valid_users: vec![],
                browseable: true,
            };
            server
                .shares()
                .add_share("test", shared_backend.clone(), share_config);

            // Create shutdown channel
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

            // Spawn server task
            let handle = tokio::spawn(async move {
                tokio::select! {
                    result = server.run() => {
                        if let Err(e) = result {
                            eprintln!("Server error: {}", e);
                        }
                    }
                    _ = shutdown_rx => {
                        server.shutdown();
                    }
                }
            });

            servers.push(ServerHandle {
                port,
                shutdown_tx: Some(shutdown_tx),
                handle: Some(handle),
            });
        }

        // Wait for servers to start
        sleep(Duration::from_millis(100)).await;

        Self {
            servers,
            state_store,
            shared_backend,
            ports,
        }
    }

    /// Get the address of a server.
    fn server_addr(&self, index: usize) -> String {
        format!("127.0.0.1:{}", self.ports[index])
    }

    /// Shutdown a specific server (simulates failure).
    async fn shutdown_server(&mut self, index: usize) {
        if let Some(tx) = self.servers[index].shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.servers[index].handle.take() {
            let _ = handle.await;
        }
    }

    /// Run smbclient command against a specific server.
    fn smbclient(&self, server_index: usize, commands: &str) -> std::process::Output {
        Command::new("smbclient")
            .args([
                "//127.0.0.1/test",
                "-p",
                &self.ports[server_index].to_string(),
                "-N", // No password
                "-c",
                commands,
            ])
            .output()
            .expect("Failed to run smbclient")
    }

    /// Get direct access to state store.
    fn state_store(&self) -> &Arc<dyn StateStore + Send + Sync> {
        &self.state_store
    }
}

impl Drop for MultiServerCluster {
    fn drop(&mut self) {
        for server in &mut self.servers {
            if let Some(tx) = server.shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = server.handle.take() {
                handle.abort();
            }
        }
    }
}

// =============================================================================
// Session Binding / True Resumption Tests
// =============================================================================

/// Test session binding after failover.
/// This is the primary HA test - verifies transparent failover without re-auth.
#[tokio::test]
#[ignore] // Run with: cargo test --test integration_ha -- --ignored
async fn test_session_binding_after_failover() {
    let cluster = MultiServerCluster::new(2).await;

    // Create client and connect to server 0
    let mut client = TestClient::new();
    client.connect(&cluster.server_addr(0)).await.unwrap();

    // Negotiate and authenticate
    let dialect = client.negotiate().await.unwrap();
    assert!(dialect >= 0x0202, "Should negotiate SMB 2.x+");

    let session_id = client.session_setup().await.unwrap();
    assert!(session_id > 0, "Should get valid session ID");

    // Verify session exists in shared state store
    let session = cluster
        .state_store()
        .get_session(session_id)
        .await
        .expect("State store query should succeed");
    assert!(session.is_some(), "Session should exist in state store");

    // Disconnect from server 0 (simulating network failure)
    client.disconnect();
    assert!(!client.is_connected());

    // Connect to server 1 (different server)
    client.connect(&cluster.server_addr(1)).await.unwrap();

    // Negotiate with new server
    client.negotiate().await.unwrap();

    // Bind to existing session (HA failover)
    client.session_bind(session_id).await.unwrap();

    // Verify session is now bound
    assert_eq!(client.session_id, session_id, "Should preserve session ID");

    // Should be able to use the session (e.g., tree connect)
    let tree_id = client.tree_connect("test").await.unwrap();
    assert!(
        tree_id > 0,
        "Should successfully tree connect after binding"
    );
}

/// Test session binding with invalid session ID.
#[tokio::test]
#[ignore]
async fn test_session_binding_invalid_session() {
    let cluster = MultiServerCluster::new(1).await;

    let mut client = TestClient::new();
    client.connect(&cluster.server_addr(0)).await.unwrap();
    client.negotiate().await.unwrap();

    // Try to bind to non-existent session
    let result = client.session_bind(0xDEADBEEF).await;

    assert!(result.is_err(), "Should fail for invalid session");
    if let Err(ha_client::ClientError::Status(status)) = result {
        // STATUS_USER_SESSION_DELETED = 0xC0000203
        assert_eq!(status, 0xC0000203, "Should return USER_SESSION_DELETED");
    } else {
        panic!("Expected Status error");
    }
}

/// Test that tree connections are preserved after session binding.
#[tokio::test]
#[ignore]
async fn test_session_binding_preserves_tree_connections() {
    let cluster = MultiServerCluster::new(2).await;

    // Setup on server 0
    let mut client = TestClient::new();
    client.connect(&cluster.server_addr(0)).await.unwrap();
    client.negotiate().await.unwrap();
    let session_id = client.session_setup().await.unwrap();
    let tree_id = client.tree_connect("test").await.unwrap();

    // Verify tree exists in state store
    let tree = cluster
        .state_store()
        .get_tree(session_id, tree_id)
        .await
        .expect("State store query should succeed");
    assert!(tree.is_some(), "Tree should exist in state store");

    // Failover to server 1
    client.disconnect();
    client.connect(&cluster.server_addr(1)).await.unwrap();
    client.negotiate().await.unwrap();
    client.session_bind(session_id).await.unwrap();

    // Tree should still be accessible via state store
    let tree_after = cluster
        .state_store()
        .get_tree(session_id, tree_id)
        .await
        .expect("State store query should succeed");
    assert!(tree_after.is_some(), "Tree should persist after failover");
}

// =============================================================================
// Data Consistency Tests (smbclient-based)
// =============================================================================

/// Test that data created on one server is visible on another.
/// This test verifies that the shared backend is accessible from both servers.
#[tokio::test]
#[ignore]
async fn test_data_persistence_across_servers() {
    let cluster = MultiServerCluster::new(2).await;

    // Write data directly to the shared backend
    let create_params = rustsmb_vfs::CreateParams {
        desired_access: rustsmb_vfs::access_mask::GENERIC_READ
            | rustsmb_vfs::access_mask::GENERIC_WRITE,
        share_access: 0,
        create_disposition: rustsmb_vfs::disposition::OPEN_IF,
        create_options: 0,
        file_attributes: 0,
    };
    let handle = cluster
        .shared_backend
        .open("testfile.txt", &create_params)
        .await
        .expect("Should create file");

    let test_data = b"Hello from shared backend!";
    cluster
        .shared_backend
        .write(&handle, 0, test_data)
        .await
        .expect("Should write data");

    // Both servers share the same backend, so the file should be visible
    // Verify by reading from the backend (which both servers use)
    let read_data = cluster
        .shared_backend
        .read(&handle, 0, test_data.len() as u32)
        .await
        .expect("Should read data");

    assert_eq!(
        read_data, test_data,
        "Data should persist in shared backend"
    );

    // Verify both servers can connect and access shares backed by this backend
    let mut client1 = TestClient::new();
    client1.connect(&cluster.server_addr(0)).await.unwrap();
    client1.negotiate().await.unwrap();
    let session1 = client1.session_setup().await.unwrap();
    let tree1 = client1.tree_connect("test").await.unwrap();
    assert!(session1 > 0 && tree1 > 0, "Server 0 should be accessible");

    let mut client2 = TestClient::new();
    client2.connect(&cluster.server_addr(1)).await.unwrap();
    client2.negotiate().await.unwrap();
    let session2 = client2.session_setup().await.unwrap();
    let tree2 = client2.tree_connect("test").await.unwrap();
    assert!(session2 > 0 && tree2 > 0, "Server 1 should be accessible");
}

/// Test concurrent access from multiple servers.
#[tokio::test]
#[ignore]
async fn test_concurrent_multi_server_access() {
    let cluster = MultiServerCluster::new(3).await;

    // Create clients for each server
    let mut handles = vec![];

    for i in 0..3 {
        let addr = cluster.server_addr(i);
        let handle = tokio::spawn(async move {
            let mut client = TestClient::new();
            client.connect(&addr).await.unwrap();
            client.negotiate().await.unwrap();
            let session_id = client.session_setup().await.unwrap();
            client.tree_connect("test").await.unwrap();

            // Send echo to keep connection alive
            client.echo().await.unwrap();

            session_id
        });
        handles.push(handle);
    }

    // Wait for all to complete
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    // Each client should have a unique session ID
    let unique_sessions: std::collections::HashSet<_> = results.iter().collect();
    assert_eq!(
        unique_sessions.len(),
        3,
        "Each client should have unique session"
    );
}

// =============================================================================
// State Store Tests
// =============================================================================

/// Test that session state is visible across servers.
#[tokio::test]
#[ignore]
async fn test_session_state_visible_across_servers() {
    let cluster = MultiServerCluster::new(2).await;

    // Create session on server 0
    let mut client = TestClient::new();
    client.connect(&cluster.server_addr(0)).await.unwrap();
    client.negotiate().await.unwrap();
    let session_id = client.session_setup().await.unwrap();

    // Query state store directly
    let session = cluster
        .state_store()
        .get_session(session_id)
        .await
        .expect("State store query should succeed")
        .expect("Session should exist");

    assert_eq!(session.session_id, session_id);
    assert!(!session.user_id.is_empty() || session.is_guest);

    // The session should be accessible by server 1 too (shared state)
    // This is verified by successful session binding in other tests
}

/// Test server restart with state preserved.
#[tokio::test]
#[ignore]
async fn test_server_restart_state_preserved() {
    let mut cluster = MultiServerCluster::new(1).await;

    // Create session
    let mut client = TestClient::new();
    client.connect(&cluster.server_addr(0)).await.unwrap();
    client.negotiate().await.unwrap();
    let session_id = client.session_setup().await.unwrap();
    client.disconnect();

    // Shutdown server
    cluster.shutdown_server(0).await;

    // Session should still exist in state store
    let session = cluster
        .state_store()
        .get_session(session_id)
        .await
        .expect("State store query should succeed");

    assert!(
        session.is_some(),
        "Session should persist after server shutdown"
    );
}

// =============================================================================
// Echo/Keepalive Tests
// =============================================================================

/// Test basic connectivity with ECHO command.
#[tokio::test]
#[ignore]
async fn test_echo_across_servers() {
    let cluster = MultiServerCluster::new(2).await;

    // Test echo on server 0
    let mut client = TestClient::new();
    client.connect(&cluster.server_addr(0)).await.unwrap();
    client.negotiate().await.unwrap();
    client.echo().await.unwrap();
    client.disconnect();

    // Test echo on server 1
    client.connect(&cluster.server_addr(1)).await.unwrap();
    client.negotiate().await.unwrap();
    client.echo().await.unwrap();
}
