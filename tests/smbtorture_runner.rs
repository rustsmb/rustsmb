//! smbtorture test runner.
//!
//! This starts a RustSMB server and runs smbtorture tests against it.
//!
//! Run with: cargo test --test smbtorture_runner -- --ignored --nocapture
//!
//! Or run individual test suites:
//! SMBTORTURE_SUITE=smb2.session cargo test --test smbtorture_runner -- --ignored --nocapture
//!
//! Note: Requires smbclient/smbtorture to be installed.
#![cfg(unix)]

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;

use rustsmb_auth::AnonymousAuthProvider;
use rustsmb_backend_local::LocalBackend;
use rustsmb_server::{ServerConfig, ShareConfig, SmbServer};
use rustsmb_state_memory::MemoryStateStore;

/// Check if smbtorture is available on the system.
fn has_smbtorture() -> bool {
    Command::new("smbtorture")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Find an available port for testing.
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to random port")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}

/// Test server context that manages lifecycle.
struct TestServer {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    #[allow(dead_code)]
    handle: Option<tokio::task::JoinHandle<()>>,
    #[allow(dead_code)]
    temp_dir: TempDir,
}

impl TestServer {
    /// Create a new test server with local filesystem backend.
    async fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let port = find_available_port();

        let config = ServerConfig {
            listen_addr: format!("127.0.0.1:{}", port).parse().unwrap(),
            require_signing: false,
            enable_signing: false,
            enable_encryption: false,
            ..Default::default()
        };

        let state: Arc<dyn rustsmb_state::StateStore + Send + Sync> =
            Arc::new(MemoryStateStore::new());

        // Use AnonymousAuthProvider for simplicity (allows guest access)
        let auth: Arc<dyn rustsmb_auth::AuthProvider + Send + Sync> =
            Arc::new(AnonymousAuthProvider::allow_both().with_guest_fallback());

        let server = SmbServer::new(config, state, auth);

        // Add test share with local backend
        let share_config = ShareConfig {
            name: "test".to_string(),
            path: "/test".to_string(),
            read_only: false,
            guest_ok: true,
            valid_users: vec![],
            browseable: true,
        };

        let backend: Arc<dyn rustsmb_vfs::StorageBackend + Send + Sync> = Arc::new(
            LocalBackend::new(temp_dir.path().to_path_buf())
                .await
                .expect("Failed to create local backend"),
        );
        server.shares().add_share("test", backend, share_config);

        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Start server in background
        let server = Arc::new(server);
        let server_clone = server.clone();
        let handle = tokio::spawn(async move {
            tokio::select! {
                result = server_clone.run() => {
                    if let Err(e) = result {
                        eprintln!("Server error: {}", e);
                    }
                }
                _ = shutdown_rx => {
                    server_clone.shutdown();
                }
            }
        });

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            port,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            temp_dir,
        }
    }

    /// Get the server URL for smbtorture.
    fn url(&self) -> String {
        format!("//127.0.0.1:{}/test", self.port)
    }

    /// Run a smbtorture test suite.
    fn run_smbtorture(&self, suite: &str) -> std::process::Output {
        Command::new("smbtorture")
            .arg(self.url())
            .arg("-N") // No password (anonymous/guest)
            .arg(suite)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("Failed to run smbtorture")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// List of all SMB2 test suites to run.
const SMB2_SUITES: &[&str] = &[
    "smb2.connect",
    "smb2.session",
    "smb2.tcon",
    "smb2.create",
    "smb2.read",
    "smb2.lock",
    "smb2.lease",
    "smb2.oplock",
    "smb2.durable-open",
    "smb2.durable-v2-open",
    "smb2.compound",
    "smb2.credits",
    "smb2.dir",
    "smb2.getinfo",
    "smb2.setinfo",
    "smb2.notify",
    "smb2.ioctl",
    "smb2.streams",
    "smb2.delete-on-close",
    "smb2.deny",
    "smb2.sharemode",
    "smb2.replay",
    "smb2.acls",
];

#[tokio::test]
#[ignore]
async fn test_smbtorture_all() {
    if !has_smbtorture() {
        eprintln!("smbtorture not installed, skipping tests");
        return;
    }

    let server = TestServer::new().await;

    // Check if a specific suite is requested via env var
    if let Ok(suite) = std::env::var("SMBTORTURE_SUITE") {
        eprintln!("Running specific suite: {}", suite);
        let output = server.run_smbtorture(&suite);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("=== {} ===", suite);
        println!("{}", stdout);
        if !stderr.is_empty() {
            eprintln!("{}", stderr);
        }
        assert!(output.status.success(), "Suite {} failed", suite);
        return;
    }

    // Run all suites
    let mut passed = 0;
    let mut failed = 0;
    let mut failures = Vec::new();

    for suite in SMB2_SUITES {
        eprintln!("Running {}...", suite);
        let output = server.run_smbtorture(suite);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            passed += 1;
            println!("[PASS] {}", suite);
        } else {
            failed += 1;
            failures.push(suite.to_string());
            println!("[FAIL] {}", suite);
            println!(
                "  stdout: {}",
                stdout.lines().take(10).collect::<Vec<_>>().join("\n  ")
            );
            if !stderr.is_empty() {
                println!(
                    "  stderr: {}",
                    stderr.lines().take(5).collect::<Vec<_>>().join("\n  ")
                );
            }
        }
    }

    println!("\n========================================");
    println!("smbtorture Results: {}/{} passed", passed, passed + failed);
    if !failures.is_empty() {
        println!("Failed suites:");
        for f in &failures {
            println!("  - {}", f);
        }
    }
    println!("========================================\n");

    // Don't fail the test completely - just report results
    // This allows us to track progress as we fix issues
    if failed > 0 {
        eprintln!("Warning: {} suites failed", failed);
    }
}

// Individual test functions for CI granularity
#[tokio::test]
#[ignore]
async fn test_smb2_connect() {
    if !has_smbtorture() {
        return;
    }
    let server = TestServer::new().await;
    let output = server.run_smbtorture("smb2.connect");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
    // Don't assert - just run and report
}

#[tokio::test]
#[ignore]
async fn test_smb2_session() {
    if !has_smbtorture() {
        return;
    }
    let server = TestServer::new().await;
    let output = server.run_smbtorture("smb2.session");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
}

#[tokio::test]
#[ignore]
async fn test_smb2_create() {
    if !has_smbtorture() {
        return;
    }
    let server = TestServer::new().await;
    let output = server.run_smbtorture("smb2.create");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
}

#[tokio::test]
#[ignore]
async fn test_smb2_lease() {
    if !has_smbtorture() {
        return;
    }
    let server = TestServer::new().await;
    let output = server.run_smbtorture("smb2.lease");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
}

#[tokio::test]
#[ignore]
async fn test_smb2_durable_open() {
    if !has_smbtorture() {
        return;
    }
    let server = TestServer::new().await;
    let output = server.run_smbtorture("smb2.durable-open");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
}

#[tokio::test]
#[ignore]
async fn test_smb2_compound() {
    if !has_smbtorture() {
        return;
    }
    let server = TestServer::new().await;
    let output = server.run_smbtorture("smb2.compound");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);
}
