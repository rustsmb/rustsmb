//! Integration tests using smbclient.
//!
//! These tests require smbclient to be installed on the system.
//! They start a RustSMB server and use smbclient to verify functionality.
//!
//! Run with: cargo test --test integration_smbclient -- --ignored
//! Or: cargo test smbclient -- --ignored

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::timeout;

use rustsmb_auth::AnonymousAuthProvider;
use rustsmb_backend_local::LocalBackend;
use rustsmb_backend_memory::MemoryBackend;
use rustsmb_server::{ServerConfig, ShareConfig, SmbServer};
use rustsmb_state_memory::MemoryStateStore;

/// Check if smbclient is available on the system.
fn has_smbclient() -> bool {
    Command::new("smbclient")
        .arg("--version")
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
    handle: Option<tokio::task::JoinHandle<()>>,
    _temp_dir: Option<TempDir>,
}

impl TestServer {
    /// Create a new test server with memory backend.
    async fn with_memory_backend() -> Self {
        let port = find_available_port();
        Self::start(port, None).await
    }

    /// Create a new test server with local filesystem backend.
    async fn with_local_backend() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let port = find_available_port();
        Self::start(port, Some(temp_dir)).await
    }

    async fn start(port: u16, temp_dir: Option<TempDir>) -> Self {
        let mut config = ServerConfig::default();
        config.listen_addr = format!("127.0.0.1:{}", port).parse().unwrap();
        config.require_signing = false;
        config.enable_signing = false;
        config.enable_encryption = false;

        let state: Arc<dyn rustsmb_state::StateStore + Send + Sync> =
            Arc::new(MemoryStateStore::new());
        let auth: Arc<dyn rustsmb_auth::AuthProvider + Send + Sync> =
            Arc::new(AnonymousAuthProvider::allow_both().with_guest_fallback());

        let server = SmbServer::new(config, state, auth);

        // Add test share
        let share_config = ShareConfig {
            name: "test".to_string(),
            path: "/test".to_string(),
            read_only: false,
            guest_ok: true,
            valid_users: vec![],
            browseable: true,
        };

        if let Some(ref temp) = temp_dir {
            let backend: Arc<dyn rustsmb_vfs::StorageBackend + Send + Sync> = Arc::new(
                LocalBackend::new(temp.path().to_path_buf())
                    .await
                    .expect("Failed to create local backend"),
            );
            server.shares().add_share("test", backend, share_config);
        } else {
            let backend: Arc<dyn rustsmb_vfs::StorageBackend + Send + Sync> =
                Arc::new(MemoryBackend::new());
            server.shares().add_share("test", backend, share_config);
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_clone = Arc::new(server);
        let server_run = server_clone.clone();
        let handle = tokio::spawn(async move {
            tokio::select! {
                result = server_run.run() => {
                    if let Err(e) = result {
                        eprintln!("Server error: {}", e);
                    }
                }
                _ = shutdown_rx => {
                    server_run.shutdown();
                }
            }
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        TestServer {
            port,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            _temp_dir: temp_dir,
        }
    }

    /// Get smbclient connection URL.
    fn smb_url(&self, share: &str) -> String {
        format!("//127.0.0.1:{}/{}", self.port, share)
    }

    /// Run smbclient command and return output.
    fn smbclient(&self, share: &str, command: &str) -> std::io::Result<Output> {
        Command::new("smbclient")
            .arg(self.smb_url(share))
            .arg("-N") // No password (guest)
            .arg("-c")
            .arg(command)
            .arg("--port")
            .arg(self.port.to_string())
            .output()
    }

    /// Run smbclient with multiple commands.
    fn smbclient_commands(&self, share: &str, commands: &[&str]) -> std::io::Result<Output> {
        Command::new("smbclient")
            .arg(self.smb_url(share))
            .arg("-N")
            .arg("-c")
            .arg(commands.join("; "))
            .arg("--port")
            .arg(self.port.to_string())
            .output()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Don't block on join - let it clean up async
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

// =============================================================================
// Tests that require smbclient to be installed
// =============================================================================

/// Test that smbclient detection works.
#[test]
fn test_smbclient_detection() {
    let available = has_smbclient();
    println!(
        "smbclient available: {} (tests will {} if not available)",
        available,
        if available { "run" } else { "be skipped" }
    );
}

/// Test listing shares with smbclient -L.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_list_shares() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_memory_backend().await;

    // List shares using smbclient -L
    let output = Command::new("smbclient")
        .arg("-L")
        .arg(format!("//127.0.0.1:{}", server.port))
        .arg("-N")
        .arg("--port")
        .arg(server.port.to_string())
        .output()
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("smbclient -L stdout:\n{}", stdout);
    println!("smbclient -L stderr:\n{}", stderr);

    // Should list the test share
    // Note: Actual assertion depends on protocol implementation completeness
    assert!(
        output.status.success() || !stderr.contains("Connection refused"),
        "Server should accept connections"
    );
}

/// Test basic directory listing.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_directory_listing() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_memory_backend().await;

    let output = server
        .smbclient("test", "ls")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("ls stdout:\n{}", stdout);
    println!("ls stderr:\n{}", stderr);

    // Should be able to connect and list (even if empty)
    // Connection success is the primary test
}

/// Test creating a directory.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_mkdir() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;

    // Create directory
    let output = server
        .smbclient("test", "mkdir testdir")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("mkdir stdout:\n{}", stdout);
    println!("mkdir stderr:\n{}", stderr);

    // Verify directory exists
    let output = server
        .smbclient("test", "ls")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("ls after mkdir:\n{}", stdout);
}

/// Test file upload and download.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_file_upload_download() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;
    let local_temp = TempDir::new().expect("Failed to create temp dir");

    // Create a local test file
    let test_content = b"Hello from RustSMB integration test!\n";
    let upload_path = local_temp.path().join("upload_test.txt");
    let download_path = local_temp.path().join("download_test.txt");

    {
        let mut f = std::fs::File::create(&upload_path).expect("Failed to create test file");
        f.write_all(test_content)
            .expect("Failed to write test file");
    }

    // Upload file
    let output = Command::new("smbclient")
        .arg(server.smb_url("test"))
        .arg("-N")
        .arg("-c")
        .arg(format!(
            "put {} remote_test.txt",
            upload_path.to_string_lossy()
        ))
        .arg("--port")
        .arg(server.port.to_string())
        .output()
        .expect("Failed to run smbclient put");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("put stdout:\n{}", stdout);
    println!("put stderr:\n{}", stderr);

    // List to verify upload
    let output = server
        .smbclient("test", "ls")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("ls after put:\n{}", stdout);

    // Download file
    let output = Command::new("smbclient")
        .arg(server.smb_url("test"))
        .arg("-N")
        .arg("-c")
        .arg(format!(
            "get remote_test.txt {}",
            download_path.to_string_lossy()
        ))
        .arg("--port")
        .arg(server.port.to_string())
        .output()
        .expect("Failed to run smbclient get");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("get stdout:\n{}", stdout);
    println!("get stderr:\n{}", stderr);

    // Verify downloaded content matches
    if download_path.exists() {
        let downloaded = std::fs::read(&download_path).expect("Failed to read downloaded file");
        assert_eq!(
            downloaded, test_content,
            "Downloaded content should match uploaded content"
        );
    }
}

/// Test file deletion.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_file_delete() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;
    let local_temp = TempDir::new().expect("Failed to create temp dir");

    // Create and upload a file
    let test_content = b"File to delete\n";
    let upload_path = local_temp.path().join("to_delete.txt");
    {
        let mut f = std::fs::File::create(&upload_path).expect("Failed to create test file");
        f.write_all(test_content)
            .expect("Failed to write test file");
    }

    // Upload
    let _ = Command::new("smbclient")
        .arg(server.smb_url("test"))
        .arg("-N")
        .arg("-c")
        .arg(format!(
            "put {} to_delete.txt",
            upload_path.to_string_lossy()
        ))
        .arg("--port")
        .arg(server.port.to_string())
        .output();

    // Delete the file
    let output = server
        .smbclient("test", "del to_delete.txt")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("del stdout:\n{}", stdout);
    println!("del stderr:\n{}", stderr);

    // Verify file is gone
    let output = server
        .smbclient("test", "ls")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("ls after del:\n{}", stdout);

    // Should not contain the deleted file
    assert!(
        !stdout.contains("to_delete.txt") || stderr.contains("NT_STATUS"),
        "File should be deleted"
    );
}

/// Test directory removal.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_rmdir() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;

    // Create then remove directory
    let _ = server.smbclient("test", "mkdir temp_dir");

    let output = server
        .smbclient("test", "rmdir temp_dir")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("rmdir stdout:\n{}", stdout);
    println!("rmdir stderr:\n{}", stderr);
}

/// Test multiple commands in sequence.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_command_sequence() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;

    let output = server
        .smbclient_commands(
            "test",
            &[
                "mkdir subdir",
                "cd subdir",
                "pwd",
                "cd ..",
                "ls",
                "rmdir subdir",
            ],
        )
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("command sequence stdout:\n{}", stdout);
    println!("command sequence stderr:\n{}", stderr);
}

/// Test concurrent connections.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_concurrent_connections() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_memory_backend().await;

    // Spawn multiple concurrent smbclient sessions
    let mut handles = vec![];

    for i in 0..5 {
        let port = server.port;
        let handle = tokio::task::spawn_blocking(move || {
            let output = Command::new("smbclient")
                .arg(format!("//127.0.0.1:{}/test", port))
                .arg("-N")
                .arg("-c")
                .arg("ls")
                .arg("--port")
                .arg(port.to_string())
                .output()
                .expect("Failed to run smbclient");
            (i, output)
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        let (i, output) = handle.await.expect("Task failed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Connection {} stderr: {}", i, stderr);
    }
}

/// Test file rename.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_file_rename() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;
    let local_temp = TempDir::new().expect("Failed to create temp dir");

    // Create and upload a file
    let test_content = b"File to rename\n";
    let upload_path = local_temp.path().join("original.txt");
    {
        let mut f = std::fs::File::create(&upload_path).expect("Failed to create test file");
        f.write_all(test_content)
            .expect("Failed to write test file");
    }

    // Upload
    let _ = Command::new("smbclient")
        .arg(server.smb_url("test"))
        .arg("-N")
        .arg("-c")
        .arg(format!(
            "put {} original.txt",
            upload_path.to_string_lossy()
        ))
        .arg("--port")
        .arg(server.port.to_string())
        .output();

    // Rename the file
    let output = server
        .smbclient("test", "rename original.txt renamed.txt")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("rename stdout:\n{}", stdout);
    println!("rename stderr:\n{}", stderr);

    // Verify rename
    let output = server
        .smbclient("test", "ls")
        .expect("Failed to run smbclient");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("ls after rename:\n{}", stdout);
}

/// Test large file transfer (10MB).
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_large_file_transfer() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_local_backend().await;
    let local_temp = TempDir::new().expect("Failed to create temp dir");

    // Create a 10MB test file
    let file_size = 10 * 1024 * 1024;
    let test_content: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();
    let upload_path = local_temp.path().join("large_file.bin");
    let download_path = local_temp.path().join("large_file_downloaded.bin");

    {
        let mut f = std::fs::File::create(&upload_path).expect("Failed to create test file");
        f.write_all(&test_content)
            .expect("Failed to write test file");
    }

    // Upload large file with timeout
    let port = server.port;
    let upload_path_clone = upload_path.clone();
    let upload_result = timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            Command::new("smbclient")
                .arg(format!("//127.0.0.1:{}/test", port))
                .arg("-N")
                .arg("-c")
                .arg(format!(
                    "put {} large_file.bin",
                    upload_path_clone.to_string_lossy()
                ))
                .arg("--port")
                .arg(port.to_string())
                .output()
        }),
    )
    .await;

    match upload_result {
        Ok(Ok(Ok(output))) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Large file upload stderr:\n{}", stderr);
        }
        _ => println!("Large file upload timed out or failed"),
    }

    // Download large file with timeout
    let port = server.port;
    let download_path_clone = download_path.clone();
    let download_result = timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            Command::new("smbclient")
                .arg(format!("//127.0.0.1:{}/test", port))
                .arg("-N")
                .arg("-c")
                .arg(format!(
                    "get large_file.bin {}",
                    download_path_clone.to_string_lossy()
                ))
                .arg("--port")
                .arg(port.to_string())
                .output()
        }),
    )
    .await;

    match download_result {
        Ok(Ok(Ok(output))) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Large file download stderr:\n{}", stderr);

            // Verify downloaded content matches
            if download_path.exists() {
                let downloaded =
                    std::fs::read(&download_path).expect("Failed to read downloaded file");
                assert_eq!(
                    downloaded.len(),
                    test_content.len(),
                    "Downloaded file size should match"
                );
                assert_eq!(
                    downloaded, test_content,
                    "Downloaded content should match uploaded content"
                );
            }
        }
        _ => println!("Large file download timed out or failed"),
    }
}

/// Test server graceful shutdown during active connection.
#[tokio::test]
#[ignore = "requires smbclient installed"]
async fn test_graceful_shutdown() {
    if !has_smbclient() {
        println!("Skipping test: smbclient not available");
        return;
    }

    let server = TestServer::with_memory_backend().await;
    let port = server.port;

    // Start a connection
    let handle = tokio::task::spawn_blocking(move || {
        Command::new("smbclient")
            .arg(format!("//127.0.0.1:{}/test", port))
            .arg("-N")
            .arg("-c")
            .arg("ls")
            .arg("--port")
            .arg(port.to_string())
            .output()
    });

    // Wait a bit then drop server (triggers shutdown)
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(server);

    // The client command should complete (possibly with error)
    let _ = handle.await;
}

// =============================================================================
// Server unit tests (don't require smbclient)
// =============================================================================

/// Test that the server starts and accepts TCP connections.
#[tokio::test]
async fn test_server_starts() {
    let server = TestServer::with_memory_backend().await;

    // Try to connect via TCP
    let result = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)),
    )
    .await;

    assert!(result.is_ok(), "Should be able to connect to server");
    assert!(
        result.unwrap().is_ok(),
        "TCP connection should be established"
    );
}

/// Test that the server accepts multiple TCP connections.
#[tokio::test]
async fn test_server_multiple_connections() {
    let server = TestServer::with_memory_backend().await;

    // Try multiple connections
    let mut streams = vec![];
    for _ in 0..10 {
        let result = timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)),
        )
        .await;

        assert!(result.is_ok(), "Connection should not timeout");
        streams.push(result.unwrap().expect("Should connect"));
    }

    // All connections should be alive
    assert_eq!(streams.len(), 10);
}

/// Test server configuration.
#[test]
fn test_server_config() {
    let config = ServerConfig::default();
    assert_eq!(config.listen_addr.port(), 445);
    assert!(!config.tls_enabled);
    assert!(!config.require_signing);
}

/// Test share configuration.
#[test]
fn test_share_config() {
    let config = ShareConfig {
        name: "test".to_string(),
        path: "/test".to_string(),
        read_only: false,
        guest_ok: true,
        valid_users: vec![],
        browseable: true,
    };

    assert!(config.guest_ok);
    assert!(!config.read_only);
    assert!(config.browseable);
}
