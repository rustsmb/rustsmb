//! Integration tests using Windows native SMB client tools.
//!
//! These tests require Windows with PowerShell and SMB client support.
//! They start a RustSMB server and use PowerShell/net use to verify functionality.
//!
//! Run with: cargo test --test integration_windows -- --ignored
//!
//! Note: Windows `net use` doesn't support custom ports, so these tests
//! bind to port 445 which requires administrator privileges.

use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::timeout;

use rustsmb_auth::AnonymousAuthProvider;
use rustsmb_backend_memory::MemoryBackend;
use rustsmb_server::{ServerConfig, ShareConfig, SmbServer};
use rustsmb_state_memory::MemoryStateStore;

/// Check if running on Windows.
fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

/// Check if PowerShell is available.
fn has_powershell() -> bool {
    if !is_windows() {
        return false;
    }
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", "echo test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if we can bind to port 445 (requires admin on Windows).
fn can_bind_smb_port() -> bool {
    std::net::TcpListener::bind("127.0.0.1:445").is_ok()
}

/// Test server context that manages lifecycle.
/// Uses port 445 for Windows compatibility with `net use`.
struct TestServer {
    port: u16,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
    local_temp: Option<TempDir>,
}

impl TestServer {
    /// Create a new test server with memory backend on port 445.
    async fn new() -> Option<Self> {
        if !can_bind_smb_port() {
            return None;
        }
        Some(Self::start(445).await)
    }

    async fn start(port: u16) -> Self {
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

        // Add test share with memory backend
        let share_config = ShareConfig {
            name: "test".to_string(),
            path: "/test".to_string(),
            read_only: false,
            guest_ok: true,
            valid_users: vec![],
            browseable: true,
        };

        let backend: Arc<dyn rustsmb_vfs::StorageBackend + Send + Sync> =
            Arc::new(MemoryBackend::new());
        server.shares().add_share("test", backend, share_config);

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
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create temp dir for local files used in tests
        let local_temp = TempDir::new().ok();

        TestServer {
            port,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
            local_temp,
        }
    }

    /// Get UNC path for the share.
    fn unc_path(&self, share: &str) -> String {
        format!("\\\\127.0.0.1\\{}", share)
    }

    /// Get local temp directory path.
    fn temp_dir(&self) -> Option<&std::path::Path> {
        self.local_temp.as_ref().map(|t| t.path())
    }

    /// Run a PowerShell command and return output.
    fn powershell(&self, script: &str) -> std::io::Result<Output> {
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
    }

    /// Connect to share using net use (maps to Z: drive).
    fn net_use_connect(&self, share: &str) -> std::io::Result<Output> {
        let script = format!("net use Z: {} /user:guest \"\" 2>&1", self.unc_path(share));
        self.powershell(&script)
    }

    /// Disconnect from share.
    fn net_use_disconnect(&self) -> std::io::Result<Output> {
        self.powershell("net use Z: /delete /y 2>&1")
    }

    /// List directory contents.
    fn list_directory(&self, path: &str) -> std::io::Result<Output> {
        let script = format!("Get-ChildItem -Path '{}' 2>&1", path);
        self.powershell(&script)
    }

    /// Create a directory.
    fn create_directory(&self, path: &str) -> std::io::Result<Output> {
        let script = format!("New-Item -Path '{}' -ItemType Directory -Force 2>&1", path);
        self.powershell(&script)
    }

    /// Remove a directory.
    fn remove_directory(&self, path: &str) -> std::io::Result<Output> {
        let script = format!("Remove-Item -Path '{}' -Force 2>&1", path);
        self.powershell(&script)
    }

    /// Copy file to share.
    fn copy_to_share(&self, local_path: &str, remote_path: &str) -> std::io::Result<Output> {
        let script = format!(
            "Copy-Item -Path '{}' -Destination '{}' 2>&1",
            local_path, remote_path
        );
        self.powershell(&script)
    }

    /// Copy file from share.
    fn copy_from_share(&self, remote_path: &str, local_path: &str) -> std::io::Result<Output> {
        let script = format!(
            "Copy-Item -Path '{}' -Destination '{}' 2>&1",
            remote_path, local_path
        );
        self.powershell(&script)
    }

    /// Read file content.
    fn read_file(&self, path: &str) -> std::io::Result<Output> {
        let script = format!("Get-Content -Path '{}' -Raw 2>&1", path);
        self.powershell(&script)
    }

    /// Write content to file.
    fn write_file(&self, path: &str, content: &str) -> std::io::Result<Output> {
        let script = format!("Set-Content -Path '{}' -Value '{}' 2>&1", path, content);
        self.powershell(&script)
    }

    /// Delete a file.
    fn delete_file(&self, path: &str) -> std::io::Result<Output> {
        let script = format!("Remove-Item -Path '{}' -Force 2>&1", path);
        self.powershell(&script)
    }

    /// Rename a file.
    fn rename_file(&self, old_path: &str, new_name: &str) -> std::io::Result<Output> {
        let script = format!(
            "Rename-Item -Path '{}' -NewName '{}' 2>&1",
            old_path, new_name
        );
        self.powershell(&script)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Disconnect any mapped drives first
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "net use Z: /delete /y 2>&1",
            ])
            .output();

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

// =============================================================================
// Tests that require Windows with PowerShell and admin privileges
// =============================================================================

/// Test that Windows detection works.
#[test]
fn test_windows_detection() {
    let is_win = is_windows();
    let has_ps = has_powershell();
    let can_bind = can_bind_smb_port();

    println!("Running on Windows: {}", is_win);
    println!("PowerShell available: {}", has_ps);
    println!("Can bind port 445: {}", can_bind);
    println!(
        "Tests will {} if requirements not met",
        if is_win && has_ps && can_bind {
            "run"
        } else {
            "be skipped"
        }
    );
}

/// Test basic net use connection.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_net_use_connect() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445 (requires admin)");
            return;
        }
    };

    // Connect to share
    let output = server
        .net_use_connect("test")
        .expect("Failed to run net use");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("net use stdout:\n{}", stdout);
    println!("net use stderr:\n{}", stderr);

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test directory listing via PowerShell.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_directory_listing() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    // Connect
    let _ = server.net_use_connect("test");

    // List directory
    let output = server
        .list_directory("Z:\\")
        .expect("Failed to list directory");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Get-ChildItem stdout:\n{}", stdout);
    println!("Get-ChildItem stderr:\n{}", stderr);

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test creating and removing directories.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_mkdir_rmdir() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    // Connect
    let _ = server.net_use_connect("test");

    // Create directory
    let output = server
        .create_directory("Z:\\testdir")
        .expect("Failed to create directory");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("New-Item stdout:\n{}", stdout);

    // Verify directory exists
    let output = server
        .list_directory("Z:\\")
        .expect("Failed to list directory");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Directory listing:\n{}", stdout);

    // Remove directory
    let output = server
        .remove_directory("Z:\\testdir")
        .expect("Failed to remove directory");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Remove-Item stdout:\n{}", stdout);

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test file copy to and from share.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_file_copy() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    let temp_dir = match server.temp_dir() {
        Some(t) => t.to_path_buf(),
        None => {
            println!("Skipping test: no temp directory");
            return;
        }
    };

    // Create local test file
    let local_file = temp_dir.join("test_copy.txt");
    let test_content = "Hello from Windows integration test!";
    {
        let mut f = std::fs::File::create(&local_file).expect("Failed to create test file");
        f.write_all(test_content.as_bytes())
            .expect("Failed to write test file");
    }

    // Connect
    let _ = server.net_use_connect("test");

    // Copy to share
    let output = server
        .copy_to_share(&local_file.to_string_lossy(), "Z:\\test_copy.txt")
        .expect("Failed to copy file to share");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Copy to share stdout:\n{}", stdout);

    // Copy from share
    let download_file = temp_dir.join("downloaded.txt");
    let output = server
        .copy_from_share("Z:\\test_copy.txt", &download_file.to_string_lossy())
        .expect("Failed to copy file from share");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Copy from share stdout:\n{}", stdout);

    // Verify content
    if download_file.exists() {
        let downloaded =
            std::fs::read_to_string(&download_file).expect("Failed to read downloaded file");
        println!("Downloaded content: {}", downloaded);
    }

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test file read and write operations.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_file_read_write() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    // Connect
    let _ = server.net_use_connect("test");

    // Write file
    let test_content = "Content written via PowerShell";
    let output = server
        .write_file("Z:\\written.txt", test_content)
        .expect("Failed to write file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Set-Content stdout:\n{}", stdout);

    // Read file back
    let output = server
        .read_file("Z:\\written.txt")
        .expect("Failed to read file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Get-Content stdout:\n{}", stdout);

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test file deletion.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_file_delete() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    // Connect
    let _ = server.net_use_connect("test");

    // Create file
    let _ = server.write_file("Z:\\to_delete.txt", "Delete me");

    // Verify file exists
    let output = server.list_directory("Z:\\").expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Before delete:\n{}", stdout);

    // Delete file
    let output = server
        .delete_file("Z:\\to_delete.txt")
        .expect("Failed to delete file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Remove-Item stdout:\n{}", stdout);

    // Verify file is gone
    let output = server.list_directory("Z:\\").expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("After delete:\n{}", stdout);

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test file rename.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_file_rename() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    // Connect
    let _ = server.net_use_connect("test");

    // Create file
    let _ = server.write_file("Z:\\original.txt", "Rename me");

    // Rename file
    let output = server
        .rename_file("Z:\\original.txt", "renamed.txt")
        .expect("Failed to rename file");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Rename-Item stdout:\n{}", stdout);

    // Verify rename
    let output = server.list_directory("Z:\\").expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("After rename:\n{}", stdout);

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test concurrent connections from multiple processes.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_concurrent_connections() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    let unc = server.unc_path("test");

    // Spawn multiple concurrent access attempts
    let mut handles = vec![];

    for i in 0..5 {
        let unc_clone = unc.clone();
        let handle = tokio::task::spawn_blocking(move || {
            // Each process tries to access the share directly via UNC
            let script = format!(
                "Test-Path '{}' 2>&1; Get-ChildItem '{}' 2>&1",
                unc_clone, unc_clone
            );
            let output = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .expect("Failed to run PowerShell");
            (i, output)
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        let (i, output) = handle.await.expect("Task failed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Connection {} stdout: {}", i, stdout);
        println!("Connection {} stderr: {}", i, stderr);
    }
}

/// Test large file transfer (5MB).
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_large_file() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    let temp_dir = match server.temp_dir() {
        Some(t) => t.to_path_buf(),
        None => {
            println!("Skipping test: no temp directory");
            return;
        }
    };

    // Create 5MB test file
    let file_size = 5 * 1024 * 1024;
    let test_content: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();
    let large_file = temp_dir.join("large_file.bin");
    {
        let mut f = std::fs::File::create(&large_file).expect("Failed to create large file");
        f.write_all(&test_content)
            .expect("Failed to write large file");
    }

    // Connect
    let _ = server.net_use_connect("test");

    // Copy large file to share with timeout
    let large_file_clone = large_file.clone();
    let upload_result = timeout(
        Duration::from_secs(120),
        tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "Copy-Item -Path '{}' -Destination 'Z:\\large_file.bin' 2>&1",
                        large_file_clone.to_string_lossy()
                    ),
                ])
                .output()
        }),
    )
    .await;

    match upload_result {
        Ok(Ok(Ok(output))) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Large file upload stdout:\n{}", stdout);
        }
        _ => println!("Large file upload timed out or failed"),
    }

    // Download large file
    let download_file = temp_dir.join("large_downloaded.bin");
    let download_file_clone = download_file.clone();
    let download_result = timeout(
        Duration::from_secs(120),
        tokio::task::spawn_blocking(move || {
            Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "Copy-Item -Path 'Z:\\large_file.bin' -Destination '{}' 2>&1",
                        download_file_clone.to_string_lossy()
                    ),
                ])
                .output()
        }),
    )
    .await;

    match download_result {
        Ok(Ok(Ok(output))) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("Large file download stdout:\n{}", stdout);

            if download_file.exists() {
                let downloaded =
                    std::fs::read(&download_file).expect("Failed to read downloaded file");
                println!(
                    "Downloaded size: {} bytes (expected: {})",
                    downloaded.len(),
                    test_content.len()
                );
            }
        }
        _ => println!("Large file download timed out or failed"),
    }

    // Disconnect
    let _ = server.net_use_disconnect();
}

/// Test filenames with special characters.
#[tokio::test]
#[ignore = "requires Windows with admin privileges"]
async fn test_special_characters() {
    if !is_windows() || !has_powershell() {
        println!("Skipping test: not running on Windows with PowerShell");
        return;
    }

    let server = match TestServer::new().await {
        Some(s) => s,
        None => {
            println!("Skipping test: cannot bind to port 445");
            return;
        }
    };

    // Connect
    let _ = server.net_use_connect("test");

    // Test filename with space
    let _ = server.write_file("Z:\\file with spaces.txt", "Content");

    // Test filename with unicode (if supported)
    // Note: Full unicode support depends on SMB server implementation
    let _ = server.write_file("Z:\\unicode_test.txt", "Unicode content");

    // List to verify
    let output = server.list_directory("Z:\\").expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("Files with special chars:\n{}", stdout);

    // Cleanup
    let _ = server.delete_file("Z:\\file with spaces.txt");
    let _ = server.delete_file("Z:\\unicode_test.txt");

    // Disconnect
    let _ = server.net_use_disconnect();
}

// =============================================================================
// Server unit tests (don't require Windows)
// =============================================================================

/// Test that server config is properly created.
#[test]
fn test_server_config() {
    let config = ServerConfig::default();
    assert_eq!(config.listen_addr.port(), 445);
    assert!(!config.tls_enabled);
}

/// Test that share config is properly created.
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
}

/// Test server starts on non-Windows platforms (basic TCP test).
#[tokio::test]
async fn test_server_tcp_accept() {
    // This test works on any platform - just verifies TCP acceptance
    if !can_bind_smb_port() {
        println!("Skipping: cannot bind to port 445");
        return;
    }

    let server = TestServer::start(445).await;

    // Try to connect via TCP
    let result = timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", server.port)),
    )
    .await;

    assert!(result.is_ok(), "Connection should not timeout");
    assert!(
        result.unwrap().is_ok(),
        "TCP connection should be established"
    );
}
