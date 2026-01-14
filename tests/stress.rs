//! Stress tests for RustSMB.
//!
//! These tests verify system behavior under load:
//! - Concurrent connections
//! - Large file operations
//! - Memory pressure
//! - Connection cleanup
//!
//! Run with: cargo test --test stress --release
//!
//! Note: Some tests are marked #[ignore] as they may take a long time
//! or require significant resources. Run them explicitly with:
//! cargo test --test stress --release -- --ignored

use rustsmb_backend_local::LocalBackend;
use rustsmb_backend_memory::MemoryBackend;
use rustsmb_state_memory::MemoryStateStore;
use rustsmb_vfs::{access_mask, disposition, CreateParams, StorageBackend};
use std::sync::Arc;
use std::time::Instant;

/// Helper to create a CreateParams for read+write+create
fn create_params_rw_create() -> CreateParams {
    CreateParams {
        desired_access: access_mask::GENERIC_READ | access_mask::GENERIC_WRITE,
        share_access: 0,
        create_disposition: disposition::OPEN_IF,
        create_options: 0,
        file_attributes: 0,
    }
}

/// Helper to create a CreateParams for read-only
fn create_params_read() -> CreateParams {
    CreateParams {
        desired_access: access_mask::GENERIC_READ,
        share_access: 0,
        create_disposition: disposition::OPEN,
        create_options: 0,
        file_attributes: 0,
    }
}
use tempfile::TempDir;
use tokio::sync::Barrier;

// ============================================================================
// Concurrent Connection Tests
// ============================================================================

mod concurrent_connections {
    use super::*;

    #[tokio::test]
    async fn test_100_concurrent_operations() {
        let backend = Arc::new(MemoryBackend::new());
        let barrier = Arc::new(Barrier::new(100));
        let mut handles = vec![];

        // Spawn 100 concurrent tasks
        for i in 0..100 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                barrier.wait().await;

                let filename = format!("file_{}.txt", i);
                let content = format!("Content for file {}", i);

                // Create file
                let handle = backend
                    .open(&filename, &create_params_rw_create())
                    .await
                    .expect("Failed to create file");

                // Write content
                let written = backend
                    .write(&handle, 0, content.as_bytes())
                    .await
                    .expect("Failed to write");
                assert_eq!(written as usize, content.len());

                // Close and reopen
                backend.close(handle).await.expect("Failed to close");

                let handle = backend
                    .open(&filename, &create_params_read())
                    .await
                    .expect("Failed to reopen");

                // Read back
                let data = backend
                    .read(&handle, 0, content.len() as u32)
                    .await
                    .expect("Failed to read");
                assert_eq!(data, content.as_bytes());

                backend.close(handle).await.expect("Failed to close");
            }));
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.expect("Task panicked");
        }
    }

    #[tokio::test]
    async fn test_concurrent_read_same_file() {
        let backend = Arc::new(MemoryBackend::new());
        let content = "Shared content for reading";

        // Create shared file
        let handle = backend
            .open("shared.txt", &create_params_rw_create())
            .await
            .unwrap();
        backend.write(&handle, 0, content.as_bytes()).await.unwrap();
        backend.close(handle).await.unwrap();

        let barrier = Arc::new(Barrier::new(50));
        let mut handles = vec![];

        // Spawn 50 concurrent readers
        for _ in 0..50 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                barrier.wait().await;

                let handle = backend
                    .open("shared.txt", &create_params_read())
                    .await
                    .expect("Failed to open");

                for _ in 0..100 {
                    let data = backend
                        .read(&handle, 0, content.len() as u32)
                        .await
                        .expect("Failed to read");
                    assert_eq!(data.len(), content.len());
                }

                backend.close(handle).await.expect("Failed to close");
            }));
        }

        for handle in handles {
            handle.await.expect("Task panicked");
        }
    }

    #[tokio::test]
    async fn test_concurrent_write_different_files() {
        let backend = Arc::new(MemoryBackend::new());
        let barrier = Arc::new(Barrier::new(50));
        let mut handles = vec![];

        // Spawn 50 concurrent writers to different files
        for i in 0..50 {
            let backend = Arc::clone(&backend);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                barrier.wait().await;

                let filename = format!("writer_{}.txt", i);
                let handle = backend
                    .open(&filename, &create_params_rw_create())
                    .await
                    .expect("Failed to create");

                // Write 1MB of data
                let data = vec![b'A'; 1024 * 1024];
                let written = backend
                    .write(&handle, 0, &data)
                    .await
                    .expect("Failed to write");
                assert_eq!(written, 1024 * 1024);

                backend.close(handle).await.expect("Failed to close");

                // Verify
                let meta = backend.stat(&filename).await.expect("Failed to stat");
                assert_eq!(meta.size, 1024 * 1024);
            }));
        }

        for handle in handles {
            handle.await.expect("Task panicked");
        }
    }
}

// ============================================================================
// Large File Tests
// ============================================================================

mod large_files {
    use super::*;

    #[tokio::test]
    async fn test_100mb_file() {
        let backend = MemoryBackend::new();
        let size = 100 * 1024 * 1024; // 100 MB

        let handle = backend
            .open("large.bin", &create_params_rw_create())
            .await
            .unwrap();

        // Write in 1MB chunks
        let chunk = vec![0xABu8; 1024 * 1024];
        for offset in (0..size).step_by(1024 * 1024) {
            backend
                .write(&handle, offset as u64, &chunk)
                .await
                .expect("Write failed");
        }

        backend.close(handle).await.unwrap();

        // Verify size
        let meta = backend.stat("large.bin").await.unwrap();
        assert_eq!(meta.size, size as u64);
    }

    #[tokio::test]
    #[ignore = "Requires significant memory - run with --ignored"]
    async fn test_1gb_file() {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalBackend::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();
        let size: u64 = 1024 * 1024 * 1024; // 1 GB

        let handle = backend
            .open("huge.bin", &create_params_rw_create())
            .await
            .unwrap();

        // Write in 4MB chunks
        let chunk = vec![0xCDu8; 4 * 1024 * 1024];
        let start = Instant::now();

        for offset in (0..size).step_by(4 * 1024 * 1024) {
            backend
                .write(&handle, offset, &chunk)
                .await
                .expect("Write failed");
        }

        let write_time = start.elapsed();
        println!("1GB write time: {:?}", write_time);

        backend.close(handle).await.unwrap();

        // Verify size
        let meta = backend.stat("huge.bin").await.unwrap();
        assert_eq!(meta.size, size);

        // Read back and verify
        let handle = backend
            .open("huge.bin", &create_params_read())
            .await
            .unwrap();

        let start = Instant::now();
        let mut total_read = 0u64;

        while total_read < size {
            let data = backend
                .read(&handle, total_read, 4 * 1024 * 1024)
                .await
                .expect("Read failed");
            total_read += data.len() as u64;
        }

        let read_time = start.elapsed();
        println!("1GB read time: {:?}", read_time);

        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_sparse_file_pattern() {
        let backend = MemoryBackend::new();

        let handle = backend
            .open("sparse.bin", &create_params_rw_create())
            .await
            .unwrap();

        // Write at sparse offsets
        let data = b"MARKER";
        for offset in [0, 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024u64] {
            backend.write(&handle, offset, data).await.unwrap();
        }

        backend.close(handle).await.unwrap();

        // Verify reads at those offsets
        let handle = backend
            .open("sparse.bin", &create_params_read())
            .await
            .unwrap();

        for offset in [0, 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024u64] {
            let read_data = backend.read(&handle, offset, 6).await.unwrap();
            assert_eq!(&read_data, data);
        }

        backend.close(handle).await.unwrap();
    }
}

// ============================================================================
// State Store Stress Tests
// ============================================================================

mod state_store_stress {
    use super::*;
    use rustsmb_core::SmbDialect;
    use rustsmb_state::StateStore;
    use rustsmb_state::{SessionState, TreeState};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn test_many_sessions() {
        let store = MemoryStateStore::new();

        // Create 1000 sessions
        let start = Instant::now();
        for i in 0..1000u64 {
            let now = now_secs();
            let session = SessionState {
                session_id: i,
                user_id: format!("user_{}", i),
                domain: Some("DOMAIN".to_string()),
                session_key: vec![(i % 256) as u8; 16],
                dialect: SmbDialect::default(),
                signing_required: true,
                encryption_required: false,
                is_guest: false,
                is_anonymous: false,
                created_at: now,
                last_access: now,
                expires_at: now + 3600,
                bound_server_id: None,
            };
            StateStore::create_session(&store, &session)
                .await
                .expect("Create failed");
        }
        let create_time = start.elapsed();
        println!("1000 sessions created in {:?}", create_time);

        // Lookup all sessions
        let start = Instant::now();
        for i in 0..1000u64 {
            StateStore::get_session(&store, i)
                .await
                .expect("Get failed");
        }
        let lookup_time = start.elapsed();
        println!("1000 session lookups in {:?}", lookup_time);

        // Delete all sessions
        let start = Instant::now();
        for i in 0..1000u64 {
            StateStore::delete_session(&store, i)
                .await
                .expect("Delete failed");
        }
        let delete_time = start.elapsed();
        println!("1000 sessions deleted in {:?}", delete_time);
    }

    #[tokio::test]
    async fn test_session_tree_operations() {
        let store = MemoryStateStore::new();
        let now = now_secs();

        // Create session
        let session = SessionState {
            session_id: 1,
            user_id: "testuser".to_string(),
            domain: Some("DOMAIN".to_string()),
            session_key: vec![0x42; 16],
            dialect: SmbDialect::default(),
            signing_required: true,
            encryption_required: false,
            is_guest: false,
            is_anonymous: false,
            created_at: now,
            last_access: now,
            expires_at: now + 3600,
            bound_server_id: None,
        };
        StateStore::create_session(&store, &session)
            .await
            .expect("Create session failed");

        // Create 100 tree connections
        for t in 0..100 {
            let tree = TreeState {
                tree_id: t,
                session_id: 1,
                share_name: format!("share_{}", t),
                share_path: format!("/shares/share_{}", t),
                access_flags: 0x001F01FF,
                is_dfs: false,
                created_at: now,
            };
            StateStore::create_tree(&store, &tree)
                .await
                .expect("Create tree failed");
        }

        // List trees
        let trees = StateStore::get_trees_by_session(&store, 1)
            .await
            .expect("Get trees failed");
        assert_eq!(trees.len(), 100);

        // Delete session
        StateStore::delete_session(&store, 1)
            .await
            .expect("Delete failed");
    }
}

// ============================================================================
// Throughput Tests
// ============================================================================

mod throughput {
    use super::*;

    #[tokio::test]
    async fn test_sequential_write_throughput() {
        let backend = MemoryBackend::new();
        let handle = backend
            .open("throughput.bin", &create_params_rw_create())
            .await
            .unwrap();

        let chunk_size = 64 * 1024; // 64KB chunks
        let total_size = 100 * 1024 * 1024; // 100MB
        let chunk = vec![0xAAu8; chunk_size];

        let start = Instant::now();
        let mut offset = 0u64;

        while offset < total_size as u64 {
            backend.write(&handle, offset, &chunk).await.unwrap();
            offset += chunk_size as u64;
        }

        let elapsed = start.elapsed();
        let throughput = total_size as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        println!(
            "Sequential write: {:.2} MB/s ({} MB in {:?})",
            throughput,
            total_size / 1024 / 1024,
            elapsed
        );

        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_sequential_read_throughput() {
        let backend = MemoryBackend::new();
        let total_size = 100 * 1024 * 1024;

        // Setup: create file
        let handle = backend
            .open("throughput.bin", &create_params_rw_create())
            .await
            .unwrap();
        let chunk = vec![0xAAu8; 64 * 1024];
        for offset in (0..total_size).step_by(64 * 1024) {
            backend.write(&handle, offset as u64, &chunk).await.unwrap();
        }
        backend.close(handle).await.unwrap();

        // Test read
        let handle = backend
            .open("throughput.bin", &create_params_read())
            .await
            .unwrap();

        let start = Instant::now();
        let mut offset = 0u64;

        while offset < total_size as u64 {
            let data = backend.read(&handle, offset, 64 * 1024).await.unwrap();
            offset += data.len() as u64;
        }

        let elapsed = start.elapsed();
        let throughput = total_size as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        println!(
            "Sequential read: {:.2} MB/s ({} MB in {:?})",
            throughput,
            total_size / 1024 / 1024,
            elapsed
        );

        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_parallel_io_throughput() {
        let backend: Arc<MemoryBackend> = Arc::new(MemoryBackend::new());
        let num_files = 10;
        let file_size = 10 * 1024 * 1024; // 10MB per file

        // Create files in parallel
        let start = Instant::now();
        let mut handles = vec![];

        for i in 0..num_files {
            let backend: Arc<MemoryBackend> = Arc::clone(&backend);
            handles.push(tokio::spawn(async move {
                let handle = backend
                    .open(&format!("file_{}.bin", i), &create_params_rw_create())
                    .await
                    .unwrap();

                let chunk = vec![i as u8; 64 * 1024];
                for offset in (0..file_size).step_by(64 * 1024) {
                    backend.write(&handle, offset as u64, &chunk).await.unwrap();
                }

                backend.close(handle).await.unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let elapsed = start.elapsed();
        let total_bytes = num_files * file_size;
        let throughput = total_bytes as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        println!(
            "Parallel write ({} files): {:.2} MB/s ({} MB in {:?})",
            num_files,
            throughput,
            total_bytes / 1024 / 1024,
            elapsed
        );
    }
}

// ============================================================================
// Memory Pressure Tests
// ============================================================================

mod memory_pressure {
    use super::*;

    #[tokio::test]
    async fn test_many_small_files() {
        let backend = MemoryBackend::new();

        // Create 10,000 small files
        let start = Instant::now();
        for i in 0..10000 {
            let handle = backend
                .open(&format!("small_{}.txt", i), &create_params_rw_create())
                .await
                .expect("Create failed");
            backend
                .write(&handle, 0, b"small content")
                .await
                .expect("Write failed");
            backend.close(handle).await.expect("Close failed");
        }
        let elapsed = start.elapsed();
        println!("Created 10,000 files in {:?}", elapsed);

        // List root directory
        let start = Instant::now();
        let entries = backend.readdir("").await.expect("Readdir failed");
        assert_eq!(entries.len(), 10000);
        let elapsed = start.elapsed();
        println!("Listed 10,000 files in {:?}", elapsed);
    }

    #[tokio::test]
    async fn test_deep_directory_tree() {
        let backend = MemoryBackend::new();

        // Create deep directory structure
        let mut path = String::new();
        for i in 0..100 {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(&format!("dir_{}", i));
            backend.mkdir(&path, 0o755).await.expect("Mkdir failed");
        }

        // Traverse the entire tree
        let start = Instant::now();
        let mut current = String::new();
        for i in 0..100 {
            if !current.is_empty() {
                current.push('/');
            }
            current.push_str(&format!("dir_{}", i));
            let meta = backend.stat(&current).await.expect("Stat failed");
            assert!(meta.file_type == rustsmb_vfs::FileType::Directory);
        }
        let elapsed = start.elapsed();
        println!("Traversed 100-deep directory in {:?}", elapsed);
    }
}
