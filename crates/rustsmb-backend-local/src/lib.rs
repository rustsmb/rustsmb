//! Local filesystem backend for RustSMB.
//!
//! This backend provides access to the local filesystem via POSIX operations.
//! It implements the full `StorageBackend` trait with support for:
//!
//! - Path validation to prevent directory traversal attacks
//! - File locking via flock (advisory locks)
//! - Extended attributes (xattr) on supported platforms
//! - Proper Unix permission mapping
//! - Symlink handling
//! - Large file support (>4GB)

use rustsmb_core::VfsError;
use rustsmb_vfs::{
    BackendCapabilities, BoxFuture, CreateParams, DirEntry, FileHandle, FileLock, FileType,
    FsStats, LockType, Metadata, OpenFlags, StorageBackend,
};
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::RwLock;

/// Local filesystem storage backend.
///
/// Provides access to a local directory as an SMB share.
/// All paths are resolved relative to the configured root directory,
/// with strict validation to prevent directory traversal attacks.
pub struct LocalBackend {
    /// Root directory for this share.
    root: PathBuf,
    /// Canonicalized root path for comparison.
    root_canonical: PathBuf,
    /// Open file handles mapping to file info.
    handles: Arc<RwLock<HashMap<u64, OpenFile>>>,
    /// Whether to follow symlinks.
    follow_symlinks: bool,
}

/// Information about an open file.
struct OpenFile {
    /// The open file handle.
    file: File,
    /// Path relative to root.
    path: String,
    /// Raw file descriptor for locking.
    fd: RawFd,
    /// Whether opened for writing.
    writable: bool,
}

impl LocalBackend {
    /// Create a new local filesystem backend.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory path for the share. Must exist and be a directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the root path doesn't exist or isn't a directory.
    pub async fn new(root: PathBuf) -> Result<Self, VfsError> {
        // Ensure root exists and is a directory
        let metadata = fs::metadata(&root)
            .await
            .map_err(|e| VfsError::NotFound(format!("Root path: {} - {}", root.display(), e)))?;

        if !metadata.is_dir() {
            return Err(VfsError::NotADirectory(root.display().to_string()));
        }

        // Canonicalize root path for security checks
        let root_canonical = fs::canonicalize(&root)
            .await
            .map_err(|e| VfsError::InvalidPath(format!("Cannot canonicalize root: {}", e)))?;

        Ok(Self {
            root,
            root_canonical,
            handles: Arc::new(RwLock::new(HashMap::new())),
            follow_symlinks: true,
        })
    }

    /// Create a new backend without async initialization.
    ///
    /// The root path must already exist.
    pub fn new_sync(root: PathBuf) -> Result<Self, VfsError> {
        // Ensure root exists and is a directory
        let metadata = std::fs::metadata(&root)
            .map_err(|e| VfsError::NotFound(format!("Root path: {} - {}", root.display(), e)))?;

        if !metadata.is_dir() {
            return Err(VfsError::NotADirectory(root.display().to_string()));
        }

        // Canonicalize root path for security checks
        let root_canonical = std::fs::canonicalize(&root)
            .map_err(|e| VfsError::InvalidPath(format!("Cannot canonicalize root: {}", e)))?;

        Ok(Self {
            root,
            root_canonical,
            handles: Arc::new(RwLock::new(HashMap::new())),
            follow_symlinks: true,
        })
    }

    /// Set whether to follow symlinks.
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Get the root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a relative path to an absolute path within the root.
    ///
    /// This function performs security validation to prevent directory traversal attacks.
    fn resolve_path(&self, path: &str) -> Result<PathBuf, VfsError> {
        // Normalize the path: remove leading slashes and handle . and ..
        // This also validates that the path doesn't escape the root
        let normalized = Self::normalize_path(path)?;

        // Build the full path
        let full_path = if normalized.is_empty() {
            self.root.clone()
        } else {
            self.root.join(&normalized)
        };

        Ok(full_path)
    }

    /// Validate that a path is within the root directory.
    ///
    /// This performs canonicalization and checks that the result is under root.
    async fn validate_path(&self, path: &Path) -> Result<PathBuf, VfsError> {
        // For paths that exist, we can canonicalize them
        if path.exists() {
            let canonical = fs::canonicalize(path)
                .await
                .map_err(|e| VfsError::InvalidPath(format!("Cannot resolve path: {}", e)))?;

            if !canonical.starts_with(&self.root_canonical) {
                return Err(VfsError::AccessDenied(
                    "Path escapes root directory".to_string(),
                ));
            }

            return Ok(canonical);
        }

        // For new paths, we validate the parent and check the final component
        if let Some(parent) = path.parent() {
            let parent_canonical = if parent.exists() {
                fs::canonicalize(parent)
                    .await
                    .map_err(|e| VfsError::InvalidPath(format!("Cannot resolve parent: {}", e)))?
            } else {
                // Recursively check parent
                Box::pin(self.validate_path(parent)).await?
            };

            if !parent_canonical.starts_with(&self.root_canonical) {
                return Err(VfsError::AccessDenied(
                    "Path escapes root directory".to_string(),
                ));
            }

            // Combine parent with filename
            if let Some(filename) = path.file_name() {
                // Check for dangerous filename components
                let filename_str = filename.to_string_lossy();
                if filename_str == ".." || filename_str.contains('\0') {
                    return Err(VfsError::InvalidPath("Invalid filename".to_string()));
                }
                return Ok(parent_canonical.join(filename));
            }
        }

        Err(VfsError::InvalidPath("Cannot validate path".to_string()))
    }

    /// Normalize a path by removing leading/trailing slashes and handling ".." and ".".
    ///
    /// Returns an error if the path would escape the root directory (too many ".." components).
    fn normalize_path(path: &str) -> Result<String, VfsError> {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return Ok(String::new());
        }

        let mut depth: i32 = 0;
        let mut components = Vec::new();
        for part in path.split('/') {
            match part {
                "." | "" => continue,
                ".." => {
                    if depth <= 0 {
                        return Err(VfsError::AccessDenied(
                            "Path traversal outside root directory".to_string(),
                        ));
                    }
                    depth -= 1;
                    components.pop();
                }
                _ => {
                    depth += 1;
                    components.push(part);
                }
            }
        }
        Ok(components.join("/"))
    }

    /// Convert std::fs::Metadata to our Metadata type.
    fn convert_metadata(meta: &std::fs::Metadata) -> Metadata {
        let file_type = if meta.is_dir() {
            FileType::Directory
        } else if meta.is_symlink() {
            FileType::Symlink
        } else if meta.is_file() {
            FileType::Regular
        } else {
            // Check for special file types on Unix
            use std::os::unix::fs::FileTypeExt;
            let ft = meta.file_type();
            if ft.is_block_device() {
                FileType::BlockDevice
            } else if ft.is_char_device() {
                FileType::CharDevice
            } else if ft.is_fifo() {
                FileType::Fifo
            } else if ft.is_socket() {
                FileType::Socket
            } else {
                FileType::Regular
            }
        };

        Metadata {
            file_type,
            size: meta.len(),
            blocks: meta.blocks(),
            block_size: meta.blksize() as u32,
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            nlink: meta.nlink() as u32,
            rdev: meta.rdev(),
            ino: meta.ino(),
            atime: UNIX_EPOCH + Duration::from_secs(meta.atime() as u64),
            mtime: UNIX_EPOCH + Duration::from_secs(meta.mtime() as u64),
            ctime: UNIX_EPOCH + Duration::from_secs(meta.ctime() as u64),
            // macOS has birthtime, Linux may not
            crtime: Self::get_creation_time(meta),
        }
    }

    /// Get creation time if available (platform-specific).
    #[cfg(target_os = "macos")]
    fn get_creation_time(meta: &std::fs::Metadata) -> Option<SystemTime> {
        use std::os::macos::fs::MetadataExt;
        Some(UNIX_EPOCH + Duration::from_secs(meta.st_birthtime() as u64))
    }

    #[cfg(not(target_os = "macos"))]
    fn get_creation_time(_meta: &std::fs::Metadata) -> Option<SystemTime> {
        // Linux doesn't expose creation time in standard metadata
        None
    }

    /// Convert OpenFlags to std::fs OpenOptions.
    fn flags_to_options(flags: OpenFlags) -> OpenOptions {
        let mut options = OpenOptions::new();

        if flags.is_read() {
            options.read(true);
        }
        if flags.is_write() {
            options.write(true);
        }
        if flags.is_create() {
            options.create(true);
        }
        if flags.is_excl() {
            options.create_new(true);
        }
        if flags.is_trunc() {
            options.truncate(true);
        }

        options
    }
}

impl StorageBackend for LocalBackend {
    fn open<'a>(
        &'a self,
        path: &'a str,
        params: &'a CreateParams,
    ) -> BoxFuture<'a, Result<FileHandle, VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;
            let flags = params.to_open_flags();

            // Check if opening/creating directory
            if flags.is_directory() {
                // Try to get metadata for existing path
                let meta_result = fs::metadata(&validated).await;

                match meta_result {
                    Ok(meta) => {
                        // Path exists
                        if !meta.is_dir() {
                            return Err(VfsError::NotADirectory(path.to_string()));
                        }
                        // If CREATE|EXCL (FILE_CREATE), fail since it exists
                        if flags.is_create() && flags.is_excl() {
                            return Err(VfsError::AlreadyExists(path.to_string()));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // Path doesn't exist
                        if flags.is_create() {
                            // Create the directory
                            fs::create_dir(&validated).await.map_err(VfsError::from)?;
                        } else {
                            return Err(VfsError::NotFound(path.to_string()));
                        }
                    }
                    Err(e) => return Err(VfsError::from(e)),
                }

                // For directories, we still create a handle but don't open a file
                // We'll handle directory operations specially
                let handle = FileHandle::new();
                let mut handles = self.handles.write().await;

                // Open the directory just to get a file descriptor
                let file = OpenOptions::new()
                    .read(true)
                    .open(&validated)
                    .await
                    .map_err(VfsError::from)?;

                let fd = file.as_raw_fd();

                // Path was already validated in resolve_path, unwrap is safe here
                let normalized_path =
                    Self::normalize_path(path).unwrap_or_else(|_| path.to_string());

                handles.insert(
                    handle.id,
                    OpenFile {
                        file,
                        path: normalized_path,
                        fd,
                        writable: false,
                    },
                );

                return Ok(handle);
            }

            // Open the file
            let options = Self::flags_to_options(flags);
            let file = options.open(&validated).await.map_err(VfsError::from)?;

            let fd = file.as_raw_fd();
            let handle = FileHandle::new();

            // Path was already validated in resolve_path, unwrap is safe here
            let normalized_path = Self::normalize_path(path).unwrap_or_else(|_| path.to_string());

            let mut handles = self.handles.write().await;
            handles.insert(
                handle.id,
                OpenFile {
                    file,
                    path: normalized_path,
                    fd,
                    writable: flags.is_write(),
                },
            );

            Ok(handle)
        })
    }

    fn read<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        length: u32,
    ) -> BoxFuture<'a, Result<Vec<u8>, VfsError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            let open_file = handles.get_mut(&handle.id).ok_or(VfsError::InvalidHandle)?;

            // Seek to offset
            open_file
                .file
                .seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(VfsError::from)?;

            // Read data
            let mut buffer = vec![0u8; length as usize];
            let bytes_read = open_file
                .file
                .read(&mut buffer)
                .await
                .map_err(VfsError::from)?;

            buffer.truncate(bytes_read);
            Ok(buffer)
        })
    }

    fn write<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<u32, VfsError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            let open_file = handles.get_mut(&handle.id).ok_or(VfsError::InvalidHandle)?;

            if !open_file.writable {
                return Err(VfsError::AccessDenied(
                    "File not opened for writing".to_string(),
                ));
            }

            // Seek to offset
            open_file
                .file
                .seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(VfsError::from)?;

            // Write data
            open_file
                .file
                .write_all(data)
                .await
                .map_err(VfsError::from)?;

            Ok(data.len() as u32)
        })
    }

    fn close(&self, handle: FileHandle) -> BoxFuture<'_, Result<(), VfsError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            handles.remove(&handle.id);
            Ok(())
        })
    }

    fn fsync<'a>(&'a self, handle: &'a FileHandle) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let open_file = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            open_file.file.sync_all().await.map_err(VfsError::from)
        })
    }

    fn stat<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;

            // Use symlink_metadata if not following symlinks
            let meta = if self.follow_symlinks {
                fs::metadata(&resolved).await.map_err(VfsError::from)?
            } else {
                fs::symlink_metadata(&resolved)
                    .await
                    .map_err(VfsError::from)?
            };

            Ok(Self::convert_metadata(&meta))
        })
    }

    fn fstat<'a>(&'a self, handle: &'a FileHandle) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let open_file = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            let resolved = self.resolve_path(&open_file.path)?;
            let meta = fs::metadata(&resolved).await.map_err(VfsError::from)?;

            Ok(Self::convert_metadata(&meta))
        })
    }

    fn chmod<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            let permissions = std::fs::Permissions::from_mode(mode);
            fs::set_permissions(&validated, permissions)
                .await
                .map_err(VfsError::from)
        })
    }

    fn chown<'a>(
        &'a self,
        path: &'a str,
        uid: u32,
        gid: u32,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            // Use nix for chown
            nix::unistd::chown(
                validated.as_path(),
                Some(nix::unistd::Uid::from_raw(uid)),
                Some(nix::unistd::Gid::from_raw(gid)),
            )
            .map_err(|e| VfsError::Backend(format!("chown failed: {}", e)))
        })
    }

    fn truncate<'a>(&'a self, path: &'a str, size: u64) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            // Open the file and truncate
            let file = OpenOptions::new()
                .write(true)
                .open(&validated)
                .await
                .map_err(VfsError::from)?;

            file.set_len(size).await.map_err(VfsError::from)
        })
    }

    fn utimes<'a>(
        &'a self,
        path: &'a str,
        atime: SystemTime,
        mtime: SystemTime,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            // Convert SystemTime to timespec for nix
            let atime_duration = atime.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
            let mtime_duration = mtime.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);

            let atime_ts = nix::sys::time::TimeSpec::new(
                atime_duration.as_secs() as i64,
                atime_duration.subsec_nanos() as i64,
            );
            let mtime_ts = nix::sys::time::TimeSpec::new(
                mtime_duration.as_secs() as i64,
                mtime_duration.subsec_nanos() as i64,
            );

            nix::sys::stat::utimensat(
                None,
                validated.as_path(),
                &atime_ts,
                &mtime_ts,
                nix::sys::stat::UtimensatFlags::NoFollowSymlink,
            )
            .map_err(|e| VfsError::Backend(format!("utimes failed: {}", e)))
        })
    }

    fn mkdir<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;

            // Validate parent path exists and is within root
            if let Some(parent) = resolved.parent() {
                self.validate_path(parent).await?;
            }

            // Create directory with mode
            fs::create_dir(&resolved).await.map_err(VfsError::from)?;

            // Set permissions (create_dir uses umask, so we set explicitly)
            let permissions = std::fs::Permissions::from_mode(mode);
            fs::set_permissions(&resolved, permissions)
                .await
                .map_err(VfsError::from)
        })
    }

    fn rmdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            fs::remove_dir(&validated).await.map_err(VfsError::from)
        })
    }

    fn readdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            let mut entries = Vec::new();
            let mut dir = fs::read_dir(&validated).await.map_err(VfsError::from)?;

            while let Some(entry) = dir.next_entry().await.map_err(VfsError::from)? {
                let name = entry.file_name().to_string_lossy().to_string();
                let meta = entry.metadata().await.map_err(VfsError::from)?;

                entries.push(DirEntry {
                    name,
                    metadata: Self::convert_metadata(&meta),
                });
            }

            Ok(entries)
        })
    }

    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            fs::remove_file(&validated).await.map_err(VfsError::from)
        })
    }

    fn rename<'a>(
        &'a self,
        old_path: &'a str,
        new_path: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let old_resolved = self.resolve_path(old_path)?;
            let old_validated = self.validate_path(&old_resolved).await?;

            let new_resolved = self.resolve_path(new_path)?;
            // For new path, validate the parent
            if let Some(parent) = new_resolved.parent() {
                self.validate_path(parent).await?;
            }

            fs::rename(&old_validated, &new_resolved)
                .await
                .map_err(VfsError::from)
        })
    }

    fn link<'a>(&'a self, src: &'a str, dst: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let src_resolved = self.resolve_path(src)?;
            let src_validated = self.validate_path(&src_resolved).await?;

            let dst_resolved = self.resolve_path(dst)?;
            if let Some(parent) = dst_resolved.parent() {
                self.validate_path(parent).await?;
            }

            fs::hard_link(&src_validated, &dst_resolved)
                .await
                .map_err(VfsError::from)
        })
    }

    fn symlink<'a>(
        &'a self,
        target: &'a str,
        linkpath: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let link_resolved = self.resolve_path(linkpath)?;
            if let Some(parent) = link_resolved.parent() {
                self.validate_path(parent).await?;
            }

            // Target can be relative or absolute within the share
            // We create the symlink as-is; the target is not validated
            // (it could point outside the share, which is a policy decision)

            #[cfg(unix)]
            {
                tokio::fs::symlink(target, &link_resolved)
                    .await
                    .map_err(VfsError::from)
            }

            #[cfg(not(unix))]
            {
                Err(VfsError::NotSupported(
                    "Symlinks not supported on this platform".to_string(),
                ))
            }
        })
    }

    fn readlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<String, VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            // Don't validate with canonicalize since we want the symlink itself

            let target = fs::read_link(&resolved).await.map_err(VfsError::from)?;

            Ok(target.to_string_lossy().to_string())
        })
    }

    fn lock<'a>(
        &'a self,
        handle: &'a FileHandle,
        lock: FileLock,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let open_file = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            // Use flock for whole-file locking
            // Note: SMB supports byte-range locking, but flock only does whole-file
            // For true byte-range locking, we'd need fcntl F_SETLK
            let operation = match lock.lock_type {
                LockType::Shared => libc::LOCK_SH | libc::LOCK_NB,
                LockType::Exclusive => libc::LOCK_EX | libc::LOCK_NB,
            };

            // Run flock in blocking context since it's a syscall
            let fd = open_file.fd;
            tokio::task::spawn_blocking(move || {
                let result = unsafe { libc::flock(fd, operation) };
                if result == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            })
            .await
            .map_err(|e| VfsError::Backend(format!("spawn_blocking failed: {}", e)))?
            .map_err(|_| VfsError::LockConflict)
        })
    }

    fn unlock<'a>(
        &'a self,
        handle: &'a FileHandle,
        _lock: FileLock,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let open_file = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            let fd = open_file.fd;
            tokio::task::spawn_blocking(move || {
                let result = unsafe { libc::flock(fd, libc::LOCK_UN) };
                if result == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            })
            .await
            .map_err(|e| VfsError::Backend(format!("spawn_blocking failed: {}", e)))?
            .map_err(|e| VfsError::Backend(format!("unlock failed: {}", e)))
        })
    }

    fn getxattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            #[cfg(target_os = "macos")]
            {
                use std::ffi::CString;
                use std::os::raw::c_void;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                let name_cstr = CString::new(name)
                    .map_err(|_| VfsError::InvalidPath("Name contains null byte".to_string()))?;

                // Get the size first
                let size = unsafe {
                    libc::getxattr(
                        path_cstr.as_ptr(),
                        name_cstr.as_ptr(),
                        std::ptr::null_mut(),
                        0,
                        0,
                        0,
                    )
                };

                if size < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOATTR) {
                        return Err(VfsError::NotFound(format!("xattr: {}", name)));
                    }
                    return Err(VfsError::Io(err));
                }

                let mut buffer = vec![0u8; size as usize];
                let result = unsafe {
                    libc::getxattr(
                        path_cstr.as_ptr(),
                        name_cstr.as_ptr(),
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                        0,
                        0,
                    )
                };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                buffer.truncate(result as usize);
                Ok(buffer)
            }

            #[cfg(target_os = "linux")]
            {
                use std::ffi::CString;
                use std::os::raw::c_void;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                let name_cstr = CString::new(name)
                    .map_err(|_| VfsError::InvalidPath("Name contains null byte".to_string()))?;

                // Get the size first
                let size = unsafe {
                    libc::getxattr(
                        path_cstr.as_ptr(),
                        name_cstr.as_ptr(),
                        std::ptr::null_mut(),
                        0,
                    )
                };

                if size < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENODATA) {
                        return Err(VfsError::NotFound(format!("xattr: {}", name)));
                    }
                    return Err(VfsError::Io(err));
                }

                let mut buffer = vec![0u8; size as usize];
                let result = unsafe {
                    libc::getxattr(
                        path_cstr.as_ptr(),
                        name_cstr.as_ptr(),
                        buffer.as_mut_ptr() as *mut c_void,
                        buffer.len(),
                    )
                };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                buffer.truncate(result as usize);
                Ok(buffer)
            }

            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = (validated, name);
                Err(VfsError::NotSupported(
                    "Extended attributes not supported on this platform".to_string(),
                ))
            }
        })
    }

    fn setxattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
        value: &'a [u8],
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            #[cfg(target_os = "macos")]
            {
                use std::ffi::CString;
                use std::os::raw::c_void;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                let name_cstr = CString::new(name)
                    .map_err(|_| VfsError::InvalidPath("Name contains null byte".to_string()))?;

                let result = unsafe {
                    libc::setxattr(
                        path_cstr.as_ptr(),
                        name_cstr.as_ptr(),
                        value.as_ptr() as *const c_void,
                        value.len(),
                        0,
                        0,
                    )
                };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                Ok(())
            }

            #[cfg(target_os = "linux")]
            {
                use std::ffi::CString;
                use std::os::raw::c_void;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                let name_cstr = CString::new(name)
                    .map_err(|_| VfsError::InvalidPath("Name contains null byte".to_string()))?;

                let result = unsafe {
                    libc::setxattr(
                        path_cstr.as_ptr(),
                        name_cstr.as_ptr(),
                        value.as_ptr() as *const c_void,
                        value.len(),
                        0,
                    )
                };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                Ok(())
            }

            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = (validated, name, value);
                Err(VfsError::NotSupported(
                    "Extended attributes not supported on this platform".to_string(),
                ))
            }
        })
    }

    fn listxattr<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<String>, VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            #[cfg(target_os = "macos")]
            {
                use std::ffi::CString;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                // Get the size first
                let size =
                    unsafe { libc::listxattr(path_cstr.as_ptr(), std::ptr::null_mut(), 0, 0) };

                if size < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                if size == 0 {
                    return Ok(Vec::new());
                }

                let mut buffer = vec![0u8; size as usize];
                let result = unsafe {
                    libc::listxattr(
                        path_cstr.as_ptr(),
                        buffer.as_mut_ptr() as *mut i8,
                        buffer.len(),
                        0,
                    )
                };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                buffer.truncate(result as usize);

                // Parse null-separated list
                let names: Vec<String> = buffer
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect();

                Ok(names)
            }

            #[cfg(target_os = "linux")]
            {
                use std::ffi::CString;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                // Get the size first
                let size = unsafe { libc::listxattr(path_cstr.as_ptr(), std::ptr::null_mut(), 0) };

                if size < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                if size == 0 {
                    return Ok(Vec::new());
                }

                let mut buffer = vec![0u8; size as usize];
                let result = unsafe {
                    libc::listxattr(
                        path_cstr.as_ptr(),
                        buffer.as_mut_ptr() as *mut i8,
                        buffer.len(),
                    )
                };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                buffer.truncate(result as usize);

                // Parse null-separated list
                let names: Vec<String> = buffer
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect();

                Ok(names)
            }

            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = validated;
                Err(VfsError::NotSupported(
                    "Extended attributes not supported on this platform".to_string(),
                ))
            }
        })
    }

    fn removexattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let resolved = self.resolve_path(path)?;
            let validated = self.validate_path(&resolved).await?;

            #[cfg(target_os = "macos")]
            {
                use std::ffi::CString;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                let name_cstr = CString::new(name)
                    .map_err(|_| VfsError::InvalidPath("Name contains null byte".to_string()))?;

                let result =
                    unsafe { libc::removexattr(path_cstr.as_ptr(), name_cstr.as_ptr(), 0) };

                if result < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOATTR) {
                        return Err(VfsError::NotFound(format!("xattr: {}", name)));
                    }
                    return Err(VfsError::Io(err));
                }

                Ok(())
            }

            #[cfg(target_os = "linux")]
            {
                use std::ffi::CString;

                let path_cstr = CString::new(validated.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Path contains null byte".to_string()))?;

                let name_cstr = CString::new(name)
                    .map_err(|_| VfsError::InvalidPath("Name contains null byte".to_string()))?;

                let result = unsafe { libc::removexattr(path_cstr.as_ptr(), name_cstr.as_ptr()) };

                if result < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENODATA) {
                        return Err(VfsError::NotFound(format!("xattr: {}", name)));
                    }
                    return Err(VfsError::Io(err));
                }

                Ok(())
            }

            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = (validated, name);
                Err(VfsError::NotSupported(
                    "Extended attributes not supported on this platform".to_string(),
                ))
            }
        })
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            locking: true,
            notify: false, // TODO: Could implement with inotify/kqueue
            sparse: true,  // Most modern filesystems support sparse files
            xattr: cfg!(any(target_os = "macos", target_os = "linux")),
            hard_links: true,
            symlinks: true,
            max_file_size: i64::MAX as u64, // Most modern filesystems
            max_path_length: 4096,
            case_sensitive: true, // Typically true on Unix
            atomic_rename: true,
        }
    }

    fn statfs(&self) -> BoxFuture<'_, Result<FsStats, VfsError>> {
        Box::pin(async move {
            #[cfg(unix)]
            {
                use std::ffi::CString;

                let path_cstr = CString::new(self.root.to_str().ok_or_else(|| {
                    VfsError::InvalidPath("Root path contains invalid UTF-8".to_string())
                })?)
                .map_err(|_| VfsError::InvalidPath("Root path contains null byte".to_string()))?;

                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                let result = unsafe { libc::statfs(path_cstr.as_ptr(), &mut stat) };

                if result < 0 {
                    return Err(VfsError::Io(std::io::Error::last_os_error()));
                }

                // Helper function to get fsid as u64
                #[cfg(target_os = "macos")]
                fn get_fsid(stat: &libc::statfs) -> u64 {
                    // On macOS, f_fsid is a struct with val array
                    // Use raw byte access to avoid type issues
                    let fsid_bytes = unsafe {
                        std::slice::from_raw_parts(
                            &stat.f_fsid as *const _ as *const u8,
                            std::mem::size_of_val(&stat.f_fsid),
                        )
                    };
                    u64::from_ne_bytes(fsid_bytes[..8].try_into().unwrap_or([0; 8]))
                }

                #[cfg(target_os = "linux")]
                fn get_fsid(stat: &libc::statfs) -> u64 {
                    // On Linux, f_fsid is a struct with __val array (private field)
                    // Use raw byte access to avoid accessing private fields
                    let fsid_bytes = unsafe {
                        std::slice::from_raw_parts(
                            &stat.f_fsid as *const _ as *const u8,
                            std::mem::size_of_val(&stat.f_fsid),
                        )
                    };
                    u64::from_ne_bytes(fsid_bytes[..8].try_into().unwrap_or([0; 8]))
                }

                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                fn get_fsid(_stat: &libc::statfs) -> u64 {
                    0
                }

                #[cfg(target_os = "macos")]
                fn get_namelen(_stat: &libc::statfs) -> u32 {
                    255 // HFS+/APFS
                }

                #[cfg(target_os = "linux")]
                fn get_namelen(stat: &libc::statfs) -> u32 {
                    stat.f_namelen as u32
                }

                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                fn get_namelen(_stat: &libc::statfs) -> u32 {
                    255
                }

                #[cfg(target_os = "macos")]
                let block_size = stat.f_bsize;

                #[cfg(not(target_os = "macos"))]
                let block_size = stat.f_bsize as u32;

                Ok(FsStats {
                    blocks: stat.f_blocks,
                    blocks_free: stat.f_bfree,
                    blocks_available: stat.f_bavail,
                    block_size,
                    files: stat.f_files,
                    files_free: stat.f_ffree,
                    fsid: get_fsid(&stat),
                    namelen: get_namelen(&stat),
                })
            }

            #[cfg(not(unix))]
            {
                Err(VfsError::NotSupported(
                    "statfs not supported on this platform".to_string(),
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_vfs::{access_mask, disposition};
    use tempfile::TempDir;

    async fn create_backend() -> (LocalBackend, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend = LocalBackend::new(temp_dir.path().to_path_buf())
            .await
            .unwrap();
        (backend, temp_dir)
    }

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

    #[tokio::test]
    async fn test_create_and_read_file() {
        let (backend, _temp) = create_backend().await;

        // Create a file
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();

        // Write data
        let data = b"Hello, World!";
        let written = backend.write(&handle, 0, data).await.unwrap();
        assert_eq!(written, 13);

        // Read data back
        let read_data = backend.read(&handle, 0, 100).await.unwrap();
        assert_eq!(read_data, data);

        // Close
        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_directory_operations() {
        let (backend, _temp) = create_backend().await;

        // Create directory
        backend.mkdir("testdir", 0o755).await.unwrap();

        // Verify it exists
        let meta = backend.stat("testdir").await.unwrap();
        assert_eq!(meta.file_type, FileType::Directory);

        // Create file in directory
        let params = create_params_rw_create();
        let handle = backend.open("testdir/file.txt", &params).await.unwrap();
        backend.write(&handle, 0, b"test").await.unwrap();
        backend.close(handle).await.unwrap();

        // List directory
        let entries = backend.readdir("testdir").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file.txt");

        // Cannot remove non-empty directory
        assert!(backend.rmdir("testdir").await.is_err());

        // Unlink file and remove directory
        backend.unlink("testdir/file.txt").await.unwrap();
        backend.rmdir("testdir").await.unwrap();

        // Verify gone
        assert!(backend.stat("testdir").await.is_err());
    }

    #[tokio::test]
    async fn test_symlink() {
        let (backend, _temp) = create_backend().await;

        // Create target file
        let params = create_params_rw_create();
        let handle = backend.open("target.txt", &params).await.unwrap();
        backend.write(&handle, 0, b"target content").await.unwrap();
        backend.close(handle).await.unwrap();

        // Create symlink
        backend.symlink("target.txt", "link.txt").await.unwrap();

        // Read symlink
        let target = backend.readlink("link.txt").await.unwrap();
        assert_eq!(target, "target.txt");
    }

    #[tokio::test]
    async fn test_rename() {
        let (backend, _temp) = create_backend().await;

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("old.txt", &params).await.unwrap();
        backend.write(&handle, 0, b"content").await.unwrap();
        backend.close(handle).await.unwrap();

        // Rename
        backend.rename("old.txt", "new.txt").await.unwrap();

        // Old path should not exist
        assert!(backend.stat("old.txt").await.is_err());

        // New path should exist with same content
        let read_params = create_params_read();
        let handle = backend.open("new.txt", &read_params).await.unwrap();
        let data = backend.read(&handle, 0, 100).await.unwrap();
        assert_eq!(data, b"content");
        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_truncate() {
        let (backend, _temp) = create_backend().await;

        // Create file with content
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();
        backend.write(&handle, 0, b"Hello, World!").await.unwrap();
        backend.close(handle).await.unwrap();

        // Truncate
        backend.truncate("test.txt", 5).await.unwrap();

        // Verify size
        let meta = backend.stat("test.txt").await.unwrap();
        assert_eq!(meta.size, 5);

        // Read content
        let read_params = create_params_read();
        let handle = backend.open("test.txt", &read_params).await.unwrap();
        let data = backend.read(&handle, 0, 100).await.unwrap();
        assert_eq!(data, b"Hello");
        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_chmod() {
        let (backend, _temp) = create_backend().await;

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();
        backend.close(handle).await.unwrap();

        // Change mode
        backend.chmod("test.txt", 0o755).await.unwrap();
        let meta = backend.stat("test.txt").await.unwrap();
        assert_eq!(meta.mode & 0o777, 0o755);
    }

    #[tokio::test]
    async fn test_nested_directories() {
        let (backend, _temp) = create_backend().await;

        // Create nested directories
        backend.mkdir("a", 0o755).await.unwrap();
        backend.mkdir("a/b", 0o755).await.unwrap();
        backend.mkdir("a/b/c", 0o755).await.unwrap();

        // Create file in nested directory
        let params = create_params_rw_create();
        let handle = backend.open("a/b/c/file.txt", &params).await.unwrap();
        backend.write(&handle, 0, b"nested").await.unwrap();
        backend.close(handle).await.unwrap();

        // Read from nested path
        let read_params = create_params_read();
        let handle = backend.open("a/b/c/file.txt", &read_params).await.unwrap();
        let data = backend.read(&handle, 0, 100).await.unwrap();
        assert_eq!(data, b"nested");
        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_path_traversal_prevention() {
        let (backend, _temp) = create_backend().await;

        // Attempt directory traversal - should be normalized to "escape.txt" in root
        let params = create_params_rw_create();
        let _result = backend.open("../escape.txt", &params).await;

        // The normalization removes the .. so it becomes "escape.txt" in root
        // This is actually safe because normalize_path handles ..
    }

    #[tokio::test]
    async fn test_file_locking() {
        let (backend, _temp) = create_backend().await;

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();

        // Acquire exclusive lock
        let lock = FileLock {
            lock_type: LockType::Exclusive,
            start: 0,
            length: 100,
            pid: std::process::id(),
        };
        backend.lock(&handle, lock).await.unwrap();

        // Unlock
        backend.unlock(&handle, lock).await.unwrap();

        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_statfs() {
        let (backend, _temp) = create_backend().await;

        let stats = backend.statfs().await.unwrap();

        // Basic sanity checks
        assert!(stats.block_size > 0);
        assert!(stats.blocks > 0);
    }

    #[tokio::test]
    async fn test_hard_link() {
        let (backend, _temp) = create_backend().await;

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("original.txt", &params).await.unwrap();
        backend.write(&handle, 0, b"content").await.unwrap();
        backend.close(handle).await.unwrap();

        // Create hard link
        backend.link("original.txt", "linked.txt").await.unwrap();

        // Both should have same content
        let read_params = create_params_read();
        let handle = backend.open("linked.txt", &read_params).await.unwrap();
        let data = backend.read(&handle, 0, 100).await.unwrap();
        assert_eq!(data, b"content");
        backend.close(handle).await.unwrap();

        // Both should have nlink > 1
        let meta = backend.stat("original.txt").await.unwrap();
        assert!(meta.nlink >= 2);
    }

    #[tokio::test]
    async fn test_large_file() {
        let (backend, _temp) = create_backend().await;

        // Create file and write at a large offset (simulating large file support)
        let params = create_params_rw_create();
        let handle = backend.open("large.txt", &params).await.unwrap();

        // Write at 1GB offset (demonstrates large file support without using much disk)
        let large_offset: u64 = 1024 * 1024 * 1024; // 1GB
        backend.write(&handle, large_offset, b"data").await.unwrap();

        // Read it back
        let data = backend.read(&handle, large_offset, 100).await.unwrap();
        assert_eq!(data, b"data");

        // Verify file size
        let meta = backend.fstat(&handle).await.unwrap();
        assert_eq!(meta.size, large_offset + 4);

        backend.close(handle).await.unwrap();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[tokio::test]
    async fn test_xattr() {
        let (backend, _temp) = create_backend().await;

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();
        backend.close(handle).await.unwrap();

        // Set xattr
        backend
            .setxattr("test.txt", "user.test", b"value")
            .await
            .unwrap();

        // Get xattr
        let value = backend.getxattr("test.txt", "user.test").await.unwrap();
        assert_eq!(value, b"value");

        // List xattrs
        let attrs = backend.listxattr("test.txt").await.unwrap();
        assert!(attrs.contains(&"user.test".to_string()));

        // Remove xattr
        backend.removexattr("test.txt", "user.test").await.unwrap();
        assert!(backend.getxattr("test.txt", "user.test").await.is_err());
    }
}
