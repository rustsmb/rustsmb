//! Core storage backend trait.

use crate::types::*;
use rustsmb_core::VfsError;
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

/// Type alias for boxed async results (object-safe async trait pattern).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Core storage backend trait.
///
/// All storage backends (local filesystem, memory, etc.) must implement this trait.
/// The trait uses BoxFuture for object safety with dynamic dispatch.
///
/// # Example
///
/// ```ignore
/// use rustsmb_vfs::{StorageBackend, BoxFuture};
///
/// struct MyBackend;
///
/// impl StorageBackend for MyBackend {
///     fn open<'a>(&'a self, path: &'a str, flags: OpenFlags, mode: u32)
///         -> BoxFuture<'a, Result<FileHandle, VfsError>>
///     {
///         Box::pin(async move {
///             // implementation
///             todo!()
///         })
///     }
///     // ... other methods
/// }
/// ```
pub trait StorageBackend: Send + Sync + 'static {
    // ========== File Operations ==========

    /// Open or create a file.
    fn open<'a>(
        &'a self,
        path: &'a str,
        flags: OpenFlags,
        mode: u32,
    ) -> BoxFuture<'a, Result<FileHandle, VfsError>>;

    /// Read data from an open file.
    fn read<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        length: u32,
    ) -> BoxFuture<'a, Result<Vec<u8>, VfsError>>;

    /// Write data to an open file.
    fn write<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<u32, VfsError>>;

    /// Close a file handle.
    fn close(&self, handle: FileHandle) -> BoxFuture<'_, Result<(), VfsError>>;

    /// Flush pending writes to storage.
    fn fsync<'a>(&'a self, handle: &'a FileHandle) -> BoxFuture<'a, Result<(), VfsError>>;

    // ========== Metadata Operations ==========

    /// Get file metadata by path.
    fn stat<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Metadata, VfsError>>;

    /// Get file metadata by handle.
    fn fstat<'a>(&'a self, handle: &'a FileHandle) -> BoxFuture<'a, Result<Metadata, VfsError>>;

    /// Change file mode/permissions.
    fn chmod<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Change file owner.
    fn chown<'a>(
        &'a self,
        path: &'a str,
        uid: u32,
        gid: u32,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Truncate file to specified size.
    fn truncate<'a>(&'a self, path: &'a str, size: u64) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Update file access and modification times.
    fn utimes<'a>(
        &'a self,
        path: &'a str,
        atime: SystemTime,
        mtime: SystemTime,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    // ========== Directory Operations ==========

    /// Create a directory.
    fn mkdir<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Remove an empty directory.
    fn rmdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Read directory contents.
    fn readdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>>;

    // ========== Link Operations ==========

    /// Remove a file.
    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Rename a file or directory.
    fn rename<'a>(
        &'a self,
        old_path: &'a str,
        new_path: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Create a hard link.
    fn link<'a>(&'a self, src: &'a str, dst: &'a str) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Create a symbolic link.
    fn symlink<'a>(
        &'a self,
        target: &'a str,
        linkpath: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Read the target of a symbolic link.
    fn readlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<String, VfsError>>;

    // ========== Locking ==========

    /// Acquire a byte-range lock.
    fn lock<'a>(
        &'a self,
        handle: &'a FileHandle,
        lock: FileLock,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// Release a byte-range lock.
    fn unlock<'a>(
        &'a self,
        handle: &'a FileHandle,
        lock: FileLock,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    // ========== Extended Attributes ==========

    /// Get an extended attribute.
    fn getxattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, VfsError>>;

    /// Set an extended attribute.
    fn setxattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
        value: &'a [u8],
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    /// List extended attributes.
    fn listxattr<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<String>, VfsError>>;

    /// Remove an extended attribute.
    fn removexattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>>;

    // ========== Filesystem Info ==========

    /// Get backend capabilities.
    fn capabilities(&self) -> BackendCapabilities;

    /// Get filesystem statistics.
    fn statfs(&self) -> BoxFuture<'_, Result<FsStats, VfsError>>;
}

/// Dynamic dispatch wrapper for storage backends.
pub type DynStorageBackend = std::sync::Arc<dyn StorageBackend>;
