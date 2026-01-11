//! In-memory filesystem backend for RustSMB.
//!
//! This backend provides an in-memory filesystem for testing purposes.
//! It implements the full `StorageBackend` trait with all VFS operations.

use rustsmb_core::VfsError;
use rustsmb_vfs::{
    BackendCapabilities, BoxFuture, CreateParams, DirEntry, FileHandle, FileLock, FileType,
    FsStats, LockType, Metadata, OpenFlags, StorageBackend,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;

/// In-memory filesystem backend.
pub struct MemoryBackend {
    /// Root of the filesystem tree.
    root: Arc<RwLock<MemoryNode>>,
    /// Open file handles mapping to paths.
    handles: Arc<RwLock<HashMap<u64, HandleInfo>>>,
    /// Inode counter for unique IDs.
    inode_counter: AtomicU64,
    /// Lock tracking per handle.
    locks: Arc<RwLock<HashMap<u64, Vec<FileLock>>>>,
}

/// Information about an open file handle.
#[derive(Debug, Clone)]
struct HandleInfo {
    /// Path to the file.
    path: String,
    /// Open flags used (preserved for potential future use).
    #[allow(dead_code)]
    flags: OpenFlags,
}

/// A node in the in-memory filesystem.
#[derive(Debug, Clone)]
enum MemoryNode {
    /// Regular file.
    File {
        content: Vec<u8>,
        metadata: NodeMetadata,
        xattrs: HashMap<String, Vec<u8>>,
    },
    /// Directory.
    Directory {
        children: HashMap<String, MemoryNode>,
        metadata: NodeMetadata,
        xattrs: HashMap<String, Vec<u8>>,
    },
    /// Symbolic link.
    Symlink {
        target: String,
        metadata: NodeMetadata,
    },
}

/// Metadata for a filesystem node.
#[derive(Debug, Clone)]
struct NodeMetadata {
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    ino: u64,
    atime: SystemTime,
    mtime: SystemTime,
    ctime: SystemTime,
    crtime: SystemTime,
}

impl NodeMetadata {
    fn new(mode: u32, ino: u64) -> Self {
        let now = SystemTime::now();
        Self {
            mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            ino,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
        }
    }
}

impl MemoryNode {
    fn file_type(&self) -> FileType {
        match self {
            MemoryNode::File { .. } => FileType::Regular,
            MemoryNode::Directory { .. } => FileType::Directory,
            MemoryNode::Symlink { .. } => FileType::Symlink,
        }
    }

    fn size(&self) -> u64 {
        match self {
            MemoryNode::File { content, .. } => content.len() as u64,
            MemoryNode::Directory { children, .. } => children.len() as u64,
            MemoryNode::Symlink { target, .. } => target.len() as u64,
        }
    }

    fn metadata(&self) -> &NodeMetadata {
        match self {
            MemoryNode::File { metadata, .. } => metadata,
            MemoryNode::Directory { metadata, .. } => metadata,
            MemoryNode::Symlink { metadata, .. } => metadata,
        }
    }

    fn metadata_mut(&mut self) -> &mut NodeMetadata {
        match self {
            MemoryNode::File { metadata, .. } => metadata,
            MemoryNode::Directory { metadata, .. } => metadata,
            MemoryNode::Symlink { metadata, .. } => metadata,
        }
    }

    fn to_vfs_metadata(&self) -> Metadata {
        let meta = self.metadata();
        Metadata {
            file_type: self.file_type(),
            size: self.size(),
            blocks: self.size().div_ceil(4096),
            block_size: 4096,
            mode: meta.mode,
            uid: meta.uid,
            gid: meta.gid,
            nlink: meta.nlink,
            rdev: 0,
            ino: meta.ino,
            atime: meta.atime,
            mtime: meta.mtime,
            ctime: meta.ctime,
            crtime: Some(meta.crtime),
        }
    }

    fn xattrs(&self) -> Option<&HashMap<String, Vec<u8>>> {
        match self {
            MemoryNode::File { xattrs, .. } => Some(xattrs),
            MemoryNode::Directory { xattrs, .. } => Some(xattrs),
            MemoryNode::Symlink { .. } => None,
        }
    }

    fn xattrs_mut(&mut self) -> Option<&mut HashMap<String, Vec<u8>>> {
        match self {
            MemoryNode::File { xattrs, .. } => Some(xattrs),
            MemoryNode::Directory { xattrs, .. } => Some(xattrs),
            MemoryNode::Symlink { .. } => None,
        }
    }
}

impl MemoryBackend {
    /// Create a new empty in-memory filesystem.
    pub fn new() -> Self {
        Self {
            root: Arc::new(RwLock::new(MemoryNode::Directory {
                children: HashMap::new(),
                metadata: NodeMetadata::new(0o755, 1),
                xattrs: HashMap::new(),
            })),
            handles: Arc::new(RwLock::new(HashMap::new())),
            inode_counter: AtomicU64::new(2),
            locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create as Arc for use as DynStorageBackend.
    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Generate a new unique inode number.
    fn next_inode(&self) -> u64 {
        self.inode_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Normalize a path by removing leading/trailing slashes and handling ".." and ".".
    fn normalize_path(path: &str) -> String {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return String::new();
        }

        let mut components = Vec::new();
        for part in path.split('/') {
            match part {
                "." | "" => continue,
                ".." => {
                    components.pop();
                }
                _ => components.push(part),
            }
        }
        components.join("/")
    }

    /// Split a path into parent directory and filename.
    fn split_path(path: &str) -> Option<(&str, &str)> {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return None;
        }
        match path.rfind('/') {
            Some(pos) => Some((&path[..pos], &path[pos + 1..])),
            None => Some(("", path)),
        }
    }

    /// Get a node at the given path.
    async fn get_node(&self, path: &str) -> Result<MemoryNode, VfsError> {
        let path = Self::normalize_path(path);
        let root = self.root.read().await;

        if path.is_empty() {
            return Ok(root.clone());
        }

        let mut current = &*root;
        for component in path.split('/') {
            match current {
                MemoryNode::Directory { children, .. } => {
                    current = children
                        .get(component)
                        .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                }
                _ => return Err(VfsError::NotADirectory(path)),
            }
        }
        Ok(current.clone())
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryBackend {
    fn open<'a>(
        &'a self,
        path: &'a str,
        params: &'a CreateParams,
    ) -> BoxFuture<'a, Result<FileHandle, VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let flags = params.to_open_flags();

            // Check if opening directory
            if flags.is_directory() {
                let node = self.get_node(&path).await?;
                if !matches!(node, MemoryNode::Directory { .. }) {
                    return Err(VfsError::NotADirectory(path));
                }
                let handle = FileHandle::new();
                let mut handles = self.handles.write().await;
                handles.insert(handle.id, HandleInfo { path, flags });
                return Ok(handle);
            }

            let mut root = self.root.write().await;

            // Navigate to parent directory
            let (parent_path, filename) = Self::split_path(&path)
                .ok_or_else(|| VfsError::InvalidPath("Cannot open root as file".to_string()))?;

            let parent_path = Self::normalize_path(parent_path);

            // Get parent directory
            let parent = if parent_path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in parent_path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(parent_path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(parent_path)),
                    }
                }
                current
            };

            let children = match parent {
                MemoryNode::Directory { children, .. } => children,
                _ => return Err(VfsError::NotADirectory(parent_path)),
            };

            // Check if file exists
            let exists = children.contains_key(filename);

            if exists {
                if flags.is_create() && flags.is_excl() {
                    return Err(VfsError::AlreadyExists(path));
                }

                let node = children.get_mut(filename).unwrap();
                if matches!(node, MemoryNode::Directory { .. }) {
                    return Err(VfsError::IsADirectory(path));
                }

                // Truncate if requested
                if flags.is_trunc() {
                    if let MemoryNode::File {
                        content, metadata, ..
                    } = node
                    {
                        content.clear();
                        metadata.mtime = SystemTime::now();
                        metadata.ctime = SystemTime::now();
                    }
                }
            } else if flags.is_create() {
                // Create new file - use default mode since SMB uses file_attributes instead
                let mode = 0o644;
                let ino = self.next_inode();
                children.insert(
                    filename.to_string(),
                    MemoryNode::File {
                        content: Vec::new(),
                        metadata: NodeMetadata::new(mode, ino),
                        xattrs: HashMap::new(),
                    },
                );
            } else {
                return Err(VfsError::NotFound(path));
            }

            // Create handle
            let handle = FileHandle::new();
            drop(root);

            let mut handles = self.handles.write().await;
            handles.insert(handle.id, HandleInfo { path, flags });

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
            let handles = self.handles.read().await;
            let info = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            let path = info.path.clone();
            drop(handles);

            let node = self.get_node(&path).await?;

            match node {
                MemoryNode::File { content, .. } => {
                    let offset = offset as usize;
                    if offset >= content.len() {
                        return Ok(Vec::new());
                    }
                    let end = std::cmp::min(offset + length as usize, content.len());
                    Ok(content[offset..end].to_vec())
                }
                MemoryNode::Directory { .. } => Err(VfsError::IsADirectory(path)),
                MemoryNode::Symlink { .. } => Err(VfsError::InvalidHandle),
            }
        })
    }

    fn write<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        data: &'a [u8],
    ) -> BoxFuture<'a, Result<u32, VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let info = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            let path = info.path.clone();
            drop(handles);

            let mut root = self.root.write().await;

            // Navigate to the file
            let node = if path.is_empty() {
                return Err(VfsError::IsADirectory(path));
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path.clone())),
                    }
                }
                current
            };

            match node {
                MemoryNode::File {
                    content, metadata, ..
                } => {
                    let offset = offset as usize;
                    let end = offset + data.len();

                    // Extend content if necessary
                    if end > content.len() {
                        content.resize(end, 0);
                    }

                    content[offset..end].copy_from_slice(data);
                    metadata.mtime = SystemTime::now();
                    metadata.ctime = SystemTime::now();

                    Ok(data.len() as u32)
                }
                MemoryNode::Directory { .. } => Err(VfsError::IsADirectory(path)),
                MemoryNode::Symlink { .. } => Err(VfsError::InvalidHandle),
            }
        })
    }

    fn close(&self, handle: FileHandle) -> BoxFuture<'_, Result<(), VfsError>> {
        Box::pin(async move {
            let mut handles = self.handles.write().await;
            handles.remove(&handle.id);

            // Remove any locks held by this handle
            let mut locks = self.locks.write().await;
            locks.remove(&handle.id);

            Ok(())
        })
    }

    fn fsync<'a>(&'a self, handle: &'a FileHandle) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            // Verify handle exists
            let handles = self.handles.read().await;
            if !handles.contains_key(&handle.id) {
                return Err(VfsError::InvalidHandle);
            }
            // No-op for in-memory filesystem
            Ok(())
        })
    }

    fn stat<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            let node = self.get_node(path).await?;
            Ok(node.to_vfs_metadata())
        })
    }

    fn fstat<'a>(&'a self, handle: &'a FileHandle) -> BoxFuture<'a, Result<Metadata, VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            let info = handles.get(&handle.id).ok_or(VfsError::InvalidHandle)?;

            let path = info.path.clone();
            drop(handles);

            let node = self.get_node(&path).await?;
            Ok(node.to_vfs_metadata())
        })
    }

    fn chmod<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let mut root = self.root.write().await;

            let node = if path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path)),
                    }
                }
                current
            };

            let metadata = node.metadata_mut();
            metadata.mode = mode;
            metadata.ctime = SystemTime::now();
            Ok(())
        })
    }

    fn chown<'a>(
        &'a self,
        path: &'a str,
        uid: u32,
        gid: u32,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let mut root = self.root.write().await;

            let node = if path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path)),
                    }
                }
                current
            };

            let metadata = node.metadata_mut();
            metadata.uid = uid;
            metadata.gid = gid;
            metadata.ctime = SystemTime::now();
            Ok(())
        })
    }

    fn truncate<'a>(&'a self, path: &'a str, size: u64) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let mut root = self.root.write().await;

            let node = if path.is_empty() {
                return Err(VfsError::IsADirectory(path));
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path.clone())),
                    }
                }
                current
            };

            match node {
                MemoryNode::File {
                    content, metadata, ..
                } => {
                    content.resize(size as usize, 0);
                    metadata.mtime = SystemTime::now();
                    metadata.ctime = SystemTime::now();
                    Ok(())
                }
                MemoryNode::Directory { .. } => Err(VfsError::IsADirectory(path)),
                MemoryNode::Symlink { .. } => Err(VfsError::InvalidPath(path)),
            }
        })
    }

    fn utimes<'a>(
        &'a self,
        path: &'a str,
        atime: SystemTime,
        mtime: SystemTime,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let mut root = self.root.write().await;

            let node = if path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path)),
                    }
                }
                current
            };

            let metadata = node.metadata_mut();
            metadata.atime = atime;
            metadata.mtime = mtime;
            metadata.ctime = SystemTime::now();
            Ok(())
        })
    }

    fn mkdir<'a>(&'a self, path: &'a str, mode: u32) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            if path.is_empty() {
                return Err(VfsError::AlreadyExists("/".to_string()));
            }

            let (parent_path, dirname) =
                Self::split_path(&path).ok_or_else(|| VfsError::InvalidPath(path.clone()))?;

            let parent_path = Self::normalize_path(parent_path);
            let mut root = self.root.write().await;

            let parent = if parent_path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in parent_path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(parent_path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(parent_path)),
                    }
                }
                current
            };

            let children = match parent {
                MemoryNode::Directory { children, .. } => children,
                _ => return Err(VfsError::NotADirectory(parent_path)),
            };

            if children.contains_key(dirname) {
                return Err(VfsError::AlreadyExists(path));
            }

            let ino = self.next_inode();
            children.insert(
                dirname.to_string(),
                MemoryNode::Directory {
                    children: HashMap::new(),
                    metadata: NodeMetadata::new(mode, ino),
                    xattrs: HashMap::new(),
                },
            );

            Ok(())
        })
    }

    fn rmdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            if path.is_empty() {
                return Err(VfsError::InvalidPath("Cannot remove root".to_string()));
            }

            let (parent_path, dirname) =
                Self::split_path(&path).ok_or_else(|| VfsError::InvalidPath(path.clone()))?;

            let parent_path = Self::normalize_path(parent_path);
            let mut root = self.root.write().await;

            let parent = if parent_path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in parent_path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(parent_path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(parent_path)),
                    }
                }
                current
            };

            let children = match parent {
                MemoryNode::Directory { children, .. } => children,
                _ => return Err(VfsError::NotADirectory(parent_path)),
            };

            let node = children
                .get(dirname)
                .ok_or_else(|| VfsError::NotFound(path.clone()))?;

            match node {
                MemoryNode::Directory {
                    children: dir_children,
                    ..
                } => {
                    if !dir_children.is_empty() {
                        return Err(VfsError::DirectoryNotEmpty(path));
                    }
                }
                _ => return Err(VfsError::NotADirectory(path)),
            }

            children.remove(dirname);
            Ok(())
        })
    }

    fn readdir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<DirEntry>, VfsError>> {
        Box::pin(async move {
            let node = self.get_node(path).await?;

            match node {
                MemoryNode::Directory { children, .. } => {
                    let entries: Vec<DirEntry> = children
                        .iter()
                        .map(|(name, child)| DirEntry {
                            name: name.clone(),
                            metadata: child.to_vfs_metadata(),
                        })
                        .collect();
                    Ok(entries)
                }
                _ => Err(VfsError::NotADirectory(Self::normalize_path(path))),
            }
        })
    }

    fn unlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            if path.is_empty() {
                return Err(VfsError::InvalidPath("Cannot unlink root".to_string()));
            }

            let (parent_path, filename) =
                Self::split_path(&path).ok_or_else(|| VfsError::InvalidPath(path.clone()))?;

            let parent_path = Self::normalize_path(parent_path);
            let mut root = self.root.write().await;

            let parent = if parent_path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in parent_path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(parent_path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(parent_path)),
                    }
                }
                current
            };

            let children = match parent {
                MemoryNode::Directory { children, .. } => children,
                _ => return Err(VfsError::NotADirectory(parent_path)),
            };

            let node = children
                .get(filename)
                .ok_or_else(|| VfsError::NotFound(path.clone()))?;

            if matches!(node, MemoryNode::Directory { .. }) {
                return Err(VfsError::IsADirectory(path));
            }

            children.remove(filename);
            Ok(())
        })
    }

    fn rename<'a>(
        &'a self,
        old_path: &'a str,
        new_path: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let old_path = Self::normalize_path(old_path);
            let new_path_norm = Self::normalize_path(new_path);

            if old_path.is_empty() || new_path_norm.is_empty() {
                return Err(VfsError::InvalidPath("Cannot rename root".to_string()));
            }

            if old_path == new_path_norm {
                return Ok(());
            }

            let (old_parent_path, old_name) = Self::split_path(&old_path)
                .ok_or_else(|| VfsError::InvalidPath(old_path.clone()))?;
            let (new_parent_path, new_name) = Self::split_path(&new_path_norm)
                .ok_or_else(|| VfsError::InvalidPath(new_path_norm.clone()))?;

            let old_parent_path = Self::normalize_path(old_parent_path);
            let new_parent_path = Self::normalize_path(new_parent_path);

            let mut root = self.root.write().await;

            // First, extract the node from old location
            let node = {
                let old_parent = if old_parent_path.is_empty() {
                    &mut *root
                } else {
                    let mut current = &mut *root;
                    for component in old_parent_path.split('/') {
                        match current {
                            MemoryNode::Directory { children, .. } => {
                                current = children
                                    .get_mut(component)
                                    .ok_or_else(|| VfsError::NotFound(old_parent_path.clone()))?;
                            }
                            _ => return Err(VfsError::NotADirectory(old_parent_path.clone())),
                        }
                    }
                    current
                };

                let children = match old_parent {
                    MemoryNode::Directory { children, .. } => children,
                    _ => return Err(VfsError::NotADirectory(old_parent_path.clone())),
                };

                children
                    .remove(old_name)
                    .ok_or_else(|| VfsError::NotFound(old_path.clone()))?
            };

            // Then, insert at new location
            let new_parent = if new_parent_path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in new_parent_path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(new_parent_path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(new_parent_path.clone())),
                    }
                }
                current
            };

            let children = match new_parent {
                MemoryNode::Directory { children, .. } => children,
                _ => return Err(VfsError::NotADirectory(new_parent_path)),
            };

            children.insert(new_name.to_string(), node);
            Ok(())
        })
    }

    fn link<'a>(&'a self, _src: &'a str, _dst: &'a str) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            // Hard links not fully supported in this simple in-memory implementation
            Err(VfsError::NotSupported(
                "Hard links not supported".to_string(),
            ))
        })
    }

    fn symlink<'a>(
        &'a self,
        target: &'a str,
        linkpath: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let linkpath = Self::normalize_path(linkpath);
            if linkpath.is_empty() {
                return Err(VfsError::InvalidPath(
                    "Cannot create symlink at root".to_string(),
                ));
            }

            let (parent_path, linkname) = Self::split_path(&linkpath)
                .ok_or_else(|| VfsError::InvalidPath(linkpath.clone()))?;

            let parent_path = Self::normalize_path(parent_path);
            let mut root = self.root.write().await;

            let parent = if parent_path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in parent_path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(parent_path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(parent_path)),
                    }
                }
                current
            };

            let children = match parent {
                MemoryNode::Directory { children, .. } => children,
                _ => return Err(VfsError::NotADirectory(parent_path)),
            };

            if children.contains_key(linkname) {
                return Err(VfsError::AlreadyExists(linkpath));
            }

            let ino = self.next_inode();
            children.insert(
                linkname.to_string(),
                MemoryNode::Symlink {
                    target: target.to_string(),
                    metadata: NodeMetadata::new(0o777, ino),
                },
            );

            Ok(())
        })
    }

    fn readlink<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<String, VfsError>> {
        Box::pin(async move {
            let node = self.get_node(path).await?;

            match node {
                MemoryNode::Symlink { target, .. } => Ok(target),
                _ => Err(VfsError::InvalidPath("Not a symlink".to_string())),
            }
        })
    }

    fn lock<'a>(
        &'a self,
        handle: &'a FileHandle,
        lock: FileLock,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            if !handles.contains_key(&handle.id) {
                return Err(VfsError::InvalidHandle);
            }
            drop(handles);

            let mut locks = self.locks.write().await;
            let handle_locks = locks.entry(handle.id).or_default();

            // Check for conflicts with existing locks
            for existing in handle_locks.iter() {
                // Check overlap
                let existing_end = if existing.length == 0 {
                    u64::MAX
                } else {
                    existing.start + existing.length
                };
                let new_end = if lock.length == 0 {
                    u64::MAX
                } else {
                    lock.start + lock.length
                };

                if lock.start < existing_end && new_end > existing.start {
                    // Overlap detected
                    if existing.lock_type == LockType::Exclusive
                        || lock.lock_type == LockType::Exclusive
                    {
                        return Err(VfsError::LockConflict);
                    }
                }
            }

            handle_locks.push(lock);
            Ok(())
        })
    }

    fn unlock<'a>(
        &'a self,
        handle: &'a FileHandle,
        lock: FileLock,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let handles = self.handles.read().await;
            if !handles.contains_key(&handle.id) {
                return Err(VfsError::InvalidHandle);
            }
            drop(handles);

            let mut locks = self.locks.write().await;
            if let Some(handle_locks) = locks.get_mut(&handle.id) {
                handle_locks.retain(|l| !(l.start == lock.start && l.length == lock.length));
            }

            Ok(())
        })
    }

    fn getxattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<u8>, VfsError>> {
        Box::pin(async move {
            let node = self.get_node(path).await?;

            let xattrs = node.xattrs().ok_or_else(|| {
                VfsError::NotSupported("No xattr support for symlinks".to_string())
            })?;

            xattrs
                .get(name)
                .cloned()
                .ok_or_else(|| VfsError::NotFound(format!("xattr: {}", name)))
        })
    }

    fn setxattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
        value: &'a [u8],
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let mut root = self.root.write().await;

            let node = if path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path)),
                    }
                }
                current
            };

            let xattrs = node.xattrs_mut().ok_or_else(|| {
                VfsError::NotSupported("No xattr support for symlinks".to_string())
            })?;

            xattrs.insert(name.to_string(), value.to_vec());
            Ok(())
        })
    }

    fn listxattr<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Result<Vec<String>, VfsError>> {
        Box::pin(async move {
            let node = self.get_node(path).await?;

            let xattrs = node.xattrs().ok_or_else(|| {
                VfsError::NotSupported("No xattr support for symlinks".to_string())
            })?;

            Ok(xattrs.keys().cloned().collect())
        })
    }

    fn removexattr<'a>(
        &'a self,
        path: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<(), VfsError>> {
        Box::pin(async move {
            let path = Self::normalize_path(path);
            let mut root = self.root.write().await;

            let node = if path.is_empty() {
                &mut *root
            } else {
                let mut current = &mut *root;
                for component in path.split('/') {
                    match current {
                        MemoryNode::Directory { children, .. } => {
                            current = children
                                .get_mut(component)
                                .ok_or_else(|| VfsError::NotFound(path.clone()))?;
                        }
                        _ => return Err(VfsError::NotADirectory(path)),
                    }
                }
                current
            };

            let xattrs = node.xattrs_mut().ok_or_else(|| {
                VfsError::NotSupported("No xattr support for symlinks".to_string())
            })?;

            xattrs
                .remove(name)
                .ok_or_else(|| VfsError::NotFound(format!("xattr: {}", name)))?;

            Ok(())
        })
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            locking: true,
            notify: false,
            sparse: false,
            xattr: true,
            hard_links: false,
            symlinks: true,
            max_file_size: u64::MAX,
            max_path_length: 4096,
            case_sensitive: true,
            atomic_rename: true,
        }
    }

    fn statfs(&self) -> BoxFuture<'_, Result<FsStats, VfsError>> {
        Box::pin(async move {
            Ok(FsStats {
                blocks: u64::MAX,
                blocks_free: u64::MAX,
                blocks_available: u64::MAX,
                block_size: 4096,
                files: u64::MAX,
                files_free: u64::MAX,
                fsid: 0x4D454D4F, // "MEMO" in hex
                namelen: 255,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustsmb_vfs::{access_mask, disposition};

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
        let backend = MemoryBackend::new();

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
        let backend = MemoryBackend::new();

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
        let backend = MemoryBackend::new();

        // Create target file
        let params = create_params_rw_create();
        let handle = backend.open("target.txt", &params).await.unwrap();
        backend.close(handle).await.unwrap();

        // Create symlink
        backend.symlink("target.txt", "link.txt").await.unwrap();

        // Read symlink
        let target = backend.readlink("link.txt").await.unwrap();
        assert_eq!(target, "target.txt");
    }

    #[tokio::test]
    async fn test_rename() {
        let backend = MemoryBackend::new();

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
    async fn test_xattr() {
        let backend = MemoryBackend::new();

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
        assert_eq!(attrs, vec!["user.test"]);

        // Remove xattr
        backend.removexattr("test.txt", "user.test").await.unwrap();
        assert!(backend.getxattr("test.txt", "user.test").await.is_err());
    }

    #[tokio::test]
    async fn test_file_locking() {
        let backend = MemoryBackend::new();

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();

        // Acquire lock
        let lock = FileLock {
            lock_type: LockType::Exclusive,
            start: 0,
            length: 100,
            pid: 1234,
        };
        backend.lock(&handle, lock).await.unwrap();

        // Conflicting lock should fail
        let lock2 = FileLock {
            lock_type: LockType::Shared,
            start: 50,
            length: 100,
            pid: 5678,
        };
        assert!(backend.lock(&handle, lock2).await.is_err());

        // Non-overlapping lock should succeed
        let lock3 = FileLock {
            lock_type: LockType::Exclusive,
            start: 200,
            length: 100,
            pid: 5678,
        };
        backend.lock(&handle, lock3).await.unwrap();

        // Unlock
        backend.unlock(&handle, lock).await.unwrap();

        backend.close(handle).await.unwrap();
    }

    #[tokio::test]
    async fn test_truncate() {
        let backend = MemoryBackend::new();

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
    async fn test_chmod_chown() {
        let backend = MemoryBackend::new();

        // Create file
        let params = create_params_rw_create();
        let handle = backend.open("test.txt", &params).await.unwrap();
        backend.close(handle).await.unwrap();

        // Change mode
        backend.chmod("test.txt", 0o755).await.unwrap();
        let meta = backend.stat("test.txt").await.unwrap();
        assert_eq!(meta.mode, 0o755);

        // Change owner
        backend.chown("test.txt", 1000, 1000).await.unwrap();
        let meta = backend.stat("test.txt").await.unwrap();
        assert_eq!(meta.uid, 1000);
        assert_eq!(meta.gid, 1000);
    }

    #[tokio::test]
    async fn test_nested_directories() {
        let backend = MemoryBackend::new();

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
}
