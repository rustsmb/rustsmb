# RustSMB Architecture

## Overview

RustSMB is a stateless SMB2/SMB3 server implemented in Rust, designed for high availability deployments with pluggable storage backends.

## Design Goals

1. **Stateless Gateway**: All session state externalized for HA failover
2. **Pluggable Storage**: Abstract backend interface for different storage systems
3. **Protocol Compliance**: Full SMB2.1/3.0/3.0.2/3.1.1 support
4. **Performance**: Async I/O with tokio, zero-copy where possible
5. **Safety**: Leverage Rust's type system for correctness

## High-Level Architecture

### Multi-Node Deployment

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │  (TCP L4)       │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  RustSMB #1   │    │  RustSMB #2   │    │  RustSMB #N   │
│  (Stateless)  │    │  (Stateless)  │    │  (Stateless)  │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ State Store   │    │ Storage       │    │ Auth          │
│ (Redis)       │    │ Backend       │    │ Provider      │
│               │    │ (Shared FS)   │    │ (LDAP/Local)  │
└───────────────┘    └───────────────┘    └───────────────┘
```

### Single Node Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         rustsmb (binary)                        │
├─────────────────────────────────────────────────────────────────┤
│                    rustsmb-server                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ TCP Listener│  │ TLS Handler │  │ Share Mgr   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│                    rustsmb-protocol                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Header Parse│  │ Cmd Dispatch│  │ Crypto      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│  rustsmb-session        │  rustsmb-auth                        │
│  ┌─────────────┐        │  ┌─────────────┐                     │
│  │ Conn State  │        │  │ NTLM        │                     │
│  │ (Stateless) │        │  │ Simple      │                     │
│  └─────────────┘        │  └─────────────┘                     │
├─────────────────────────┴───────────────────────────────────────┤
│  rustsmb-state                      │  rustsmb-vfs             │
│  ┌─────────────┐  ┌─────────────┐   │  ┌─────────────┐         │
│  │ Memory Store│  │ Redis Store │   │  │ Backend Trait│        │
│  └─────────────┘  └─────────────┘   │  └─────────────┘         │
├─────────────────────────────────────┴───────────────────────────┤
│  Storage Backends                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Local FS    │  │ Memory FS   │  │ (Future)    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│                    rustsmb-core                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Error Types │  │ NT_STATUS   │  │ Common Types│             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## Core Traits

### StorageBackend (rustsmb-vfs)

POSIX-like interface for storage operations:

```rust
pub trait StorageBackend: Send + Sync + 'static {
    // File operations
    fn open(&self, path: &str, flags: OpenFlags, mode: u32)
        -> BoxFuture<Result<FileHandle, VfsError>>;
    fn read(&self, handle: &FileHandle, buf: &mut [u8], offset: u64)
        -> BoxFuture<Result<usize, VfsError>>;
    fn write(&self, handle: &FileHandle, buf: &[u8], offset: u64)
        -> BoxFuture<Result<usize, VfsError>>;
    fn close(&self, handle: FileHandle)
        -> BoxFuture<Result<(), VfsError>>;
    fn fsync(&self, handle: &FileHandle)
        -> BoxFuture<Result<(), VfsError>>;

    // Metadata operations
    fn stat(&self, path: &str)
        -> BoxFuture<Result<Metadata, VfsError>>;
    fn fstat(&self, handle: &FileHandle)
        -> BoxFuture<Result<Metadata, VfsError>>;
    fn chmod(&self, path: &str, mode: u32)
        -> BoxFuture<Result<(), VfsError>>;
    fn chown(&self, path: &str, uid: u32, gid: u32)
        -> BoxFuture<Result<(), VfsError>>;
    fn truncate(&self, path: &str, size: u64)
        -> BoxFuture<Result<(), VfsError>>;
    fn utimes(&self, path: &str, atime: SystemTime, mtime: SystemTime)
        -> BoxFuture<Result<(), VfsError>>;

    // Directory operations
    fn mkdir(&self, path: &str, mode: u32)
        -> BoxFuture<Result<(), VfsError>>;
    fn rmdir(&self, path: &str)
        -> BoxFuture<Result<(), VfsError>>;
    fn readdir(&self, path: &str)
        -> BoxFuture<Result<Vec<DirEntry>, VfsError>>;

    // Link operations
    fn unlink(&self, path: &str)
        -> BoxFuture<Result<(), VfsError>>;
    fn rename(&self, old_path: &str, new_path: &str)
        -> BoxFuture<Result<(), VfsError>>;
    fn link(&self, src: &str, dst: &str)
        -> BoxFuture<Result<(), VfsError>>;
    fn symlink(&self, target: &str, linkpath: &str)
        -> BoxFuture<Result<(), VfsError>>;
    fn readlink(&self, path: &str)
        -> BoxFuture<Result<String, VfsError>>;

    // Locking
    fn lock(&self, handle: &FileHandle, lock: FileLock)
        -> BoxFuture<Result<(), VfsError>>;
    fn unlock(&self, handle: &FileHandle, lock: FileLock)
        -> BoxFuture<Result<(), VfsError>>;

    // Extended attributes (optional)
    fn getxattr(&self, path: &str, name: &str)
        -> BoxFuture<Result<Vec<u8>, VfsError>>;
    fn setxattr(&self, path: &str, name: &str, value: &[u8])
        -> BoxFuture<Result<(), VfsError>>;
    fn listxattr(&self, path: &str)
        -> BoxFuture<Result<Vec<String>, VfsError>>;
    fn removexattr(&self, path: &str, name: &str)
        -> BoxFuture<Result<(), VfsError>>;

    // Capabilities
    fn capabilities(&self) -> BackendCapabilities;
    fn statfs(&self) -> BoxFuture<Result<FsStats, VfsError>>;
}
```

### StateStore (rustsmb-state)

External state storage for HA support:

```rust
pub trait StateStore: Send + Sync + 'static {
    // Session management
    fn create_session(&self, session: &SessionState)
        -> BoxFuture<Result<(), StateError>>;
    fn get_session(&self, session_id: u64)
        -> BoxFuture<Result<Option<SessionState>, StateError>>;
    fn update_session(&self, session: &SessionState)
        -> BoxFuture<Result<(), StateError>>;
    fn delete_session(&self, session_id: u64)
        -> BoxFuture<Result<(), StateError>>;
    fn refresh_session(&self, session_id: u64, ttl: Duration)
        -> BoxFuture<Result<(), StateError>>;

    // Tree connection management
    fn create_tree(&self, tree: &TreeState)
        -> BoxFuture<Result<(), StateError>>;
    fn get_tree(&self, session_id: u64, tree_id: u32)
        -> BoxFuture<Result<Option<TreeState>, StateError>>;
    fn get_trees_by_session(&self, session_id: u64)
        -> BoxFuture<Result<Vec<TreeState>, StateError>>;
    fn delete_tree(&self, session_id: u64, tree_id: u32)
        -> BoxFuture<Result<(), StateError>>;

    // Handle management (for durable handles)
    fn create_handle(&self, handle: &HandleState)
        -> BoxFuture<Result<(), StateError>>;
    fn get_handle(&self, persistent_id: u128)
        -> BoxFuture<Result<Option<HandleState>, StateError>>;
    fn get_handles_by_session(&self, session_id: u64)
        -> BoxFuture<Result<Vec<HandleState>, StateError>>;
    fn delete_handle(&self, persistent_id: u128)
        -> BoxFuture<Result<(), StateError>>;

    // Lock management
    fn create_lock(&self, lock: &LockState)
        -> BoxFuture<Result<(), StateError>>;
    fn get_locks(&self, persistent_id: u128)
        -> BoxFuture<Result<Vec<LockState>, StateError>>;
    fn delete_lock(&self, lock_id: u64)
        -> BoxFuture<Result<(), StateError>>;

    // Distributed locking (for multi-node coordination)
    fn acquire_distributed_lock(&self, key: &str, ttl: Duration)
        -> BoxFuture<Result<Option<String>, StateError>>;  // Returns lock token
    fn release_distributed_lock(&self, key: &str, token: &str)
        -> BoxFuture<Result<(), StateError>>;
    fn extend_distributed_lock(&self, key: &str, token: &str, ttl: Duration)
        -> BoxFuture<Result<bool, StateError>>;

    // ID generation
    fn next_session_id(&self) -> BoxFuture<Result<u64, StateError>>;
    fn next_tree_id(&self, session_id: u64) -> BoxFuture<Result<u32, StateError>>;
    fn next_handle_id(&self) -> BoxFuture<Result<u128, StateError>>;
}
```

### AuthProvider (rustsmb-auth)

Authentication abstraction:

```rust
pub trait AuthProvider: Send + Sync + 'static {
    fn authenticate(&self, context: &mut AuthContext, token: &[u8])
        -> BoxFuture<Result<AuthResult, AuthError>>;

    fn get_user(&self, username: &str, domain: Option<&str>)
        -> BoxFuture<Result<Option<UserInfo>, AuthError>>;

    fn validate_session_key(&self, session_id: u64, key: &[u8])
        -> BoxFuture<Result<bool, AuthError>>;

    fn supported_mechanisms(&self) -> Vec<AuthMechanism>;
}

pub enum AuthResult {
    Success { user: UserInfo, session_key: Vec<u8> },
    Continue { response_token: Vec<u8> },
    Failure { reason: AuthError },
}
```

## Data Flow

### Request Processing

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ TCP Read │────▶│ Parse    │────▶│ Verify   │────▶│ Lookup   │
│          │     │ Header   │     │ Signature│     │ Session  │
└──────────┘     └──────────┘     └──────────┘     └────┬─────┘
                                                        │
     ┌──────────────────────────────────────────────────┘
     ▼
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Dispatch │────▶│ Execute  │────▶│ Build    │────▶│ Sign &   │
│ Command  │     │ Handler  │     │ Response │     │ Send     │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                      │
                      ▼
               ┌──────────────┐
               │ VFS / State  │
               │ Operations   │
               └──────────────┘
```

### Session Establishment

```
Client                    RustSMB                   StateStore
   │                         │                          │
   │── NEGOTIATE ───────────▶│                          │
   │                         │                          │
   │◀── NEGOTIATE Response ──│                          │
   │                         │                          │
   │── SESSION_SETUP(1) ────▶│                          │
   │   (NTLM Negotiate)      │                          │
   │                         │── next_session_id() ────▶│
   │                         │◀─────────────────────────│
   │◀── More Processing ─────│                          │
   │   (NTLM Challenge)      │                          │
   │                         │                          │
   │── SESSION_SETUP(2) ────▶│                          │
   │   (NTLM Auth)           │                          │
   │                         │── create_session() ─────▶│
   │                         │◀─────────────────────────│
   │◀── Success ─────────────│                          │
   │   (SessionId)           │                          │
```

## SMB2 Protocol Handling

### Header Structure (64 bytes)

```rust
#[derive(BinRead, BinWrite)]
#[brw(little)]
pub struct Smb2Header {
    #[brw(magic = b"\xFESMB")]
    magic: (),
    structure_size: u16,      // Must be 64
    credit_charge: u16,
    status: NtStatus,
    command: Smb2Command,
    credits: u16,
    flags: Smb2Flags,
    next_command: u32,
    message_id: u64,
    reserved: u32,
    tree_id: u32,
    session_id: u64,
    signature: [u8; 16],
}
```

### Command Dispatch

```rust
impl CommandDispatcher {
    pub async fn dispatch(
        &self,
        conn: &Connection,
        header: &Smb2Header,
        body: &[u8],
    ) -> Result<Response, SmbError> {
        match header.command {
            Smb2Command::Negotiate => self.negotiate(conn, body).await,
            Smb2Command::SessionSetup => self.session_setup(conn, header, body).await,
            Smb2Command::TreeConnect => self.tree_connect(conn, header, body).await,
            Smb2Command::Create => self.create(conn, header, body).await,
            Smb2Command::Read => self.read(conn, header, body).await,
            Smb2Command::Write => self.write(conn, header, body).await,
            Smb2Command::Close => self.close(conn, header, body).await,
            // ... other commands
        }
    }
}
```

## Error Handling

### Error Hierarchy

```
SmbError
├── Protocol(ProtocolError)
│   ├── InvalidHeader
│   ├── UnknownCommand
│   ├── SignatureInvalid
│   └── DecryptionFailed
├── Auth(AuthError)
│   ├── InvalidCredentials
│   ├── AccountDisabled
│   └── UnsupportedMechanism
├── Vfs(VfsError)
│   ├── NotFound
│   ├── AccessDenied
│   ├── AlreadyExists
│   └── Io(std::io::Error)
├── State(StateError)
│   ├── ConnectionFailed
│   ├── Timeout
│   └── SerializationError
└── Session(SessionError)
    ├── InvalidSessionId
    ├── InvalidTreeId
    └── SessionExpired
```

### NT_STATUS Mapping

```rust
impl From<&VfsError> for NtStatus {
    fn from(err: &VfsError) -> Self {
        match err {
            VfsError::NotFound(_) => NtStatus::ObjectNameNotFound,
            VfsError::AccessDenied(_) => NtStatus::AccessDenied,
            VfsError::AlreadyExists(_) => NtStatus::ObjectNameCollision,
            VfsError::NotADirectory(_) => NtStatus::NotADirectory,
            VfsError::IsADirectory(_) => NtStatus::FileIsADirectory,
            VfsError::DirectoryNotEmpty(_) => NtStatus::DirectoryNotEmpty,
            VfsError::DiskFull => NtStatus::DiskFull,
            VfsError::SharingViolation(_) => NtStatus::SharingViolation,
            VfsError::LockConflict => NtStatus::FileLockConflict,
            _ => NtStatus::InternalError,
        }
    }
}
```

## Security

### Signing (SMB 3.0+)

- Session key derived during NTLM authentication
- AES-CMAC (SMB 3.0) or AES-GMAC (SMB 3.1.1)
- Signature placed in header's 16-byte signature field

### Encryption (SMB 3.0+)

- Transform header with 0xFD 'S' 'M' 'B' signature
- AES-128-CCM (SMB 3.0) or AES-128/256-GCM (SMB 3.1.1)
- Per-session or per-share encryption

### Session Key Storage

Session keys stored encrypted in StateStore:

```rust
pub struct SessionState {
    pub session_id: u64,
    pub user_id: String,
    pub session_key_encrypted: Vec<u8>,  // Encrypted with server master key
    pub dialect: SmbDialect,
    pub signing_required: bool,
    pub encryption_required: bool,
    pub created_at: u64,
    pub expires_at: u64,
}
```

## Configuration

### Server Configuration

```toml
[server]
listen = "0.0.0.0:445"
tls_enabled = false
max_connections = 1000
worker_threads = 4

[session]
timeout = "1h"
max_sessions_per_connection = 16

[state]
backend = "redis"  # or "memory"

[state.redis]
url = "redis://localhost:6379"
pool_size = 10

[auth]
provider = "simple"  # or "ntlm", "ldap"

[auth.simple]
users_file = "/etc/rustsmb/users.toml"

[[shares]]
name = "public"
path = "/srv/samba/public"
read_only = false
guest_ok = true

[[shares]]
name = "private"
path = "/srv/samba/private"
valid_users = ["alice", "bob"]
```

## Testing Strategy

### Unit Tests

Each crate has comprehensive unit tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse() {
        let bytes = include_bytes!("../testdata/negotiate_request.bin");
        let header = Smb2Header::read(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(header.command, Smb2Command::Negotiate);
    }

    #[tokio::test]
    async fn test_memory_backend_read_write() {
        let backend = MemoryBackend::new();
        let handle = backend.open("/test.txt", OpenFlags::CREATE, 0o644).await.unwrap();
        backend.write(&handle, b"hello", 0).await.unwrap();

        let mut buf = [0u8; 5];
        backend.read(&handle, &mut buf, 0).await.unwrap();
        assert_eq!(&buf, b"hello");
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_session_flow() {
    let server = TestServer::start().await;
    let mut client = SmbClient::connect(server.addr()).await.unwrap();

    client.negotiate().await.unwrap();
    client.session_setup("guest", "").await.unwrap();
    let tree_id = client.tree_connect("\\\\localhost\\public").await.unwrap();

    let file = client.create(tree_id, "test.txt", CreateFlags::CREATE).await.unwrap();
    client.write(file, b"test data").await.unwrap();
    client.close(file).await.unwrap();

    client.tree_disconnect(tree_id).await.unwrap();
    client.logoff().await.unwrap();
}
```

### Interoperability Tests

```bash
# Test with smbclient
smbclient //localhost/public -N -c "put testfile.txt"

# Test with Windows
net use Z: \\server\share /user:guest
```

## Performance Considerations

1. **Zero-copy reads**: Use `sendfile` for large transfers
2. **Connection pooling**: Reuse Redis connections via deadpool
3. **Async I/O**: Non-blocking operations throughout
4. **Buffer management**: Pre-allocated buffers for protocol messages
5. **Batch state updates**: Coalesce StateStore writes where possible
