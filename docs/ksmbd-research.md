# Linux Kernel ksmbd Research

## Overview

ksmbd (kernel SMB daemon) is the in-kernel SMB3 server implementation in Linux, designed for high performance file sharing. It was merged into the mainline kernel in version 5.15.

## Architecture

### Split Architecture Model

ksmbd follows a split architecture where:

1. **Kernel Space (ksmbd.ko)**: Handles performance-critical operations
   - Protocol parsing and message handling
   - File I/O operations via VFS
   - Connection and session management
   - Signing and encryption

2. **User Space (ksmbd.mountd)**: Handles configuration and management
   - Configuration file parsing (smb.conf equivalent)
   - User/password database management
   - Share definitions
   - IPC with kernel module via netlink

### Key Insight

> "The subset of performance related operations belong in kernelspace and the other subset which belong to operations which are not really related with performance in userspace."

This principle guides our design: keep the hot path (protocol handling + I/O) optimized, while configuration can be handled separately.

## Kernel Module Components

### Connection Management

```
struct ksmbd_conn {
    struct socket *sock;
    enum conn_status status;
    struct list_head requests;
    struct list_head sessions;
    // ... transport info, credits, etc.
}
```

- One `ksmbd_conn` per TCP connection
- Maintains list of active sessions
- Handles request queuing and credit management

### Session Management

```
struct ksmbd_session {
    u64 id;
    struct ksmbd_user *user;
    unsigned int state;
    char sess_key[CIFS_SESS_KEY_SIZE];
    struct list_head tree_conns;
    // ... encryption keys, etc.
}
```

- Authenticated user session
- Contains session key for signing/encryption
- Manages tree connections (shares)

### Tree Connection

```
struct ksmbd_tree_connect {
    int id;
    struct ksmbd_share_config *share_conf;
    struct ksmbd_session *session;
    // ... flags, etc.
}
```

- Represents connection to a specific share
- Links to share configuration

### File Handle (ksmbd_file)

```
struct ksmbd_file {
    struct file *filp;          // VFS file pointer
    u64 persistent_id;          // SMB persistent file ID
    u64 volatile_id;            // SMB volatile file ID
    struct ksmbd_inode *inode;  // Internal inode tracking
    // ... oplock info, etc.
}
```

## Request Processing Flow

```
TCP Packet Received
        │
        ▼
┌───────────────────┐
│ ksmbd_conn_handler│  (kernel thread per connection)
│ ksmbd_recv_pdu()  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Parse SMB2 Header │
│  Verify Signature  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Dispatch to       │
│ Command Handler   │
│ (smb2_negotiate,  │
│  smb2_create, etc)│
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ VFS Operations    │
│ (vfs_read, etc.)  │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│ Build Response    │
│ Sign if needed    │
│ Send to client    │
└───────────────────┘
```

## VFS Integration

ksmbd uses the kernel's VFS (Virtual File System) layer for all file operations:

```c
// Example: smb2_open() flow
smb2_open()
    └── ksmbd_vfs_create()
            └── vfs_create()  // kernel VFS

// Example: smb2_read() flow
smb2_read()
    └── ksmbd_vfs_read()
            └── kernel_read()  // kernel VFS
```

### Key VFS Functions Used

| ksmbd Function | Kernel VFS Function |
|---------------|---------------------|
| ksmbd_vfs_create | vfs_create |
| ksmbd_vfs_mkdir | vfs_mkdir |
| ksmbd_vfs_read | kernel_read |
| ksmbd_vfs_write | kernel_write |
| ksmbd_vfs_getattr | vfs_getattr |
| ksmbd_vfs_setattr | notify_change |
| ksmbd_vfs_unlink | vfs_unlink |
| ksmbd_vfs_rename | vfs_rename |

## SMB2 Command Handlers

Located in `fs/smb/server/smb2pdu.c`:

```c
int (*smb2_cmd_handlers[])(struct ksmbd_work *work) = {
    [SMB2_NEGOTIATE]        = smb2_negotiate,
    [SMB2_SESSION_SETUP]    = smb2_session_setup,
    [SMB2_TREE_CONNECT]     = smb2_tree_connect,
    [SMB2_TREE_DISCONNECT]  = smb2_tree_disconnect,
    [SMB2_LOGOFF]           = smb2_session_logoff,
    [SMB2_CREATE]           = smb2_open,
    [SMB2_CLOSE]            = smb2_close,
    [SMB2_FLUSH]            = smb2_flush,
    [SMB2_READ]             = smb2_read,
    [SMB2_WRITE]            = smb2_write,
    [SMB2_LOCK]             = smb2_lock,
    [SMB2_IOCTL]            = smb2_ioctl,
    [SMB2_CANCEL]           = smb2_cancel,
    [SMB2_ECHO]             = smb2_echo,
    [SMB2_QUERY_DIRECTORY]  = smb2_query_dir,
    [SMB2_CHANGE_NOTIFY]    = smb2_notify,
    [SMB2_QUERY_INFO]       = smb2_query_info,
    [SMB2_SET_INFO]         = smb2_set_info,
    [SMB2_OPLOCK_BREAK]     = smb2_oplock_break,
};
```

## Security Features

### Signing (SMB 3.0+)

- Uses AES-CMAC for SMB 3.0
- Uses AES-GMAC for SMB 3.1.1
- Session key derived during authentication

### Encryption (SMB 3.0+)

- AES-128-CCM for SMB 3.0
- AES-128-GCM or AES-256-GCM for SMB 3.1.1
- Transform header with 0xFD signature

### Pre-auth Integrity (SMB 3.1.1)

- SHA-512 hash of negotiate messages
- Prevents downgrade attacks

## Oplock/Lease Management

```c
struct oplock_info {
    struct ksmbd_session *sess;
    struct ksmbd_file *o_fp;
    int level;              // OPLOCK_NONE, OPLOCK_EXCLUSIVE, etc.
    struct lease *o_lease;  // SMB2 lease info
};
```

Lease types:
- R-lease: Read caching
- RW-lease: Read + Write caching
- RWH-lease: Read + Write + Handle caching

## Differences from Samba

| Aspect | ksmbd | Samba |
|--------|-------|-------|
| Location | Kernel | Userspace |
| Performance | Higher (no context switches) | Lower |
| Complexity | Simpler (SMB2/3 only) | Full feature set |
| SMB1 | Not supported | Supported |
| Printing | Not supported | Supported |
| AD DC | Not supported | Supported |

## Implications for RustSMB

### What to Adopt

1. **Command dispatch pattern**: Use function table for command routing
2. **Session/Tree/File hierarchy**: Maintain same object relationships
3. **VFS abstraction**: Clean interface between protocol and storage
4. **Split configuration**: Separate config from protocol handling

### What to Adapt

1. **Async instead of threads**: Use tokio instead of kernel threads
2. **Trait-based VFS**: Use Rust traits instead of function pointers
3. **State externalization**: Support external state store for HA
4. **Error types**: Use Rust's Result instead of errno

### Key Data Structures to Port

```rust
// Connection (equivalent to ksmbd_conn)
pub struct Connection {
    pub id: u64,
    pub peer_addr: SocketAddr,
    pub dialect: SmbDialect,
    pub state: ConnectionState,
    // No sessions stored - fetched from StateStore
}

// Session (equivalent to ksmbd_session)
pub struct SessionState {
    pub session_id: u64,
    pub user_id: String,
    pub session_key: Vec<u8>,
    pub dialect: SmbDialect,
    // Stored in StateStore for HA
}

// Tree Connect (equivalent to ksmbd_tree_connect)
pub struct TreeState {
    pub tree_id: u32,
    pub session_id: u64,
    pub share_name: String,
    pub access_flags: u32,
}

// File Handle (equivalent to ksmbd_file)
pub struct HandleState {
    pub persistent_id: u128,
    pub volatile_id: u128,
    pub tree_id: u32,
    pub session_id: u64,
    pub path: String,
    pub access_mask: u32,
}
```

## Source Files Reference

Key ksmbd source files in Linux kernel:

```
fs/smb/server/
├── connection.c      # Connection handling
├── session.c         # Session management
├── smb2pdu.c         # SMB2 command handlers (main file)
├── smb2ops.c         # SMB2 operation dispatch
├── vfs.c             # VFS wrapper functions
├── oplock.c          # Oplock/lease management
├── auth.c            # Authentication
├── crypto.c          # Signing/encryption
├── transport_tcp.c   # TCP transport
└── server.c          # Main server initialization
```

## References

- [Kernel Documentation](https://docs.kernel.org/filesystems/smb/ksmbd.html)
- [Samba Wiki - ksmbd](https://wiki.samba.org/index.php/Linux_Kernel_Server)
- [LWN Article on ksmbd](https://lwn.net/Articles/858216/)
- [ksmbd-tools Repository](https://github.com/cifsd-team/ksmbd-tools)
