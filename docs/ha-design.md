# RustSMB High Availability Design

## Overview

This document describes the high availability (HA) architecture for RustSMB, enabling stateless SMB server deployments with seamless client failover.

**Key Features:**
- Stateless servers - all session state stored externally
- Session binding - clients can reconnect to different servers without re-authenticating
- Shared state via Redis - enables horizontal scaling
- Transparent failover - minimal disruption to active operations

## Architecture

### Stateless Server Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Load Balancer                                │
│                    (HAProxy, nginx, etc.)                           │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
    │Server A │          │Server B │          │Server C │
    │ :445    │          │ :445    │          │ :445    │
    └────┬────┘          └────┬────┘          └────┬────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Redis Cluster   │
                    │   (State Store)   │
                    └───────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Shared Storage   │
                    │  (NFS, S3, etc.)  │
                    └───────────────────┘
```

RustSMB servers are designed to be **stateless** - they do not hold any session state locally. All state is persisted to an external StateStore (Redis in production), enabling:

1. **Horizontal scaling** - Add/remove servers without affecting clients
2. **Fault tolerance** - Any server can handle any client session
3. **Rolling upgrades** - Update servers one at a time with zero downtime

### State Components

The StateStore persists four types of state:

| Component | Description | TTL |
|-----------|-------------|-----|
| `SessionState` | User credentials, session key, flags | 1 hour |
| `TreeState` | Share connections (session → share mapping) | Session TTL |
| `HandleState` | File handles with persistent IDs | Session TTL |
| `LockState` | Byte-range locks | Until released |

#### SessionState

```rust
pub struct SessionState {
    pub session_id: u64,          // Unique identifier
    pub user_id: String,          // Username
    pub domain: Option<String>,   // Domain (for AD auth)
    pub session_key: Vec<u8>,     // Encrypted session key
    pub dialect: SmbDialect,      // Negotiated SMB version
    pub signing_required: bool,   // Security flags
    pub encryption_required: bool,
    pub is_guest: bool,           // Guest session flag
    pub created_at: u64,          // Unix timestamp
    pub last_access: u64,         // Last activity
    pub expires_at: u64,          // TTL expiration
}
```

#### TreeState

```rust
pub struct TreeState {
    pub tree_id: u32,             // Per-session tree ID
    pub session_id: u64,          // Parent session
    pub share_name: String,       // Share name
    pub share_path: String,       // Backend path
    pub access_flags: u32,        // Access permissions
    pub is_dfs: bool,             // DFS flag
}
```

#### HandleState

```rust
pub struct HandleState {
    pub persistent_id: u128,      // Survives failover
    pub volatile_id: u128,        // Per-connection ID
    pub tree_id: u32,             // Parent tree
    pub session_id: u64,          // Parent session
    pub path: String,             // File path
    pub access_mask: u32,         // Access permissions
    pub share_access: u32,        // Share flags
    pub create_options: u32,      // Creation flags
    pub is_durable: bool,         // Durable handle support
    pub is_persistent: bool,      // Persistent handle support
    pub created_at: u64,
    pub last_access: u64,
}
```

## SMB Session Binding Protocol

Session binding is the SMB2/SMB3 protocol feature that enables seamless failover. It is defined in MS-SMB2 Section 3.2.4.2.4.

### How It Works

1. Client authenticates to Server A, receives `session_id`
2. Server A stores session state in Redis
3. Server A crashes or becomes unavailable
4. Client detects connection loss
5. Client connects to Server B
6. Client sends SESSION_SETUP with `SESSION_BINDING` flag
7. Server B looks up session in Redis
8. If valid, session is bound to new connection
9. Client continues operations with same `session_id`

### Protocol Details

**SESSION_SETUP Request (for binding):**
```
SessionSetupRequest {
    structure_size: 25,
    flags: SESSION_BINDING (0x01),     // Binding flag set
    security_mode: ...,
    capabilities: ...,
    channel: 0,
    security_buffer_offset: ...,
    security_buffer_length: ...,
    previous_session_id: <existing_session_id>,  // Key field
}
```

**Server Processing:**
1. Check if `flags & SESSION_BINDING` is set
2. Look up `previous_session_id` in StateStore
3. Validate session exists and hasn't expired
4. Bind session to current connection
5. Return success with same `session_id`

**Error Responses:**
- `STATUS_USER_SESSION_DELETED (0xC0000203)` - Session not found or expired
- `STATUS_ACCESS_DENIED` - Session key validation failed

### Session Binding Flow

```
Client                   Server A                Server B           Redis
   │                         │                       │                │
   ├──NEGOTIATE──────────────>                       │                │
   <────────────────NEGOTIATE─┤                       │                │
   │                         │                       │                │
   ├──SESSION_SETUP──────────>                       │                │
   │                         ├──SET session:1000────────────────────>│
   <────────────────SESSION_SETUP (session_id=1000)─┤                │
   │                         │                       │                │
   ├──TREE_CONNECT───────────>                       │                │
   │                         ├──SET tree:1000:5─────────────────────>│
   <────────────────TREE_CONNECT (tree_id=5)────────┤                │
   │                         │                       │                │
   ├──CREATE (file.txt)──────>                       │                │
   │                         ├──SET handle:42───────────────────────>│
   <────────────────CREATE (handle_id=42)───────────┤                │
   │                         │                       │                │
   ├──WRITE data─────────────>                       │                │
   <────────────────WRITE OK─┤                       │                │
   │                         │                       │                │
   │    [SERVER A CRASHES] ✗ │                       │                │
   │                         │                       │                │
   ├──TCP CONNECT to B───────────────────────────────>               │
   ├──NEGOTIATE──────────────────────────────────────>               │
   <────────────────────────NEGOTIATE────────────────┤               │
   │                         │                       │                │
   ├──SESSION_SETUP (BINDING, prev=1000)─────────────>               │
   │                         │                       ├──GET session:1000──>│
   │                         │                       <──SessionState──────┤
   <────────────────────────SESSION_SETUP (OK)───────┤               │
   │                         │                       │                │
   │  [SESSION 1000 NOW BOUND TO SERVER B]           │                │
   │                         │                       │                │
   ├──READ (tree=5, handle=42)───────────────────────>               │
   │                         │                       ├──GET handle:42─────>│
   │                         │                       <──HandleState───────┤
   <────────────────────────READ (data)──────────────┤               │
   │                         │                       │                │
```

## StateStore Implementation

### Redis Schema

```
# Session state
smb:session:{session_id}                  → JSON(SessionState)
smb:session:user:{user_id}                → SET of session IDs

# Tree connections
smb:tree:{session_id}:{tree_id}           → JSON(TreeState)
smb:tree:session:{session_id}             → SET of tree IDs

# File handles
smb:handle:{persistent_id}                → JSON(HandleState)
smb:handle:session:{session_id}           → SET of handle IDs

# Byte-range locks
smb:lock:{lock_id}                        → JSON(LockState)
smb:lock:handle:{persistent_id}           → SET of lock IDs

# Distributed locks (for multi-server coordination)
smb:distlock:{key}                        → lock token

# ID counters
smb:counter:session                       → INCR for session IDs
smb:counter:tree:{session_id}             → INCR for tree IDs
smb:counter:handle                        → INCR for handle IDs
```

### TTL Management

- Sessions have configurable TTL (default: 1 hour)
- Redis `EXPIRE` automatically removes stale sessions
- `last_access` updated on each operation
- `refresh_session()` extends TTL on activity

### Distributed Locking

For operations requiring multi-server coordination (e.g., file locking), Redis-based distributed locks are used:

```rust
// Acquire lock
let token = state_store.acquire_distributed_lock(
    "file:/share/path/to/file",
    Duration::from_secs(30)
).await?;

// Perform exclusive operation
// ...

// Release lock
state_store.release_distributed_lock("file:/share/path/to/file", &token).await?;
```

Uses Lua scripts for atomic lock operations:
```lua
-- Release only if we own the lock
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
```

## Deployment Scenarios

### Development (Single Server)

For development and testing, use `MemoryStateStore`:

```rust
let state_store = Arc::new(MemoryStateStore::new());
let server = SmbServer::new(config, state_store, auth);
```

- No external dependencies
- All state in memory
- Not HA-capable (single point of failure)

### Production HA (Multi-Server)

For production deployments with HA:

```rust
let state_store = Arc::new(RedisStateStore::new("redis://redis-cluster:6379").await?);
let server = SmbServer::new(config, state_store, auth);
```

**Requirements:**
- Redis cluster or Sentinel for Redis HA
- Shared storage backend (NFS, S3, etc.)
- Load balancer for client distribution

### Example: Docker Compose

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data

  smb-server-1:
    image: rustsmb:latest
    environment:
      - RUSTSMB_REDIS_URL=redis://redis:6379
      - RUSTSMB_SHARE_PATH=/data
    volumes:
      - shared-data:/data
    ports:
      - "10445:445"

  smb-server-2:
    image: rustsmb:latest
    environment:
      - RUSTSMB_REDIS_URL=redis://redis:6379
      - RUSTSMB_SHARE_PATH=/data
    volumes:
      - shared-data:/data
    ports:
      - "10446:445"

  haproxy:
    image: haproxy:latest
    ports:
      - "445:445"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg

volumes:
  redis-data:
  shared-data:
    driver: nfs
    driver_opts:
      share: "nfs-server:/exports/smb"
```

## Failure Handling

### Server Failure

When a server crashes:

1. **TCP connection breaks** - Client detects connection loss
2. **Client reconnects** - May connect to different server via load balancer
3. **Session binding** - Client sends SESSION_SETUP with BINDING flag
4. **State lookup** - New server retrieves session from Redis
5. **Operations resume** - Client continues with same session/tree/handle IDs

**Client perspective:** Brief interruption (<5 seconds typically), then transparent recovery.

### Redis Failure

Redis HA should be configured separately:
- **Redis Sentinel** - Automatic failover for single master
- **Redis Cluster** - Distributed, sharded deployment

If Redis is unavailable:
- New sessions cannot be created
- Existing sessions cannot be validated
- Server returns `STATUS_INTERNAL_ERROR`

### Session Expiration

Sessions expire after TTL (default: 1 hour of inactivity):

1. Client tries to use expired session
2. Server looks up session in Redis
3. Redis has already deleted expired key
4. Server returns `STATUS_USER_SESSION_DELETED`
5. Client must re-authenticate

## Security Considerations

### Session Key Storage

Session keys are stored in Redis. For security:
- Use Redis AUTH for authentication
- Use TLS for Redis connections in production
- Consider encrypting session keys at rest

### Connection Validation

When binding a session:
- Validate `previous_session_id` exists
- Check session hasn't expired
- Optionally validate client IP (configurable)

### Audit Logging

All session binding events should be logged:
```
INFO conn_id=42 session_id=1000 user="alice" "Session bound (HA failover)"
```

## Implementation Status

| Component | Status |
|-----------|--------|
| StateStore trait | Complete |
| MemoryStateStore | Complete |
| RedisStateStore | Complete |
| Session binding (server) | **TODO** |
| HA integration tests | **TODO** |

## References

- [MS-SMB2 Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [MS-SMB2 Section 3.2.4.2.4 - Session Binding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f)
- [Redis Documentation](https://redis.io/docs/)
