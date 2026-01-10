# State Store and Coordinator Design

This document describes the design for RustSMB's state management and coordination architecture, enabling deployment with 1000+ clients, 10M+ file handles, and 10+ SMB servers with strong consistency guarantees.

## Overview

The architecture uses two separate subsystems with different responsibilities:

| Subsystem | Component | Deployment | Purpose |
|-----------|-----------|------------|---------|
| **State Store** | `RedisStateStore` + `CachedStateStore` | Redis cluster | Session/handle/tree/lease/lock CRUD |
| **Coordinator** | `rustsmb-coordinator` service | 3/5 Raft nodes | Server membership, failure detection, epoch broadcast |

**Key design principle**: SMB servers are **pure serverless** - they hold no persistent state. The coordinator is a **separate stateful service** that manages cluster membership.

## Architecture Diagram

```
                              SMB Clients (1000+)
                                      │
                            ┌─────────▼─────────┐
                            │   Load Balancer   │
                            └─────────┬─────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                     RustSMB Server (Serverless)                           │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                    CachedStateStore (Optional)                       │  │
│  │  ┌─────────────────┐     ┌───────────────────────────────────────┐  │  │
│  │  │   LocalCache    │◄────│  Epoch updates from Coordinator       │  │  │
│  │  │   (LRU+Epoch)   │     │  (caching ONLY if coordinator present)│  │  │
│  │  └────────┬────────┘     └───────────────────────────────────────┘  │  │
│  │           │                                                          │  │
│  │  ┌────────▼────────┐                                                │  │
│  │  │ RedisStateStore │ ◄──── All data: sessions, handles, trees,      │  │
│  │  │                 │       leases, locks (with WATCH conflict check)│  │
│  │  └─────────────────┘                                                │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │              CoordinatorClient (Optional gRPC client)                │  │
│  │  • Registers server on startup, sends periodic heartbeats           │  │
│  │  • Receives epoch change notifications via streaming RPC            │  │
│  │  • Receives server failure notifications                            │  │
│  └────────────────────────────────────────────┬────────────────────────┘  │
└───────────────────────────────────────────────┼───────────────────────────┘
                                                │ gRPC
                                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                    Coordinator Service (3/5 Raft nodes)                   │
│                         rustsmb-coordinator binary                        │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                        gRPC Service                                  │  │
│  │  • RegisterServer, Heartbeat, LeaveCluster, GetServers              │  │
│  │  • GetEpoch, SubscribeEpochChanges (server streaming)               │  │
│  │  • SubscribeServerFailures (server streaming)                       │  │
│  └────────────────────────────────────────────┬────────────────────────┘  │
│                                                │                          │
│  ┌─────────────────────────────────────────────▼────────────────────────┐ │
│  │              CoordinationState (Raft replicated)                     │ │
│  │  • servers: HashMap<String, ServerRegistration>                      │ │
│  │  • cache_epoch: u64                                                  │ │
│  │  • heartbeat timestamps (for failure detection)                      │ │
│  │                                                                       │ │
│  │  NO leases, NO locks (all in Redis StateStore)                       │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │           Raft Consensus (tikv/raft-rs)                             │  │
│  │  • Replicates state across 3/5 coordinator nodes                    │  │
│  │  • Leader election, heartbeats between coordinators                 │  │
│  │  • Failure detection (triggers epoch increment)                     │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────────┘
                                  │
                          Raft Protocol
                          (between coordinator nodes)
```

## Crate Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rustsmb-server                                 │
│                      (uses CachedStateStore + CoordinatorClient)            │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ uses
              ┌─────────────────────┴─────────────────────┐
              │                                           │
              ▼                                           ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│    rustsmb-state-cached      │            │  rustsmb-coordinator-client  │
│    ─────────────────────     │            │  ────────────────────────    │
│    CachedStateStore          │            │  CoordinatorClient           │
│    • Wraps any StateStore    │            │  • gRPC client               │
│    • LRU cache per type      │            │  • Reconnection/retry        │
│    • Epoch-based invalidation│            │  impl CoordinationBackend    │
│    • Cache only if coord     │            │                              │
│    impl StateStore           │            └──────────────────────────────┘
└──────────────┬───────────────┘                          │
               │ wraps                                    │ imports types
               ▼                                          │
┌──────────────────────────────┐                          │
│    rustsmb-state-redis       │                          │
│    ────────────────────      │                          │
│    RedisStateStore           │                          │
│    • Connection pooling      │                          │
│    • JSON serialization      │                          │
│    • TTL management          │                          │
│    • Lease/lock WATCH        │                          │
│    impl StateStore           │                          │
└──────────────┬───────────────┘                          │
               │ implements                               │
               ▼                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rustsmb-state                                  │
│  ┌───────────────────────────────────────┐ ┌───────────────────────────────┐│
│  │       trait StateStore (34 methods)   │ │ trait CoordinationBackend     ││
│  │ ─────────────────────────────         │ │ (8 methods)                   ││
│  │ Sessions: create/get/update/delete    │ │ ─────────────────────────     ││
│  │          refresh/list                 │ │ Server membership:            ││
│  │ Trees: create/get/delete/list         │ │  • register_server            ││
│  │ Handles: create/get/update/delete/list│ │  • heartbeat                  ││
│  │ Locks: create/get/delete              │ │  • leave_cluster              ││
│  │ Distributed locks: acquire/release    │ │  • get_servers                ││
│  │ ID generation: next_*_id              │ │  • subscribe_server_failures  ││
│  │                                       │ │ Cache epoch:                  ││
│  │ Leases (NEW in Phase 13):             │ │  • get_epoch                  ││
│  │  • create_lease                       │ │  • subscribe_epoch_changes    ││
│  │  • get_lease                          │ │  • increment_epoch            ││
│  │  • update_lease                       │ │                               ││
│  │  • delete_lease                       │ │ NO leases, NO locks           ││
│  │  • get_leases_for_file                │ │ (moved to StateStore)         ││
│  │  • check_and_create_lease             │ └───────────────────────────────┘│
│  │                                       │                                  │
│  │ File Locks (NEW in Phase 13):         │                                  │
│  │  • acquire_file_lock                  │                                  │
│  │  • release_file_lock                  │                                  │
│  │  • get_file_locks                     │                                  │
│  │  • release_file_locks_for_session     │                                  │
│  └───────────────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           rustsmb-coordinator                               │
│                         (standalone binary)                                 │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  main.rs: CLI, config loading, gRPC server startup                    │  │
│  │  service.rs: gRPC handlers implementing CoordinatorService            │  │
│  │  raft.rs: Raft node management, leader election                       │  │
│  │  state.rs: CoordinationState (servers + epoch only)                   │  │
│  │  transport.rs: Raft message transport between coordinator nodes       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                    │                                        │
│                                    │ uses                                   │
│                                    ▼                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  rustsmb-coordinator-proto                                            │  │
│  │  • coordinator.proto: gRPC service definition                         │  │
│  │  • Generated Rust code via prost/tonic                                │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Storage Separation

| Data | StateStore (Redis) | Coordinator (Raft) | Notes |
|------|:------------------:|:------------------:|-------|
| **SessionState** | Persisted | - | User auth, session keys, dialect |
| **TreeState** | Persisted | - | Share connections |
| **HandleState** | Persisted | - | File handles (10M+), durable info |
| **LockState** | Persisted | - | Per-handle lock persistence |
| **LeaseEntry** | Persisted | - | SMB lease state (NEW: moved from coordinator) |
| **FileLock** | Persisted | - | Byte-range locks (NEW: moved from coordinator) |
| **ServerRegistration** | - | Replicated | Cluster membership, heartbeats |
| **cache_epoch** | - | Replicated | Cache invalidation trigger |

### Why Move Leases/Locks to Redis?

1. **Scale**: Can have millions of leases/locks (10M+ handles), too large for Raft state
2. **Simplicity**: Single source of truth (Redis) for all persistent data
3. **Coordinator focus**: Coordinator only handles membership (small state, fast consensus)
4. **Conflict detection**: Redis WATCH provides atomic conflict checking

## Data Flow

### Read (Cache Hit) - ~10us
```
Client -> Server -> CachedStateStore -> LocalCache (hit) -> Response
```

### Read (Cache Miss) - ~1-5ms
```
Client -> Server -> CachedStateStore -> LocalCache (miss)
                                     -> RedisStateStore -> Update Cache -> Response
```

### Write - ~1-5ms
```
Client -> Server -> CachedStateStore -> RedisStateStore (write)
                                     -> Update Cache -> Response
```

### Lease Creation (with conflict check) - ~2-10ms
```
Client -> Server -> StateStore.check_and_create_lease()
                       -> Redis WATCH file:{path}
                       -> GET existing leases
                       -> Check conflicts locally
                       -> MULTI/EXEC (atomic)
                       -> Response (granted_state or retry)
```

### Server Registration - ~5-20ms
```
Server startup -> CoordinatorClient.register_server()
                      -> gRPC to Coordinator
                      -> Raft consensus
                      -> Response with current_epoch
```

### Server Failure Detection - ~15s
```
Server A crashes
    -> Coordinator Raft election timeout (10-15s)
    -> New leader detects missing heartbeat
    -> Apply: UnregisterServer(A)
    -> Apply: IncrementEpoch
    -> Stream: EpochChangeEvent to all connected servers
    -> All servers: CachedStateStore.invalidate_all()
```

## Requirements

| Requirement | Value |
|-------------|-------|
| Scale | 1000+ clients, 10M+ handles, 10+ servers |
| Consistency | Strong (CP) - reject writes during partition |
| Failure detection | ~15 seconds (Raft election timeout) |
| Cache invalidation | All caches invalidate on any server failure |
| Coordinator deployment | 3 or 5 nodes (Raft quorum) |
| SMB server deployment | Serverless (any number) |

## gRPC Service Definition

```protobuf
syntax = "proto3";

package rustsmb.coordinator.v1;

import "google/protobuf/empty.proto";

service CoordinatorService {
    // Server membership
    rpc RegisterServer(RegisterServerRequest) returns (RegisterServerResponse);
    rpc Heartbeat(HeartbeatRequest) returns (google.protobuf.Empty);
    rpc LeaveCluster(LeaveClusterRequest) returns (google.protobuf.Empty);
    rpc GetServers(google.protobuf.Empty) returns (GetServersResponse);

    // Epoch and events (streaming RPCs)
    rpc GetEpoch(google.protobuf.Empty) returns (GetEpochResponse);
    rpc SubscribeEpochChanges(google.protobuf.Empty) returns (stream EpochChangeEvent);
    rpc SubscribeServerFailures(google.protobuf.Empty) returns (stream ServerFailureEvent);
}

message ServerRegistration {
    string server_id = 1;
    string hostname = 2;
    uint32 port = 3;
    uint64 registered_at = 4;
    uint64 last_heartbeat = 5;
}

message RegisterServerRequest {
    ServerRegistration registration = 1;
}

message RegisterServerResponse {
    uint64 current_epoch = 1;
}

message HeartbeatRequest {
    string server_id = 1;
}

message LeaveClusterRequest {
    string server_id = 1;
}

message GetServersResponse {
    repeated ServerRegistration servers = 1;
}

message GetEpochResponse {
    uint64 epoch = 1;
}

message EpochChangeEvent {
    uint64 new_epoch = 1;
    string reason = 2;  // "server_failure", "manual", etc.
}

message ServerFailureEvent {
    string server_id = 1;
    uint64 new_epoch = 2;
}
```

## CoordinationBackend Trait (Simplified)

The `CoordinationBackend` trait is reduced to 8 methods (from 19 in Phase 12):

```rust
/// Simplified coordination backend for server membership and cache epochs.
/// Leases and locks are now handled by StateStore (Redis with WATCH).
pub trait CoordinationBackend: Send + Sync + 'static {
    // ========== Server Membership (5 methods) ==========

    /// Register this server with the cluster.
    fn register_server<'a>(
        &'a self,
        registration: &'a ServerRegistration,
    ) -> BoxFuture<'a, Result<(), CoordError>>;

    /// Update server heartbeat.
    fn heartbeat(&self, server_id: &str) -> BoxFuture<'_, Result<(), CoordError>>;

    /// Leave the cluster gracefully.
    fn leave_cluster(&self) -> BoxFuture<'_, Result<(), CoordError>>;

    /// Get all registered servers.
    fn get_servers(&self) -> BoxFuture<'_, Result<Vec<ServerRegistration>, CoordError>>;

    /// Subscribe to server failure events.
    fn subscribe_server_failures(&self) -> BoxFuture<'_, ServerFailureStream>;

    // ========== Cache Epoch (3 methods) ==========

    /// Get the current cache epoch.
    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>>;

    /// Subscribe to epoch changes (for cache invalidation).
    fn subscribe_epoch_changes(&self) -> BoxFuture<'_, EpochStream>;

    /// Force epoch increment (for testing/admin).
    fn increment_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>>;
}
```

**Removed methods** (moved to StateStore):
- `create_lease`, `get_lease`, `update_lease`, `delete_lease`
- `request_lease_break`, `subscribe_lease_breaks`
- `get_leases_for_file`, `check_lease_conflict`
- `acquire_lock`, `release_lock`, `get_locks_for_file`
- `release_locks_for_session`, `release_locks_for_handle`

## StateStore Trait (Extended)

The `StateStore` trait is extended with lease and lock methods:

```rust
pub trait StateStore: Send + Sync + 'static {
    // ... existing 24 methods (sessions, trees, handles, locks, IDs) ...

    // ========== Lease Management (NEW in Phase 13) ==========

    /// Create a lease entry.
    fn create_lease<'a>(
        &'a self,
        lease: &'a LeaseEntry,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Get a lease by key.
    fn get_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<Option<LeaseEntry>, StateError>>;

    /// Update an existing lease.
    fn update_lease<'a>(
        &'a self,
        lease: &'a LeaseEntry,
    ) -> BoxFuture<'a, Result<(), StateError>>;

    /// Delete a lease.
    fn delete_lease(&self, lease_key: &str) -> BoxFuture<'_, Result<(), StateError>>;

    /// Get all leases for a file path.
    fn get_leases_for_file(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<LeaseEntry>, StateError>>;

    /// Check for conflicts and create lease atomically.
    /// Uses Redis WATCH + MULTI/EXEC for optimistic locking.
    fn check_and_create_lease<'a>(
        &'a self,
        file_path: &'a str,
        lease: &'a LeaseEntry,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseGrantResult, StateError>>;

    // ========== File Lock Coordination (NEW in Phase 13) ==========

    /// Acquire a file lock, checking for conflicts.
    /// Uses Redis WATCH for atomic conflict detection.
    fn acquire_file_lock<'a>(
        &'a self,
        lock: &'a FileLock,
    ) -> BoxFuture<'a, Result<bool, StateError>>;

    /// Release a file lock.
    fn release_file_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), StateError>>;

    /// Get all locks for a file path.
    fn get_file_locks(
        &self,
        file_path: &str,
    ) -> BoxFuture<'_, Result<Vec<FileLock>, StateError>>;

    /// Release all locks for a session.
    fn release_file_locks_for_session(&self, session_id: u64) -> BoxFuture<'_, Result<(), StateError>>;
}
```

## Redis WATCH Pattern for Lease Conflict Detection

Lease conflict detection uses Redis WATCH for optimistic locking:

```rust
impl StateStore for RedisStateStore {
    fn check_and_create_lease<'a>(
        &'a self,
        file_path: &'a str,
        lease: &'a LeaseEntry,
        requested_state: u32,
    ) -> BoxFuture<'a, Result<LeaseGrantResult, StateError>> {
        Box::pin(async move {
            let mut conn = self.get_conn().await?;
            let file_leases_key = format!("smb:lease:file:{}", file_path);
            let lease_key_redis = format!("smb:lease:{}", lease.lease_key);

            // Retry loop for optimistic locking
            for _attempt in 0..3 {
                // 1. WATCH the file's lease set
                redis::cmd("WATCH")
                    .arg(&file_leases_key)
                    .query_async::<_, ()>(&mut *conn)
                    .await?;

                // 2. GET existing leases and check conflicts
                let existing_keys: Vec<String> = conn.smembers(&file_leases_key).await?;
                let mut conflicts = Vec::new();
                let mut granted_state = requested_state;

                for key in &existing_keys {
                    if key == &lease.lease_key { continue; }
                    if let Some(json) = conn.get::<_, Option<String>>(key).await? {
                        let existing: LeaseEntry = serde_json::from_str(&json)?;
                        if leases_conflict(existing.lease_state, requested_state) {
                            conflicts.push(existing);
                        }
                    }
                }

                // 3. Reduce state if conflicts
                if !conflicts.is_empty() {
                    granted_state = reduce_lease_state(requested_state, &conflicts);
                }

                // 4. MULTI/EXEC atomic transaction
                let mut granted_lease = lease.clone();
                granted_lease.lease_state = granted_state;
                let lease_json = serde_json::to_string(&granted_lease)?;

                let result: redis::RedisResult<Option<()>> = redis::pipe()
                    .atomic()
                    .set(&lease_key_redis, &lease_json)
                    .sadd(&file_leases_key, &lease.lease_key)
                    .query_async(&mut *conn)
                    .await;

                match result {
                    Ok(Some(())) => {
                        return Ok(LeaseGrantResult::granted(granted_state));
                    }
                    Ok(None) => continue, // WATCH failed, retry
                    Err(e) => return Err(StateError::Internal(e.to_string())),
                }
            }

            Err(StateError::Conflict("Too many retries".to_string()))
        })
    }
}
```

## Lease Conflict Rules

| Existing | Requested | Conflict? | Granted |
|----------|-----------|-----------|---------|
| R | R | No | R |
| R | W | **Yes** | R (W stripped) |
| R | RWH | **Yes** | R |
| W | R | **Yes** | None (must break) |
| W | W | **Yes** | None (must break) |
| RWH | R | **Yes** | R (after break) |
| RWH | RWH | **Yes** | R (after break) |

**Rule**: Write caching (W) is exclusive - only one client can hold W at a time.

## CachedStateStore Conditional Caching

Caching is only enabled when a coordinator is available:

```rust
pub struct CachedStateStore {
    bulk_store: DynStateStore,
    cache: Option<Arc<LocalCache>>,  // None if no coordinator
    coordinator: Option<Arc<dyn CoordinationBackend>>,
}

impl CachedStateStore {
    pub fn new(
        bulk_store: DynStateStore,
        cache_config: CacheConfig,
        coordinator: Option<Arc<dyn CoordinationBackend>>,
    ) -> Self {
        Self {
            cache: coordinator.as_ref().map(|_| {
                Arc::new(LocalCache::new(cache_config))
            }),
            bulk_store,
            coordinator,
        }
    }

    pub fn with_coordinator(
        bulk_store: DynStateStore,
        cache_config: CacheConfig,
        coordinator: Arc<dyn CoordinationBackend>,
    ) -> Self {
        Self::new(bulk_store, cache_config, Some(coordinator))
    }

    pub fn without_coordinator(bulk_store: DynStateStore) -> Self {
        Self::new(bulk_store, CacheConfig::default(), None)
    }
}
```

**Behavior**:
- **With coordinator**: LRU cache enabled, epoch-based invalidation on server failure
- **Without coordinator**: Direct Redis pass-through, no caching

## Coordinator State Machine

The coordinator's Raft state machine only manages server membership:

```rust
/// Raft state machine state (replicated across coordinator nodes)
pub struct CoordinationState {
    /// Global cache epoch (incremented on server failure)
    pub cache_epoch: u64,

    /// Active server membership
    pub servers: HashMap<String, ServerRegistration>,
}

/// Commands applied to the state machine
pub enum CoordRequest {
    RegisterServer(ServerRegistration),
    UnregisterServer(String),
    UpdateHeartbeat { server_id: String, timestamp: u64 },
    IncrementEpoch,
}
```

**No leases, no locks** in coordinator state - all moved to Redis.

## Server Failure Handling

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Server Failure Detection Flow                        │
└─────────────────────────────────────────────────────────────────────────┘

SMB Server A          Coordinator (Leader)         SMB Server B
     │                       │                          │
     │──heartbeat (5s)──────>│                          │
     │                       │                          │
     │──heartbeat (5s)──────>│                          │
     │                       │                          │
     X [CRASH]               │                          │
                             │                          │
              [No heartbeat for 15s]                    │
                             │                          │
                [Raft: UnregisterServer(A)]             │
                [Raft: IncrementEpoch]                  │
                             │                          │
                             │──EpochChangeEvent(2)────>│
                             │                          │
                             │              [CachedStateStore.invalidate_all()]
                             │                          │
```

## Timing Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Server heartbeat | 5 seconds | Keep-alive to coordinator |
| Heartbeat timeout | 15 seconds | Mark server as failed |
| Raft election timeout | 10-15 seconds | Leader election |
| Cache TTL | 60 seconds | Local cache entry expiration |
| WATCH retry | 3 attempts | Optimistic lock retries |

## Performance Expectations

| Operation | Latency | Notes |
|-----------|---------|-------|
| Cache hit | ~10us | Local memory only |
| Cache miss | ~1-5ms | Redis round-trip |
| Lease grant (no conflict) | ~2-10ms | Redis WATCH + EXEC |
| Lease grant (with conflict) | ~5-20ms | May need retries |
| Server registration | ~5-20ms | Raft consensus |
| Server failure detection | ~15s | Raft election timeout |

## Deployment

### Coordinator Cluster (Stateful)
```yaml
# docker-compose.yml
services:
  coordinator-1:
    image: rustsmb-coordinator:latest
    command: --node-id 1 --peers coordinator-2:9000,coordinator-3:9000
    ports:
      - "9000:9000"  # gRPC

  coordinator-2:
    image: rustsmb-coordinator:latest
    command: --node-id 2 --peers coordinator-1:9000,coordinator-3:9000
    ports:
      - "9001:9000"

  coordinator-3:
    image: rustsmb-coordinator:latest
    command: --node-id 3 --peers coordinator-1:9000,coordinator-2:9000
    ports:
      - "9002:9000"
```

### SMB Servers (Serverless)
```yaml
services:
  smb-server:
    image: rustsmb:latest
    environment:
      - REDIS_URL=redis://redis:6379
      - COORDINATOR_ADDRS=coordinator-1:9000,coordinator-2:9000,coordinator-3:9000
    deploy:
      replicas: 10  # Scale as needed
```

## Testing Strategy

### Unit Tests
- LocalCache: LRU eviction, TTL, epoch invalidation
- CachedStateStore: with/without coordinator
- Redis WATCH: lease conflict detection, retry logic
- gRPC client: reconnection, streaming

### Integration Tests
- 3-node coordinator cluster formation
- Server registration and heartbeat
- Epoch change propagation
- Server failure detection
- Lease conflict across servers
- Lock conflict across servers

### Chaos Tests
- Kill random coordinator node
- Kill random SMB server
- Network partition between servers and coordinator
- Redis failover during lease operation
