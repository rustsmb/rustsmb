# Hyperscale State Store Design

This document describes the design for RustSMB's hyperscale state store, enabling deployment with 1000+ clients, 10M+ file handles, and 10+ SMB servers with strong consistency guarantees.

## Overview

The state management uses two separate subsystems with different responsibilities:

| Subsystem | Trait | Implementation | Purpose |
|-----------|-------|----------------|---------|
| **State Store** | `StateStore` | `CachedStateStore` wrapping `RedisStateStore` | Session/handle/tree CRUD |
| **Coordination** | `CoordinationBackend` | `RaftCoordinator` | Server membership, leases, locks, epochs |

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
│                            RustSMB Server                                 │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                      ServerCoordination                             │  │
│  │           (orchestrates both subsystems, listens to epoch)          │  │
│  └───────────────────────────┬─────────────────────────────────────────┘  │
│                              │                                            │
│            ┌─────────────────┴─────────────────┐                          │
│            │                                   │                          │
│            ▼                                   ▼                          │
│  ┌───────────────────────┐         ┌───────────────────────┐              │
│  │                       │         │                       │              │
│  │  StateStore Path      │         │ CoordinationBackend   │              │
│  │                       │         │                       │              │
│  │  ┌─────────────────┐  │ epoch   │  ┌─────────────────┐  │              │
│  │  │CachedStateStore │◄─┼─changes─┼──│ RaftCoordinator │  │              │
│  │  │ ┌─────────────┐ │  │         │  │ (tikv/raft-rs)  │  │              │
│  │  │ │ LocalCache  │ │  │         │  └────────┬────────┘  │              │
│  │  │ │ (LRU+Epoch) │ │  │         │           │           │              │
│  │  │ └─────────────┘ │  │         │  ┌────────▼────────┐  │              │
│  │  └────────┬────────┘  │         │  │CoordinationState│  │              │
│  │           │           │         │  │   (in-memory,   │  │              │
│  │  ┌────────▼────────┐  │         │  │    replicated)  │  │              │
│  │  │ RedisStateStore │  │         │  └─────────────────┘  │              │
│  │  │   (bulk data)   │  │         │                       │              │
│  │  └─────────────────┘  │         └───────────────────────┘              │
│  │                       │                    │                           │
│  └───────────────────────┘                    │                           │
│             │                                 │ Raft Protocol             │
└─────────────┼─────────────────────────────────┼───────────────────────────┘
              │                                 │
              │                                 │ (consensus between servers)
              │                                 │
              ▼                                 │
    ┌──────────────────┐                        │
    │  Redis Cluster   │◄───────────────────────┘
    │  ───────────────  │
    │  • SessionState  │
    │  • HandleState   │
    │  • TreeState     │
    │  • LockState     │
    └──────────────────┘
```

## Crate Relationships

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rustsmb-server                                 │
│                         ServerCoordination struct                           │
│    - Creates and owns both CachedStateStore and RaftCoordinator             │
│    - Listens to epoch changes and invalidates cache                         │
│    - Spawns heartbeat task                                                  │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ uses
              ┌─────────────────────┴─────────────────────┐
              │                                           │
              ▼                                           ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│    rustsmb-state-cached      │            │     rustsmb-coord-raft       │
│    ─────────────────────     │            │     ──────────────────       │
│    CachedStateStore          │            │     RaftCoordinator          │
│    • Wraps any StateStore    │            │     • Uses tikv/raft-rs      │
│    • LRU cache per type      │            │     • Manages CoordinationState
│    • Epoch-based invalidation│            │     • Broadcasts epoch changes│
│    impl StateStore           │            │     impl CoordinationBackend │
└──────────────┬───────────────┘            └──────────────────────────────┘
               │ wraps                                     │
               ▼                                           │ imports types
┌──────────────────────────────┐                           │
│    rustsmb-state-redis       │                           │
│    ────────────────────      │                           │
│    RedisStateStore           │                           │
│    • Connection pooling      │                           │
│    • JSON serialization      │                           │
│    • TTL management          │                           │
│    impl StateStore           │                           │
└──────────────┬───────────────┘                           │
               │ implements                                │
               ▼                                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              rustsmb-state                                  │
│  ┌───────────────────────────────────┐ ┌───────────────────────────────────┐│
│  │       trait StateStore            │ │    trait CoordinationBackend      ││
│  │ ─────────────────────────────     │ │ ─────────────────────────────     ││
│  │ Session CRUD:                     │ │ Server membership:                ││
│  │  • create/get/update/delete_session│ │  • register_server               ││
│  │  • list_sessions                  │ │  • leave_cluster                  ││
│  │                                   │ │  • get_servers                    ││
│  │ Tree CRUD:                        │ │  • subscribe_server_failures      ││
│  │  • create/get/delete_tree         │ │                                   ││
│  │                                   │ │ Cache epoch:                      ││
│  │ Handle CRUD:                      │ │  • get_epoch                      ││
│  │  • create/get/update/delete_handle│ │  • subscribe_epoch_changes        ││
│  │                                   │ │                                   ││
│  │ Lock persistence:                 │ │ Lease coordination:               ││
│  │  • create/get/delete_lock         │ │  • create/get/update/delete_lease ││
│  │  (per-handle, for recovery)       │ │  • check_lease_conflict           ││
│  │                                   │ │  • request_lease_break            ││
│  │ ID generation:                    │ │                                   ││
│  │  • next_session_id/tree_id/handle_id│ │ Lock coordination:              ││
│  │                                   │ │  • acquire_lock (conflict check)  ││
│  └───────────────────────────────────┘ │  • release_lock                   ││
│                                        │  • get_locks_for_file             ││
│                                        └───────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Storage Separation

| Data | StateStore (Redis) | Coordinator (Raft) | Purpose |
|------|:------------------:|:------------------:|---------|
| **SessionState** | Persisted | - | User auth, session keys, dialect |
| **TreeState** | Persisted | - | Share connections |
| **HandleState** | Persisted | - | File handles (10M+), durable info |
| **LockState** | Per-handle | - | Lock persistence for reconnection |
| **ServerRegistration** | - | Replicated | Cluster membership, heartbeats |
| **LeaseEntry** | - | Replicated | SMB lease state & conflicts |
| **DistributedLock** | - | Replicated | Cross-server lock conflicts |
| **cache_epoch** | - | Replicated | Cache invalidation trigger |

### Why Locks Exist in Both?

| Layer | Type | Key | Purpose |
|-------|------|-----|---------|
| **Redis** | `LockState` | `persistent_id` (handle) | Persistence, recovery on reconnect |
| **Raft** | `DistributedLock` | `file_path` | Real-time conflict detection |

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

### Coordination (Lease/Lock) - ~1-5ms
```
Client -> Server -> RaftCoordinator -> Raft Consensus
                                    -> CoordinationState (apply) -> Response
```

### Server Failure - ~15s detection
```
Server A crashes
    -> Raft election timeout (10-15s)
    -> New leader elected
    -> RaftCoordinator.handle_server_failure()
        -> Unregister server
        -> Increment epoch        -----> All servers: CachedStateStore.invalidate_all()
        -> Release server's locks
        -> Release server's leases
```

## Requirements

| Requirement | Value |
|-------------|-------|
| Scale | 1000+ clients, 10M+ handles, 10+ servers |
| Consistency | Strong (CP) - reject writes during partition |
| Failure detection | 15 seconds |
| Cache invalidation | All caches invalidate on any server failure |
| Deployment | Bare metal/VMs (no Kubernetes) |

## Embedded Raft Coordination

### Why Embedded Raft?

| Aspect | Embedded Raft | External etcd |
|--------|---------------|---------------|
| Deployment | Single binary | Separate cluster |
| Latency | In-process, ~1ms | Network hop, ~5-20ms |
| Dependencies | None | etcd cluster (3+ nodes) |
| Scaling | Limited to ~7 nodes | Unlimited clients |
| Complexity | More code | Ops complexity |

We chose embedded Raft because:
- No external dependencies simplifies deployment
- Lower latency for coordination operations
- Full control over failure detection timing
- Single binary deployment

### Design Principle

The rest of RustSMB only sees the `CoordinationBackend` trait. Raft implementation details are encapsulated inside a coordinator struct:

```rust
// The ONLY trait the rest of the system sees
pub trait CoordinationBackend: Send + Sync + 'static {
    fn register_server(...) -> BoxFuture<...>;
    fn get_epoch(...) -> BoxFuture<...>;
    fn create_lease(...) -> BoxFuture<...>;
    // ... other coordination operations
}

// Coordinator implements this trait using Raft internally
impl CoordinationBackend for RaftCoordinator {
    // All coordination operations go through Raft consensus
}
```

| Raft Library Provides | We Implement |
|-----------------------|--------------|
| Consensus algorithm | `CoordinationBackend` trait |
| Leader election | `RaftCoordinator` (implements trait) |
| Log replication | `CoordinationState` (application state) |
| Heartbeat/failure detection | Business logic (leases, locks, epochs) |
| Membership changes | |

### Coordination State Machine

The Raft state machine manages coordination data (small dataset):

```rust
/// Raft state machine state (replicated across all nodes)
pub struct CoordinationState {
    /// Global cache epoch (incremented on server failure)
    pub cache_epoch: u64,

    /// Active server membership
    pub servers: HashMap<String, ServerRegistration>,

    /// SMB lease table (lease_key -> LeaseEntry)
    pub leases: HashMap<String, LeaseEntry>,

    /// Active byte-range locks (for conflict detection)
    pub locks: HashMap<String, Vec<DistributedLock>>,
}
```

### Raft Commands

```rust
pub enum CoordRequest {
    // Server membership
    RegisterServer(ServerRegistration),
    UnregisterServer(String),
    UpdateHeartbeat { server_id, timestamp },

    // Cache invalidation
    IncrementEpoch,

    // Lease management
    CreateLease(LeaseEntry),
    UpdateLease(LeaseEntry),
    DeleteLease(String),
    CheckLeaseConflict { file_path, requestor_lease_key, requested_state },
    ReleaseLeasesForServer(String),

    // Lock management
    AcquireLock(DistributedLock),
    ReleaseLock(u64),
    ReleaseLocksForSession(u64),
    ReleaseLocksForHandle(u128),
    ReleaseLocksForServer(String),
}
```

## Local Cache Design

### Cache Structure

```rust
pub struct LocalCache {
    /// Cached sessions (key: session_id)
    sessions: RwLock<LruCache<u64, CacheEntry<SessionState>>>,

    /// Cached handles (key: persistent_id)
    handles: RwLock<LruCache<u128, CacheEntry<HandleState>>>,

    /// Cached trees (key: (session_id, tree_id))
    trees: RwLock<LruCache<(u64, u32), CacheEntry<TreeState>>>,

    /// Current global cache epoch
    current_epoch: AtomicU64,

    /// Configuration
    config: CacheConfig,
}
```

### Cache Entry

```rust
pub struct CacheEntry<T> {
    /// The cached data
    pub data: T,

    /// Cache epoch when this entry was created
    pub epoch: u64,

    /// When this entry was cached
    pub cached_at: Instant,

    /// TTL for this entry
    pub ttl: Duration,
}
```

### Epoch-Based Invalidation

When any server fails, ALL caches on ALL surviving servers are invalidated by incrementing the global epoch:

```rust
impl LocalCache {
    pub fn invalidate_all(&self) {
        // Simply increment epoch - all cached entries become stale
        self.current_epoch.fetch_add(1, Ordering::Release);
    }

    pub fn get(&self, key: K) -> Option<T> {
        let entry = self.cache.get(&key)?;

        // Check if entry is from current epoch
        if entry.epoch != self.current_epoch.load(Ordering::Acquire) {
            return None; // Stale entry
        }

        // Check TTL
        if entry.cached_at.elapsed() > entry.ttl {
            return None; // Expired
        }

        Some(entry.data.clone())
    }
}
```

**Why invalidate all?**
- Strong consistency (CP) requirement
- Cannot know exactly which entries the dead server had cached
- Safe default: assume anything could be stale
- Entries refetched from Redis on next access

### Cache Configuration

```rust
pub struct CacheConfig {
    /// Maximum cached sessions
    pub max_sessions: usize,      // Default: 10,000

    /// Maximum cached handles
    pub max_handles: usize,       // Default: 100,000

    /// Maximum cached trees
    pub max_trees: usize,         // Default: 50,000

    /// Default TTL for entries
    pub default_ttl: Duration,    // Default: 60 seconds
}
```

## Server Failure Detection

### Heartbeat Flow

```
Server A                  Raft Cluster              Server B & C
   |                          |                          |
   |--AppendEntries (5s)----->|                          |
   |<-------------------------|                          |
   |                          |                          |
   |--AppendEntries (5s)----->|                          |
   |<-------------------------|                          |
   |                          |                          |
   X [CRASH]                  |                          |
                              |                          |
              [election_timeout (10-15s)]                |
                              |                          |
                    [New leader elected]                 |
                              |                          |
                              |--RemoveServer(A)-------->|
                              |--IncrementEpoch--------->|
                              |                          |
                              |         +----------------+
                              |         | invalidate_all()
                              |         +----------------+
```

### Timing Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Heartbeat interval | 5 seconds | Raft leader sends to followers |
| Election timeout | 10-15 seconds | Random, triggers leader election |
| Failure detection | ~15 seconds | Max time to detect dead server |

## Lease Coordination

### Lease Entry

```rust
pub struct LeaseEntry {
    /// Unique lease key (usually derived from file path)
    pub lease_key: String,

    /// Client that owns this lease
    pub client_guid: String,

    /// Session owning the lease
    pub session_id: u64,

    /// Server currently serving this lease
    pub server_id: String,

    /// Current lease state (R, W, H flags)
    pub lease_state: u32,

    /// Lease epoch (incremented on state change)
    pub epoch: u16,
}
```

### Lease Break Flow

```
Client A          Server 1         Raft           Server 2    Client B
   |                 |              |                 |           |
   |  Has lease RWH  |              |                 |           |
   |  on file.txt    |              |                 |           |
   |                 |              |                 |<--CREATE--|
   |                 |              |                 |  file.txt |
   |                 |              |                 |  want W   |
   |                 |              |<--BreakLease----|           |
   |                 |              |  (file.txt,W)   |           |
   |                 |<-------------|  Apply break    |           |
   |<--OPLOCK_BREAK--|              |                 |           |
   |  (new_state=R)  |              |                 |           |
   |--flush writes-->|              |                 |           |
   |--OPLOCK_ACK---->|              |                 |           |
   |                 |--AckBreak--->|                 |           |
   |                 |              |--Lease granted->|           |
   |                 |              |                 |--CREATE-->|
   |                 |              |                 |  response |
```

## Lock Conflict Detection

### Distributed Lock

```rust
pub struct DistributedLock {
    /// Unique lock ID
    pub lock_id: u64,

    /// Handle holding the lock
    pub handle_id: u128,

    /// Session ID
    pub session_id: u64,

    /// Server that granted the lock
    pub server_id: String,

    /// File path
    pub file_path: String,

    /// Lock offset
    pub offset: u64,

    /// Lock length
    pub length: u64,

    /// Is exclusive lock
    pub exclusive: bool,
}
```

### Conflict Detection

Before granting a lock, the Raft state machine checks for conflicts:

```rust
fn check_lock_conflict(existing: &DistributedLock, new: &DistributedLock) -> bool {
    // Check if ranges overlap
    let existing_end = existing.offset.saturating_add(existing.length);
    let new_end = new.offset.saturating_add(new.length);

    let overlap = existing.offset < new_end && new.offset < existing_end;

    if !overlap {
        return false; // No conflict
    }

    // Overlapping ranges - check exclusivity
    // Shared locks (both non-exclusive) don't conflict
    existing.exclusive || new.exclusive
}
```

## State Type Extensions

To support server-aware cleanup, state types include server binding:

```rust
pub struct SessionState {
    // ... existing fields ...

    /// Server currently serving this session
    #[serde(default)]
    pub bound_server_id: Option<String>,
}

pub struct HandleState {
    // ... existing fields ...

    /// Server that opened this handle
    #[serde(default)]
    pub bound_server_id: Option<String>,
}
```

## Server Cleanup on Failure

When a server is detected as failed:

1. **Raft proposes RemoveServer** - Server removed from membership
2. **Raft proposes IncrementEpoch** - All caches invalidated
3. **Background cleanup task**:
   - Find sessions bound to dead server
   - Mark sessions as unbound (clients can rebind)
   - Clean up non-durable handles
   - Release byte-range locks held by dead server

```rust
async fn cleanup_dead_server(server_id: &str, bulk_store: &dyn BulkStateStore) {
    // 1. Find orphaned sessions
    let sessions = bulk_store.list_sessions_by_server(server_id).await?;
    for mut session in sessions {
        session.bound_server_id = None;
        bulk_store.update_session(&session).await?;
    }

    // 2. Clean up non-durable handles
    let handles = bulk_store.list_handles_by_server(server_id).await?;
    for handle in handles {
        if !handle.is_durable {
            bulk_store.delete_handle(handle.persistent_id).await?;
        }
    }

    // 3. Release locks (done via Raft coordination)
    // Locks are in Raft state, cleaned up automatically
}
```

## Dependencies

```toml
[workspace.dependencies]
# Caching
lru = "0.12"

# Async utilities
tokio-stream = "0.1"

# Raft library (using tikv/raft-rs)
raft = "0.7"
```

## Performance Expectations

| Operation | Latency | Notes |
|-----------|---------|-------|
| Cache hit | ~10us | Local memory only |
| Cache miss | ~1-5ms | Redis round-trip |
| Lease grant (no conflict) | ~1-5ms | Raft consensus |
| Lease break | ~5-20ms | Multi-server coordination |
| Lock acquire (no conflict) | ~1-5ms | Raft consensus |
| Server failure detection | ~15s | Raft election timeout |
| Full cache refill | ~30-60s | Background, non-blocking |

## Testing Strategy

### Unit Tests
- LocalCache: LRU eviction, TTL, epoch invalidation
- CachedStateStore: Cache hit/miss, write-through
- Raft state machine: Command application, conflict detection

### Integration Tests
- 3-node Raft cluster formation
- Server join/leave
- Leader election on failure
- Cache invalidation propagation
- Lease break across servers
- Lock conflict detection

### Chaos Tests
- Kill random server, verify cache invalidation
- Network partition, verify CP behavior
- Load test with 1000 concurrent sessions
