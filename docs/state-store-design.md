# Hyperscale State Store Design

This document describes the design for RustSMB's hyperscale state store, enabling deployment with 1000+ clients, 10M+ file handles, and 10+ SMB servers with strong consistency guarantees.

## Overview

The state store uses a three-tier architecture:

1. **Local Cache** - LRU cache with epoch-based invalidation (~10μs reads)
2. **Coordination Layer** - Embedded Raft for consensus (~1ms operations)
3. **Bulk Data Layer** - Redis for persistent state storage (~1-5ms operations)

```
┌─────────────────────────────────────────────────────────────────┐
│                       SMB Clients (1000+)                       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Load Balancer      │
                    └───────────┬───────────┘
                                │
    ┌───────────────────────────┼───────────────────────────┐
    │                           │                           │
    ▼                           ▼                           ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  RustSMB #1     │     │  RustSMB #2     │     │  RustSMB #N     │
│ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ LocalCache  │ │     │ │ LocalCache  │ │     │ │ LocalCache  │ │
│ │ (LRU+Epoch) │ │     │ │ (LRU+Epoch) │ │     │ │ (LRU+Epoch) │ │
│ └──────┬──────┘ │     │ └──────┬──────┘ │     │ └──────┬──────┘ │
│ ┌──────▼──────┐ │     │ ┌──────▼──────┐ │     │ ┌──────▼──────┐ │
│ │CachedStore  │ │     │ │CachedStore  │ │     │ │CachedStore  │ │
│ └──────┬──────┘ │     │ └──────┬──────┘ │     │ └──────┬──────┘ │
│ ┌──────▼──────┐ │     │ ┌──────▼──────┐ │     │ ┌──────▼──────┐ │
│ │ Raft Node   │◄┼─────┼►│ Raft Node   │◄┼─────┼►│ Raft Node   │ │
│ │ (Embedded)  │ │     │ │ (Embedded)  │ │     │ │ (Embedded)  │ │
│ └─────────────┘ │     │ └─────────────┘ │     │ └─────────────┘ │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                  ┌─────────────────────────────┐
                  │     Bulk Data Layer         │
                  │  ┌───────────────────────┐  │
                  │  │     Redis Cluster     │  │
                  │  │  ─────────────────    │  │
                  │  │  • SessionState       │  │
                  │  │  • HandleState (10M+) │  │
                  │  │  • TreeState          │  │
                  │  │  • LockState          │  │
                  │  └───────────────────────┘  │
                  └─────────────────────────────┘
```

## Requirements

| Requirement | Value |
|-------------|-------|
| Scale | 1000+ clients, 10M+ handles, 10+ servers |
| Consistency | Strong (CP) - reject writes during partition |
| Failure detection | 15 seconds |
| Cache invalidation | All caches invalidate on any server failure |
| Deployment | Bare metal/VMs (no Kubernetes) |

## Data Flow

### Read (Cache Hit) - ~10μs
```
Client → Server → LocalCache (hit) → Response
```

### Read (Cache Miss) - ~1-5ms
```
Client → Server → LocalCache (miss) → Redis → Update Cache → Response
```

### Write - ~1-5ms
```
Client → Server → Redis (write) → Raft (invalidation) → Response
```

### Coordination (Lease/Lock) - ~1-5ms
```
Client → Server → Raft (consensus) → Redis (if needed) → Response
```

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

### Raft Library: openraft

We use [openraft](https://github.com/datafuselabs/openraft) because:
- Async-native with Tokio (matches RustSMB)
- Event-driven architecture (efficient, no periodic ticks)
- Actively maintained (v0.9.20, June 2025)
- Production-proven (Databend, CnosDB)
- 92% test coverage

### What openraft Provides vs What We Build

openraft is a **Raft consensus library** - it provides the core distributed consensus algorithm. We use it as a dependency, not implement Raft ourselves.

| openraft Provides | We Implement |
|-------------------|--------------|
| Raft consensus algorithm | `CoordinationBackend` trait |
| Leader election | `RaftCoordinator` (implements trait using openraft) |
| Log replication | `CoordinationState` (our application state) |
| Heartbeat/failure detection | Business logic (leases, locks, epochs) |
| Membership changes | |
| Linearizable reads | |

**Design principle:** The rest of RustSMB only sees `CoordinationBackend` trait. The openraft implementation details (storage, network, state machine) are encapsulated inside `RaftCoordinator`.

```rust
// The ONLY trait the rest of the system sees
pub trait CoordinationBackend: Send + Sync + 'static {
    fn register_server(...) -> BoxFuture<...>;
    fn get_epoch(...) -> BoxFuture<...>;
    fn create_lease(...) -> BoxFuture<...>;
    // ... other coordination operations
}

// RaftCoordinator implements this trait using openraft internally
pub struct RaftCoordinator {
    raft: openraft::Raft<...>,           // openraft instance
    state: Arc<RwLock<CoordinationState>>, // our application state
    // ... internal details hidden
}

impl CoordinationBackend for RaftCoordinator {
    // All coordination operations go through Raft consensus
}
```

**What we don't implement:**
- Leader election algorithm
- Log replication protocol
- Heartbeat/timeout logic
- Raft consensus correctness guarantees

All of these are handled by openraft internally.

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
    pub leases: HashMap<[u8; 16], LeaseEntry>,

    /// Active byte-range locks (for conflict detection)
    pub locks: HashMap<String, Vec<DistributedLock>>,
}
```

### Raft Commands

```rust
pub enum RaftCommand {
    // Server membership
    AddServer(ServerRegistration),
    RemoveServer(String),

    // Cache invalidation
    IncrementEpoch,

    // Lease management
    CreateLease(LeaseEntry),
    BreakLease { lease_key: [u8; 16], new_state: u32 },
    ReleaseLease([u8; 16]),

    // Lock management
    AcquireLock(DistributedLock),
    ReleaseLock(u64),
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
   │                          │                          │
   ├──AppendEntries (5s)─────►│                          │
   │◄─────────────────────────┤                          │
   │                          │                          │
   ├──AppendEntries (5s)─────►│                          │
   │◄─────────────────────────┤                          │
   │                          │                          │
   ✗ [CRASH]                  │                          │
                              │                          │
              [election_timeout (10-15s)]                │
                              │                          │
                    [New leader elected]                 │
                              │                          │
                              ├──RemoveServer(A)────────►│
                              ├──IncrementEpoch─────────►│
                              │                          │
                              │         ┌────────────────┤
                              │         │ invalidate_all()
                              │         └────────────────┤
```

### Timing Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Heartbeat interval | 5 seconds | Raft leader sends to followers |
| Election timeout | 10-15 seconds | Random, triggers leader election |
| Failure detection | ~15 seconds | Max time to detect dead server |

## Coordination Backend Trait

```rust
pub trait CoordinationBackend: Send + Sync + 'static {
    // === Server Membership ===
    fn register_server<'a>(
        &'a self,
        registration: &'a ServerRegistration,
    ) -> BoxFuture<'a, Result<(), CoordError>>;

    fn leave_cluster(&self) -> BoxFuture<'_, Result<(), CoordError>>;

    fn get_servers(&self) -> BoxFuture<'_, Result<Vec<ServerRegistration>, CoordError>>;

    // === Cache Epoch ===
    fn get_epoch(&self) -> BoxFuture<'_, Result<u64, CoordError>>;

    fn subscribe_epoch_changes(&self) -> BoxFuture<'_, EpochStream>;

    // === Lease Coordination ===
    fn create_lease<'a>(
        &'a self,
        lease: &'a LeaseEntry,
    ) -> BoxFuture<'a, Result<(), CoordError>>;

    fn get_lease(
        &self,
        lease_key: &[u8; 16],
    ) -> BoxFuture<'_, Result<Option<LeaseEntry>, CoordError>>;

    fn break_lease<'a>(
        &'a self,
        lease_key: &[u8; 16],
        new_state: u32,
    ) -> BoxFuture<'a, Result<(), CoordError>>;

    fn subscribe_lease_breaks(
        &self,
        server_id: &str,
    ) -> BoxFuture<'_, LeaseBreakStream>;

    // === Lock Coordination ===
    fn acquire_lock<'a>(
        &'a self,
        lock: &'a DistributedLock,
    ) -> BoxFuture<'a, Result<bool, CoordError>>;

    fn release_lock(&self, lock_id: u64) -> BoxFuture<'_, Result<(), CoordError>>;

    fn get_locks_for_file(
        &self,
        path: &str,
    ) -> BoxFuture<'_, Result<Vec<DistributedLock>, CoordError>>;
}
```

## Lease Coordination

### Lease Entry

```rust
pub struct LeaseEntry {
    /// Unique lease key (usually derived from file path)
    pub lease_key: [u8; 16],

    /// Client that owns this lease
    pub client_id: String,

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
   │                 │              │                 │           │
   │  Has lease RWH  │              │                 │           │
   │  on file.txt    │              │                 │           │
   │                 │              │                 │◄──CREATE──┤
   │                 │              │                 │  file.txt │
   │                 │              │                 │  want W   │
   │                 │              │◄──BreakLease────┤           │
   │                 │              │  (file.txt,W)   │           │
   │                 │◄─────────────│ Apply break     │           │
   │◄──OPLOCK_BREAK──│              │                 │           │
   │  (new_state=R)  │              │                 │           │
   ├──flush writes──►│              │                 │           │
   ├──OPLOCK_ACK────►│              │                 │           │
   │                 │──AckBreak───►│                 │           │
   │                 │              │──Lease granted─►│           │
   │                 │              │                 ├──CREATE───►
   │                 │              │                 │  response │
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

## Crate Structure

```
crates/
├── rustsmb-state/                   # State trait definitions
│   └── src/
│       ├── traits.rs                # StateStore, CoordinationBackend
│       ├── types.rs                 # SessionState, HandleState, etc.
│       ├── coordination.rs          # Coordination types (LeaseEntry, etc.)
│       └── lib.rs                   # Re-exports

├── rustsmb-state-cached/            # Cached state store
│   └── src/
│       ├── lib.rs                   # CachedStateStore wrapper
│       └── cache.rs                 # LocalCache (LRU + epoch)

├── rustsmb-coord-raft/              # Embedded Raft coordination
│   └── src/
│       ├── lib.rs                   # RaftCoordinator (implements CoordinationBackend)
│       └── state.rs                 # CoordinationState (application state)
│   # Note: openraft handles storage, network, consensus internally

├── rustsmb-state-redis/             # Bulk data storage (existing)
```

**Key simplification:** `RaftCoordinator` is the only public type from `rustsmb-coord-raft`. It implements `CoordinationBackend` and encapsulates all openraft internals (storage, network, state machine traits).

## Dependencies

```toml
[workspace.dependencies]
# Embedded Raft
openraft = "0.10"

# Caching
lru = "0.12"

# Async utilities
tokio-stream = "0.1"
pin-project = "1.1"

# Serialization
bincode = "1.3"
```

## Performance Expectations

| Operation | Latency | Notes |
|-----------|---------|-------|
| Cache hit | ~10μs | Local memory only |
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
