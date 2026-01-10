# SMB Oplock and Lease Design

## Overview

Oplocks (Opportunistic Locks) and Leases are SMB mechanisms that allow clients to cache file data locally, improving performance by reducing network round-trips. This document describes the RustSMB implementation.

## Oplock vs Lease

| Feature | Oplock (SMB 2.0) | Lease (SMB 2.1+) |
|---------|------------------|------------------|
| Scope | Per-handle | Per-file (across handles) |
| Identified by | File handle | 16-byte lease key |
| Survives reconnect | No | Yes (with same lease key) |
| Recommended | Legacy | Modern clients |

RustSMB primarily uses **leases** as they provide better semantics for multi-server deployments.

## Lease States

```
┌─────────────────────────────────────────────────────────────┐
│                    Lease State Bits                          │
├─────────────────────────────────────────────────────────────┤
│  Bit 0 (0x01): READ_CACHING                                 │
│    - Client can cache reads                                 │
│    - Multiple clients can hold simultaneously               │
│                                                             │
│  Bit 1 (0x02): WRITE_CACHING                                │
│    - Client can cache writes (exclusive)                    │
│    - Only one client can hold WRITE at a time               │
│                                                             │
│  Bit 2 (0x04): HANDLE_CACHING                               │
│    - Client can delay close operations                      │
│    - Allows handle reuse without server round-trip          │
└─────────────────────────────────────────────────────────────┘
```

### Common Lease Combinations

| State | Value | Meaning |
|-------|-------|---------|
| None | 0x00 | No caching allowed |
| Read | 0x01 | Read caching only |
| Read-Handle | 0x05 | Read + handle caching |
| Read-Write | 0x03 | Read + write caching (exclusive) |
| Read-Write-Handle | 0x07 | Full caching (exclusive) |

## Lease Compatibility Matrix

When a new client requests a lease, the server checks compatibility with existing leases:

| Existing \ Requested | R (0x01) | W (0x02) | H (0x04) | RW | RH | WH | RWH |
|---------------------|----------|----------|----------|-----|-----|-----|------|
| R (Read)            | ✓        | ✗        | ✓        | ✗   | ✓   | ✗   | ✗    |
| W (Write)           | ✗        | ✗        | ✗        | ✗   | ✗   | ✗   | ✗    |
| H (Handle)          | ✓        | ✗        | ✓        | ✗   | ✓   | ✗   | ✗    |
| RW                  | ✗        | ✗        | ✗        | ✗   | ✗   | ✗   | ✗    |
| RH                  | ✓        | ✗        | ✓        | ✗   | ✓   | ✗   | ✗    |
| WH                  | ✗        | ✗        | ✗        | ✗   | ✗   | ✗   | ✗    |
| RWH                 | ✗        | ✗        | ✗        | ✗   | ✗   | ✗   | ✗    |

**Key rule:** WRITE_CACHING is exclusive - only one client can have it.

## Architecture

### Single-Server Lease Flow

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│  Client A  │         │   Server   │         │  Client B  │
└─────┬──────┘         └─────┬──────┘         └─────┬──────┘
      │                      │                      │
      │ CREATE file.txt      │                      │
      │ lease=RWH            │                      │
      │─────────────────────>│                      │
      │                      │                      │
      │ SUCCESS              │                      │
      │ lease_granted=RWH    │                      │
      │<─────────────────────│                      │
      │                      │                      │
      │ (caching locally)    │  CREATE file.txt    │
      │                      │  lease=RWH          │
      │                      │<─────────────────────│
      │                      │                      │
      │ LEASE_BREAK          │  (conflict!)        │
      │ new_state=RH         │                      │
      │<─────────────────────│                      │
      │                      │                      │
      │ flush writes         │                      │
      │                      │                      │
      │ LEASE_BREAK_ACK      │                      │
      │ state=RH             │                      │
      │─────────────────────>│                      │
      │                      │                      │
      │                      │ SUCCESS             │
      │                      │ lease_granted=R     │
      │                      │─────────────────────>│
      │                      │                      │
```

### Multi-Server Lease Flow (Reduce Grant)

In a multi-server deployment, cross-server lease breaks are complex. RustSMB uses a **reduce grant** approach:

```
┌────────────┐    ┌────────────┐         ┌────────────┐    ┌────────────┐
│  Client A  │    │  Server A  │         │  Server B  │    │  Client B  │
└─────┬──────┘    └─────┬──────┘         └─────┬──────┘    └─────┬──────┘
      │                 │                      │                 │
      │ CREATE          │                      │                 │
      │ lease=RW        │                      │                 │
      │────────────────>│                      │                 │
      │                 │ store in Redis       │                 │
      │                 │─────────────────────>│                 │
      │ SUCCESS         │                      │                 │
      │ granted=RW      │                      │                 │
      │<────────────────│                      │                 │
      │                 │                      │                 │
      │                 │                      │ CREATE          │
      │                 │                      │ lease=RW        │
      │                 │                      │<────────────────│
      │                 │                      │                 │
      │                 │    check Redis       │                 │
      │                 │    conflict found!   │                 │
      │                 │<─────────────────────│                 │
      │                 │                      │                 │
      │ (no break sent) │                      │ SUCCESS         │
      │                 │                      │ granted=NONE    │ (reduced!)
      │                 │                      │────────────────>│
      │                 │                      │                 │
```

**Why no break?** Server B cannot send a lease break to Client A because Client A is connected to Server A. Instead of implementing complex inter-server communication, we simply reduce Client B's grant.

## Data Structures

### LeaseEntry (stored in Redis)

```rust
pub struct LeaseEntry {
    /// Unique lease identifier (16-byte key as hex string)
    pub lease_key: String,
    /// Client GUID that owns this lease
    pub client_guid: String,
    /// Session that owns this lease
    pub session_id: u64,
    /// Server that created this lease
    pub server_id: String,
    /// File path this lease applies to
    pub file_path: String,
    /// Current lease state (READ|WRITE|HANDLE flags)
    pub lease_state: u32,
    /// When the lease was created
    pub created_at: u64,
}
```

### LeaseConflictResult (from check_and_create_lease)

```rust
pub struct LeaseConflictResult {
    /// Whether the lease can be granted as requested
    pub can_grant: bool,
    /// Actual state that can be granted (may be reduced)
    pub granted_state: u32,
    /// Conflicting leases that would need to be broken
    pub conflicts: Vec<LeaseEntry>,
}
```

## Redis Storage

### Key Schema

```
smb:lease:{lease_key}           → LeaseEntry JSON
smb:lease:file:{file_path}      → Set of lease_keys for this file
smb:lease:server:{server_id}    → Set of lease_keys for this server
```

### Conflict Detection (WATCH Pattern)

```
WATCH smb:lease:file:{file_path}

# Read existing leases
existing = SMEMBERS smb:lease:file:{file_path}

# Check compatibility
granted_state = compute_compatible_state(existing, requested)

# Atomic create
MULTI
  SET smb:lease:{lease_key} {json}
  SADD smb:lease:file:{file_path} {lease_key}
  SADD smb:lease:server:{server_id} {lease_key}
EXEC

# If EXEC returns nil, someone else modified - retry
```

## Lease Lifecycle

### Creation (CREATE handler)

1. Client sends CREATE with lease request context
2. Server extracts lease_key and requested_state
3. Server calls `check_and_create_lease(file_path, lease, requested_state)`
4. Redis checks for conflicts, returns granted_state
5. Server responds with granted_state (may be reduced)

### Cleanup (CLOSE handler)

1. Client sends CLOSE
2. Server gets handle to find lease_key
3. Server calls `delete_lease(lease_key)`
4. Server deletes handle

### Session End

1. Session times out or client disconnects
2. Server iterates all handles for session
3. For each handle with lease_key, calls `delete_lease()`
4. Deletes all handles

### Server Failure

1. Coordinator detects server heartbeat timeout
2. Broadcasts server failure event
3. Each server calls `delete_leases_for_server(failed_server_id)`
4. Stale leases removed from Redis

## Future Enhancements (Phase 15+)

### Same-Server Oplock Breaks

For clients on the same server, we can implement full oplock breaks:

```rust
pub struct LeaseBreakManager {
    /// Map lease_key → connection channel
    lease_connections: DashMap<String, mpsc::Sender<LeaseBreakNotification>>,
    /// Pending break acknowledgments
    pending_breaks: DashMap<String, PendingBreak>,
}
```

Flow:
1. Detect conflict with lease on same server
2. Send `LeaseBreakNotification` via channel
3. Wait up to 35 seconds for `LeaseBreakAcknowledgment`
4. Client flushes cached writes, acknowledges
5. Grant conflicting lease

### Cross-Server Oplock Breaks

Options for future implementation:
1. **Redis Pub/Sub**: Publish break request, servers subscribe
2. **Coordinator RPC**: Route breaks through coordinator service
3. **Direct gRPC**: Server-to-server communication

## References

- [MS-SMB2: Server Message Block Protocol Version 2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- Section 3.3.1.4: Lease Management
- Section 2.2.13.2: SMB2 CREATE Request - Lease contexts
