# SMB Persistent Handles and Leases

## Overview

This document explains two critical SMB2/SMB3 features for enterprise high availability:

- **Persistent Handles** - File handles that survive server failures
- **Leases** - Client-side caching with server-managed cache coherency

Together, these features enable transparent failover where applications continue working after a server crash without losing data or reopening files.

## Why Are They Needed?

### The Problem: Session-Level HA Is Not Enough

RustSMB's Phase 10 implemented session binding, which allows clients to reconnect to a different server without re-authenticating. However, this only preserves the session - not the file handles.

**Current behavior (without persistent handles):**

```
1. Client opens file.txt on Server A
   → Gets handle_id = 0x1234
   → File position at byte 1000

2. Server A crashes

3. Client connects to Server B
   → Session binding succeeds (Phase 10) ✓

4. Client tries to READ using handle_id = 0x1234
   → Server B: "Unknown handle!"
   → Returns STATUS_FILE_CLOSED

5. Client must re-open file
   → File position reset to 0
   → Any unsaved data is lost
   → Application may fail or corrupt data
```

**Desired behavior (with persistent handles):**

```
1. Client opens file.txt with DurableHandleRequest
   → Server stores: {handle_id=0x1234, path="file.txt", position=1000}

2. Server A crashes

3. Client connects to Server B
   → Session binding succeeds ✓

4. Client sends CREATE with DurableHandleReconnect(handle_id=0x1234)
   → Server B looks up handle state in Redis
   → Reopens file at same path
   → Returns same handle_id = 0x1234

5. Client continues READ/WRITE
   → No data loss
   → Application unaware of failover
```

### Who Needs This?

| Client Type | Need Persistent Handles? | Need Leases? |
|-------------|-------------------------|--------------|
| Linux/Unix (smbclient, mount.cifs) | No - apps expect handles to fail | No |
| Windows desktop | Yes - apps expect transparent recovery | Yes - for performance |
| SQL Server, Hyper-V | **Required** - continuous availability | **Required** |
| Office applications | Yes - to prevent data loss | Yes |

## Persistent Handles

### What Is a Persistent Handle?

A persistent handle is a file handle whose state is stored externally (in Redis) so it can be recovered after:
- Network disconnection
- Server crash
- Failover to another server

SMB defines two types:

| Type | Introduced | Survives | Use Case |
|------|-----------|----------|----------|
| **Durable Handle** | SMB 2.1 | Network glitch, server crash | Desktop applications |
| **Persistent Handle** | SMB 3.0 | Everything + planned failover | Hyper-V, SQL Server |

### How Durable Handles Work

Durable handles are negotiated during the CREATE (file open) request using CREATE contexts.

**Protocol Flow:**

```
Client                          Server                      Redis
   │                               │                          │
   ├──CREATE file.txt─────────────>│                          │
   │  with DurableHandleRequest    │                          │
   │                               ├──Store HandleState──────>│
   │                               │  {handle_id, path, ...}  │
   │<──────────────CREATE response─┤                          │
   │  with DurableHandleResponse   │                          │
   │  handle_id = 0x1234           │                          │
   │                               │                          │
   ├──WRITE data──────────────────>│                          │
   │  handle_id = 0x1234           ├──Update position────────>│
   │                               │                          │
   │  [CONNECTION LOST]            │                          │
   │                               │                          │
   │  [RECONNECT TO NEW SERVER]    │                          │
   │                               │                          │
   ├──CREATE file.txt─────────────>│                          │
   │  with DurableHandleReconnect  │                          │
   │  handle_id = 0x1234           ├──Lookup HandleState─────>│
   │                               │<─────────────────────────┤
   │                               │  Reopen file at path     │
   │<──────────────CREATE response─┤                          │
   │  same handle_id = 0x1234      │                          │
   │                               │                          │
   ├──READ─────────────────────────>│                          │
   │  handle_id = 0x1234           │  (Works!)                │
```

### CREATE Contexts

Clients request durable handles using CREATE contexts (MS-SMB2 Section 2.2.13.2):

| Context Name | Type | Purpose |
|--------------|------|---------|
| `DHnQ` | DurableHandleRequest | Request durable handle (SMB 2.1) |
| `DHnC` | DurableHandleReconnect | Reconnect to existing handle |
| `DH2Q` | DurableHandleRequestV2 | Request durable/persistent (SMB 3.0+) |
| `DH2C` | DurableHandleReconnectV2 | Reconnect with GUID validation |

**DurableHandleRequestV2 flags:**

```
Flags:
  0x01 - Reserved
  0x02 - PERSISTENT - Request persistent handle (survives planned failover)
```

### Handle State Storage

For handles to survive failover, we store their state in Redis:

```rust
pub struct HandleState {
    // Identity
    pub persistent_id: u128,        // Unique ID (returned to client)
    pub volatile_id: u128,          // Per-connection ID
    pub create_guid: [u8; 16],      // For reconnection validation

    // Session association
    pub session_id: u64,
    pub tree_id: u32,
    pub share_name: String,

    // File state
    pub path: String,               // File path for reopening
    pub access_mask: u32,           // How file was opened
    pub share_access: u32,          // Sharing flags
    pub create_options: u32,        // Creation options
    pub file_offset: u64,           // Current file position

    // Durability
    pub is_durable: bool,           // Can survive disconnect
    pub is_persistent: bool,        // Can survive planned failover
    pub durable_timeout: u32,       // How long to keep after disconnect
    pub reconnect_deadline: u64,    // When handle expires
}
```

### Persistent vs Durable Handles

| Feature | Durable (SMB 2.1) | Persistent (SMB 3.0) |
|---------|-------------------|----------------------|
| Survives network glitch | Yes | Yes |
| Survives server crash | Yes | Yes |
| Survives planned failover | No | Yes |
| Requires encryption | No | Yes (SMB 3.0+) |
| Timeout | Client-specified | Indefinite |
| Use case | Desktop apps | Hyper-V, SQL Server |

## Leases

### What Is a Lease?

A **lease** is SMB's mechanism for client-side caching with server-managed coherency. It allows clients to:
- Cache file data locally (avoid network round-trips)
- Cache metadata (reduce latency)
- Buffer writes locally (batch I/O)

The server tracks who has leases and sends **lease break** notifications when another client needs incompatible access.

### Why Leases Matter for Performance

Without leases:
```
Every READ → Network round-trip to server → Response
Every WRITE → Network round-trip to server → Acknowledgment
```

With leases:
```
First READ → Get data + READ lease
Subsequent READs → Local cache (no network!)
WRITEs → Local buffer with WRITE lease
Sync → Single batch write to server
```

**Performance impact:** 10-100x improvement for random I/O workloads.

### Lease States

Leases have three independent states that can be combined:

| State | Flag | Effect |
|-------|------|--------|
| **Read Caching** (R) | 0x01 | Client may cache read data |
| **Handle Caching** (H) | 0x02 | Client may keep handle open locally |
| **Write Caching** (W) | 0x04 | Client may buffer writes locally |

Common combinations:

| Lease | Meaning |
|-------|---------|
| R | Read-only caching |
| RH | Read + handle caching |
| RWH | Full caching (exclusive access) |
| None | No caching allowed |

### Lease Protocol Flow

```
Client A                    Server                    Client B
    │                          │                          │
    ├──CREATE file.txt────────>│                          │
    │  LeaseRequest(R-W-H)     │                          │
    │<──────────CREATE─────────┤                          │
    │  LeaseResponse(R-W-H)    │                          │
    │                          │                          │
    │  [Client A caches file]  │                          │
    │                          │                          │
    │                          │<──CREATE file.txt────────┤
    │                          │  (wants write access)    │
    │                          │                          │
    │<──OPLOCK_BREAK──────────┤                          │
    │  "Give up W lease"       │                          │
    │                          │                          │
    │  [Client A flushes]      │                          │
    │                          │                          │
    ├──OPLOCK_BREAK_ACK───────>│                          │
    │  "OK, W released"        │                          │
    │                          │                          │
    │                          ├──CREATE response────────>│
    │                          │  (Client B can write)    │
```

### Lease Break Notifications

When a lease must be broken, the server sends an unsolicited OPLOCK_BREAK (lease break) notification:

```rust
pub struct LeaseBreakNotification {
    pub structure_size: u16,      // Always 44
    pub new_epoch: u16,           // Incremented on each state change
    pub flags: u32,               // Break flags
    pub lease_key: [u8; 16],      // Which lease is breaking
    pub current_lease_state: u32, // Current state
    pub new_lease_state: u32,     // State to transition to
    pub break_reason: u32,        // Why breaking
    pub access_mask_hint: u32,    // Hint about conflicting access
    pub share_mask_hint: u32,     // Hint about conflicting share
}
```

The client must acknowledge the break within a timeout (default 35 seconds) or the server forcibly breaks the lease.

### Client Crash: Lease Break Timeout

What happens when a client holding a lease crashes and cannot acknowledge the break?

**Timeout and Forced Break:**

```
Client A (crashed)          Server                    Client B
      ✗                        │                          │
                               │<──CREATE file.txt────────┤
                               │  (wants write access)    │
                               │                          │
      ✗←──LEASE_BREAK─────────┤                          │
         (no response)         │                          │
                               │                          │
                               │  [TIMEOUT: 35 seconds]   │
                               │                          │
                               │  Server forcibly breaks  │
                               │  Client A's lease        │
                               │                          │
                               ├──CREATE response────────>│
                               │  (Client B can proceed)  │
```

**What happens to cached data when Client A resumes?**

| Scenario | Cached Write Data | Reason |
|----------|-------------------|--------|
| Client truly crashed | **Lost forever** | Data was only in client RAM |
| Network glitch, client still alive | **Must discard** | Lease broken, epoch changed |
| Client reconnects before timeout | **Can flush** | Lease still valid |

**The Lease Epoch Mechanism:**

```
Before break:  lease_epoch = 5,  lease_state = RWH
After break:   lease_epoch = 6,  lease_state = None
```

When client A reconnects and sees the epoch changed:
- Its cached data is **stale** - another client may have written
- Protocol requires discarding cache and re-syncing with server
- Attempting to write stale data would corrupt the file

**Key insight:** The server never had the cached write data - it only existed in client A's memory. Once the lease is broken, that data is gone.

**Implications for Applications:**

1. **Flush frequently** - Don't hold large amounts of unflushed data
2. **Expect data loss on crash** - Same as local filesystem crash behavior
3. **The 35-second timeout is the recovery window** - Client must reconnect and flush within this window to preserve cached writes

### Lease vs Oplock

Leases (SMB 2.1+) supersede the older oplock mechanism:

| Feature | Oplock (SMB 1.0) | Lease (SMB 2.1+) |
|---------|------------------|------------------|
| Per-handle | Yes | No - per lease key |
| Multiple handles | No | Yes - share lease |
| Directory caching | No | Yes (SMB 3.0+) |
| Epoch tracking | No | Yes |
| Preferred | No | Yes |

## Effects and Trade-offs

### Benefits

1. **Transparent failover** - Applications continue working after server failure
2. **No data loss** - Unsaved writes are not lost during failover
3. **Performance** - Client-side caching reduces network I/O dramatically
4. **Enterprise compatibility** - Required for Hyper-V, SQL Server over SMB

### Complexity Cost

1. **Protocol complexity** - CREATE context parsing, lease state machine
2. **State management** - Handle state must be stored in Redis
3. **Testing burden** - Need to test all failover scenarios
4. **Debugging difficulty** - Distributed state makes issues harder to diagnose

### When to Skip This

Consider not implementing if:
- Only Linux/Unix clients (they handle reconnection at mount level)
- Simple file sharing (users can retry operations)
- No enterprise requirements (no Hyper-V/SQL Server)

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| HandleState in Redis | Complete | Phase 10 - stores persistent_id |
| CREATE context parsing | Not implemented | Need to parse DHnQ, DHnC, etc. |
| Durable handle request | Not implemented | Need to set is_durable flag |
| Durable handle reconnect | Not implemented | Need reopen logic |
| Persistent handles | Not implemented | Need SMB 3.0 validation |
| Lease request parsing | Not implemented | Need to parse RqLs context |
| Lease state machine | Not implemented | Need LeaseManager |
| Oplock break handler | Not implemented | Need unsolicited notifications |

## References

- [MS-SMB2 Section 2.2.13.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997) - CREATE Request Extensions (CREATE Contexts)
- [MS-SMB2 Section 2.2.13.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5f60bf26-ec0e-4e17-b9bb-0e0f71a66f94) - Durable Handle Request
- [MS-SMB2 Section 2.2.13.2.8](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee3faa51-53e0-4158-9b16-3a69c4c91a5b) - Lease Context
- [MS-SMB2 Section 2.2.23](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1c04f926-0a7a-453f-8bba-79bf91c90a62) - Lease Break Notification
- [Hyper-V over SMB Requirements](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-direct) - Continuous Availability requirements
