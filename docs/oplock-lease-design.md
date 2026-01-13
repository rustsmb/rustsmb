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

## Phase 18: Oplock/Lease Break Notifications

This section documents the implementation design for same-server oplock/lease break notifications per MS-SMB2 specification sections 2.2.23-2.2.25 and 3.3.4.6-3.3.4.7.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LeaseBreakRegistry                                 │
│  (Arc<> shared across all connections, held in SmbServer)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  lease_connections: DashMap<lease_key, LeaseConnectionEntry>                │
│  pending_breaks: DashMap<break_id, PendingBreak>                            │
└─────────────────────────────────────────────────────────────────────────────┘
         │
         │  mpsc channels
         ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  ConnectionHandler│    │  ConnectionHandler│    │  ConnectionHandler│
│  break_rx: Receiver│   │  break_rx: Receiver│   │  break_rx: Receiver│
└──────────────────┘    └──────────────────┘    └──────────────────┘
```

**Key design decisions:**
- Same-server breaks use local mpsc channels (no network hop)
- Cross-server conflicts continue using reduced-grant strategy (NOT implemented - see below)
- 35-second break timeout per MS-SMB2 spec
- MessageId=0xFFFFFFFFFFFFFFFF for unsolicited notifications

### Data Structures

```rust
/// Registry for managing lease break notifications across connections.
pub struct LeaseBreakRegistry {
    /// Map from lease_key (hex) to connection entry.
    lease_connections: DashMap<String, LeaseConnectionEntry>,
    /// Map from break_id to pending break info.
    pending_breaks: DashMap<u64, PendingBreak>,
    /// Next break ID.
    next_break_id: AtomicU64,
    /// Break timeout duration (35 seconds per MS-SMB2).
    break_timeout: Duration,
}

/// Entry for a connection that owns a lease.
pub struct LeaseConnectionEntry {
    /// Channel to send break notifications to this connection.
    pub break_tx: mpsc::Sender<LeaseBreakEvent>,
    /// Server ID that owns this connection.
    pub server_id: String,
    /// Client GUID for this connection.
    pub client_guid: String,
}

/// A lease break event to be sent to a client.
pub struct LeaseBreakEvent {
    /// Lease key being broken.
    pub lease_key: [u8; 16],
    /// Current lease state before break.
    pub current_state: u32,
    /// New lease state to transition to.
    pub new_state: u32,
    /// New epoch (SMB 3.x).
    pub new_epoch: u16,
    /// Whether acknowledgment is required.
    pub ack_required: bool,
    /// Unique break ID for tracking acknowledgment.
    pub break_id: u64,
}

/// Result of a lease break attempt.
pub enum LeaseBreakResult {
    /// Client acknowledged the break.
    Acknowledged { new_state: u32, epoch: u16 },
    /// Break timed out (forced to NONE).
    TimedOut,
    /// Client disconnected during break.
    Disconnected,
}
```

### LeaseEntry Extensions

Add fields to `LeaseEntry` in `coordination.rs` for break tracking:

```rust
pub struct LeaseEntry {
    // ... existing fields ...

    /// Whether a break is in progress.
    pub breaking: bool,
    /// Target state for the break.
    pub break_to_state: u32,
    /// When break started (for timeout).
    pub break_started_at: Option<u64>,
}
```

### Implementation Phases

#### Phase 18A: Core Infrastructure

Create new module `crates/rustsmb-server/src/lease_break.rs`:
- `LeaseBreakRegistry` struct with DashMap-based storage
- `LeaseBreakEvent`, `PendingBreak`, `LeaseBreakResult` types
- Methods: `register_lease()`, `unregister_lease()`, `break_lease()`, `handle_acknowledgment()`
- Background timeout processor task

#### Phase 18B: Connection Handler Integration

Modify `ConnectionHandler`:
1. Add `break_rx: mpsc::Receiver<LeaseBreakEvent>` field
2. Add `lease_registry: Arc<LeaseBreakRegistry>` field
3. Change `run()` loop to use `tokio::select!`:

```rust
loop {
    tokio::select! {
        message_result = self.read_message() => {
            // Handle client request
        }
        Some(break_event) = self.break_rx.recv() => {
            self.send_lease_break_notification(&break_event).await?;
        }
    }
}
```

4. Implement `send_lease_break_notification()` to build and send notification with:
   - MessageId = 0xFFFFFFFFFFFFFFFF
   - SessionId = 0, TreeId = 0
   - No signing (per MS-SMB2 3.3.4.7)

#### Phase 18C: CREATE Handler Changes

Modify CREATE handler after `check_and_create_lease()`:
1. Partition conflicts by `server_id == self.server_id`
2. For same-server conflicts:
   - Calculate break-to state using `calculate_break_state()`
   - Call `lease_registry.break_lease()` (async, waits for ack/timeout)
   - Update lease state in StateStore
3. For cross-server conflicts: continue with reduced grant (existing behavior)
4. Register lease with `lease_registry.register_lease()`

#### Phase 18D: OPLOCK_BREAK Handler

Replace `STATUS_NOT_SUPPORTED` with proper handling:
1. Parse acknowledgment (detect lease vs oplock by structure_size: 36 for lease, 24 for oplock)
2. Validate lease state is subset of break-to state (per MS-SMB2 3.3.5.22.2)
3. Call `lease_registry.handle_acknowledgment()`
4. Update lease in StateStore
5. Return LeaseBreakResponse/OplockBreakResponse

#### Phase 18E: CLOSE Handler Integration

On CLOSE:
1. Call `lease_registry.unregister_lease()` for handle's lease
2. Delete lease from StateStore (existing code)

On disconnect:
1. Unregister all leases for this connection

### Protocol Requirements (MS-SMB2)

1. **Notification format** (Section 2.2.23.2):
   - Structure size: 44 bytes for lease break
   - Flags: ACK_REQUIRED (0x01) unless READ_CACHING only
   - Epoch: increment on each state change

2. **When ACK required** (Section 3.3.4.7):
   - READ_CACHING only: No ACK required, break completes immediately
   - Any other state: ACK required, start 35s timer

3. **Acknowledgment validation** (Section 3.3.5.22.2):
   - LeaseState MUST be subset of NewLeaseState from notification
   - Reject with STATUS_REQUEST_NOT_ACCEPTED if not

4. **Timeout handling** (Section 3.3.6.5):
   - If timer expires and Lease.Breaking is TRUE
   - Force LeaseState to NONE
   - Set Lease.Breaking to FALSE

### Files to Modify

| File | Changes |
|------|---------|
| `crates/rustsmb-server/src/lease_break.rs` | NEW - LeaseBreakRegistry, events, timeout handling |
| `crates/rustsmb-server/src/lib.rs` | Export lease_break module |
| `crates/rustsmb-server/src/server.rs` | Create Arc<LeaseBreakRegistry>, pass to handlers |
| `crates/rustsmb-server/src/handler.rs` | Channel integration, select! loop, break notification, OPLOCK_BREAK handler |
| `crates/rustsmb-state/src/coordination.rs` | Add breaking/break_to_state to LeaseEntry |
| `crates/rustsmb-server/Cargo.toml` | Add dashmap dependency |

### Unit Tests (MS-SMB2 Compliance)

Unit tests organized by MS-SMB2 specification chapter:

#### 3.3.4.7 Tests - Sending a Lease Break Notification

```rust
#[test]
fn test_lease_break_notification_structure_size() {
    // Verify structure size is 44 bytes per MS-SMB2 2.2.23.2
}

#[test]
fn test_lease_break_notification_message_id() {
    // MessageId MUST be 0xFFFFFFFFFFFFFFFF per MS-SMB2 3.3.4.7
}

#[test]
fn test_lease_break_notification_session_tree_zero() {
    // SessionId and TreeId MUST be 0 per MS-SMB2 3.3.4.7
}

#[test]
fn test_lease_break_ack_required_non_read() {
    // ACK_REQUIRED flag set when state includes WRITE or HANDLE
    // Per MS-SMB2 3.3.4.7: "If Lease.LeaseState is not SMB2_LEASE_READ_CACHING"
}

#[test]
fn test_lease_break_no_ack_required_read_only() {
    // No ACK required when breaking to READ_CACHING only
    // Per MS-SMB2 3.3.4.7: "Otherwise the server does not require acknowledgment"
}

#[test]
fn test_lease_break_epoch_increment() {
    // NewEpoch is incremented on each break per MS-SMB2 3.3.4.7
}

#[test]
fn test_lease_break_not_signed() {
    // Break notifications should NOT be signed per MS-SMB2 3.3.4.7
}
```

#### 3.3.5.22 Tests - Receiving OPLOCK_BREAK Acknowledgment

```rust
#[test]
fn test_lease_ack_state_must_be_subset() {
    // LeaseState MUST be subset of Lease.BreakToLeaseState
    // Per MS-SMB2 3.3.5.22.2: reject with STATUS_REQUEST_NOT_ACCEPTED
}

#[test]
fn test_lease_ack_invalid_lease_key() {
    // Return STATUS_OBJECT_NAME_NOT_FOUND if lease not found
}

#[test]
fn test_lease_ack_not_breaking() {
    // Return error if lease is not in Breaking state
}

#[test]
fn test_lease_ack_updates_state() {
    // After ACK, Lease.LeaseState = acknowledged state
    // Lease.Breaking = FALSE per MS-SMB2 3.3.5.22.2
}

#[test]
fn test_oplock_ack_structure_size_24() {
    // Oplock ACK has structure size 24, lease ACK has 36
}

#[test]
fn test_oplock_ack_file_not_found() {
    // Return STATUS_FILE_CLOSED if handle not found
}
```

#### 3.3.6.5 Tests - Lease Break Acknowledgment Timer Event

```rust
#[test]
fn test_lease_break_timeout_35_seconds() {
    // Break times out after 35 seconds per MS-SMB2
}

#[test]
fn test_lease_break_timeout_forces_none() {
    // On timeout, LeaseState forced to NONE per MS-SMB2 3.3.6.5
}

#[test]
fn test_lease_break_timeout_clears_breaking() {
    // On timeout, Lease.Breaking set to FALSE
}
```

#### LeaseBreakRegistry Tests

```rust
#[test]
fn test_registry_register_lease() {
    // Register lease creates entry with channel
}

#[test]
fn test_registry_unregister_lease() {
    // Unregister removes entry
}

#[test]
fn test_registry_break_sends_event() {
    // break_lease() sends LeaseBreakEvent via channel
}

#[test]
fn test_registry_handle_ack_completes_break() {
    // handle_acknowledgment() notifies waiting caller
}

#[test]
fn test_registry_concurrent_breaks() {
    // Multiple concurrent breaks to different leases
}

#[test]
fn test_registry_break_nonexistent_lease() {
    // Breaking unregistered lease returns appropriate error
}
```

#### Integration Tests

```rust
#[tokio::test]
async fn test_two_clients_lease_break_flow() {
    // Client A opens file with RWH lease
    // Client B opens same file
    // Client A receives break notification
    // Client A acknowledges with reduced state
    // Client B's open completes
}

#[tokio::test]
async fn test_lease_break_timeout_integration() {
    // Client A opens file with RWH lease
    // Client B opens same file
    // Client A does NOT acknowledge
    // After 35s timeout, Client B's open completes
}

#[tokio::test]
async fn test_client_disconnect_during_break() {
    // Client A opens file with lease
    // Client B opens same file (triggers break)
    // Client A disconnects before ACK
    // Client B's open completes
}
```

### Cross-Server Lease Breaks (NOT IMPLEMENTED)

Cross-server lease breaks require inter-server communication and are significantly more complex. The current design continues using the **reduced grant** strategy from Phase 14 for cross-server conflicts:

- When Server B detects a conflict with a lease held on Server A, it grants a reduced lease state to the new client
- No break notification is sent to the client on Server A
- The file open still succeeds with reduced caching capability

Future options for cross-server breaks (not planned):
1. **Redis Pub/Sub**: Publish break request, servers subscribe
2. **Coordinator RPC**: Route breaks through coordinator service
3. **Direct gRPC**: Server-to-server communication

## References

- [MS-SMB2: Server Message Block Protocol Version 2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- Section 2.2.23: SMB2 OPLOCK_BREAK Notification
- Section 2.2.24: SMB2 OPLOCK_BREAK Acknowledgment
- Section 3.3.4.6: Sending an Oplock Break Notification
- Section 3.3.4.7: Sending a Lease Break Notification
- Section 3.3.5.22: Receiving an SMB2 OPLOCK_BREAK Acknowledgment
- Section 3.3.6.5: Lease Break Acknowledgment Timer Event
