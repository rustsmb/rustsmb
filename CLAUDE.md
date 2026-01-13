# RustSMB - Project Guidelines

## Project Overview

RustSMB is a Rust-based SMB2/SMB3 server with pluggable storage backends, designed as a stateless gateway for high availability deployments.

## Documentation

All project documentation is maintained in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [CLAUDE.md](./CLAUDE.md) | Project guidelines, coding conventions, and quick reference (this file) |
| [docs/architecture.md](./docs/architecture.md) | Detailed system architecture, core traits, data flow, and design decisions |
| [docs/ksmbd-research.md](./docs/ksmbd-research.md) | Linux kernel ksmbd research notes and lessons learned |
| [docs/ha-design.md](./docs/ha-design.md) | High availability design, session binding, Redis state store |
| [docs/persistent-handles-leases.md](./docs/persistent-handles-leases.md) | Persistent handles and leases for enterprise HA |
| [docs/state-store-design.md](./docs/state-store-design.md) | State store design with separate coordinator service and Redis leases/locks |
| [docs/oplock-lease-design.md](./docs/oplock-lease-design.md) | SMB oplock and lease design, conflict detection, multi-server handling |
| [docs/smb-protocol-testing.md](./docs/smb-protocol-testing.md) | SMB protocol testing with smbtorture, MS Protocol Test Suites, and smbprotocol |
| [docs/postmortem/](./docs/postmortem/) | Incident postmortems and lessons learned |

### Documentation Update Policy

- Update relevant docs after completing each task
- Run `make ci doc` and commit changes after completing each phase
- Keep CLAUDE.md as the entry point referencing all other docs

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Configuration Layer                          │
├─────────────────────────────────────────────────────────────────┤
│                    Transport Layer (TCP/TLS)                    │
├─────────────────────────────────────────────────────────────────┤
│                    Protocol Layer (rustsmb-protocol)            │
│  (SMB2/3 message parsing, command dispatch, signing/encryption)│
├─────────────────────────────────────────────────────────────────┤
│                    Session Layer (rustsmb-session)              │
│  (Stateless - via StateStore trait)                            │
├─────────────────────────────────────────────────────────────────┤
│                    VFS Layer (rustsmb-vfs)                      │
│  (StorageBackend trait - POSIX-like interface)                 │
├─────────────────────────────────────────────────────────────────┤
│                    Storage Backend Layer                        │
│  (rustsmb-backend-local, rustsmb-backend-memory)               │
└─────────────────────────────────────────────────────────────────┘
```

## Crate Structure

| Crate | Description |
|-------|-------------|
| `rustsmb-core` | Core types, errors, NT_STATUS codes |
| `rustsmb-protocol` | SMB2/3 protocol parsing and commands |
| `rustsmb-auth` | Authentication (NTLM, Simple) |
| `rustsmb-vfs` | StorageBackend trait definition |
| `rustsmb-state` | StateStore trait for HA support (includes leases/locks in Phase 13) |
| `rustsmb-state-memory` | In-memory state store (dev/testing) |
| `rustsmb-state-redis` | Redis state store (production, with WATCH-based lease/lock conflict detection) |
| `rustsmb-state-cached` | Cached state store with LRU + epoch invalidation (caching requires coordinator) |
| `rustsmb-coordinator` | Standalone coordinator service binary (Phase 13) |
| `rustsmb-coordinator-client` | gRPC client for connecting to coordinator service (Phase 13) |
| `rustsmb-coordinator-proto` | Protobuf/gRPC definitions for coordinator (Phase 13) |
| `rustsmb-coord-raft` | **DEPRECATED** - replaced by rustsmb-coordinator |
| `rustsmb-backend-local` | Local filesystem backend |
| `rustsmb-backend-memory` | In-memory filesystem (testing) |
| `rustsmb-session` | Session/connection management |
| `rustsmb-server` | Main server implementation |

## Coding Conventions

### Rust Style

- Follow standard Rust formatting (`cargo fmt`)
- Use `clippy` with default lints (`cargo clippy`)
- Prefer `&str` over `String` for function parameters when ownership isn't needed
- Use `thiserror` for error types in library crates
- Use `anyhow` only in the binary crate

### Naming Conventions

```rust
// Types: PascalCase
pub struct SessionState { ... }
pub enum NtStatus { ... }
pub trait StorageBackend { ... }

// Functions/methods: snake_case
pub fn create_session() { ... }
pub async fn read_file() { ... }

// Constants: SCREAMING_SNAKE_CASE
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
pub const MAX_READ_SIZE: u32 = 8 * 1024 * 1024;

// Modules: snake_case
mod session_manager;
mod protocol_handler;
```

### Async Patterns

```rust
// Use BoxFuture for object-safe async traits
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// Trait methods return BoxFuture
pub trait StorageBackend: Send + Sync + 'static {
    fn read<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        length: u32,
    ) -> BoxFuture<'a, Result<ReadResult, VfsError>>;
}

// Implementation wraps async block in Box::pin
impl StorageBackend for LocalBackend {
    fn read<'a>(
        &'a self,
        handle: &'a FileHandle,
        offset: u64,
        length: u32,
    ) -> BoxFuture<'a, Result<ReadResult, VfsError>> {
        Box::pin(async move {
            // async implementation
        })
    }
}
```

### Error Handling

```rust
// Define errors with thiserror
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VfsError {
    #[error("File not found: {0}")]
    NotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// Map to NT_STATUS for protocol responses
impl From<&VfsError> for NtStatus {
    fn from(err: &VfsError) -> Self {
        match err {
            VfsError::NotFound(_) => NtStatus::ObjectNameNotFound,
            VfsError::AccessDenied(_) => NtStatus::AccessDenied,
            _ => NtStatus::InternalError,
        }
    }
}
```

### Documentation

```rust
/// Brief description of the item.
///
/// More detailed explanation if needed.
///
/// # Arguments
///
/// * `param` - Description of the parameter
///
/// # Returns
///
/// Description of what is returned.
///
/// # Errors
///
/// Describes when this function returns an error.
///
/// # Examples
///
/// ```rust
/// let result = function(arg);
/// assert!(result.is_ok());
/// ```
pub fn function(param: Type) -> Result<Output, Error> { ... }
```

### Testing

```rust
// Unit tests in the same file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        // Arrange
        let input = create_test_input();

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_async_functionality() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}

// Integration tests in tests/ directory
// Property-based tests with proptest
#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_roundtrip(input in any::<u64>()) {
            let encoded = encode(input);
            let decoded = decode(&encoded).unwrap();
            prop_assert_eq!(input, decoded);
        }
    }
}
```

### Binary Protocol Parsing

```rust
use binrw::{BinRead, BinWrite};

/// SMB2 Header (64 bytes)
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct Smb2Header {
    #[brw(magic = b"\xFESMB")]
    pub protocol_id: (),

    #[brw(assert(structure_size == 64))]
    pub structure_size: u16,

    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    // ... rest of header
}
```

## Key Commands

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all

# Run the server
cargo run -- --config config.toml

# Run benchmarks
cargo bench

# Or use Makefile shortcuts
make test      # Run all tests
make clippy    # Run clippy
make fmt       # Format code
make ci        # Run fmt-check + clippy + test (full CI)

# Run smbtorture tests (requires Docker)
docker build -f tests/Dockerfile.smbtorture \
  --build-context scripts=tests/scripts \
  -t rustsmb-smbtorture .
docker run --rm rustsmb-smbtorture              # Run all test suites
docker run --rm rustsmb-smbtorture smb2.session # Run specific suite
docker run --rm -e RUST_LOG=debug rustsmb-smbtorture smb2.connect  # With debug output
```

## Development Workflow

**IMPORTANT: After completing each task, always run:**

```bash
make ci
```

Or manually:

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

This ensures:
1. Code is properly formatted
2. No clippy warnings
3. All tests pass

Do not commit code that fails any of these checks.

## Protocol References

**Primary Reference (all implementations and tests must be based on this):**
- [docs/MS-SMB2-250728.md](./docs/MS-SMB2-250728.md) - Local copy of MS-SMB2 specification (July 2025)

**Additional References:**
- [MS-SMB2 Specification (online)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [Linux ksmbd Documentation](https://docs.kernel.org/filesystems/smb/ksmbd.html)

## SMB2 Commands (19 total)

| Command | Code | Description |
|---------|------|-------------|
| NEGOTIATE | 0x00 | Protocol negotiation |
| SESSION_SETUP | 0x01 | Authentication |
| LOGOFF | 0x02 | Session termination |
| TREE_CONNECT | 0x03 | Connect to share |
| TREE_DISCONNECT | 0x04 | Disconnect from share |
| CREATE | 0x05 | Open/create file |
| CLOSE | 0x06 | Close file handle |
| FLUSH | 0x07 | Flush pending writes |
| READ | 0x08 | Read file data |
| WRITE | 0x09 | Write file data |
| LOCK | 0x0A | File locking |
| IOCTL | 0x0B | IO control |
| CANCEL | 0x0C | Cancel pending request |
| ECHO | 0x0D | Keep-alive |
| QUERY_DIRECTORY | 0x0E | List directory |
| CHANGE_NOTIFY | 0x0F | Directory watch |
| QUERY_INFO | 0x10 | Get file info |
| SET_INFO | 0x11 | Set file info |
| OPLOCK_BREAK | 0x12 | Oplock notification |

## Git Workflow

- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep commits atomic and focused
- Write descriptive commit messages

## Security Considerations

- Never log sensitive data (passwords, session keys)
- Validate all paths to prevent directory traversal
- Use constant-time comparison for signatures
- Encrypt session keys in state store

## Lessons Learned

### Protocol Implementation Best Practices

1. **Read the MS-SMB2 spec before implementing**: All SMB protocol implementations MUST follow the MS-SMB2 specification. Before writing any code, read the relevant spec section (e.g., 2.2.x for message formats, 3.3.5.x for server processing rules). The spec is the source of truth - do not guess or assume protocol behavior.

2. **Verify byte offsets per command type**: SMB2 command structures have different layouts. Always consult the specific MS-SMB2 section (2.2.x) for each command before implementing byte-level operations.

3. **Add trace logging during development**: Include trace! statements showing actual values at critical decision points. Can be disabled in production via log level.

4. **Reference spec section numbers in code**: Document which MS-SMB2 section defines the behavior being implemented.

5. **Read entire spec section including footnotes**: MS-SMB2 footnotes often contain critical implementation details (e.g., footnote <214> on FileId substitution).

6. **Test byte-level operations explicitly**: Unit tests should verify exact field positions in serialized structures, not just high-level behavior.

### FileId Body Offsets by Command

| Command | Body Offset | MS-SMB2 Section |
|---------|-------------|-----------------|
| CLOSE | 8 | 2.2.15 |
| FLUSH | 8 | 2.2.17 |
| LOCK | 8 | 2.2.26 |
| QUERY_DIRECTORY | 8 | 2.2.33 |
| READ | 16 | 2.2.19 |
| WRITE | 16 | 2.2.21 |
| SET_INFO | 16 | 2.2.39 |
| QUERY_INFO | 24 | 2.2.37 |

See [docs/postmortem/2026-01-compound-request-bugs.md](./docs/postmortem/2026-01-compound-request-bugs.md) for full incident details.

## Implementation Status

### Phase 1: Project Setup & Documentation - COMPLETED
- [x] Workspace Cargo.toml with all crate definitions
- [x] CLAUDE.md with coding conventions
- [x] docs/ksmbd-research.md with kernel research
- [x] docs/architecture.md with detailed design
- [x] CI configuration (.github/workflows/ci.yml)
- [x] All crate structures created

### Phase 2: Core Infrastructure - COMPLETED
- [x] rustsmb-core: Complete error types and NT_STATUS (40+ status codes, 6 error types)
- [x] rustsmb-vfs: StorageBackend trait with 27 POSIX-like methods
- [x] rustsmb-state: StateStore trait with 24 methods for HA support
- [x] rustsmb-state-memory: In-memory state store (full implementation)
- [x] rustsmb-backend-memory: In-memory filesystem (full StorageBackend implementation with 9 tests)

### Phase 3: Protocol Layer - COMPLETED
- [x] SMB2 header parsing with binrw (64-byte header)
- [x] SMB2 transform header for encryption (52-byte header)
- [x] All 19 SMB2 commands with request/response structures:
  - NEGOTIATE, SESSION_SETUP, LOGOFF
  - TREE_CONNECT, TREE_DISCONNECT
  - CREATE, CLOSE, FLUSH, READ, WRITE
  - LOCK, IOCTL, CANCEL, ECHO
  - QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO
  - OPLOCK_BREAK (with lease support)
- [x] Dialect negotiation helpers (DialectNegotiator, context parsing)
- [x] Message signing (AES-CMAC for SMB 3.0, AES-GMAC for SMB 3.1.1)
- [x] Message encryption (AES-128-CCM, AES-128-GCM, AES-256-GCM)
- [x] 100 unit tests passing

### Phase 4: Session Management - COMPLETED
- [x] rustsmb-session: Connection state machine (multi-session support, idle tracking)
- [x] rustsmb-session: Session manager with StateStore integration
- [x] rustsmb-session: Tree connection manager
- [x] rustsmb-session: File handle manager (volatile + persistent IDs)
- [x] rustsmb-session: Credit management for multi-credit operations
- [x] rustsmb-session: Compound request handling (related/unrelated)
- [x] rustsmb-session: Async request tracking (for CHANGE_NOTIFY, LOCK, etc.)
- [x] rustsmb-session: Request context validation (session/tree/handle)
- [x] 39 unit tests passing

### Phase 5: Authentication - COMPLETED
- [x] rustsmb-auth: AuthProvider trait with guest/anonymous support
- [x] rustsmb-auth: Simple auth provider (username/password)
- [x] rustsmb-auth: NTLM authentication (NTLMv2 with full crypto)
- [x] rustsmb-auth: SPNEGO/GSS-API wrapper (ASN.1/DER parsing)
- [x] rustsmb-auth: Session key derivation (SP800-108 KDF for SMB 3.0/3.1.1)
- [x] rustsmb-auth: Pre-auth integrity hash (SHA-512 for SMB 3.1.1)
- [x] rustsmb-auth: Guest and anonymous session support
- [x] rustsmb-auth: CompositeAuthProvider for chaining providers
- [x] 48 unit tests passing

### Phase 6: Server Implementation - COMPLETED
- [x] rustsmb-server: TCP listener with connection handling
- [x] rustsmb-server: TLS support (optional)
- [x] rustsmb-server: Configuration loading (TOML)
- [x] rustsmb-server: Share manager (share definitions, access control)
- [x] rustsmb-server: Command dispatcher (route to handlers)
- [x] rustsmb-server: All 19 command handlers implementation
- [x] rustsmb-server: Graceful shutdown and connection draining
- [x] rustsmb-server: Metrics and logging (via tracing)

### Phase 7: Local Filesystem Backend - COMPLETED
- [x] rustsmb-backend-local: Full StorageBackend implementation (27 methods)
- [x] rustsmb-backend-local: Path validation (prevent traversal attacks via canonicalization)
- [x] rustsmb-backend-local: File locking (advisory locks via libc flock)
- [x] rustsmb-backend-local: Extended attributes support (xattr on macOS/Linux)
- [x] rustsmb-backend-local: Proper permission mapping (Unix to SMB via MetadataExt)
- [x] rustsmb-backend-local: Symlink handling (create, read, follow option)
- [x] rustsmb-backend-local: Large file support (>4GB via sparse file writes)
- [x] 13 unit tests for local backend

### Phase 8: Redis State Store - COMPLETED
- [x] rustsmb-state-redis: Full StateStore implementation (24 methods)
- [x] rustsmb-state-redis: Connection pooling (deadpool-redis)
- [x] rustsmb-state-redis: Session state serialization (serde_json)
- [x] rustsmb-state-redis: TTL-based session expiration
- [x] rustsmb-state-redis: Distributed locking (SET NX EX with Lua scripts)
- [x] rustsmb-state-redis: Atomic ID generation (INCR)
- [x] rustsmb-state-redis: 6 integration tests (require Redis)

### Phase 9: Testing & Hardening - COMPLETED
- [x] Integration tests with smbclient (16 tests - requires smbclient installed)
- [x] Integration tests with Windows client (10 tests - requires Windows with admin privileges)
- [x] Fuzz testing infrastructure (cargo-fuzz targets for headers and commands)
- [x] Property-based tests for all command roundtrips (36 proptest tests)
- [x] Stress testing (concurrent connections, large files - 13 tests)
- [x] Security tests (path traversal prevention, input validation - 25 tests)
- [x] Performance benchmarks (protocol parsing, throughput)
- [ ] Documentation (rustdoc, examples, deployment guide)

### Phase 10: High Availability - COMPLETED
- [x] docs/ha-design.md: HA design document (architecture, session binding, Redis)
- [x] Session binding support in server (SESSION_SETUP with SESSION_BINDING flag)
- [x] NT_STATUS UserSessionDeleted code for binding failures
- [x] Custom SMB2 test client (tests/ha_client.rs) for session binding tests
- [x] HA integration tests (tests/integration_ha.rs) with Redis state store
- [x] CI workflow for HA tests with Redis service container

### Phase 11: Persistent Handles & Leases - COMPLETED
- [x] docs/persistent-handles-leases.md: Design document for persistent handles and leases
- [x] Phase 11A: CREATE context parsing (DHnQ, DHnC, DH2Q, DH2C, RqLs, RqLsV2)
- [x] Phase 11A: Durable handle request/reconnect support in CREATE handler
- [x] Phase 11A: Extend HandleState with reconnection fields (create_guid, file_offset, durable_timeout, etc.)
- [x] Phase 11A: update_handle() added to StateStore trait and implementations
- [x] Phase 11B: Lease request/response contexts (LeaseV1, LeaseV2) parsing
- [x] Phase 11B: Basic lease handling in CREATE flow (grant requested lease state)
- [x] Phase 11C: Persistent handles validation (SMB 3.0+ requirement)
- [x] Phase 11B (Advanced): Lease conflict detection with reduced grant (Phase 14)
- [x] Phase 11B (Advanced): Same-server oplock break notifications to clients (Phase 18)

### Phase 12: Hyperscale State Store - COMPLETED
- [x] docs/state-store-design.md: Design document for hyperscale state store
- [x] Phase 12A: Extend rustsmb-state with CoordinationBackend trait
- [x] Phase 12A: Add bound_server_id to SessionState and HandleState
- [x] Phase 12B: Create rustsmb-state-cached crate (LocalCache with LRU + epoch)
- [x] Phase 12C: Create rustsmb-coord-raft crate (InMemoryCoordinator using Tokio broadcast)
- [x] Phase 12D: Server failure detection and cache invalidation (15s heartbeat timeout)
- [x] Phase 12E: Lease/lock coordination (SMB lease conflict detection)
- [x] Phase 12F: Server integration (ServerCoordination layer, with_coordination())

### Phase 13: Coordinator Service Refactoring - COMPLETED
- [x] Phase 13A: Update documentation (CLAUDE.md, docs/state-store-design.md)
- [x] Phase 13B: Create rustsmb-coordinator-proto crate (gRPC definitions)
- [x] Phase 13B: Create rustsmb-coordinator-client crate (gRPC client)
- [x] Phase 13C: Move lease methods to StateStore trait
- [x] Phase 13C: Move lock methods to StateStore trait
- [x] Phase 13C: Implement lease/lock in RedisStateStore with WATCH
- [x] Phase 13D: Simplify CoordinationBackend trait (remove lease/lock, keep membership + epoch)
- [x] Phase 13E: Create rustsmb-coordinator binary (standalone service with Raft)
- [x] Phase 13E: Implement gRPC service handlers
- [x] Phase 13E: Implement Raft transport between coordinator nodes (gRPC)
- [x] Phase 13F: Update CachedStateStore (caching conditional on coordinator)
- [x] Phase 13G: Update server integration (use CoordinatorClient or embedded Raft)

### Phase 14: Lease Lifecycle & Conflict Detection - COMPLETED
- [x] docs/oplock-lease-design.md: Oplock/lease design document with multi-server handling
- [x] Phase 14A: Fix lease lifecycle cleanup
  - CLOSE handler deletes lease before handle
  - Session cleanup deletes leases for all handles
  - Server failure cleanup deletes leases and locks for failed server
- [x] Phase 14B: Add lease conflict detection
  - Add server_id to ConnectionHandler for lease tracking
  - Add client_guid_string() helper to Connection
  - Use check_and_create_lease() in CREATE handler with conflict detection
- [x] Phase 14C: Implement reduced grant for cross-server conflicts
  - WRITE_CACHING is exclusive (conflicts with any other lease)
  - Conflicting lease requests get reduced grant instead of oplock break
  - File open still succeeds with reduced/no lease (affects caching only)

### Phase 15: SMB Specification Testing - COMPLETED
- [x] docs/smb-protocol-testing.md: Comprehensive testing documentation
- [x] Phase 15A: smbtorture integration
  - tests/scripts/smbtorture.sh: Shell script test runner (used by CI)
  - tests/scripts/run_smbtorture.sh: Bash script for running against external server
  - CI job for smbtorture tests
- [x] Phase 15B: Python smbprotocol tests
  - tests/python/: Python test environment
  - Tests for NEGOTIATE, SESSION, CREATE, READ/WRITE, leases
  - CI job for Python tests
- [x] Phase 15C: Microsoft Protocol Test Suites setup
  - tests/ms-protocol/setup.sh: Setup script for MS test suites
  - tests/ms-protocol/run_tests.sh: Test runner
  - tests/ms-protocol/FileServer.ptfconfig: Configuration file
- [x] CI workflow updated with spec test jobs

### Phase 16: Fix smbtorture Test Failures - COMPLETED
Fix smbtorture test failures by implementing missing SMB2 functionality per MS-SMB2 spec.
- [x] Phase 16A: Fix smb2.credits (credit charge validation per MS-SMB2 3.3.5.2.5)
  - Added `supports_multi_credit()` to Connection
  - Added `validate_credit_charge()` helper to ConnectionHandler
  - Call validation in READ, WRITE, IOCTL, QUERY_DIRECTORY, QUERY_INFO handlers
- [x] Phase 16B: Fix smb2.tcon (ShareFlags, Capabilities, MaximalAccess per MS-SMB2 2.2.10)
  - Compute MaximalAccess based on share read_only config
  - Set ShareFlags based on share properties (DFS support)
  - Set ShareCapabilities based on available features
- [x] Phase 16C: Fix smb2.read (MinimumCount validation per MS-SMB2 3.3.5.14)
  - Return STATUS_END_OF_FILE when read returns less than MinimumCount at EOF
- [x] Phase 16D: Fix smb2.getinfo (InfoType routing per MS-SMB2 3.3.5.20)
  - Route QUERY_INFO by InfoType (File, FileSystem, Security, Quota)
  - Add `build_fs_info()` for filesystem info classes (1, 3, 4, 5, 7)
  - Add `build_security_info()` for security descriptor responses
  - Validate output buffer size per spec
- [x] Phase 16E: Fix smb2.setinfo (implement SET_INFO handler per MS-SMB2 3.3.5.21)
  - Route SET_INFO by InfoType (File, FileSystem, Security)
  - Implement FileBasicInformation (4): set timestamps via utimes
  - Implement FileDispositionInformation (13): delete-on-close flag
  - Implement FileRenameInformation (10): rename files with UTF-16 path parsing
  - Implement FileEndOfFileInformation (20): truncate/extend files
  - Implement FileAllocationInformation (19): set allocation size
  - Add `delete_on_close` field to HandleState
  - Add `filetime_to_unix()` and `parse_utf16_string()` helpers
- [x] Phase 16F: Fix smb2.create (create contexts, validation per MS-SMB2 3.3.5.9)
  - Impersonation level validation (0-3 only, return STATUS_BAD_IMPERSONATION_LEVEL)
  - Leading slash path validation (return STATUS_INVALID_PARAMETER)
  - Durable handle grant requirements (Batch oplock or lease with handle caching)
  - Allocation size context support (AlSi)
  - Query maximal access context support (MxAc)
  - Fixed allocation size context name (AlSi not AISi)
- [x] Phase 16G: Fix smb2.lock (request validation per MS-SMB2 3.3.5.14)
  - LockCount validation (return STATUS_INVALID_PARAMETER when 0)
  - Lock flag validation (require exactly one of SHARED, EXCLUSIVE, or UNLOCK)
  - Lock range validation (return STATUS_INVALID_LOCK_RANGE for >63-bit ranges)
  - Handle validation (return STATUS_FILE_CLOSED for missing handles)
  - Proper FileLock struct usage with VFS lock/unlock operations
- [x] Phase 16H: smb2.oplock - Skipped (requires oplock break notifications)
- [x] Phase 16I: smb2.dir - Skipped (causes smbtorture client crash)
- [x] Phase 16J: smb2.session bind_negative - Skipped (requires multi-dialect signing)

### Phase 17: Unit Tests for MS-SMB2 3.3.5 Compliance - COMPLETED

Add unit tests to `handler.rs` organized by MS-SMB2 specification chapter:

- [x] Phase 17A: Reorganize existing tests by spec chapter order
  - Tests now organized by MS-SMB2 3.3.5.x chapter number
  - Section headers added for each chapter: 3.3.5.2, 3.3.5.4, 3.3.5.5, 3.3.5.6, 3.3.5.7, 3.3.5.8, 3.3.5.9, 3.3.5.10, 3.3.5.12, 3.3.5.14
- [x] Phase 17B: Add new tests by chapter
  - 3.3.5.2 Credit charge validation: `test_credit_charge_zero_large_payload`, `test_credit_charge_insufficient`, `test_credit_charge_sufficient`, `test_credit_charge_smb202_no_validation`
  - 3.3.5.4 NEGOTIATE: `test_negotiate_dialect_count_zero`, `test_negotiate_no_common_dialect`, `test_negotiate_selects_highest_dialect`
  - 3.3.5.7 TREE_CONNECT: `test_tree_connect_bad_network_name`
  - 3.3.5.14 LOCK: `test_lock_count_zero`, `test_lock_invalid_flags`, `test_lock_invalid_range`, `test_lock_valid_range_at_boundary`, `test_lock_invalid_handle`
- Total tests in handler.rs: 89 (increased from 76)

**Not Implemented (requires significant infrastructure changes):**
- **Lock stacking**: Tracking locks at SMB layer to allow same-handle re-locking
- **Lock conflict detection**: Proper conflict detection between different handles
- **Multi-channel session binding**: Signing key derivation across different dialect connections
- **Cross-server lease break notifications**: Async notification when lease conflicts occur across servers (same-server breaks implemented in Phase 18)

### Phase 18: Oplock/Lease Break Notifications - COMPLETED

Implement same-server oplock/lease break notifications per MS-SMB2 sections 2.2.23-2.2.25 and 3.3.4.6-3.3.4.7.

- [x] Phase 18A: Core Infrastructure
  - Create `lease_break.rs` module with LeaseBreakRegistry
  - Add `breaking`, `break_to_state` fields to LeaseEntry
  - Unit tests organized by MS-SMB2 spec chapters (3.3.4.7, 3.3.5.22, 3.3.6.5)
- [x] Phase 18B: Connection Handler Integration
  - Add mpsc channel for break notifications to ConnectionHandler
  - Share LeaseBreakRegistry across connections via server.rs
  - Implement `send_lease_break_notification()` per MS-SMB2 3.3.4.7
  - Cleanup: unregister leases on connection close
- [x] Phase 18C: CREATE Handler Changes
  - Partition conflicts by server_id (same-server vs cross-server)
  - Trigger breaks for same-server conflicts, wait for ack
  - Update lease state in StateStore after break completes
  - Continue reduced grant for cross-server conflicts
  - Register new leases with break registry
- [x] Phase 18D: OPLOCK_BREAK Handler
  - Parse lease/oplock acknowledgment by structure_size (24=oplock, 36=lease)
  - Validate state is subset of break-to state per MS-SMB2 3.3.5.22.2
  - Return LeaseBreakResponse/OplockBreakResponse
  - Integrate with LeaseBreakRegistry for pending break completion
- [x] Phase 18E: CLOSE Handler Integration
  - Unregister leases from LeaseBreakRegistry when handles are closed
  - Connection cleanup already unregisters all leases on disconnect

**Note:** Cross-server lease breaks are NOT implemented. Cross-server conflicts continue using reduced grant strategy from Phase 14.

### Phase 19: Tree ID Validation - COMPLETED

Implement proper Tree ID validation per MS-SMB2 section 3.3.5.2.11.

- [x] Phase 19A: Fix pre-dispatch validation
  - Add TreeDisconnect and Ioctl to requires_tree command list
  - Remove tree_id != 0 check (tree_id = 0 is NOT valid for tree-requiring commands)
- [x] Phase 19B: Add tree ID matching for handle operations
  - Add `validate_handle_tree_id()` helper function
  - Apply validation in CLOSE, READ, WRITE, LOCK, QUERY_DIRECTORY, QUERY_INFO, SET_INFO handlers
  - Reject with STATUS_INVALID_PARAMETER when header.tree_id != handle.tree_id
- [x] Phase 19C: Add unit tests for MS-SMB2 3.3.5.2.11
  - test_write_with_tree_id_zero_returns_network_name_deleted
  - test_write_with_nonexistent_tree_id_returns_network_name_deleted
  - test_ioctl_with_nonexistent_tree_id_returns_network_name_deleted

### Phase 20: READ Command Compliance - COMPLETED

Implement proper READ request handling per MS-SMB2 section 3.3.5.12.

- [x] Phase 20A: Add NtStatus::InvalidDeviceRequest (0xC0000010)
- [x] Phase 20B: Add is_directory field to HandleState
  - Track whether handle is for a directory vs file
  - Set from file metadata during CREATE
- [x] Phase 20C: Add directory check in handle_read
  - Per spec: "If Open.IsPersistent is FALSE and Open.IsDirectory is TRUE,
    the server SHOULD fail the request with STATUS_INVALID_DEVICE_REQUEST"
- [x] Phase 20D: Add unit tests for MS-SMB2 3.3.5.12
  - test_read_directory_check_logic (directory + persistent combinations)
  - test_minimum_count_logic (EOF handling already implemented)

### Phase 21: Compound Request Support - COMPLETED

Implement compound SMB2 request handling per MS-SMB2 section 3.3.5.2.7.

- [x] Phase 21A: Modify process_message for compound detection
  - Check header.next_command to detect compound requests
  - Delegate to process_compound_request() for compounds
- [x] Phase 21B: Add compound request processor
  - Parse command offsets using parse_compound_offsets()
  - Detect related vs unrelated by checking SMB2_FLAGS_RELATED_OPERATIONS
  - Create CompoundContext for tracking state across commands
- [x] Phase 21C: Add related command processor
  - Resolve session/tree IDs using sentinel value substitution (0xFFFFFFFF...)
  - Propagate errors to subsequent related commands
- [x] Phase 21D: Add compound response combiner
  - Combine responses with 8-byte alignment
  - Set NextCommand field to point to next response
  - Set SMB2_FLAGS_RELATED_OPERATIONS on responses after first (if related)
- [x] Phase 21E: Add FileId substitution for file operations
  - Substitute FileId in READ/WRITE/CLOSE/etc. from previous CREATE
  - Extract FileId from CREATE response for compound context
- [x] Phase 21F: Add unit tests for MS-SMB2 3.3.5.2.7
  - test_parse_compound_offsets_* (offset parsing)
  - test_compound_padding_alignment (8-byte alignment)
  - test_compound_context_* (session/tree/file ID resolution)
  - test_compound_context_error_propagation

**Note:** Uses existing infrastructure from rustsmb-session::compound module (parse_compound_offsets, CompoundContext, etc.) that was previously not wired up to the handler.

### Phase 22: Postmortem & Protocol Safety - COMPLETED

Document lessons learned from Phase 21 compound bugs and implement safety improvements.

- [x] Phase 22A: Write postmortem document (docs/postmortem/2026-01-compound-request-bugs.md)
- [x] Phase 22B: Add Lessons Learned section to CLAUDE.md
- [x] Phase 22C: Add FileId offset constants to rustsmb-protocol
  - Add `fileid_body_offset()` helper function
  - Document MS-SMB2 section for each offset
- [x] Phase 22D: Add unit tests for FileId positions
  - Tests verify byte offsets in serialized command buffers
- [x] Phase 22E: Update handler.rs to use protocol constants

### Phase 23: Fix smb2.read Test Compliance - COMPLETED

Fix smb2.read smbtorture test failures per MS-SMB2 3.3.5.12.

- [x] Phase 23A: Add access rights validation (FILE_READ_DATA or FILE_EXECUTE)
- [x] Phase 23B: Fix EOF handling (return STATUS_END_OF_FILE when read returns 0 bytes)
- [x] Phase 23C: Update file position after READ operations
- [x] Phase 23D: Fix FileAllInformation structure (position at offset 80 per MS-FSCC 2.4.18)
- [x] Phase 23E: Update handle_query_info to pass position to build_file_info

All smb2.read tests now pass: eof, position, dir, access.

### Phase 24: Fix smb2.durable-open Test Failures - COMPLETED

Fix smb2.durable-open smbtorture test failures per MS-SMB2 specification.

- [x] Phase 24A: Fix SMB2_CREATE_DURABLE_HANDLE_RESPONSE format
  - DHnQ response must include 8 bytes of Reserved data (per MS-SMB2 2.2.14.2.3)
  - Previously sent empty data, causing NT_STATUS_INVALID_NETWORK_RESPONSE
- [x] Phase 24B: Fix OplockLevel parsing for sparse enum values
  - binrw `repr = u8` doesn't work for non-contiguous values (0, 1, 8, 9, 255)
  - Added `#[br(map = |x: u8| OplockLevel::from_u8(x))]` directive
- [x] Phase 24C: Fix CreateContextBuilder empty data handling
  - Fixed capacity overflow when data_offset was 0
- [x] Phase 24D: Preserve durable handles on session deletion (MS-SMB2 3.3.7.1)
  - Modified delete_session to skip deleting durable/persistent handles
  - Added should_preserve_for_reconnect() method to HandleState
  - Added prepare_for_reconnect() to clear session_id/tree_id and set deadline
- [x] Phase 24E: Prepare handles for reconnect on connection close (MS-SMB2 3.3.7.1)
  - When connection closes, prepare all durable handles for reconnection
  - Set session_id to 0 so handles can be reconnected on new session
- [x] Phase 24F: Validate session_id in durable reconnect (MS-SMB2 3.3.5.9.7)
  - Reconnect only succeeds if handle is in disconnected state (session_id == 0)
  - Prevents reconnect attempts on still-open handles
- [x] Phase 24G: Fix file_attributes in durable reconnect response
  - Compute attributes from actual file metadata, not cached request attributes
  - Returns FILE_ATTRIBUTE_ARCHIVE (0x20) correctly
- [x] Phase 24H: Add unit tests for durable handle operations
  - Tests for should_preserve_for_reconnect(), prepare_for_reconnect(), can_reconnect()
  - Tests organized by MS-SMB2 spec chapter (3.3.7.1, 3.3.5.9.7)

**Results**: 10 tests now pass (up from 7):
- open-oplock, open-lease, reopen1, reopen1a, reopen2a, reopen3, reopen4
- lock-oplock, lock-lease, stat-open

**Remaining failures** (12 tests) require advanced oplock/lease break handling:
- oplock, lease, open2-oplock, open2-lease: Require tracking oplock state during reconnect
- reopen2, reopen*-lease: Require proper oplock break handling for cross-connection conflicts
- delete_on_close1/2: Delete-on-close with durable handles
- file-position: File position persistence
- alloc-size, read-only: Allocation size and read-only attribute handling

## smbtorture Test Analysis

### Test Results Summary (January 2026)

| Suite | Status | Key Issues |
|-------|--------|------------|
| smb2.connect | **PASS** | - |
| smb2.session | **FAIL** | reauth5/6, bind_negative_* (multi-dialect signing) |
| smb2.tcon | **PASS** | - |
| smb2.create | **FAIL** | gentest, blob, aclfile, acldir, nulldacl |
| smb2.read | **PASS** | All tests pass (eof, position, dir, access) - Fixed in Phase 23 |
| smb2.lock | **FAIL** | Lock stacking, error codes, cross-handle conflicts |
| smb2.lease | **PASS** | - |
| smb2.oplock | **PARTIAL (17/42)** | brl3 (lock error codes), levelii500 (break failure), statopen1 |
| smb2.durable-open | **PARTIAL (7/22)** | open-oplock, open-lease, lock-oplock/lease, stat-open pass; reconnect tests fail |
| smb2.durable-v2-open | **FAIL** | Client crash (smbtorture bug) |
| smb2.compound | **PARTIAL** | related1, compound-break, create-write-close pass; others need IOCTL |

### Missing Features vs ksmbd

| Feature | ksmbd | RustSMB | Priority |
|---------|-------|---------|----------|
| Compound requests (related/unrelated) | ✅ | ✅ | - |
| Oplock break notifications | ✅ | ⚠️ Same-server only | - |
| Lock stacking (same-handle re-lock) | ✅ | ❌ | P2 |
| LOCK_NOT_GRANTED vs FILE_LOCK_CONFLICT | ✅ | ❌ | P2 |
| Cross-handle lock conflicts | ✅ | ❌ | P2 |
| Tree ID validation | ✅ | ✅ | - |
| Read past EOF → STATUS_END_OF_FILE | ✅ | ✅ | - |
| Read directory → STATUS_INVALID_DEVICE_REQUEST | ✅ | ✅ | - |
| File position tracking | ✅ | ✅ | - |
| Attributes-only opens (no oplock break) | ✅ | ❌ | P3 |
| SMB2_CAP_MULTI_CHANNEL | ⚠️ Experimental | ❌ | P3 |
| SMB Direct (RDMA) | ✅ | ❌ | - |
| POSIX extensions | ✅ | ❌ | - |
| Durable handles v1/v2 | ⚠️ (kernel 6.9+) | ✅ | - |

### Priority Fixes

**P0 - Critical (blocks many tests):**
- ~~Implement oplock/lease break notifications~~ DONE in Phase 18 (same-server only)

**P1 - Security/Compliance:**
- ~~Tree ID validation (reject operations with wrong TID)~~ DONE in Phase 19
- ~~Read past EOF should return STATUS_END_OF_FILE~~ DONE (already implemented, verified in Phase 20)
- ~~Read on directory should return STATUS_INVALID_DEVICE_REQUEST~~ DONE in Phase 20

**P2 - Lock semantics:**
- Lock stacking (allow same handle to re-lock same range)
- Correct error codes (LOCK_NOT_GRANTED first, FILE_LOCK_CONFLICT after)
- Cross-handle/cross-session lock conflict detection

**P3 - Nice to have:**
- File position tracking in FileAllInformation
- Attributes-only opens without sharing violations
- Multi-channel capability advertisement
