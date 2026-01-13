# Post-Mortem: SMB2 Compound Request Bugs

**Date:** January 2026
**Phase:** 21 (Compound Request Support)
**Author:** Claude
**Status:** Resolved

## Executive Summary

Three bugs in compound request handling caused smb2.compound tests to fail. The bugs were introduced during Phase 21 implementation and took significant time to diagnose due to subtle protocol details and inadequate initial testing.

## Timeline

1. Phase 21 implemented compound request processing
2. smb2.compound tests failed with signature errors and invalid handle errors
3. Investigation revealed three distinct bugs, each masked by the previous
4. All three bugs fixed in commit `ee45d95`

---

## Bug 1: RELATED_OPERATIONS Flag on All Responses

### What Happened
The code only set `SMB2_FLAGS_RELATED_OPERATIONS` on response messages with index > 0:
```rust
if is_related && i > 0 {
    // Set flag...
}
```

### Root Cause
Misinterpretation of MS-SMB2 3.3.4.1.3 which states: "the server MUST set SMB2_FLAGS_RELATED_OPERATIONS in the Flags field of **each response**" — meaning ALL responses, including the first.

### Impact
Signature verification failed because the flag affects the signed message content. The client computed signatures assuming the flag was set on all responses.

### Fix
Changed condition from `if is_related && i > 0` to `if is_related`.

---

## Bug 2: FileId Offset Varies by Command Type

### What Happened
The code assumed FileId is at offset 16 in all command request bodies:
```rust
let file_id_body_offset = 16; // Wrong for many commands!
```

### Root Cause
Failure to consult MS-SMB2 specification for each command structure. The actual offsets vary:

| Command | FileId Offset | MS-SMB2 Section | Reason |
|---------|---------------|-----------------|--------|
| CLOSE | 8 | 2.2.15 | Only Flags (2) + Reserved (4) + structure_size (2) before FileId |
| FLUSH | 8 | 2.2.17 | Minimal header |
| LOCK | 8 | 2.2.26 | LockCount + Reserved before FileId |
| QUERY_DIRECTORY | 8 | 2.2.33 | FileInfoClass + Flags + FileIndex before FileId |
| READ | 16 | 2.2.19 | Padding + Flags + Length + Offset before FileId |
| WRITE | 16 | 2.2.21 | Similar structure to READ |
| SET_INFO | 16 | 2.2.39 | InfoType + Class + BufferLength + BufferOffset before FileId |
| QUERY_INFO | **24** | 2.2.37 | AdditionalInformation (4) + Flags (4) before FileId |

### Impact
When processing a related QUERY_INFO request, the code modified the wrong bytes in the message, leaving the actual FileId unchanged. This caused STATUS_INVALID_HANDLE errors.

### Fix
Added proper offset mapping:
```rust
let file_id_body_offset = match header.command {
    Smb2Command::Close
    | Smb2Command::Flush
    | Smb2Command::Lock
    | Smb2Command::QueryDirectory => 8,
    Smb2Command::QueryInfo => 24,
    _ => 16, // READ, WRITE, SET_INFO
};
```

---

## Bug 3: FileId Substitution Logic

### What Happened
The code required BOTH persistent and volatile FileId parts to be the sentinel value:
```rust
if req_persistent == u64::MAX && req_volatile == u64::MAX {
    // Only then substitute
}
```

### Root Cause
The smbtorture test sent `req_persistent=0, req_volatile=0xFFFFFFFFFFFFFFFF`. This is valid per MS-SMB2 — the client might know the persistent handle from CREATE but use sentinel for volatile, or vice versa. Additionally, MS-SMB2 footnote <214> suggests Windows servers use the previous FileId regardless for related operations.

### Impact
FileId substitution didn't occur even when the request clearly indicated it should use the previous CREATE's FileId.

### Fix
Substitute each field independently, and also substitute when it's a related compound with a different FileId:
```rust
let use_ctx_persistent = req_persistent == u64::MAX
    || (ctx.related && req_persistent != persistent);
let use_ctx_volatile =
    req_volatile == u64::MAX || (ctx.related && req_volatile != volatile);
```

---

## Why It Took Time to Find Root Causes

### 1. Layered Failure Modes
- Bug 1 caused signature failures → masked Bug 2
- Bug 2 caused invalid handle errors → required fixing Bug 1 first to expose
- Bug 3 caused subtle FileId mismatches → only visible after Bugs 1 & 2 fixed

### 2. Insufficient Trace Logging
Initial implementation lacked logging at critical decision points:
- No logging of FileId values before/after substitution
- No logging of which offset was being used
- No logging of flag modifications

### 3. Protocol Complexity
MS-SMB2 specification is 400+ pages. Each command has a different structure layout, and the FileId position is buried within each command's section (2.2.15, 2.2.17, 2.2.19, 2.2.21, 2.2.26, 2.2.33, 2.2.37, 2.2.39).

### 4. Test-First Gap
The unit tests added in the plan focused on high-level behavior but didn't verify:
- Exact byte offsets for FileId substitution
- Flag settings on each response position
- Partial sentinel value scenarios

---

## Prevention Measures

### 1. Create Command-Specific Offset Tests
Add unit tests that verify FileId offset for each command type:
```rust
#[test]
fn test_fileid_offset_query_info() {
    let req = QueryInfoRequest { ... };
    let mut buf = vec![];
    req.write(&mut Cursor::new(&mut buf)).unwrap();
    // Verify FileId is at expected offset
    assert_eq!(&buf[24..32], expected_persistent_bytes);
}
```

### 2. Add Comprehensive Trace Logging During Development
Add temporary trace! statements showing actual byte values:
```rust
trace!(
    "FileId substitution: cmd={:?}, offset={}, req=({:#x}, {:#x}), ctx=({:#x}, {:#x})",
    header.command, file_id_body_offset, req_persistent, req_volatile, persistent, volatile
);
```

### 3. Reference Spec Section Numbers in Code
```rust
// Per MS-SMB2 2.2.37, QUERY_INFO request has:
// - structure_size (2 bytes, offset 0)
// - InfoType (1 byte, offset 2)
// - FileInfoClass (1 byte, offset 3)
// ...
// - FileId (16 bytes, offset 24) ← This is what we need
const QUERY_INFO_FILEID_OFFSET: usize = 24;
```

### 4. Create Offset Constants in Protocol Crate
Add constants to `rustsmb-protocol` for each command's FileId offset:
```rust
// In commands/mod.rs
pub const QUERY_INFO_FILEID_BODY_OFFSET: usize = 24;
pub const CLOSE_FILEID_BODY_OFFSET: usize = 8;
```

### 5. Test Against Real smbtorture Early
Run actual smbtorture tests during development, not just unit tests. The integration tests catch protocol compliance issues that unit tests miss.

### 6. Read the ENTIRE Relevant Spec Section
Before implementing a feature, read the full specification section including footnotes. MS-SMB2 footnote <214> would have clarified the FileId substitution behavior immediately.

---

## Action Items Implemented

1. **FileId offset constants added** to rustsmb-protocol for all commands that use FileId
2. **Unit tests added** verifying FileId position in serialized command buffers
3. **Trace logging kept** for compound operations (can be disabled via log level)
4. **Offset sources documented** with MS-SMB2 section references in code comments
5. **CLAUDE.md updated** with lesson learned about command structure variations

---

## Related Commits

- `5054553` feat: implement MS-SMB2 3.3.5.2.7 compound request handling
- `ee45d95` fix: correct FileId offset and RELATED_OPERATIONS flag for compound requests
