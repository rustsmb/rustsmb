# SMB2 CREATE Field Validation: Samba vs ksmbd vs MS-SMB2 Spec

## Overview

The smbtorture `smb2.create.gentest` test validates CREATE request field handling by testing each bit of each field individually. This document compares three SMB2 server implementations:

| Implementation | CreateOptions Mask | Approach |
|---------------|-------------------|----------|
| **MS-SMB2 Spec** | 0x00003FFF (bits 0-13) | Strict: reserved bits "MUST be 0" |
| **RustSMB** | 0x00efdf7f (like Samba) | Permissive: ignores most reserved bits |
| **Samba** | 0x00efcf7e (ok_mask) | Permissive: ignores most reserved bits |
| **ksmbd** | 0x00FFFFFF (bits 0-23) | Permissive: allows bits 0-23 |

**Note:** ksmbd is the Linux kernel's in-kernel SMB3 server (formerly cifsd).

## CreateOptions Field (Offset 40-43)

**Masks:**
- Samba ok_mask: `0x00efcf7e`
- ksmbd CREATE_OPTIONS_MASK: `0x00FFFFFF`
- RustSMB REJECTED_CREATE_OPTIONS: `0xFF102080` (rejects bits 7, 13, 20, 24-31)

| Bit | Value | MS-SMB2 Name | MS-SMB2 | Samba | ksmbd | RustSMB |
|-----|-------|--------------|---------|-------|-------|---------|
| 0 | 0x00000001 | FILE_DIRECTORY_FILE | Valid | ERROR* | OK | OK |
| 1 | 0x00000002 | FILE_WRITE_THROUGH | Valid | OK | OK | OK |
| 2 | 0x00000004 | FILE_SEQUENTIAL_ONLY | Valid | OK | OK | OK |
| 3 | 0x00000008 | FILE_NO_INTERMEDIATE_BUFFERING | Valid | OK | OK | OK |
| 4 | 0x00000010 | FILE_SYNCHRONOUS_IO_ALERT | Valid | OK | OK | OK |
| 5 | 0x00000020 | FILE_SYNCHRONOUS_IO_NONALERT | Valid | OK | OK | OK |
| 6 | 0x00000040 | FILE_NON_DIRECTORY_FILE | Valid | OK | OK | OK |
| 7 | 0x00000080 | FILE_CREATE_TREE_CONNECTION | Reserved | ERROR | OK | ERROR |
| 8 | 0x00000100 | FILE_COMPLETE_IF_OPLOCKED | Valid | OK | OK | OK |
| 9 | 0x00000200 | FILE_NO_EA_KNOWLEDGE | Valid | OK | OK | OK |
| 10 | 0x00000400 | FILE_OPEN_REMOTE_INSTANCE | Valid | OK | OK | OK |
| 11 | 0x00000800 | FILE_RANDOM_ACCESS | Valid | OK | OK | OK |
| 12 | 0x00001000 | FILE_DELETE_ON_CLOSE | Valid | ERROR* | OK | OK |
| 13 | 0x00002000 | FILE_OPEN_BY_FILE_ID | Reserved | ERROR | OK | ERROR |
| 14 | 0x00004000 | FILE_OPEN_FOR_BACKUP_INTENT | Reserved | OK | OK | OK |
| 15 | 0x00008000 | FILE_NO_COMPRESSION | Reserved | OK | OK | OK |
| 16 | 0x00010000 | (undefined) | Reserved | OK | OK | OK |
| 17 | 0x00020000 | FILE_OPEN_REQUIRING_OPLOCK | Reserved | OK | OK | OK |
| 18 | 0x00040000 | FILE_DISALLOW_EXCLUSIVE | Reserved | OK | OK | OK |
| 19 | 0x00080000 | (undefined) | Reserved | OK | OK | OK |
| 20 | 0x00100000 | FILE_RESERVE_OPFILTER | Reserved | ERROR | ERROR | ERROR |
| 21 | 0x00200000 | FILE_OPEN_REPARSE_POINT | Reserved | OK | OK | OK |
| 22 | 0x00400000 | FILE_OPEN_NO_RECALL | Reserved | OK | OK | OK |
| 23 | 0x00800000 | FILE_OPEN_FOR_FREE_SPACE_QUERY | Reserved | OK | OK | OK |
| 24-31 | 0xFF000000 | (undefined) | Reserved | ERROR | ERROR | ERROR |

*Bit 0 (FILE_DIRECTORY_FILE) and Bit 12 (FILE_DELETE_ON_CLOSE) fail for semantic reasons in Samba (directory on file, missing DELETE access), not validation.

### Key Alignment: Reserved Bits 14-19, 21-23

**MS-SMB2 Specification (Section 2.2.13):**
> CreateOptions (4 bytes): Specifies the options to be applied when creating or opening the file. Combinations of the bit positions... **All other bits are reserved.**

**RustSMB and Samba Behavior:**
Both RustSMB and Samba ignore reserved bits 14-19, 21-23 for forward compatibility. Setting these bits does not cause an error - the operation proceeds as if those bits were not set. This allows clients using newer protocol features to work with older servers.

## DesiredAccess Field (Offset 24-27)

**Masks:**
- ksmbd DESIRED_ACCESS_MASK: `0xF21F01FF`
- RustSMB ACCESS_DENIED_BITS: `0x0DF0FE00` (matches Samba gentest)

**MS-SMB2 Specification (Section 2.2.13.1):**
- Bits 0-8: File access rights (valid)
- Bits 9-15: Reserved (should be 0)
- Bits 16-20: Standard access rights (valid per spec)
- Bits 21-23: Reserved (should be 0)
- Bit 24: ACCESS_SYSTEM_SECURITY (requires SeSecurityPrivilege)
- Bit 25: MAXIMUM_ALLOWED (valid)
- Bits 26-27: Reserved
- Bits 28-31: Generic access rights (valid, translated to specific rights)

**Samba Behavior (per gentest):**
Samba returns ACCESS_DENIED for reserved bits in DesiredAccess:
- Bits 9-15 (0x0000FE00): Reserved
- Bits 20-23 (0x00F00000): Reserved (includes SYNCHRONIZE, unlike MS-SMB2 spec)
- Bit 24 (0x01000000): ACCESS_SYSTEM_SECURITY (requires privilege)
- Bits 26-27 (0x0C000000): Reserved
- desired_access = 0: Returns ACCESS_DENIED

**RustSMB Behavior:**
RustSMB follows Samba's gentest validation:
- ACCESS_DENIED_BITS: `0x0DF0FE00` (rejects bits 9-15, 20-27 except 25)
- desired_access = 0: Returns ACCESS_DENIED
- Note: Validation order matters - path validation (leading slash) happens BEFORE DesiredAccess validation

## FileAttributes Field (Offset 28-31)

**MS-SMB2/MS-FSCC Specification:**
Certain attributes cannot be set by clients:
- FILE_ATTRIBUTE_DEVICE (0x40) - System-managed
- Bit 3 (0x08) - Undefined

**Samba Behavior (per gentest):**
INVALID_FILE_ATTRIBUTES mask: `0xFFFF8048`
- Valid bits: 0-2, 4-5, 7-14 (READONLY, HIDDEN, SYSTEM, DIRECTORY, ARCHIVE, NORMAL, TEMPORARY, SPARSE_FILE, REPARSE_POINT, COMPRESSED, OFFLINE, NOT_CONTENT_INDEXED, ENCRYPTED)
- Invalid bits (return INVALID_PARAMETER): bit 3 (undefined), bit 6 (DEVICE), bits 15-31 (reserved)

**RustSMB Behavior:**
RustSMB validates FileAttributes per Samba gentest:
- INVALID_FILE_ATTRIBUTES: `0xFFFF8048`
- Invalid bits return INVALID_PARAMETER

## SecurityFlags Field (Offset 2)

**MS-SMB2 Specification:**
> This field MUST NOT be used and MUST be reserved. The client MUST set this to 0.

**Samba Behavior:**
Samba may not strictly validate this field. Our implementation rejects non-zero values.

## SmbCreateFlags Field (Offset 8-15)

**MS-SMB2 Specification:**
> This field MUST NOT be used and MUST be reserved. The client SHOULD set this field to zero.

**Samba Behavior:**
Samba may not strictly validate this field. Our implementation rejects non-zero values.

## Reserved Field (Offset 16-23)

**MS-SMB2 Specification:**
> Reserved (8 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to zero.

**Samba Behavior:**
Samba may not strictly validate this field. Our implementation rejects non-zero values.

## RequestedOplockLevel Field (Offset 3)

**MS-SMB2 Specification (Section 2.2.13):**
Valid values:
- 0x00: SMB2_OPLOCK_LEVEL_NONE
- 0x01: SMB2_OPLOCK_LEVEL_II
- 0x08: SMB2_OPLOCK_LEVEL_EXCLUSIVE
- 0x09: SMB2_OPLOCK_LEVEL_BATCH
- 0xFF: SMB2_OPLOCK_LEVEL_LEASE

**Samba Behavior:**
Unknown. Our implementation rejects invalid oplock level values (0x02-0x07, 0x0A-0xFE).

## ImpersonationLevel Field (Offset 4-7)

**MS-SMB2 Specification:**
Valid values:
- 0x00000000: Anonymous
- 0x00000001: Identification
- 0x00000002: Impersonation
- 0x00000003: Delegate

**Samba Behavior:**
Both implementations validate this field. Values > 3 return INVALID_PARAMETER.

## ShareAccess Field (Offset 32-35)

**MS-SMB2 Specification:**
Valid bits:
- Bit 0: FILE_SHARE_READ (0x01)
- Bit 1: FILE_SHARE_WRITE (0x02)
- Bit 2: FILE_SHARE_DELETE (0x04)

**Samba Behavior:**
Unknown if Samba validates bits 3-31. Our implementation rejects non-zero bits 3-31.

## CreateDisposition Field (Offset 36-39)

**MS-SMB2 Specification:**
Valid values:
- 0: FILE_SUPERSEDE
- 1: FILE_OPEN
- 2: FILE_CREATE
- 3: FILE_OPEN_IF
- 4: FILE_OVERWRITE
- 5: FILE_OVERWRITE_IF

**Samba Behavior:**
Both implementations validate this field. Values > 5 return INVALID_PARAMETER.

## Summary: Implementation Comparison

### CreateOptions Validation Spectrum

```
Most Strict                                                Most Permissive
    |                                                              |
    v                                                              v
MS-SMB2 Spec (0x00003FFF)  <  RustSMB/Samba  <  ksmbd (0x00FFFFFF)
         |                         |                    |
         +-- Reserved bits error   +-- Forward compat   +-- Very permissive
```

### RustSMB Alignment with Samba (gentest)

RustSMB follows Samba's gentest validation for protocol compliance:

| Field | RustSMB Behavior | Error Code |
|-------|-----------------|------------|
| SecurityFlags | Ignored (like Samba) | - |
| SmbCreateFlags | Ignored (like Samba) | - |
| Reserved (8 bytes) | Ignored (like Samba) | - |
| CreateOptions | Bits 24-31 invalid, bits 7,13,20 not supported | INVALID_PARAMETER / NOT_SUPPORTED |
| DesiredAccess | Mask 0x0DF0FE00, zero=denied | ACCESS_DENIED |
| FileAttributes | Mask 0xFFFF8048 (bits 3,6,15-31 invalid) | INVALID_PARAMETER |
| ShareAccess | Only uses bits 0-2, ignores rest | - |
| ImpersonationLevel | Validates 0-3 | INVALID_PARAMETER |
| CreateDisposition | Validates 0-5 | INVALID_PARAMETER |

**Validation Order (important for gentest):**
1. CreateOptions validation
2. Path validation (leading slash) ← Must come before DesiredAccess!
3. DesiredAccess validation
4. FileAttributes validation
5. Other validations...

### Design Rationale

| Approach | Implementation | Pros | Cons |
|----------|---------------|------|------|
| **Strict** | MS-SMB2 spec | Protocol compliant, catches malformed requests | May break future clients using new bits |
| **Permissive** | RustSMB, Samba | Forward compatible, maximum client support | May accept technically invalid requests |
| **Very Permissive** | ksmbd | Maximum compatibility | May mask protocol bugs |

The permissive approach is more practical for real-world deployments since it allows clients using newer protocol features to work with older servers.

### ksmbd Source Reference

ksmbd validation can be found in the Linux kernel source:
- `fs/smb/common/smb2pdu.h` - Mask definitions (CREATE_OPTIONS_MASK, DESIRED_ACCESS_MASK)
- `fs/smb/server/smb2pdu.c` - Request validation and processing

ksmbd is notably more permissive than Samba in CreateOptions validation (0x00FFFFFF vs 0x00efcf7e), accepting all bits 0-23.
