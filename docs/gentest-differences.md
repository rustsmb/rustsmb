# Samba gentest vs MS-SMB2 Specification Differences

## Overview

The smbtorture `smb2.create.gentest` test validates CREATE request field handling by testing each bit of each field individually. This document lists the differences between what the Samba test framework expects and what the MS-SMB2 specification defines.

## CreateOptions Field (Offset 40-43)

**Samba Expected ok_mask: `0x00efcf7e`**

| Bit | Value | MS-SMB2 Name | MS-SMB2 Spec | Samba Expects | Difference |
|-----|-------|--------------|--------------|---------------|------------|
| 0 | 0x00000001 | FILE_DIRECTORY_FILE | Valid | ERROR | Samba expects error (directory creation fails on regular file path?) |
| 1 | 0x00000002 | FILE_WRITE_THROUGH | Valid | OK | Match |
| 2 | 0x00000004 | FILE_SEQUENTIAL_ONLY | Valid | OK | Match |
| 3 | 0x00000008 | FILE_NO_INTERMEDIATE_BUFFERING | Valid | OK | Match |
| 4 | 0x00000010 | FILE_SYNCHRONOUS_IO_ALERT | Valid | OK | Match |
| 5 | 0x00000020 | FILE_SYNCHRONOUS_IO_NONALERT | Valid | OK | Match |
| 6 | 0x00000040 | FILE_NON_DIRECTORY_FILE | Valid | OK | Match |
| 7 | 0x00000080 | FILE_CREATE_TREE_CONNECTION | Valid but reserved | ERROR | Samba rejects this reserved bit |
| 8 | 0x00000100 | FILE_COMPLETE_IF_OPLOCKED | Valid | OK | Match |
| 9 | 0x00000200 | FILE_NO_EA_KNOWLEDGE | Valid | OK | Match |
| 10 | 0x00000400 | FILE_OPEN_REMOTE_INSTANCE | Valid | OK | Match |
| 11 | 0x00000800 | FILE_RANDOM_ACCESS | Valid | OK | Match |
| 12 | 0x00001000 | FILE_DELETE_ON_CLOSE | Valid | ERROR | Requires DELETE access right |
| 13 | 0x00002000 | FILE_OPEN_BY_FILE_ID | Valid but reserved | ERROR | Samba rejects this reserved bit |
| 14 | 0x00004000 | FILE_OPEN_FOR_BACKUP_INTENT | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 15 | 0x00008000 | FILE_NO_COMPRESSION | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 16 | 0x00010000 | (undefined) | Reserved | **OK** | **Samba ignores, we reject** |
| 17 | 0x00020000 | FILE_OPEN_REQUIRING_OPLOCK | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 18 | 0x00040000 | FILE_DISALLOW_EXCLUSIVE | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 19 | 0x00080000 | (undefined) | Reserved | **OK** | **Samba ignores, we reject** |
| 20 | 0x00100000 | FILE_RESERVE_OPFILTER | Reserved | ERROR | Match (both reject) |
| 21 | 0x00200000 | FILE_OPEN_REPARSE_POINT | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 22 | 0x00400000 | FILE_OPEN_NO_RECALL | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 23 | 0x00800000 | FILE_OPEN_FOR_FREE_SPACE_QUERY | Reserved per MS-SMB2 | **OK** | **Samba ignores, we reject** |
| 24-31 | 0xFF000000 | (undefined) | Reserved | ERROR | Match |

### Key Difference: Reserved Bits 14-19, 21-23

**MS-SMB2 Specification (Section 2.2.13):**
> CreateOptions (4 bytes): Specifies the options to be applied when creating or opening the file. Combinations of the bit positions... **All other bits are reserved.**

Our implementation returns `STATUS_INVALID_PARAMETER` for bits 14+ per the spec.

**Samba Behavior:**
Samba ignores these reserved bits for forward compatibility. Setting bits 14-15, 16-19, or 21-23 does not cause an error - the operation proceeds as if those bits were not set.

## DesiredAccess Field (Offset 24-27)

**MS-SMB2 Specification (Section 2.2.13.1):**
- Bits 0-8: File access rights (valid)
- Bits 9-15: Reserved (should be 0)
- Bits 16-20: Standard access rights (valid)
- Bits 21-23: Reserved (should be 0)
- Bit 24: ACCESS_SYSTEM_SECURITY (requires SeSecurityPrivilege)
- Bit 25: MAXIMUM_ALLOWED (valid)
- Bits 26-27: Reserved
- Bits 28-31: Generic access rights (valid, translated to specific rights)

**Samba Behavior:**
Samba ignores reserved bits in DesiredAccess. Setting bits 9-15 or 21-27 (except bit 24) does not cause an error.

## FileAttributes Field (Offset 28-31)

**MS-SMB2/MS-FSCC Specification:**
Certain attributes cannot be set by clients:
- FILE_ATTRIBUTE_DEVICE (0x40) - System-managed
- FILE_ATTRIBUTE_VOLUME (0x08) - System-managed

**Samba Behavior:**
Samba ignores invalid FileAttributes bits rather than rejecting them.

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

## Summary: Why gentest Fails

The primary reason our implementation fails the gentest is:

**We strictly reject reserved CreateOptions bits (14-19, 21-23) with `INVALID_PARAMETER`, while Samba ignores them and returns `OK`.**

This is a design choice:
- **Strict approach (our implementation):** Follow MS-SMB2 spec literally; reserved bits should be rejected
- **Permissive approach (Samba):** Ignore unknown bits for forward compatibility with future protocol versions

### Options to Pass gentest

1. **Change to permissive validation:** Remove validation for CreateOptions bits 14-19, 21-23 (ignore reserved bits like Samba)
2. **Accept the difference:** Document that we follow MS-SMB2 more strictly than Samba

The permissive approach is arguably more practical since it allows clients to use newer protocol features without breaking, but the strict approach ensures protocol compliance.
