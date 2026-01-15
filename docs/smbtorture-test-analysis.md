# smbtorture Test Analysis

## Test Results Summary (January 2026)

### smb2.connect (1/1 PASS)

| Test | Status | Issue |
|------|--------|-------|
| connect | PASS | - |

### smb2.session (8/17 tested, 49 skipped)

| Test | Status | Issue |
|------|--------|-------|
| reconnect1 | PASS | - |
| reconnect2 | PASS | - |
| reauth1 | PASS | - |
| reauth2 | PASS | - |
| reauth3 | PASS | - |
| reauth4 | PASS | - |
| reauth5 | FAIL | Multi-dialect reauthentication requires dialect-aware signing |
| reauth6 | FAIL | Multi-dialect reauthentication requires dialect-aware signing |
| two_logoff | PASS | - |
| ntlmssp_bug14932 | PASS | Fixed in Phase 27 |
| expire1n/s/e | SKIP | Requires SMB 3.1.1 |
| expire2s/e | SKIP | Requires SMB 3.1.1 |
| expire_disconnect | SKIP | Requires SMB 3.1.1 |
| bind1, bind2 | SKIP | Requires SMB 3.1.1 multi-channel |
| bind_negative_smb202 | FAIL | Multi-dialect signing (HMAC-SHA-256 vs AES-CMAC) |
| bind_negative_smb210s/d | FAIL | Multi-dialect signing |
| bind_negative_smb2to3s/d | FAIL | Multi-dialect signing |
| bind_negative_smb3to2s/d | FAIL | Multi-dialect signing |
| bind_negative_smb3to3s/d | SKIP | Requires SMB 3.1.1 |
| bind_negative_smb3enc* | SKIP | Requires SMB 3.1.1 encryption |
| bind_negative_smb3sign* | SKIP | Requires SMB 3.1.1 signing variants |

### smb2.tcon (1/1 PASS)

| Test | Status | Issue |
|------|--------|-------|
| tcon | PASS | - |

### smb2.create (5/14 PASS)

| Test | Status | Issue |
|------|--------|-------|
| gentest | FAIL | Generic test infrastructure |
| blob | FAIL | Extended attribute blobs |
| brlocked | PASS | - |
| delete | FAIL | Delete semantics |
| leading-slash | PASS | - |
| impersonation | FAIL | Impersonation level handling |
| aclfile | FAIL | ACL support not implemented |
| acldir | FAIL | ACL support not implemented |
| nulldacl | FAIL | ACL support not implemented |
| mkdir-dup | PASS | - |
| dir-alloc-size | PASS | - |
| quota-fake-file | FAIL | Quota support not implemented |

### smb2.read (4/4 PASS)

| Test | Status | Issue |
|------|--------|-------|
| eof | PASS | Fixed in Phase 23 |
| position | PASS | Fixed in Phase 23 |
| dir | PASS | Fixed in Phase 20 |
| access | PASS | Fixed in Phase 23 |
| bug14607 | SKIP | Requires SMB 3.1.1 |

### smb2.lock (6/23 PASS)

| Test | Status | Issue |
|------|--------|-------|
| valid-request | FAIL | Lock request validation |
| rw-none | SKIP | Requires SMB 3.0 |
| rw-shared | FAIL | Read/write with shared lock |
| rw-exclusive | FAIL | Read/write with exclusive lock |
| auto-unlock | PASS | - |
| lock | FAIL | Basic lock operations |
| async | FAIL | Async lock waiting not implemented |
| cancel | FAIL | Lock cancel not implemented |
| cancel-tdis | FAIL | Cancel on tree disconnect |
| cancel-logoff | FAIL | Cancel on logoff |
| errorcode | PASS | Fixed in Phase 26 |
| zerobytelength | FAIL | Zero-length lock handling |
| zerobyteread | PASS | - |
| unlock | FAIL | Unlock operations |
| multiple-unlock | FAIL | Multiple unlock in single request |
| stacking | FAIL | Lock stacking edge cases |
| contend | PASS | - |
| context | FAIL | Lock context handling |
| range | FAIL | Lock range validation |
| overlap | FAIL | Overlapping lock detection |
| truncate | PASS | - |
| replay_* | FAIL/SKIP | Replay detection requires SMB 3.x |

### smb2.oplock (21/42 PASS)

| Test | Status | Issue |
|------|--------|-------|
| exclusive1 | PASS | - |
| exclusive2 | PASS | - |
| exclusive3 | FAIL | Oplock break notification |
| exclusive4 | FAIL | Oplock break notification |
| exclusive5 | PASS | - |
| exclusive6 | FAIL | Oplock break notification |
| exclusive9 | FAIL | Oplock break notification |
| batch1 | FAIL | Batch oplock break |
| batch2 | PASS | - |
| batch3 | FAIL | Batch oplock break |
| batch4 | PASS | - |
| batch5 | PASS | - |
| batch6 | FAIL | Batch oplock break |
| batch7 | FAIL | Batch oplock break |
| batch8 | FAIL | Batch oplock break |
| batch9 | FAIL | Batch oplock break |
| batch9a | FAIL | Batch oplock break |
| batch10 | FAIL | Batch oplock break |
| batch11 | FAIL | Batch oplock break |
| batch12 | FAIL | Batch oplock break |
| batch13 | PASS | - |
| batch14 | PASS | - |
| batch15 | PASS | - |
| batch16 | PASS | - |
| batch19 | FAIL | Batch oplock break |
| batch20 | FAIL | Batch oplock break |
| batch21 | PASS | - |
| batch22a | PASS | - |
| batch22b | FAIL | Batch oplock break |
| batch23 | PASS | - |
| batch24 | PASS | - |
| batch25 | PASS | - |
| batch26 | PASS | - |
| stream1 | FAIL | Stream support not implemented |
| doc | FAIL | Document oplock semantics |
| brl1 | FAIL | Byte-range lock + oplock |
| brl2 | PASS | - |
| brl3 | FAIL | Lock error codes with oplock |
| levelii500 | FAIL | Level II oplock break |
| levelii501 | PASS | - |
| levelii502 | PASS | - |
| statopen1 | FAIL | Stat open without oplock break |

### smb2.lease (2/39 PASS)

| Test | Status | Issue |
|------|--------|-------|
| request | FAIL | Lease request handling |
| break_twice | FAIL | Double lease break |
| nobreakself | FAIL | No break to self |
| statopen | FAIL | Stat open with lease |
| statopen2 | PASS | - |
| statopen3 | PASS | - |
| statopen4 | FAIL | Stat open variant |
| upgrade | FAIL | Lease upgrade |
| upgrade2/3 | FAIL | Lease upgrade variants |
| break | FAIL | Lease break notification |
| oplock | FAIL | Oplock/lease interaction |
| multibreak | FAIL | Multiple lease breaks |
| breaking1-6 | FAIL | Lease breaking scenarios |
| v2_breaking3 | FAIL | V2 lease breaking |
| lock1 | FAIL | Lease + lock interaction |
| complex1 | FAIL | Complex lease scenario |
| v2_request* | FAIL | V2 lease requests |
| v2_epoch1-3 | FAIL | V2 epoch handling |
| v2_complex1/2 | FAIL | V2 complex scenarios |
| v2_rename | FAIL | V2 lease + rename |
| dynamic_share | SKIP | Dynamic share not implemented |
| timeout | FAIL | Lease timeout |
| unlink | FAIL | Lease + unlink |
| timeout-disconnect | FAIL | Timeout on disconnect |
| rename_wait | FAIL | Rename wait for lease |
| duplicate_create/open | FAIL | Duplicate lease handling |
| v1_bug15148 | FAIL | Samba bug 15148 (v1) |
| v2_bug15148 | FAIL | Samba bug 15148 (v2) |

### smb2.durable-open (17/23 PASS)

| Test | Status | Issue |
|------|--------|-------|
| open-oplock | PASS | - |
| open-lease | PASS | - |
| reopen1 | PASS | - |
| reopen1a | PASS | - |
| reopen1a-lease | FAIL | Complex lease reconnect |
| reopen2 | PASS | - |
| reopen2-lease | FAIL | Complex lease reconnect |
| reopen2-lease-v2 | FAIL | Lease V2 reconnect |
| reopen2a | PASS | - |
| reopen3 | PASS | - |
| reopen4 | PASS | - |
| delete_on_close1 | FAIL | Delete-on-close + durable |
| delete_on_close2 | PASS | - |
| file-position | PASS | Fixed in Phase 25 |
| oplock | PASS | - |
| lease | FAIL | Lease state restoration |
| lock-oplock | PASS | - |
| lock-lease | PASS | - |
| open2-lease | FAIL | Two opens with lease |
| open2-oplock | PASS | - |
| alloc-size | FAIL | Allocation size tracking |
| read-only | FAIL | Read-only attribute handling |
| stat-open | PASS | - |

### smb2.durable-v2-open (0/N - Client crash)

| Test | Status | Issue |
|------|--------|-------|
| * | CRASH | smbtorture client crashes (Samba bug) |

### smb2.compound (3/19 PASS)

| Test | Status | Issue |
|------|--------|-------|
| related1 | PASS | - |
| related2-9 | FAIL | Compound response signing - client sees "Bad SMB2 signature" |
| unrelated1 | FAIL | Compound response signing - client sees "Bad SMB2 signature" |
| invalid1-4 | FAIL | Compound response signing issues |
| interim1-2 | FAIL | Async interim responses not implemented |
| compound-break | PASS | - |
| compound-padding | FAIL | Compound padding validation |
| create-write-close | PASS | - |

### smb2.credits (0/3 FAIL)

| Test | Status | Issue |
|------|--------|-------|
| session_setup_credits_granted | FAIL | Credit grant algorithm |
| single_req_credits_granted | FAIL | Credit grant algorithm |
| skipped_mid | FAIL | Message ID gap handling |

### smb2.getinfo (0/8 FAIL)

| Test | Status | Issue |
|------|--------|-------|
| complex | FAIL | Complex info queries |
| fsinfo | FAIL | Filesystem info classes |
| qfs_buffercheck | FAIL | Buffer size validation |
| qfile_buffercheck | FAIL | Buffer size validation |
| qsec_buffercheck | FAIL | Security buffer validation |
| granted | FAIL | Access granted info |
| normalized | FAIL | Path normalization |
| getinfo_access | FAIL | Access mask in info |

### smb2.setinfo (0/1 FAIL)

| Test | Status | Issue |
|------|--------|-------|
| setinfo | FAIL | Set info operations |

### smb2.ioctl (21/73 PASS, 44 SKIP, 8 FAIL)

| Test | Status | Issue |
|------|--------|-------|
| req_resume_key | PASS | Phase 28 |
| req_two_resume_keys | PASS | Phase 28 |
| copy_chunk_simple | PASS | Phase 28 |
| copy_chunk_multi | PASS | Phase 28 |
| copy_chunk_*_lock | PASS | Phase 28 (lock conflict detection) |
| copy_chunk_bad_access | PASS | Phase 28 (access rights) |
| copy_chunk_limits | PASS | Phase 28 (server limits) |
| copy_chunk_across_shares* | PASS | Phase 28 |
| copy_chunk_src_exceed | FAIL | Source file size validation needed |
| copy_chunk_max_output_sz | FAIL | Output buffer size validation |
| shadow_copy | SKIP | VSS not implemented |
| compress_* | SKIP/FAIL | Compression not implemented |
| network_interface_info | SKIP | Multi-channel not implemented |
| sparse_* | SKIP | Sparse files not implemented |
| dup_extents_* | SKIP | Deduplication not implemented |

### smb2.rename (0/11 FAIL)

| Test | Status | Issue |
|------|--------|-------|
| simple | FAIL | Rename operations |
| simple_nodelete | FAIL | Rename without delete |
| no_sharing | FAIL | Sharing violation on rename |
| share_delete_* | FAIL | Delete share mode handling |
| msword | FAIL | MS Word rename pattern |
| rename_dir_openfile | FAIL | Rename dir with open file |
| rename_dir_bench | FAIL | Rename benchmark |
| close-full-information | FAIL | Close with full info |

### smb2.notify (0/N FAIL)

| Test | Status | Issue |
|------|--------|-------|
| valid-req | FAIL | Change notify not fully implemented |
| tcon | FAIL | Notify on tree connect |
| dir | FAIL | Directory notify |
| mask | FAIL | Notify mask handling |

## Missing Features vs ksmbd

| Feature | ksmbd | RustSMB | Priority |
|---------|-------|---------|----------|
| Compound requests (related/unrelated) | ✅ | ✅ | - |
| Oplock break notifications | ✅ | ⚠️ Same-server only | - |
| Lock stacking (same-handle re-lock) | ✅ | ✅ | Phase 26 |
| LOCK_NOT_GRANTED vs FILE_LOCK_CONFLICT | ✅ | ✅ | Phase 26 |
| Cross-handle lock conflicts | ✅ | ✅ | Phase 26 |
| Tree ID validation | ✅ | ✅ | - |
| Read past EOF → STATUS_END_OF_FILE | ✅ | ✅ | - |
| Read directory → STATUS_INVALID_DEVICE_REQUEST | ✅ | ✅ | - |
| File position tracking | ✅ | ✅ | - |
| Attributes-only opens (no oplock break) | ✅ | ❌ | P3 |
| Session binding validations | ✅ | ✅ (same-dialect) | Phase 27 |
| SMB2_CAP_MULTI_CHANNEL | ⚠️ Experimental | ❌ | P3 |
| SMB Direct (RDMA) | ✅ | ❌ | - |
| POSIX extensions | ✅ | ❌ | - |
| Durable handles v1/v2 | ⚠️ (kernel 6.9+) | ✅ | - |

## Priority Fixes

**P0 - Critical (blocks many tests):**
- ~~Implement oplock/lease break notifications~~ DONE in Phase 18 (same-server only)

**P1 - Security/Compliance:**
- ~~Tree ID validation (reject operations with wrong TID)~~ DONE in Phase 19
- ~~Read past EOF should return STATUS_END_OF_FILE~~ DONE (already implemented, verified in Phase 20)
- ~~Read on directory should return STATUS_INVALID_DEVICE_REQUEST~~ DONE in Phase 20

**P2 - Lock semantics:** DONE in Phase 26
- ~~Lock stacking (allow same handle to re-lock same range)~~ DONE
- ~~Correct error codes (LOCK_NOT_GRANTED first, FILE_LOCK_CONFLICT after)~~ DONE
- ~~Cross-handle/cross-session lock conflict detection~~ DONE

**P3 - Nice to have:**
- ~~File position tracking in FileAllInformation~~ DONE in Phase 23
- Attributes-only opens without sharing violations
- Multi-channel capability advertisement
