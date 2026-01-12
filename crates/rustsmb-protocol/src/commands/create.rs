//! SMB2 CREATE command.
//!
//! Used to create or open a file, directory, or named pipe.
//! See MS-SMB2 Section 2.2.13 and 2.2.14.
//!
//! # CREATE Contexts
//!
//! CREATE contexts are extensible request/response parameters for file operations.
//! They enable features like durable handles and leases.
//!
//! See MS-SMB2 Section 2.2.13.2 for CREATE context definitions.

use binrw::{BinRead, BinWrite};

/// SMB2 CREATE request structure size.
pub const CREATE_REQUEST_SIZE: u16 = 57;

/// SMB2 CREATE response structure size.
pub const CREATE_RESPONSE_SIZE: u16 = 89;

/// SMB2 CREATE Request.
///
/// See MS-SMB2 Section 2.2.13.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CreateRequest {
    /// Structure size (must be 57).
    pub structure_size: u16,

    /// Security flags (must be 0).
    pub security_flags: u8,

    /// Requested oplock level.
    pub requested_oplock_level: OplockLevel,

    /// Impersonation level (u32 for validation, valid values 0-3).
    pub impersonation_level: u32,

    /// SMB2 create flags.
    pub smb_create_flags: u64,

    /// Reserved (must be 0).
    pub reserved: u64,

    /// Desired access mask.
    pub desired_access: u32,

    /// File attributes.
    pub file_attributes: u32,

    /// Share access flags.
    pub share_access: u32,

    /// Create disposition.
    pub create_disposition: u32,

    /// Create options.
    pub create_options: u32,

    /// Name offset from beginning of header.
    pub name_offset: u16,

    /// Name length in bytes.
    pub name_length: u16,

    /// Create contexts offset.
    pub create_contexts_offset: u32,

    /// Create contexts length.
    pub create_contexts_length: u32,
    // Name follows (Unicode string)
    // Create contexts follow
}

impl Default for CreateRequest {
    fn default() -> Self {
        Self {
            structure_size: CREATE_REQUEST_SIZE,
            security_flags: 0,
            requested_oplock_level: OplockLevel::None,
            impersonation_level: 2, // Impersonation
            smb_create_flags: 0,
            reserved: 0,
            desired_access: 0,
            file_attributes: 0,
            share_access: 0,
            create_disposition: 0,
            create_options: 0,
            name_offset: 0,
            name_length: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
        }
    }
}

/// SMB2 CREATE Response.
///
/// See MS-SMB2 Section 2.2.14.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct CreateResponse {
    /// Structure size (must be 89).
    pub structure_size: u16,

    /// Oplock level granted.
    pub oplock_level: OplockLevel,

    /// Flags.
    pub flags: CreateResponseFlags,

    /// Create action.
    pub create_action: u32,

    /// Creation time.
    pub creation_time: u64,

    /// Last access time.
    pub last_access_time: u64,

    /// Last write time.
    pub last_write_time: u64,

    /// Change time.
    pub change_time: u64,

    /// Allocation size.
    pub allocation_size: u64,

    /// End of file (file size).
    pub end_of_file: u64,

    /// File attributes.
    pub file_attributes: u32,

    /// Reserved2.
    pub reserved2: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Create contexts offset.
    pub create_contexts_offset: u32,

    /// Create contexts length.
    pub create_contexts_length: u32,
    // Create contexts follow
}

impl Default for CreateResponse {
    fn default() -> Self {
        Self {
            structure_size: CREATE_RESPONSE_SIZE,
            oplock_level: OplockLevel::None,
            flags: CreateResponseFlags(0),
            create_action: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
            reserved2: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            create_contexts_offset: 0,
            create_contexts_length: 0,
        }
    }
}

/// Oplock level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u8)]
#[repr(u8)]
pub enum OplockLevel {
    /// No oplock.
    #[default]
    None = 0x00,
    /// Level II oplock.
    LevelII = 0x01,
    /// Exclusive oplock.
    Exclusive = 0x08,
    /// Batch oplock.
    Batch = 0x09,
    /// Lease.
    Lease = 0xFF,
}

impl OplockLevel {
    /// Convert to u8 value.
    pub fn as_u8(&self) -> u8 {
        match self {
            OplockLevel::None => 0x00,
            OplockLevel::LevelII => 0x01,
            OplockLevel::Exclusive => 0x08,
            OplockLevel::Batch => 0x09,
            OplockLevel::Lease => 0xFF,
        }
    }

    /// Convert from u8 value.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => OplockLevel::None,
            0x01 => OplockLevel::LevelII,
            0x08 => OplockLevel::Exclusive,
            0x09 => OplockLevel::Batch,
            0xFF => OplockLevel::Lease,
            _ => OplockLevel::None,
        }
    }
}

/// Impersonation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
#[brw(repr = u32)]
#[repr(u32)]
pub enum ImpersonationLevel {
    /// Anonymous.
    Anonymous = 0,
    /// Identification.
    Identification = 1,
    /// Impersonation.
    #[default]
    Impersonation = 2,
    /// Delegation.
    Delegation = 3,
}

/// Create response flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct CreateResponseFlags(pub u8);

impl CreateResponseFlags {
    /// Reparse point.
    pub const REPARSEPOINT: u8 = 0x01;

    /// Create new flags.
    #[inline]
    pub fn new(value: u8) -> Self {
        Self(value)
    }

    /// Check if reparse point.
    #[inline]
    pub fn is_reparse_point(self) -> bool {
        (self.0 & Self::REPARSEPOINT) != 0
    }
}

/// Create options flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CreateOptions(pub u32);

impl CreateOptions {
    /// Directory file.
    pub const DIRECTORY_FILE: u32 = 0x00000001;
    /// Write through.
    pub const WRITE_THROUGH: u32 = 0x00000002;
    /// Sequential only.
    pub const SEQUENTIAL_ONLY: u32 = 0x00000004;
    /// No intermediate buffering.
    pub const NO_INTERMEDIATE_BUFFERING: u32 = 0x00000008;
    /// Synchronous IO alert.
    pub const SYNCHRONOUS_IO_ALERT: u32 = 0x00000010;
    /// Synchronous IO non-alert.
    pub const SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
    /// Non-directory file.
    pub const NON_DIRECTORY_FILE: u32 = 0x00000040;
    /// Complete if oplocked.
    pub const COMPLETE_IF_OPLOCKED: u32 = 0x00000100;
    /// No EA knowledge.
    pub const NO_EA_KNOWLEDGE: u32 = 0x00000200;
    /// Random access.
    pub const RANDOM_ACCESS: u32 = 0x00000800;
    /// Delete on close.
    pub const DELETE_ON_CLOSE: u32 = 0x00001000;
    /// Open by file ID.
    pub const OPEN_BY_FILE_ID: u32 = 0x00002000;
    /// Open for backup intent.
    pub const OPEN_FOR_BACKUP_INTENT: u32 = 0x00004000;
    /// No compression.
    pub const NO_COMPRESSION: u32 = 0x00008000;
    /// Open remote instance.
    pub const OPEN_REMOTE_INSTANCE: u32 = 0x00000400;
    /// Open requiring oplock.
    pub const OPEN_REQUIRING_OPLOCK: u32 = 0x00010000;
    /// Disallow exclusive.
    pub const DISALLOW_EXCLUSIVE: u32 = 0x00020000;
    /// Reserve opfilter.
    pub const RESERVE_OPFILTER: u32 = 0x00100000;
    /// Open reparse point.
    pub const OPEN_REPARSE_POINT: u32 = 0x00200000;
    /// Open no recall.
    pub const OPEN_NO_RECALL: u32 = 0x00400000;
    /// Open for free space query.
    pub const OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x00800000;

    /// Create new options.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if directory file.
    #[inline]
    pub fn is_directory(self) -> bool {
        (self.0 & Self::DIRECTORY_FILE) != 0
    }

    /// Check if non-directory file.
    #[inline]
    pub fn is_non_directory(self) -> bool {
        (self.0 & Self::NON_DIRECTORY_FILE) != 0
    }

    /// Check if delete on close.
    #[inline]
    pub fn delete_on_close(self) -> bool {
        (self.0 & Self::DELETE_ON_CLOSE) != 0
    }
}

/// Create disposition values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum CreateDisposition {
    /// Supersede - if exists, supersede; if not, create.
    Supersede = 0,
    /// Open - if exists, open; if not, fail.
    Open = 1,
    /// Create - if exists, fail; if not, create.
    Create = 2,
    /// Open if - if exists, open; if not, create.
    #[default]
    OpenIf = 3,
    /// Overwrite - if exists, open and truncate; if not, fail.
    Overwrite = 4,
    /// Overwrite if - if exists, open and truncate; if not, create.
    OverwriteIf = 5,
}

impl CreateDisposition {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Supersede,
            1 => Self::Open,
            2 => Self::Create,
            3 => Self::OpenIf,
            4 => Self::Overwrite,
            5 => Self::OverwriteIf,
            _ => return None,
        })
    }
}

/// Create action values (response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CreateAction {
    /// File was superseded.
    Superseded = 0,
    /// Existing file was opened.
    Opened = 1,
    /// New file was created.
    Created = 2,
    /// Existing file was overwritten.
    Overwritten = 3,
}

impl CreateAction {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Superseded,
            1 => Self::Opened,
            2 => Self::Created,
            3 => Self::Overwritten,
            _ => return None,
        })
    }
}

// =============================================================================
// CREATE Context Definitions (MS-SMB2 Section 2.2.13.2)
// =============================================================================

/// CREATE context name constants.
///
/// These are 4-character names that identify each context type.
/// See MS-SMB2 Section 2.2.13.2.
pub mod create_context_name {
    /// Extended attributes buffer.
    pub const EA_BUFFER: &[u8; 4] = b"ExtA";
    /// Security descriptor buffer.
    pub const SD_BUFFER: &[u8; 4] = b"SecD";
    /// Durable handle request (SMB 2.1).
    pub const DURABLE_HANDLE_REQUEST: &[u8; 4] = b"DHnQ";
    /// Durable handle reconnect (SMB 2.1).
    pub const DURABLE_HANDLE_RECONNECT: &[u8; 4] = b"DHnC";
    /// Allocation size.
    pub const ALLOCATION_SIZE: &[u8; 4] = b"AlSi";
    /// Query maximal access.
    pub const QUERY_MAXIMAL_ACCESS: &[u8; 4] = b"MxAc";
    /// Timewarp token.
    pub const TIMEWARP_TOKEN: &[u8; 4] = b"TWrp";
    /// Query on-disk ID.
    pub const QUERY_ON_DISK_ID: &[u8; 4] = b"QFid";
    /// Lease request (SMB 2.1+).
    pub const LEASE_REQUEST: &[u8; 4] = b"RqLs";
    /// Durable handle request V2 (SMB 3.0+).
    pub const DURABLE_HANDLE_REQUEST_V2: &[u8; 4] = b"DH2Q";
    /// Durable handle reconnect V2 (SMB 3.0+).
    pub const DURABLE_HANDLE_RECONNECT_V2: &[u8; 4] = b"DH2C";
    /// App instance ID (SMB 3.0+).
    pub const APP_INSTANCE_ID: &[u8; 4] = b"\x45\xBC\xA6\x6A";
    /// App instance version (SMB 3.0.2+).
    pub const APP_INSTANCE_VERSION: &[u8; 4] = b"\xB9\x82\xD0\xB7";
    /// SMB2 Create SVHDX Request (for virtual disk).
    pub const SVHDX_OPEN_DEVICE_CONTEXT: &[u8; 4] = b"\x9C\xCB\xCF\x9E";
}

/// CREATE context header.
///
/// Each context in a CREATE request/response is prefixed by this header.
/// Contexts form a linked list, with `next` pointing to the next context.
///
/// See MS-SMB2 Section 2.2.13.2.
#[derive(Debug, Clone, Default)]
pub struct CreateContextHeader {
    /// Offset to next context (0 if last).
    pub next: u32,
    /// Offset to name from start of this struct.
    pub name_offset: u16,
    /// Length of name.
    pub name_length: u16,
    /// Reserved.
    pub reserved: u16,
    /// Offset to data from start of this struct.
    pub data_offset: u16,
    /// Length of data.
    pub data_length: u32,
}

impl CreateContextHeader {
    /// Header size in bytes.
    pub const SIZE: usize = 16;

    /// Parse header from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            next: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            name_offset: u16::from_le_bytes([data[4], data[5]]),
            name_length: u16::from_le_bytes([data[6], data[7]]),
            reserved: u16::from_le_bytes([data[8], data[9]]),
            data_offset: u16::from_le_bytes([data[10], data[11]]),
            data_length: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.next.to_le_bytes());
        buf[4..6].copy_from_slice(&self.name_offset.to_le_bytes());
        buf[6..8].copy_from_slice(&self.name_length.to_le_bytes());
        buf[8..10].copy_from_slice(&self.reserved.to_le_bytes());
        buf[10..12].copy_from_slice(&self.data_offset.to_le_bytes());
        buf[12..16].copy_from_slice(&self.data_length.to_le_bytes());
        buf
    }
}

/// Durable handle request V2 flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DurableHandleFlags(pub u32);

impl DurableHandleFlags {
    /// Request persistent handle (survives planned failover).
    pub const PERSISTENT: u32 = 0x00000002;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if persistent handle requested.
    #[inline]
    pub fn is_persistent(self) -> bool {
        (self.0 & Self::PERSISTENT) != 0
    }
}

/// Parsed CREATE context.
///
/// Represents a CREATE context after parsing from the request buffer.
#[derive(Debug, Clone)]
pub enum CreateContext {
    /// Durable handle request (SMB 2.1).
    /// Empty data - just presence indicates request.
    DurableHandleRequest,

    /// Durable handle reconnect (SMB 2.1).
    DurableHandleReconnect {
        /// File ID to reconnect.
        file_id: FileId,
    },

    /// Durable handle request V2 (SMB 3.0+).
    DurableHandleRequestV2 {
        /// Timeout in milliseconds.
        timeout: u32,
        /// Flags (0x02 = persistent).
        flags: DurableHandleFlags,
        /// Reserved.
        reserved: u64,
        /// Create GUID for reconnection validation.
        create_guid: [u8; 16],
    },

    /// Durable handle reconnect V2 (SMB 3.0+).
    DurableHandleReconnectV2 {
        /// File ID to reconnect.
        file_id: FileId,
        /// Create GUID for validation.
        create_guid: [u8; 16],
        /// Flags.
        flags: DurableHandleFlags,
    },

    /// Lease request (SMB 2.1).
    LeaseRequest {
        /// Lease key (client-generated).
        lease_key: [u8; 16],
        /// Requested lease state.
        lease_state: u32,
        /// Lease flags.
        lease_flags: u32,
        /// Lease duration (must be 0).
        lease_duration: u64,
    },

    /// Lease request V2 (SMB 3.0+).
    LeaseRequestV2 {
        /// Lease key.
        lease_key: [u8; 16],
        /// Requested lease state.
        lease_state: u32,
        /// Flags.
        flags: u32,
        /// Lease duration (must be 0).
        lease_duration: u64,
        /// Parent lease key (for directory leases).
        parent_lease_key: [u8; 16],
        /// Epoch.
        epoch: u16,
        /// Reserved.
        reserved: u16,
    },

    /// Query maximal access.
    QueryMaximalAccess {
        /// Timestamp (optional).
        timestamp: Option<u64>,
    },

    /// Query on-disk ID.
    QueryOnDiskId,

    /// Allocation size.
    AllocationSize {
        /// Allocation size.
        allocation_size: u64,
    },

    /// App instance ID (SMB 3.0+).
    AppInstanceId {
        /// Structure size.
        structure_size: u16,
        /// Reserved.
        reserved: u16,
        /// App instance ID.
        app_instance_id: [u8; 16],
    },

    /// Unknown context (preserve for passthrough).
    Unknown {
        /// Context name.
        name: Vec<u8>,
        /// Context data.
        data: Vec<u8>,
    },
}

/// File ID (persistent + volatile).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileId {
    /// Persistent file ID (survives reconnection).
    pub persistent: u64,
    /// Volatile file ID (per-connection).
    pub volatile: u64,
}

impl FileId {
    /// Create a new file ID.
    pub fn new(persistent: u64, volatile: u64) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        Some(Self {
            persistent: u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            volatile: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&self.persistent.to_le_bytes());
        buf[8..16].copy_from_slice(&self.volatile.to_le_bytes());
        buf
    }

    /// Get the persistent file ID.
    pub fn persistent_id(&self) -> u64 {
        self.persistent
    }

    /// Get the volatile file ID.
    pub fn volatile_id(&self) -> u64 {
        self.volatile
    }

    /// Get as u128 (persistent in low bits, volatile in high bits).
    pub fn as_u128(&self) -> u128 {
        ((self.volatile as u128) << 64) | (self.persistent as u128)
    }
}

/// Error parsing CREATE contexts.
#[derive(Debug, Clone)]
pub enum CreateContextError {
    /// Buffer too small.
    BufferTooSmall,
    /// Invalid header.
    InvalidHeader,
    /// Invalid context data.
    InvalidData(String),
    /// Invalid offset.
    InvalidOffset,
}

impl std::fmt::Display for CreateContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "Buffer too small for CREATE context"),
            Self::InvalidHeader => write!(f, "Invalid CREATE context header"),
            Self::InvalidData(s) => write!(f, "Invalid CREATE context data: {}", s),
            Self::InvalidOffset => write!(f, "Invalid offset in CREATE context"),
        }
    }
}

impl std::error::Error for CreateContextError {}

/// Parse CREATE contexts from a request buffer.
///
/// The buffer should start at the first context (after header + name).
/// Contexts are stored as a linked list.
pub fn parse_create_contexts(data: &[u8]) -> Result<Vec<CreateContext>, CreateContextError> {
    let mut contexts = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        // Parse header
        let remaining = &data[offset..];
        let header =
            CreateContextHeader::parse(remaining).ok_or(CreateContextError::InvalidHeader)?;

        // Get name
        let name_start = header.name_offset as usize;
        let name_end = name_start + header.name_length as usize;
        if name_end > remaining.len() {
            return Err(CreateContextError::InvalidOffset);
        }
        let name = &remaining[name_start..name_end];

        // Get data
        let data_start = header.data_offset as usize;
        let data_end = data_start + header.data_length as usize;
        if data_end > remaining.len() {
            return Err(CreateContextError::InvalidOffset);
        }
        let ctx_data = &remaining[data_start..data_end];

        // Parse based on name
        let context = parse_single_context(name, ctx_data)?;
        contexts.push(context);

        // Move to next context
        if header.next == 0 {
            break;
        }
        offset += header.next as usize;
    }

    Ok(contexts)
}

/// Parse a single CREATE context by name.
fn parse_single_context(name: &[u8], data: &[u8]) -> Result<CreateContext, CreateContextError> {
    // Check for 4-byte names
    if name.len() >= 4 {
        let name4: &[u8; 4] = name[..4].try_into().unwrap();

        match name4 {
            create_context_name::DURABLE_HANDLE_REQUEST => {
                return Ok(CreateContext::DurableHandleRequest);
            }
            create_context_name::DURABLE_HANDLE_RECONNECT => {
                let file_id = FileId::from_bytes(data)
                    .ok_or_else(|| CreateContextError::InvalidData("Invalid file ID".into()))?;
                return Ok(CreateContext::DurableHandleReconnect { file_id });
            }
            create_context_name::DURABLE_HANDLE_REQUEST_V2 => {
                if data.len() < 32 {
                    return Err(CreateContextError::InvalidData(
                        "DH2Q data too small".into(),
                    ));
                }
                let timeout = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let flags = DurableHandleFlags::new(u32::from_le_bytes([
                    data[4], data[5], data[6], data[7],
                ]));
                let reserved = u64::from_le_bytes([
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                ]);
                let mut create_guid = [0u8; 16];
                create_guid.copy_from_slice(&data[16..32]);
                return Ok(CreateContext::DurableHandleRequestV2 {
                    timeout,
                    flags,
                    reserved,
                    create_guid,
                });
            }
            create_context_name::DURABLE_HANDLE_RECONNECT_V2 => {
                if data.len() < 36 {
                    return Err(CreateContextError::InvalidData(
                        "DH2C data too small".into(),
                    ));
                }
                let file_id = FileId::from_bytes(&data[0..16]).ok_or_else(|| {
                    CreateContextError::InvalidData("Invalid file ID in DH2C".into())
                })?;
                let mut create_guid = [0u8; 16];
                create_guid.copy_from_slice(&data[16..32]);
                let flags = DurableHandleFlags::new(u32::from_le_bytes([
                    data[32], data[33], data[34], data[35],
                ]));
                return Ok(CreateContext::DurableHandleReconnectV2 {
                    file_id,
                    create_guid,
                    flags,
                });
            }
            create_context_name::LEASE_REQUEST => {
                if data.len() < 32 {
                    return Err(CreateContextError::InvalidData(
                        "RqLs data too small".into(),
                    ));
                }
                let mut lease_key = [0u8; 16];
                lease_key.copy_from_slice(&data[0..16]);
                let lease_state = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                let lease_flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
                let lease_duration = u64::from_le_bytes([
                    data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
                ]);

                // Check if this is V2 (has parent lease key)
                if data.len() >= 52 {
                    let mut parent_lease_key = [0u8; 16];
                    parent_lease_key.copy_from_slice(&data[32..48]);
                    let epoch = u16::from_le_bytes([data[48], data[49]]);
                    let reserved = u16::from_le_bytes([data[50], data[51]]);
                    return Ok(CreateContext::LeaseRequestV2 {
                        lease_key,
                        lease_state,
                        flags: lease_flags,
                        lease_duration,
                        parent_lease_key,
                        epoch,
                        reserved,
                    });
                }

                return Ok(CreateContext::LeaseRequest {
                    lease_key,
                    lease_state,
                    lease_flags,
                    lease_duration,
                });
            }
            create_context_name::QUERY_MAXIMAL_ACCESS => {
                let timestamp = if data.len() >= 8 {
                    Some(u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]))
                } else {
                    None
                };
                return Ok(CreateContext::QueryMaximalAccess { timestamp });
            }
            create_context_name::QUERY_ON_DISK_ID => {
                return Ok(CreateContext::QueryOnDiskId);
            }
            create_context_name::ALLOCATION_SIZE => {
                if data.len() < 8 {
                    return Err(CreateContextError::InvalidData(
                        "AISi data too small".into(),
                    ));
                }
                let allocation_size = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                return Ok(CreateContext::AllocationSize { allocation_size });
            }
            create_context_name::APP_INSTANCE_ID => {
                if data.len() < 20 {
                    return Err(CreateContextError::InvalidData(
                        "AppInstanceId data too small".into(),
                    ));
                }
                let structure_size = u16::from_le_bytes([data[0], data[1]]);
                let reserved = u16::from_le_bytes([data[2], data[3]]);
                let mut app_instance_id = [0u8; 16];
                app_instance_id.copy_from_slice(&data[4..20]);
                return Ok(CreateContext::AppInstanceId {
                    structure_size,
                    reserved,
                    app_instance_id,
                });
            }
            _ => {}
        }
    }

    // Unknown context
    Ok(CreateContext::Unknown {
        name: name.to_vec(),
        data: data.to_vec(),
    })
}

/// Builder for CREATE response contexts.
#[derive(Debug, Default)]
pub struct CreateContextBuilder {
    contexts: Vec<(Vec<u8>, Vec<u8>)>, // (name, data) pairs
}

impl CreateContextBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add durable handle response.
    pub fn add_durable_handle_response(mut self) -> Self {
        // Empty data for durable handle response
        self.contexts
            .push((create_context_name::DURABLE_HANDLE_REQUEST.to_vec(), vec![]));
        self
    }

    /// Add durable handle V2 response.
    pub fn add_durable_handle_response_v2(mut self, timeout: u32, flags: u32) -> Self {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&timeout.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        self.contexts.push((
            create_context_name::DURABLE_HANDLE_REQUEST_V2.to_vec(),
            data,
        ));
        self
    }

    /// Add lease response.
    pub fn add_lease_response(
        mut self,
        lease_key: [u8; 16],
        lease_state: u32,
        lease_flags: u32,
    ) -> Self {
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&lease_key);
        data.extend_from_slice(&lease_state.to_le_bytes());
        data.extend_from_slice(&lease_flags.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes()); // lease_duration
        self.contexts
            .push((create_context_name::LEASE_REQUEST.to_vec(), data));
        self
    }

    /// Add lease V2 response.
    pub fn add_lease_response_v2(
        mut self,
        lease_key: [u8; 16],
        lease_state: u32,
        flags: u32,
        parent_lease_key: [u8; 16],
        epoch: u16,
    ) -> Self {
        let mut data = Vec::with_capacity(52);
        data.extend_from_slice(&lease_key);
        data.extend_from_slice(&lease_state.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes()); // lease_duration
        data.extend_from_slice(&parent_lease_key);
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // reserved
        self.contexts
            .push((create_context_name::LEASE_REQUEST.to_vec(), data));
        self
    }

    /// Add maximal access response.
    pub fn add_maximal_access_response(mut self, query_status: u32, maximal_access: u32) -> Self {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&query_status.to_le_bytes());
        data.extend_from_slice(&maximal_access.to_le_bytes());
        self.contexts
            .push((create_context_name::QUERY_MAXIMAL_ACCESS.to_vec(), data));
        self
    }

    /// Add on-disk ID response.
    pub fn add_on_disk_id_response(mut self, disk_file_id: u64, volume_id: u64) -> Self {
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&disk_file_id.to_le_bytes());
        data.extend_from_slice(&volume_id.to_le_bytes());
        data.extend_from_slice(&[0u8; 16]); // Reserved
        self.contexts
            .push((create_context_name::QUERY_ON_DISK_ID.to_vec(), data));
        self
    }

    /// Build the CREATE contexts buffer.
    pub fn build(self) -> Vec<u8> {
        if self.contexts.is_empty() {
            return vec![];
        }

        let mut result = Vec::new();

        for (i, (name, data)) in self.contexts.iter().enumerate() {
            let is_last = i == self.contexts.len() - 1;

            // Calculate sizes and offsets
            let name_offset = 16u16; // Right after header
            let name_len = name.len() as u16;
            // Data offset is always calculated, even if data is empty
            // This matches Windows client expectations (data_offset points past name+padding)
            let data_offset = ((16 + name.len() + 7) & !7) as u16; // 8-byte aligned
            let data_len = data.len() as u32;

            // Calculate total size of this context (8-byte aligned)
            let context_size = ((data_offset as usize + data.len() + 7) & !7) as u32;

            let header = CreateContextHeader {
                next: if is_last { 0 } else { context_size },
                name_offset,
                name_length: name_len,
                reserved: 0,
                data_offset,
                data_length: data_len,
            };

            result.extend_from_slice(&header.to_bytes());
            result.extend_from_slice(name);

            // Pad to data_offset
            let pad_to_data = data_offset as usize - 16 - name.len();
            result.extend(std::iter::repeat(0u8).take(pad_to_data));

            result.extend_from_slice(data);

            // Pad to 8-byte alignment for next context
            if !is_last {
                let pad_to_align =
                    context_size as usize - (16 + name.len() + pad_to_data + data.len());
                result.extend(std::iter::repeat(0u8).take(pad_to_align));
            }
        }

        result
    }

    /// Check if any contexts have been added.
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_create_request_default() {
        let req = CreateRequest::default();
        assert_eq!(req.structure_size, CREATE_REQUEST_SIZE);
    }

    #[test]
    fn test_create_response_default() {
        let resp = CreateResponse::default();
        assert_eq!(resp.structure_size, CREATE_RESPONSE_SIZE);
    }

    #[test]
    fn test_oplock_level() {
        assert_eq!(OplockLevel::None as u8, 0x00);
        assert_eq!(OplockLevel::Exclusive as u8, 0x08);
        assert_eq!(OplockLevel::Lease as u8, 0xFF);
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = CreateResponse {
            structure_size: CREATE_RESPONSE_SIZE,
            oplock_level: OplockLevel::Exclusive,
            flags: CreateResponseFlags(0),
            create_action: CreateAction::Created as u32,
            creation_time: 132000000000000000,
            last_access_time: 132000000000000000,
            last_write_time: 132000000000000000,
            change_time: 132000000000000000,
            allocation_size: 4096,
            end_of_file: 1024,
            file_attributes: 0x20, // Archive
            reserved2: 0,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            create_contexts_offset: 0,
            create_contexts_length: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = CreateResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.oplock_level, OplockLevel::Exclusive);
        assert_eq!(parsed.create_action, CreateAction::Created as u32);
        assert_eq!(parsed.file_id_persistent, 0x123456789ABCDEF0);
        assert_eq!(parsed.file_id_volatile, 0x0FEDCBA987654321);
    }

    #[test]
    fn test_create_options() {
        let opts =
            CreateOptions::new(CreateOptions::DIRECTORY_FILE | CreateOptions::DELETE_ON_CLOSE);
        assert!(opts.is_directory());
        assert!(opts.delete_on_close());
        assert!(!opts.is_non_directory());
    }

    // ==========================================================================
    // CREATE Context Tests
    // ==========================================================================

    #[test]
    fn test_file_id() {
        let file_id = FileId::new(0x123456789ABCDEF0, 0x0FEDCBA987654321);
        let bytes = file_id.to_bytes();
        let parsed = FileId::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.persistent, 0x123456789ABCDEF0);
        assert_eq!(parsed.volatile, 0x0FEDCBA987654321);
    }

    #[test]
    fn test_create_context_header() {
        let header = CreateContextHeader {
            next: 32,
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 16,
        };
        let bytes = header.to_bytes();
        let parsed = CreateContextHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.next, 32);
        assert_eq!(parsed.name_offset, 16);
        assert_eq!(parsed.name_length, 4);
        assert_eq!(parsed.data_offset, 24);
        assert_eq!(parsed.data_length, 16);
    }

    #[test]
    fn test_durable_handle_flags() {
        let flags = DurableHandleFlags::new(DurableHandleFlags::PERSISTENT);
        assert!(flags.is_persistent());

        let flags2 = DurableHandleFlags::new(0);
        assert!(!flags2.is_persistent());
    }

    #[test]
    fn test_parse_durable_handle_request() {
        // Build a DHnQ context manually
        let header = CreateContextHeader {
            next: 0,
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 0, // DHnQ has no data
        };

        let mut data = Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(create_context_name::DURABLE_HANDLE_REQUEST);
        // Pad to data_offset
        data.extend_from_slice(&[0u8; 4]);

        let contexts = parse_create_contexts(&data).unwrap();
        assert_eq!(contexts.len(), 1);
        assert!(matches!(contexts[0], CreateContext::DurableHandleRequest));
    }

    #[test]
    fn test_parse_durable_handle_reconnect() {
        let file_id = FileId::new(0x123, 0x456);

        let header = CreateContextHeader {
            next: 0,
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 16,
        };

        let mut data = Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(create_context_name::DURABLE_HANDLE_RECONNECT);
        data.extend_from_slice(&[0u8; 4]); // Pad
        data.extend_from_slice(&file_id.to_bytes());

        let contexts = parse_create_contexts(&data).unwrap();
        assert_eq!(contexts.len(), 1);
        if let CreateContext::DurableHandleReconnect { file_id: fid } = &contexts[0] {
            assert_eq!(fid.persistent, 0x123);
            assert_eq!(fid.volatile, 0x456);
        } else {
            panic!("Expected DurableHandleReconnect");
        }
    }

    #[test]
    fn test_parse_durable_handle_request_v2() {
        let create_guid = [0x11u8; 16];

        let header = CreateContextHeader {
            next: 0,
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 32,
        };

        let mut data = Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(create_context_name::DURABLE_HANDLE_REQUEST_V2);
        data.extend_from_slice(&[0u8; 4]); // Pad

        // DH2Q data
        data.extend_from_slice(&60000u32.to_le_bytes()); // timeout
        data.extend_from_slice(&DurableHandleFlags::PERSISTENT.to_le_bytes()); // flags
        data.extend_from_slice(&0u64.to_le_bytes()); // reserved
        data.extend_from_slice(&create_guid);

        let contexts = parse_create_contexts(&data).unwrap();
        assert_eq!(contexts.len(), 1);
        if let CreateContext::DurableHandleRequestV2 {
            timeout,
            flags,
            create_guid: guid,
            ..
        } = &contexts[0]
        {
            assert_eq!(*timeout, 60000);
            assert!(flags.is_persistent());
            assert_eq!(guid, &create_guid);
        } else {
            panic!("Expected DurableHandleRequestV2");
        }
    }

    #[test]
    fn test_parse_lease_request() {
        let lease_key = [0x22u8; 16];

        let header = CreateContextHeader {
            next: 0,
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 32,
        };

        let mut data = Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(create_context_name::LEASE_REQUEST);
        data.extend_from_slice(&[0u8; 4]); // Pad

        // Lease data
        data.extend_from_slice(&lease_key);
        data.extend_from_slice(&0x07u32.to_le_bytes()); // R+H+W
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u64.to_le_bytes()); // duration

        let contexts = parse_create_contexts(&data).unwrap();
        assert_eq!(contexts.len(), 1);
        if let CreateContext::LeaseRequest {
            lease_key: key,
            lease_state,
            ..
        } = &contexts[0]
        {
            assert_eq!(key, &lease_key);
            assert_eq!(*lease_state, 0x07);
        } else {
            panic!("Expected LeaseRequest");
        }
    }

    #[test]
    fn test_parse_multiple_contexts() {
        // Build two contexts: DHnQ + MxAc
        let header1 = CreateContextHeader {
            next: 24, // Next context starts at offset 24
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 0,
        };

        let header2 = CreateContextHeader {
            next: 0,
            name_offset: 16,
            name_length: 4,
            reserved: 0,
            data_offset: 24,
            data_length: 0,
        };

        let mut data = Vec::new();
        // First context
        data.extend_from_slice(&header1.to_bytes());
        data.extend_from_slice(create_context_name::DURABLE_HANDLE_REQUEST);
        data.extend_from_slice(&[0u8; 4]); // Pad to 24

        // Second context
        data.extend_from_slice(&header2.to_bytes());
        data.extend_from_slice(create_context_name::QUERY_MAXIMAL_ACCESS);
        data.extend_from_slice(&[0u8; 4]); // Pad

        let contexts = parse_create_contexts(&data).unwrap();
        assert_eq!(contexts.len(), 2);
        assert!(matches!(contexts[0], CreateContext::DurableHandleRequest));
        assert!(matches!(
            contexts[1],
            CreateContext::QueryMaximalAccess { timestamp: None }
        ));
    }

    #[test]
    fn test_context_builder() {
        let builder = CreateContextBuilder::new()
            .add_durable_handle_response()
            .add_lease_response([0x33u8; 16], 0x07, 0);

        let data = builder.build();
        assert!(!data.is_empty());

        // Parse it back
        let contexts = parse_create_contexts(&data).unwrap();
        assert_eq!(contexts.len(), 2);
    }

    #[test]
    fn test_empty_context_builder() {
        let builder = CreateContextBuilder::new();
        assert!(builder.is_empty());
        let data = builder.build();
        assert!(data.is_empty());
    }
}
