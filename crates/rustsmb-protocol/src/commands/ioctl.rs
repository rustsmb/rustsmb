//! SMB2 IOCTL command.
//!
//! Used to send device control codes.
//! See MS-SMB2 Section 2.2.31 and 2.2.32.

use binrw::{BinRead, BinWrite};

/// SMB2 IOCTL request structure size.
pub const IOCTL_REQUEST_SIZE: u16 = 57;

/// SMB2 IOCTL response structure size.
pub const IOCTL_RESPONSE_SIZE: u16 = 49;

/// SMB2 IOCTL Request.
///
/// See MS-SMB2 Section 2.2.31.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct IoctlRequest {
    /// Structure size (must be 57).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,

    /// Control code.
    pub ctl_code: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Input offset from beginning of header.
    pub input_offset: u32,

    /// Input count.
    pub input_count: u32,

    /// Max input response.
    pub max_input_response: u32,

    /// Output offset from beginning of header.
    pub output_offset: u32,

    /// Output count.
    pub output_count: u32,

    /// Max output response.
    pub max_output_response: u32,

    /// Flags.
    pub flags: IoctlFlags,

    /// Reserved2 (must be 0).
    pub reserved2: u32,
    // Input buffer follows
}

impl Default for IoctlRequest {
    fn default() -> Self {
        Self {
            structure_size: IOCTL_REQUEST_SIZE,
            reserved: 0,
            ctl_code: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            input_offset: 0,
            input_count: 0,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 0,
            flags: IoctlFlags(0),
            reserved2: 0,
        }
    }
}

/// SMB2 IOCTL Response.
///
/// See MS-SMB2 Section 2.2.32.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct IoctlResponse {
    /// Structure size (must be 49).
    pub structure_size: u16,

    /// Reserved (must be 0).
    pub reserved: u16,

    /// Control code.
    pub ctl_code: u32,

    /// File ID (persistent).
    pub file_id_persistent: u64,

    /// File ID (volatile).
    pub file_id_volatile: u64,

    /// Input offset from beginning of header.
    pub input_offset: u32,

    /// Input count.
    pub input_count: u32,

    /// Output offset from beginning of header.
    pub output_offset: u32,

    /// Output count.
    pub output_count: u32,

    /// Flags.
    pub flags: u32,

    /// Reserved2.
    pub reserved2: u32,
    // Output buffer follows
}

impl Default for IoctlResponse {
    fn default() -> Self {
        Self {
            structure_size: IOCTL_RESPONSE_SIZE,
            reserved: 0,
            ctl_code: 0,
            file_id_persistent: 0,
            file_id_volatile: 0,
            input_offset: 0,
            input_count: 0,
            output_offset: 0,
            output_count: 0,
            flags: 0,
            reserved2: 0,
        }
    }
}

/// IOCTL flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BinRead, BinWrite)]
pub struct IoctlFlags(pub u32);

impl IoctlFlags {
    /// IOCTL is a FSCTL.
    pub const IS_FSCTL: u32 = 0x00000001;

    /// Create new flags.
    #[inline]
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Check if this is a FSCTL.
    #[inline]
    pub fn is_fsctl(self) -> bool {
        (self.0 & Self::IS_FSCTL) != 0
    }
}

/// Common FSCTL codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsctlCode {
    /// DFS get referrals.
    DfsGetReferrals = 0x00060194,
    /// Pipe peek.
    PipePeek = 0x0011400C,
    /// Pipe wait.
    PipeWait = 0x00110018,
    /// Pipe transceive.
    PipeTransceive = 0x0011C017,
    /// SRV request resume key.
    SrvRequestResumeKey = 0x00140078,
    /// SRV read hash.
    SrvReadHash = 0x001441BB,
    /// SRV copychunk.
    SrvCopychunk = 0x001440F2,
    /// SRV copychunk write.
    SrvCopychunkWrite = 0x001480F2,
    /// LMR request resiliency.
    LmrRequestResiliency = 0x001401D4,
    /// Query network interface info.
    QueryNetworkInterfaceInfo = 0x001401FC,
    /// Set reparse point.
    SetReparsePoint = 0x000900A4,
    /// Get reparse point.
    GetReparsePoint = 0x000900A8,
    /// Delete reparse point.
    DeleteReparsePoint = 0x000900AC,
    /// File level trim.
    FileLevelTrim = 0x00098208,
    /// Validate negotiate info.
    ValidateNegotiateInfo = 0x00140204,
}

impl FsctlCode {
    /// Create from u32.
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0x00060194 => Self::DfsGetReferrals,
            0x0011400C => Self::PipePeek,
            0x00110018 => Self::PipeWait,
            0x0011C017 => Self::PipeTransceive,
            0x00140078 => Self::SrvRequestResumeKey,
            0x001441BB => Self::SrvReadHash,
            0x001440F2 => Self::SrvCopychunk,
            0x001480F2 => Self::SrvCopychunkWrite,
            0x001401D4 => Self::LmrRequestResiliency,
            0x001401FC => Self::QueryNetworkInterfaceInfo,
            0x000900A4 => Self::SetReparsePoint,
            0x000900A8 => Self::GetReparsePoint,
            0x000900AC => Self::DeleteReparsePoint,
            0x00098208 => Self::FileLevelTrim,
            0x00140204 => Self::ValidateNegotiateInfo,
            _ => return None,
        })
    }
}

// =============================================================================
// FSCTL_SRV_REQUEST_RESUME_KEY - MS-SMB2 2.2.32.3
// =============================================================================

/// SRV_REQUEST_RESUME_KEY response.
///
/// This is the response to FSCTL_SRV_REQUEST_RESUME_KEY (0x00140078).
/// The server returns a 24-byte opaque key that identifies the open.
/// See MS-SMB2 Section 2.2.32.3.
///
/// Note: Total size is 32 bytes (24 + 4 + 4 reserved) per spec requirement.
#[derive(Debug, Clone, Default, BinRead, BinWrite)]
#[brw(little)]
pub struct SrvRequestResumeKeyResponse {
    /// 24-byte opaque server-generated resume key.
    /// The server SHOULD use Open.DurableFileId for this value.
    pub resume_key: [u8; 24],

    /// Context length. Server MUST set this to 0.
    pub context_length: u32,

    /// Reserved/context padding to make structure 32 bytes total.
    /// Per MS-SMB2 3.3.5.15.5: "MaxOutputBufferLength should be set to 32 bytes"
    pub reserved: u32,
}

// =============================================================================
// FSCTL_SRV_COPYCHUNK - MS-SMB2 2.2.31.1 and 2.2.32.1
// =============================================================================

/// SRV_COPYCHUNK_COPY request structure.
///
/// This is the input buffer for FSCTL_SRV_COPYCHUNK (0x001440F2) and
/// FSCTL_SRV_COPYCHUNK_WRITE (0x001480F2).
/// See MS-SMB2 Section 2.2.31.1.
#[derive(Debug, Clone)]
pub struct SrvCopychunkCopy {
    /// Source key obtained from FSCTL_SRV_REQUEST_RESUME_KEY.
    pub source_key: [u8; 24],

    /// Number of chunks to copy.
    pub chunk_count: u32,

    /// Reserved (must be 0).
    pub reserved: u32,

    /// Array of chunk descriptors.
    pub chunks: Vec<SrvCopychunkCopyChunk>,
}

impl SrvCopychunkCopy {
    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, std::io::Error> {
        if data.len() < 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SRV_COPYCHUNK_COPY buffer too small",
            ));
        }

        let mut source_key = [0u8; 24];
        source_key.copy_from_slice(&data[0..24]);

        let chunk_count = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let reserved = u32::from_le_bytes(data[28..32].try_into().unwrap());

        // Each chunk is 24 bytes
        let expected_len = 32 + (chunk_count as usize * 24);
        if data.len() < expected_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "SRV_COPYCHUNK_COPY buffer too small for {} chunks",
                    chunk_count
                ),
            ));
        }

        let mut chunks = Vec::with_capacity(chunk_count as usize);
        for i in 0..chunk_count as usize {
            let offset = 32 + i * 24;
            let chunk = SrvCopychunkCopyChunk {
                source_offset: u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()),
                target_offset: u64::from_le_bytes(
                    data[offset + 8..offset + 16].try_into().unwrap(),
                ),
                length: u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()),
                reserved: u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap()),
            };
            chunks.push(chunk);
        }

        Ok(Self {
            source_key,
            chunk_count,
            reserved,
            chunks,
        })
    }
}

/// Single chunk descriptor in SRV_COPYCHUNK_COPY.
///
/// See MS-SMB2 Section 2.2.31.1.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct SrvCopychunkCopyChunk {
    /// Offset in the source file to copy from.
    pub source_offset: u64,

    /// Offset in the target file to copy to.
    /// 0xFFFFFFFFFFFFFFFF means append to end of file.
    pub target_offset: u64,

    /// Number of bytes to copy. Must be > 0.
    pub length: u32,

    /// Reserved (must be 0).
    pub reserved: u32,
}

/// SRV_COPYCHUNK response structure.
///
/// This is the output buffer for FSCTL_SRV_COPYCHUNK.
/// See MS-SMB2 Section 2.2.32.1.
#[derive(Debug, Clone, Default, BinRead, BinWrite)]
#[brw(little)]
pub struct SrvCopychunkResponse {
    /// Number of chunks successfully written.
    pub chunks_written: u32,

    /// Number of bytes written in the last successful chunk.
    /// If partial write occurred, this indicates how many bytes were written.
    pub chunk_bytes_written: u32,

    /// Total number of bytes written across all chunks.
    pub total_bytes_written: u32,
}

impl SrvCopychunkResponse {
    /// Create a response indicating server limits exceeded.
    ///
    /// Per MS-SMB2 3.3.5.15.6, when limits are exceeded, the server returns
    /// STATUS_INVALID_PARAMETER with chunks_written set to the limit values.
    pub fn with_limits(max_chunks: u32, max_chunk_size: u32, max_data_size: u32) -> Self {
        Self {
            chunks_written: max_chunks,
            chunk_bytes_written: max_chunk_size,
            total_bytes_written: max_data_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ioctl_request_default() {
        let req = IoctlRequest::default();
        assert_eq!(req.structure_size, IOCTL_REQUEST_SIZE);
    }

    #[test]
    fn test_ioctl_response_default() {
        let resp = IoctlResponse::default();
        assert_eq!(resp.structure_size, IOCTL_RESPONSE_SIZE);
    }

    #[test]
    fn test_request_roundtrip() {
        let req = IoctlRequest {
            structure_size: IOCTL_REQUEST_SIZE,
            reserved: 0,
            ctl_code: FsctlCode::PipeTransceive as u32,
            file_id_persistent: 0x123456789ABCDEF0,
            file_id_volatile: 0x0FEDCBA987654321,
            input_offset: 120,
            input_count: 64,
            max_input_response: 0,
            output_offset: 0,
            output_count: 0,
            max_output_response: 4096,
            flags: IoctlFlags::new(IoctlFlags::IS_FSCTL),
            reserved2: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = IoctlRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.ctl_code, FsctlCode::PipeTransceive as u32);
        assert!(parsed.flags.is_fsctl());
        assert_eq!(parsed.max_output_response, 4096);
    }

    #[test]
    fn test_fsctl_codes() {
        assert_eq!(
            FsctlCode::from_u32(0x00140204),
            Some(FsctlCode::ValidateNegotiateInfo)
        );
        assert_eq!(FsctlCode::from_u32(0xFFFFFFFF), None);
    }

    // =========================================================================
    // MS-SMB2 2.2.32.3: SRV_REQUEST_RESUME_KEY Tests
    // =========================================================================

    #[test]
    fn test_resume_key_response_size() {
        // Per MS-SMB2 3.3.5.15.5: Total size is 32 bytes
        // (24 bytes resume_key + 4 bytes context_length + 4 bytes reserved)
        let resp = SrvRequestResumeKeyResponse::default();
        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn test_resume_key_response_roundtrip() {
        let mut resume_key = [0u8; 24];
        resume_key[0..8].copy_from_slice(&0x123456789ABCDEFu64.to_le_bytes());

        let resp = SrvRequestResumeKeyResponse {
            resume_key,
            context_length: 0,
            reserved: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = SrvRequestResumeKeyResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.resume_key[0..8], resume_key[0..8]);
        assert_eq!(parsed.context_length, 0);
        assert_eq!(parsed.reserved, 0);
    }

    // =========================================================================
    // MS-SMB2 2.2.31.1: SRV_COPYCHUNK_COPY Tests
    // =========================================================================

    #[test]
    fn test_copychunk_copy_parse_single_chunk() {
        // Build a buffer with 1 chunk
        let mut data = vec![0u8; 32 + 24]; // header + 1 chunk

        // Source key (24 bytes)
        data[0..8].copy_from_slice(&0x1234567890ABCDEFu64.to_le_bytes());

        // Chunk count (4 bytes)
        data[24..28].copy_from_slice(&1u32.to_le_bytes());

        // Reserved (4 bytes)
        data[28..32].copy_from_slice(&0u32.to_le_bytes());

        // Chunk 0
        data[32..40].copy_from_slice(&100u64.to_le_bytes()); // source_offset
        data[40..48].copy_from_slice(&200u64.to_le_bytes()); // target_offset
        data[48..52].copy_from_slice(&1024u32.to_le_bytes()); // length
        data[52..56].copy_from_slice(&0u32.to_le_bytes()); // reserved

        let parsed = SrvCopychunkCopy::parse(&data).unwrap();
        assert_eq!(parsed.chunk_count, 1);
        assert_eq!(parsed.chunks.len(), 1);
        assert_eq!(parsed.chunks[0].source_offset, 100);
        assert_eq!(parsed.chunks[0].target_offset, 200);
        assert_eq!(parsed.chunks[0].length, 1024);
    }

    #[test]
    fn test_copychunk_copy_parse_multiple_chunks() {
        // Build a buffer with 3 chunks
        let mut data = vec![0u8; 32 + 3 * 24]; // header + 3 chunks

        // Chunk count
        data[24..28].copy_from_slice(&3u32.to_le_bytes());

        // Fill chunks
        for i in 0..3 {
            let offset = 32 + i * 24;
            data[offset..offset + 8].copy_from_slice(&((i * 1000) as u64).to_le_bytes());
            data[offset + 8..offset + 16].copy_from_slice(&((i * 2000) as u64).to_le_bytes());
            data[offset + 16..offset + 20].copy_from_slice(&((i + 1) as u32 * 100).to_le_bytes());
        }

        let parsed = SrvCopychunkCopy::parse(&data).unwrap();
        assert_eq!(parsed.chunk_count, 3);
        assert_eq!(parsed.chunks.len(), 3);
        assert_eq!(parsed.chunks[2].source_offset, 2000);
        assert_eq!(parsed.chunks[2].target_offset, 4000);
        assert_eq!(parsed.chunks[2].length, 300);
    }

    #[test]
    fn test_copychunk_copy_parse_buffer_too_small() {
        let data = vec![0u8; 16]; // Too small for header
        assert!(SrvCopychunkCopy::parse(&data).is_err());
    }

    #[test]
    fn test_copychunk_copy_parse_missing_chunks() {
        let mut data = vec![0u8; 32]; // Header only
        data[24..28].copy_from_slice(&2u32.to_le_bytes()); // Says 2 chunks but none present

        assert!(SrvCopychunkCopy::parse(&data).is_err());
    }

    // =========================================================================
    // MS-SMB2 2.2.32.1: SRV_COPYCHUNK_RESPONSE Tests
    // =========================================================================

    #[test]
    fn test_copychunk_response_size() {
        // Per MS-SMB2 2.2.32.1: 4 + 4 + 4 = 12 bytes
        let resp = SrvCopychunkResponse::default();
        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();
        assert_eq!(buf.len(), 12);
    }

    #[test]
    fn test_copychunk_response_roundtrip() {
        let resp = SrvCopychunkResponse {
            chunks_written: 5,
            chunk_bytes_written: 4096,
            total_bytes_written: 20480,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = SrvCopychunkResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.chunks_written, 5);
        assert_eq!(parsed.chunk_bytes_written, 4096);
        assert_eq!(parsed.total_bytes_written, 20480);
    }

    #[test]
    fn test_copychunk_response_with_limits() {
        let resp = SrvCopychunkResponse::with_limits(256, 1048576, 16777216);
        assert_eq!(resp.chunks_written, 256);
        assert_eq!(resp.chunk_bytes_written, 1048576);
        assert_eq!(resp.total_bytes_written, 16777216);
    }
}
