//! SMB2 Transform Header for encrypted messages.
//!
//! The transform header appears before encrypted SMB2 messages (SMB 3.0+).
//! See MS-SMB2 Section 2.2.41.

use binrw::{BinRead, BinWrite};

/// SMB2 Transform header magic bytes (0xFD 'S' 'M' 'B').
pub const SMB2_TRANSFORM_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];

/// SMB2 Transform header size in bytes.
pub const SMB2_TRANSFORM_HEADER_SIZE: usize = 52;

/// SMB2 Transform Header (52 bytes).
///
/// Used for encrypted messages in SMB 3.0+.
/// See MS-SMB2 Section 2.2.41.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little, magic = b"\xFDSMB")]
pub struct Smb2TransformHeader {
    /// Signature (16 bytes) - AES-GMAC for SMB 3.1.1, AES-CMAC for SMB 3.0.
    pub signature: [u8; 16],

    /// Nonce (16 bytes) - AES-GCM nonce (12 bytes used) or AES-CCM nonce (11 bytes used).
    pub nonce: [u8; 16],

    /// Original message size (encrypted data length).
    pub original_message_size: u32,

    /// Reserved (must be 0).
    pub reserved: u16,

    /// Flags/EncryptionAlgorithm.
    /// For SMB 3.0: EncryptionAlgorithm (0x0001 = AES-128-CCM)
    /// For SMB 3.1.1: Flags (0x0001 = Encrypted)
    pub flags: u16,

    /// Session ID of the session that encrypted this message.
    pub session_id: u64,
}

impl Default for Smb2TransformHeader {
    fn default() -> Self {
        Self {
            signature: [0; 16],
            nonce: [0; 16],
            original_message_size: 0,
            reserved: 0,
            flags: 0x0001, // Encrypted
            session_id: 0,
        }
    }
}

impl Smb2TransformHeader {
    /// Create a new transform header for the given session.
    pub fn new(session_id: u64, message_size: u32) -> Self {
        Self {
            session_id,
            original_message_size: message_size,
            ..Default::default()
        }
    }

    /// Set the nonce for encryption.
    pub fn with_nonce(mut self, nonce: [u8; 16]) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set the signature after encryption.
    pub fn with_signature(mut self, signature: [u8; 16]) -> Self {
        self.signature = signature;
        self
    }
}

/// Encryption algorithms for SMB 3.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EncryptionAlgorithm {
    /// AES-128-CCM (SMB 3.0/3.0.2)
    Aes128Ccm = 0x0001,
    /// AES-128-GCM (SMB 3.1.1)
    Aes128Gcm = 0x0002,
    /// AES-256-CCM (SMB 3.1.1)
    Aes256Ccm = 0x0003,
    /// AES-256-GCM (SMB 3.1.1)
    Aes256Gcm = 0x0004,
}

impl EncryptionAlgorithm {
    /// Create from u16 value.
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0x0001 => Self::Aes128Ccm,
            0x0002 => Self::Aes128Gcm,
            0x0003 => Self::Aes256Ccm,
            0x0004 => Self::Aes256Gcm,
            _ => return None,
        })
    }

    /// Get the nonce size in bytes.
    pub fn nonce_size(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes256Ccm => 11,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
        }
    }

    /// Get the key size in bytes.
    pub fn key_size(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes128Gcm => 16,
            Self::Aes256Ccm | Self::Aes256Gcm => 32,
        }
    }

    /// Check if this is a GCM algorithm.
    pub fn is_gcm(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes256Gcm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_transform_header_size() {
        assert_eq!(SMB2_TRANSFORM_HEADER_SIZE, 52);
    }

    #[test]
    fn test_transform_header_roundtrip() {
        let header = Smb2TransformHeader::new(0x123456789ABCDEF0, 1024)
            .with_nonce([1; 16])
            .with_signature([2; 16]);

        let mut buf = Vec::new();
        header.write(&mut Cursor::new(&mut buf)).unwrap();

        assert_eq!(buf.len(), SMB2_TRANSFORM_HEADER_SIZE);
        assert_eq!(&buf[0..4], &SMB2_TRANSFORM_MAGIC);

        let parsed = Smb2TransformHeader::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.session_id, 0x123456789ABCDEF0);
        assert_eq!(parsed.original_message_size, 1024);
        assert_eq!(parsed.nonce, [1; 16]);
        assert_eq!(parsed.signature, [2; 16]);
    }

    #[test]
    fn test_encryption_algorithm() {
        assert_eq!(EncryptionAlgorithm::Aes128Ccm.nonce_size(), 11);
        assert_eq!(EncryptionAlgorithm::Aes128Gcm.nonce_size(), 12);
        assert_eq!(EncryptionAlgorithm::Aes128Ccm.key_size(), 16);
        assert_eq!(EncryptionAlgorithm::Aes256Gcm.key_size(), 32);
        assert!(!EncryptionAlgorithm::Aes128Ccm.is_gcm());
        assert!(EncryptionAlgorithm::Aes128Gcm.is_gcm());
    }
}
