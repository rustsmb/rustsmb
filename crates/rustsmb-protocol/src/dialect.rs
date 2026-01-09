//! SMB2 dialect negotiation helpers.
//!
//! This module provides utilities for negotiating SMB2/3 dialects
//! and handling negotiate contexts (SMB 3.1.1).

use binrw::{BinRead, BinWrite};
use rustsmb_core::SmbDialect;

use crate::commands::negotiate::{Capabilities, NegotiateResponse, SecurityMode};
use crate::crypto::signing::SigningAlgorithm;
use crate::transform::EncryptionAlgorithm;

/// Negotiate context types (SMB 3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NegotiateContextType {
    /// Pre-authentication integrity capabilities.
    PreauthIntegrityCaps = 0x0001,
    /// Encryption capabilities.
    EncryptionCaps = 0x0002,
    /// Compression capabilities.
    CompressionCaps = 0x0003,
    /// Netname negotiate context ID.
    NetnamNegotiateContextId = 0x0005,
    /// Transport capabilities.
    TransportCaps = 0x0006,
    /// RDMA transform capabilities.
    RdmaTransformCaps = 0x0007,
    /// Signing capabilities.
    SigningCaps = 0x0008,
}

impl NegotiateContextType {
    /// Create from u16.
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0x0001 => Self::PreauthIntegrityCaps,
            0x0002 => Self::EncryptionCaps,
            0x0003 => Self::CompressionCaps,
            0x0005 => Self::NetnamNegotiateContextId,
            0x0006 => Self::TransportCaps,
            0x0007 => Self::RdmaTransformCaps,
            0x0008 => Self::SigningCaps,
            _ => return None,
        })
    }
}

/// Negotiate context header.
#[derive(Debug, Clone, BinRead, BinWrite)]
#[brw(little)]
pub struct NegotiateContextHeader {
    /// Context type.
    pub context_type: u16,
    /// Data length.
    pub data_length: u16,
    /// Reserved.
    pub reserved: u32,
}

/// Pre-authentication integrity hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HashAlgorithm {
    /// SHA-512.
    Sha512 = 0x0001,
}

impl HashAlgorithm {
    /// Create from u16.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Negotiate context for pre-authentication integrity.
#[derive(Debug, Clone)]
pub struct PreauthIntegrityContext {
    /// Hash algorithms (client offers, server selects).
    pub hash_algorithms: Vec<HashAlgorithm>,
    /// Salt value.
    pub salt: Vec<u8>,
}

impl Default for PreauthIntegrityContext {
    fn default() -> Self {
        Self {
            hash_algorithms: vec![HashAlgorithm::Sha512],
            salt: vec![0u8; 32], // 32-byte salt
        }
    }
}

/// Negotiate context for encryption capabilities.
#[derive(Debug, Clone)]
pub struct EncryptionContext {
    /// Encryption algorithms (client offers, server selects).
    pub ciphers: Vec<EncryptionAlgorithm>,
}

impl Default for EncryptionContext {
    fn default() -> Self {
        Self {
            ciphers: vec![
                EncryptionAlgorithm::Aes128Gcm,
                EncryptionAlgorithm::Aes128Ccm,
            ],
        }
    }
}

/// Negotiate context for signing capabilities.
#[derive(Debug, Clone)]
pub struct SigningContext {
    /// Signing algorithms (client offers, server selects).
    pub algorithms: Vec<SigningAlgorithm>,
}

impl Default for SigningContext {
    fn default() -> Self {
        Self {
            algorithms: vec![SigningAlgorithm::AesGmac, SigningAlgorithm::AesCmac],
        }
    }
}

/// Generic negotiate context.
#[derive(Debug, Clone)]
pub enum NegotiateContext {
    /// Pre-authentication integrity.
    PreauthIntegrity(PreauthIntegrityContext),
    /// Encryption capabilities.
    Encryption(EncryptionContext),
    /// Signing capabilities.
    Signing(SigningContext),
    /// Unknown context (preserved for round-trip).
    Unknown { context_type: u16, data: Vec<u8> },
}

/// Dialect negotiation result.
#[derive(Debug, Clone)]
pub struct NegotiationResult {
    /// Selected dialect.
    pub dialect: SmbDialect,
    /// Server GUID.
    pub server_guid: [u8; 16],
    /// Selected capabilities.
    pub capabilities: Capabilities,
    /// Security mode.
    pub security_mode: SecurityMode,
    /// Maximum transaction size.
    pub max_transact_size: u32,
    /// Maximum read size.
    pub max_read_size: u32,
    /// Maximum write size.
    pub max_write_size: u32,
    /// Selected hash algorithm (SMB 3.1.1).
    pub hash_algorithm: Option<HashAlgorithm>,
    /// Selected encryption algorithm.
    pub encryption_algorithm: Option<EncryptionAlgorithm>,
    /// Selected signing algorithm.
    pub signing_algorithm: Option<SigningAlgorithm>,
    /// Pre-auth integrity hash value (SMB 3.1.1).
    pub preauth_integrity_hash: Option<Vec<u8>>,
}

/// Dialect negotiator for server-side negotiation.
pub struct DialectNegotiator {
    /// Supported dialects (in preference order, highest first).
    supported_dialects: Vec<SmbDialect>,
    /// Server GUID.
    server_guid: [u8; 16],
    /// Server capabilities.
    capabilities: Capabilities,
    /// Security mode.
    security_mode: SecurityMode,
    /// Maximum transaction size.
    max_transact_size: u32,
    /// Maximum read size.
    max_read_size: u32,
    /// Maximum write size.
    max_write_size: u32,
    /// Require signing.
    require_signing: bool,
    /// Require encryption.
    require_encryption: bool,
}

impl Default for DialectNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl DialectNegotiator {
    /// Create a new dialect negotiator with default settings.
    pub fn new() -> Self {
        Self {
            supported_dialects: vec![
                SmbDialect::Smb311,
                SmbDialect::Smb302,
                SmbDialect::Smb300,
                SmbDialect::Smb210,
                SmbDialect::Smb202,
            ],
            server_guid: [0; 16],
            capabilities: Capabilities::new(
                Capabilities::LEASING
                    | Capabilities::LARGE_MTU
                    | Capabilities::MULTI_CREDIT
                    | Capabilities::DIRECTORY_LEASING,
            ),
            security_mode: SecurityMode::new(SecurityMode::SIGNING_ENABLED),
            max_transact_size: 8 * 1024 * 1024,
            max_read_size: 8 * 1024 * 1024,
            max_write_size: 8 * 1024 * 1024,
            require_signing: false,
            require_encryption: false,
        }
    }

    /// Set the server GUID.
    pub fn with_server_guid(mut self, guid: [u8; 16]) -> Self {
        self.server_guid = guid;
        self
    }

    /// Set supported dialects.
    pub fn with_dialects(mut self, dialects: Vec<SmbDialect>) -> Self {
        self.supported_dialects = dialects;
        self
    }

    /// Set server capabilities.
    pub fn with_capabilities(mut self, caps: Capabilities) -> Self {
        self.capabilities = caps;
        self
    }

    /// Set whether signing is required.
    pub fn with_signing_required(mut self, required: bool) -> Self {
        self.require_signing = required;
        if required {
            self.security_mode =
                SecurityMode::new(SecurityMode::SIGNING_ENABLED | SecurityMode::SIGNING_REQUIRED);
        }
        self
    }

    /// Set whether encryption is required.
    pub fn with_encryption_required(mut self, required: bool) -> Self {
        self.require_encryption = required;
        if required {
            self.capabilities = Capabilities::new(self.capabilities.0 | Capabilities::ENCRYPTION);
        }
        self
    }

    /// Set maximum sizes.
    pub fn with_max_sizes(mut self, transact: u32, read: u32, write: u32) -> Self {
        self.max_transact_size = transact;
        self.max_read_size = read;
        self.max_write_size = write;
        self
    }

    /// Select the best dialect from client's offered dialects.
    pub fn select_dialect(&self, client_dialects: &[u16]) -> Option<SmbDialect> {
        // Find the highest common dialect
        self.supported_dialects
            .iter()
            .find(|&&dialect| client_dialects.contains(&dialect.revision()))
            .copied()
    }

    /// Build a negotiate response for the given request.
    pub fn negotiate(&self, client_dialects: &[u16]) -> Option<NegotiateResponse> {
        let dialect = self.select_dialect(client_dialects)?;

        Some(NegotiateResponse {
            structure_size: 65,
            security_mode: self.security_mode,
            dialect_revision: dialect.revision(),
            negotiate_context_count: 0,
            server_guid: self.server_guid,
            capabilities: self.capabilities,
            max_transact_size: self.max_transact_size,
            max_read_size: self.max_read_size,
            max_write_size: self.max_write_size,
            system_time: current_filetime(),
            server_start_time: 0,
            security_buffer_offset: 0,
            security_buffer_length: 0,
            negotiate_context_offset: 0,
        })
    }

    /// Check if a dialect supports encryption.
    pub fn dialect_supports_encryption(dialect: SmbDialect) -> bool {
        dialect.supports_encryption()
    }

    /// Check if a dialect requires pre-auth integrity.
    pub fn dialect_requires_preauth(dialect: SmbDialect) -> bool {
        dialect.requires_preauth_integrity()
    }
}

/// Convert SystemTime to Windows FILETIME (100-nanosecond intervals since 1601-01-01).
fn current_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Difference between Windows epoch (1601) and Unix epoch (1970) in 100-ns intervals
    const EPOCH_DIFF: u64 = 116444736000000000;

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let nanos = duration.as_nanos() as u64;
            let intervals = nanos / 100;
            intervals + EPOCH_DIFF
        }
        Err(_) => 0,
    }
}

/// Parse dialects from a negotiate request buffer.
pub fn parse_dialects(buffer: &[u8], count: u16) -> Vec<u16> {
    let mut dialects = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let offset = i * 2;
        if offset + 2 <= buffer.len() {
            let dialect = u16::from_le_bytes([buffer[offset], buffer[offset + 1]]);
            dialects.push(dialect);
        }
    }
    dialects
}

/// Check if a dialect list includes SMB 3.1.1.
pub fn has_smb311(dialects: &[u16]) -> bool {
    dialects.contains(&SmbDialect::Smb311.revision())
}

/// Get the highest dialect from a list.
pub fn highest_dialect(dialects: &[u16]) -> Option<SmbDialect> {
    dialects
        .iter()
        .filter_map(|&d| SmbDialect::from_revision(d))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_context_types() {
        assert_eq!(NegotiateContextType::PreauthIntegrityCaps as u16, 0x0001);
        assert_eq!(NegotiateContextType::EncryptionCaps as u16, 0x0002);
        assert_eq!(NegotiateContextType::SigningCaps as u16, 0x0008);
        assert_eq!(
            NegotiateContextType::from_u16(0x0001),
            Some(NegotiateContextType::PreauthIntegrityCaps)
        );
    }

    #[test]
    fn test_dialect_selection() {
        let negotiator = DialectNegotiator::new();

        // Client offers all dialects
        let client = vec![0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
        assert_eq!(negotiator.select_dialect(&client), Some(SmbDialect::Smb311));

        // Client only offers older dialects
        let client = vec![0x0202, 0x0210];
        assert_eq!(negotiator.select_dialect(&client), Some(SmbDialect::Smb210));

        // No common dialect
        let negotiator = DialectNegotiator::new().with_dialects(vec![SmbDialect::Smb311]);
        let client = vec![0x0202];
        assert_eq!(negotiator.select_dialect(&client), None);
    }

    #[test]
    fn test_parse_dialects() {
        let buffer = [0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03];
        let dialects = parse_dialects(&buffer, 5);
        assert_eq!(dialects, vec![0x0202, 0x0210, 0x0300, 0x0302, 0x0311]);
    }

    #[test]
    fn test_has_smb311() {
        assert!(has_smb311(&[0x0202, 0x0311]));
        assert!(!has_smb311(&[0x0202, 0x0302]));
    }

    #[test]
    fn test_highest_dialect() {
        assert_eq!(
            highest_dialect(&[0x0202, 0x0311, 0x0300]),
            Some(SmbDialect::Smb311)
        );
        assert_eq!(
            highest_dialect(&[0x0202, 0x0210]),
            Some(SmbDialect::Smb210)
        );
        assert_eq!(highest_dialect(&[0x1234]), None);
    }

    #[test]
    fn test_negotiate_response() {
        let mut guid = [0u8; 16];
        guid[0] = 0x12;

        let negotiator = DialectNegotiator::new()
            .with_server_guid(guid)
            .with_signing_required(true);

        let client = vec![0x0311, 0x0302, 0x0300];
        let response = negotiator.negotiate(&client).unwrap();

        assert_eq!(response.dialect_revision, SmbDialect::Smb311.revision());
        assert_eq!(response.server_guid[0], 0x12);
        assert!(response.security_mode.signing_required());
    }

    #[test]
    fn test_dialect_capabilities() {
        assert!(DialectNegotiator::dialect_supports_encryption(
            SmbDialect::Smb300
        ));
        assert!(!DialectNegotiator::dialect_supports_encryption(
            SmbDialect::Smb210
        ));
        assert!(DialectNegotiator::dialect_requires_preauth(
            SmbDialect::Smb311
        ));
        assert!(!DialectNegotiator::dialect_requires_preauth(
            SmbDialect::Smb302
        ));
    }
}
