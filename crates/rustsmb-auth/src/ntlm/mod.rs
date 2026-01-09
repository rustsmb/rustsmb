//! NTLM authentication implementation.
//!
//! This module implements NTLMv2 authentication as specified in MS-NLMP.
//!
//! # Protocol Flow
//!
//! 1. Client sends NEGOTIATE_MESSAGE
//! 2. Server responds with CHALLENGE_MESSAGE
//! 3. Client sends AUTHENTICATE_MESSAGE with NTLMv2 response
//! 4. Server validates and generates session key

mod crypto;
mod messages;
mod provider;

pub use crypto::*;
pub use messages::*;
pub use provider::*;

/// NTLM signature (8 bytes).
pub const NTLM_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLM message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NtlmMessageType {
    /// NEGOTIATE_MESSAGE (Type 1)
    Negotiate = 1,
    /// CHALLENGE_MESSAGE (Type 2)
    Challenge = 2,
    /// AUTHENTICATE_MESSAGE (Type 3)
    Authenticate = 3,
}

impl TryFrom<u32> for NtlmMessageType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Negotiate),
            2 => Ok(Self::Challenge),
            3 => Ok(Self::Authenticate),
            _ => Err(()),
        }
    }
}

/// NTLM negotiate flags (MS-NLMP section 2.2.2.5).
#[derive(Debug, Clone, Copy, Default)]
pub struct NtlmFlags(pub u32);

impl NtlmFlags {
    // Capability flags
    pub const NEGOTIATE_56: u32 = 0x80000000;
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x40000000;
    pub const NEGOTIATE_128: u32 = 0x20000000;
    pub const NEGOTIATE_VERSION: u32 = 0x02000000;
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x00800000;
    pub const REQUEST_NON_NT_SESSION_KEY: u32 = 0x00400000;
    pub const NEGOTIATE_IDENTIFY: u32 = 0x00100000;
    pub const NEGOTIATE_EXTENDED_SESSION_SECURITY: u32 = 0x00080000;
    pub const TARGET_TYPE_SERVER: u32 = 0x00020000;
    pub const TARGET_TYPE_DOMAIN: u32 = 0x00010000;
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;
    pub const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x00002000;
    pub const NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x00001000;
    pub const NEGOTIATE_ANONYMOUS: u32 = 0x00000800;
    pub const NEGOTIATE_NTLM: u32 = 0x00000200;
    pub const NEGOTIATE_LM_KEY: u32 = 0x00000080;
    pub const NEGOTIATE_DATAGRAM: u32 = 0x00000040;
    pub const NEGOTIATE_SEAL: u32 = 0x00000020;
    pub const NEGOTIATE_SIGN: u32 = 0x00000010;
    pub const REQUEST_TARGET: u32 = 0x00000004;
    pub const NEGOTIATE_OEM: u32 = 0x00000002;
    pub const NEGOTIATE_UNICODE: u32 = 0x00000001;

    /// Default flags for server.
    pub fn server_default() -> Self {
        Self(
            Self::NEGOTIATE_UNICODE
                | Self::NEGOTIATE_NTLM
                | Self::NEGOTIATE_EXTENDED_SESSION_SECURITY
                | Self::NEGOTIATE_TARGET_INFO
                | Self::TARGET_TYPE_SERVER
                | Self::NEGOTIATE_128
                | Self::NEGOTIATE_56
                | Self::NEGOTIATE_KEY_EXCH
                | Self::REQUEST_TARGET,
        )
    }

    /// Check if a flag is set.
    #[inline]
    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    /// Set a flag.
    #[inline]
    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clear a flag.
    #[inline]
    pub fn clear(&mut self, flag: u32) {
        self.0 &= !flag;
    }
}

/// AV_PAIR types for target info (MS-NLMP section 2.2.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AvId {
    /// End of list.
    MsvAvEOL = 0,
    /// NetBIOS computer name.
    MsvAvNbComputerName = 1,
    /// NetBIOS domain name.
    MsvAvNbDomainName = 2,
    /// DNS computer name.
    MsvAvDnsComputerName = 3,
    /// DNS domain name.
    MsvAvDnsDomainName = 4,
    /// DNS tree name.
    MsvAvDnsTreeName = 5,
    /// Flags.
    MsvAvFlags = 6,
    /// Timestamp.
    MsvAvTimestamp = 7,
    /// Single host data.
    MsvAvSingleHost = 8,
    /// Target name.
    MsvAvTargetName = 9,
    /// Channel bindings.
    MsvAvChannelBindings = 10,
}

impl TryFrom<u16> for AvId {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MsvAvEOL),
            1 => Ok(Self::MsvAvNbComputerName),
            2 => Ok(Self::MsvAvNbDomainName),
            3 => Ok(Self::MsvAvDnsComputerName),
            4 => Ok(Self::MsvAvDnsDomainName),
            5 => Ok(Self::MsvAvDnsTreeName),
            6 => Ok(Self::MsvAvFlags),
            7 => Ok(Self::MsvAvTimestamp),
            8 => Ok(Self::MsvAvSingleHost),
            9 => Ok(Self::MsvAvTargetName),
            10 => Ok(Self::MsvAvChannelBindings),
            _ => Err(()),
        }
    }
}

/// AV_PAIR for target info.
#[derive(Debug, Clone)]
pub struct AvPair {
    pub id: u16,
    pub value: Vec<u8>,
}

impl AvPair {
    /// Create a new AV_PAIR.
    pub fn new(id: AvId, value: Vec<u8>) -> Self {
        Self {
            id: id as u16,
            value,
        }
    }

    /// Create a string AV_PAIR (UTF-16LE encoded).
    pub fn string(id: AvId, s: &str) -> Self {
        let value: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        Self::new(id, value)
    }

    /// Create a timestamp AV_PAIR.
    pub fn timestamp(filetime: u64) -> Self {
        Self::new(AvId::MsvAvTimestamp, filetime.to_le_bytes().to_vec())
    }

    /// Create end-of-list marker.
    pub fn eol() -> Self {
        Self {
            id: AvId::MsvAvEOL as u16,
            value: Vec::new(),
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.value.len());
        buf.extend_from_slice(&self.id.to_le_bytes());
        buf.extend_from_slice(&(self.value.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.value);
        buf
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let id = u16::from_le_bytes([data[0], data[1]]);
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        let value = data[4..4 + len].to_vec();
        Some((Self { id, value }, 4 + len))
    }
}

/// Build target info blob.
pub fn build_target_info(
    nb_domain: &str,
    nb_computer: &str,
    dns_domain: &str,
    dns_computer: &str,
    timestamp: u64,
) -> Vec<u8> {
    let pairs = vec![
        AvPair::string(AvId::MsvAvNbDomainName, nb_domain),
        AvPair::string(AvId::MsvAvNbComputerName, nb_computer),
        AvPair::string(AvId::MsvAvDnsDomainName, dns_domain),
        AvPair::string(AvId::MsvAvDnsComputerName, dns_computer),
        AvPair::timestamp(timestamp),
        AvPair::eol(),
    ];

    let mut buf = Vec::new();
    for pair in pairs {
        buf.extend_from_slice(&pair.to_bytes());
    }
    buf
}

/// Parse target info blob.
pub fn parse_target_info(data: &[u8]) -> Vec<AvPair> {
    let mut pairs = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        if let Some((pair, len)) = AvPair::parse(&data[offset..]) {
            let is_eol = pair.id == AvId::MsvAvEOL as u16;
            pairs.push(pair);
            if is_eol {
                break;
            }
            offset += len;
        } else {
            break;
        }
    }

    pairs
}

/// Get current time as Windows FILETIME.
pub fn current_filetime() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    // FILETIME is 100-nanosecond intervals since January 1, 1601
    // Unix epoch is January 1, 1970
    // Difference is 11644473600 seconds
    const EPOCH_DIFF: u64 = 11644473600;

    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    (unix_time + EPOCH_DIFF) * 10_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_flags() {
        let mut flags = NtlmFlags::server_default();
        assert!(flags.has(NtlmFlags::NEGOTIATE_UNICODE));
        assert!(flags.has(NtlmFlags::NEGOTIATE_NTLM));
        assert!(flags.has(NtlmFlags::NEGOTIATE_EXTENDED_SESSION_SECURITY));

        flags.clear(NtlmFlags::NEGOTIATE_UNICODE);
        assert!(!flags.has(NtlmFlags::NEGOTIATE_UNICODE));

        flags.set(NtlmFlags::NEGOTIATE_UNICODE);
        assert!(flags.has(NtlmFlags::NEGOTIATE_UNICODE));
    }

    #[test]
    fn test_av_pair() {
        let pair = AvPair::string(AvId::MsvAvNbComputerName, "SERVER");
        let bytes = pair.to_bytes();

        let (parsed, len) = AvPair::parse(&bytes).unwrap();
        assert_eq!(parsed.id, AvId::MsvAvNbComputerName as u16);
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn test_target_info() {
        let info = build_target_info("DOMAIN", "SERVER", "domain.local", "server.domain.local", 0);
        let pairs = parse_target_info(&info);

        assert!(!pairs.is_empty());
        assert_eq!(pairs.last().unwrap().id, AvId::MsvAvEOL as u16);
    }

    #[test]
    fn test_message_type() {
        assert_eq!(NtlmMessageType::try_from(1), Ok(NtlmMessageType::Negotiate));
        assert_eq!(NtlmMessageType::try_from(2), Ok(NtlmMessageType::Challenge));
        assert_eq!(
            NtlmMessageType::try_from(3),
            Ok(NtlmMessageType::Authenticate)
        );
        assert!(NtlmMessageType::try_from(4).is_err());
    }
}
