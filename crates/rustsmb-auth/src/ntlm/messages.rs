//! NTLM message structures and parsing.
//!
//! Implements NEGOTIATE, CHALLENGE, and AUTHENTICATE messages.

use super::{NtlmFlags, NtlmMessageType, NTLM_SIGNATURE};

/// NTLM NEGOTIATE_MESSAGE (Type 1).
#[derive(Debug, Clone)]
pub struct NegotiateMessage {
    /// Negotiate flags.
    pub flags: NtlmFlags,
    /// Domain name (optional).
    pub domain_name: Option<String>,
    /// Workstation name (optional).
    pub workstation: Option<String>,
    /// Version (optional).
    pub version: Option<NtlmVersion>,
}

impl NegotiateMessage {
    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }

        // Check signature
        if &data[..8] != NTLM_SIGNATURE {
            return None;
        }

        // Check message type
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if msg_type != NtlmMessageType::Negotiate as u32 {
            return None;
        }

        let flags = NtlmFlags(u32::from_le_bytes([data[12], data[13], data[14], data[15]]));

        // Domain name security buffer (offset 16)
        let domain_len = u16::from_le_bytes([data[16], data[17]]) as usize;
        let domain_offset = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
        let domain_name = if domain_len > 0 && domain_offset + domain_len <= data.len() {
            parse_string(&data[domain_offset..domain_offset + domain_len], flags.0)
        } else {
            None
        };

        // Workstation security buffer (offset 24)
        let ws_len = u16::from_le_bytes([data[24], data[25]]) as usize;
        let ws_offset = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
        let workstation = if ws_len > 0 && ws_offset + ws_len <= data.len() {
            parse_string(&data[ws_offset..ws_offset + ws_len], flags.0)
        } else {
            None
        };

        // Version (if NEGOTIATE_VERSION flag is set)
        let version = if flags.has(NtlmFlags::NEGOTIATE_VERSION) && data.len() >= 40 {
            NtlmVersion::parse(&data[32..40])
        } else {
            None
        };

        Some(Self {
            flags,
            domain_name,
            workstation,
            version,
        })
    }

    /// Build negotiate message bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);

        // Signature
        buf.extend_from_slice(NTLM_SIGNATURE);
        // Message type
        buf.extend_from_slice(&(NtlmMessageType::Negotiate as u32).to_le_bytes());
        // Flags
        buf.extend_from_slice(&self.flags.0.to_le_bytes());

        // Domain name security buffer (empty for now)
        buf.extend_from_slice(&[0u8; 8]);
        // Workstation security buffer (empty for now)
        buf.extend_from_slice(&[0u8; 8]);

        // Version (optional)
        if self.flags.has(NtlmFlags::NEGOTIATE_VERSION) {
            if let Some(ref ver) = self.version {
                buf.extend_from_slice(&ver.to_bytes());
            } else {
                buf.extend_from_slice(&[0u8; 8]);
            }
        }

        buf
    }
}

impl Default for NegotiateMessage {
    fn default() -> Self {
        Self {
            flags: NtlmFlags::server_default(),
            domain_name: None,
            workstation: None,
            version: None,
        }
    }
}

/// NTLM CHALLENGE_MESSAGE (Type 2).
#[derive(Debug, Clone)]
pub struct ChallengeMessage {
    /// Target name.
    pub target_name: String,
    /// Negotiate flags.
    pub flags: NtlmFlags,
    /// Server challenge (8 bytes).
    pub server_challenge: [u8; 8],
    /// Target info.
    pub target_info: Vec<u8>,
    /// Version (optional).
    pub version: Option<NtlmVersion>,
}

impl ChallengeMessage {
    /// Create a new challenge message.
    pub fn new(
        target_name: &str,
        server_challenge: [u8; 8],
        target_info: Vec<u8>,
        flags: NtlmFlags,
    ) -> Self {
        Self {
            target_name: target_name.to_string(),
            flags,
            server_challenge,
            target_info,
            version: Some(NtlmVersion::current()),
        }
    }

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 56 {
            return None;
        }

        // Check signature
        if &data[..8] != NTLM_SIGNATURE {
            return None;
        }

        // Check message type
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if msg_type != NtlmMessageType::Challenge as u32 {
            return None;
        }

        // Target name security buffer (offset 12)
        let target_len = u16::from_le_bytes([data[12], data[13]]) as usize;
        let target_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let flags = NtlmFlags(u32::from_le_bytes([data[20], data[21], data[22], data[23]]));

        // Server challenge (offset 24, 8 bytes)
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(&data[24..32]);

        // Reserved (offset 32, 8 bytes)

        // Target info security buffer (offset 40)
        let info_len = u16::from_le_bytes([data[40], data[41]]) as usize;
        let info_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;

        // Version (offset 48, 8 bytes)
        let version = if flags.has(NtlmFlags::NEGOTIATE_VERSION) && data.len() >= 56 {
            NtlmVersion::parse(&data[48..56])
        } else {
            None
        };

        let target_name = if target_len > 0 && target_offset + target_len <= data.len() {
            parse_string(&data[target_offset..target_offset + target_len], flags.0)
                .unwrap_or_default()
        } else {
            String::new()
        };

        let target_info = if info_len > 0 && info_offset + info_len <= data.len() {
            data[info_offset..info_offset + info_len].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            target_name,
            flags,
            server_challenge,
            target_info,
            version,
        })
    }

    /// Build challenge message bytes.
    pub fn build(&self) -> Vec<u8> {
        // Calculate sizes
        let target_name_bytes = encode_string(&self.target_name, self.flags.0);
        let target_name_len = target_name_bytes.len();
        let target_info_len = self.target_info.len();

        // Base size is 56 bytes
        let payload_offset = 56;
        let target_name_offset = payload_offset;
        let target_info_offset = target_name_offset + target_name_len;

        let mut buf = Vec::with_capacity(payload_offset + target_name_len + target_info_len);

        // Signature
        buf.extend_from_slice(NTLM_SIGNATURE);
        // Message type
        buf.extend_from_slice(&(NtlmMessageType::Challenge as u32).to_le_bytes());

        // Target name security buffer
        buf.extend_from_slice(&(target_name_len as u16).to_le_bytes());
        buf.extend_from_slice(&(target_name_len as u16).to_le_bytes());
        buf.extend_from_slice(&(target_name_offset as u32).to_le_bytes());

        // Negotiate flags
        buf.extend_from_slice(&self.flags.0.to_le_bytes());

        // Server challenge
        buf.extend_from_slice(&self.server_challenge);

        // Reserved
        buf.extend_from_slice(&[0u8; 8]);

        // Target info security buffer
        buf.extend_from_slice(&(target_info_len as u16).to_le_bytes());
        buf.extend_from_slice(&(target_info_len as u16).to_le_bytes());
        buf.extend_from_slice(&(target_info_offset as u32).to_le_bytes());

        // Version
        if let Some(ref ver) = self.version {
            buf.extend_from_slice(&ver.to_bytes());
        } else {
            buf.extend_from_slice(&[0u8; 8]);
        }

        // Payload
        buf.extend_from_slice(&target_name_bytes);
        buf.extend_from_slice(&self.target_info);

        buf
    }
}

/// NTLM AUTHENTICATE_MESSAGE (Type 3).
#[derive(Debug, Clone)]
pub struct AuthenticateMessage {
    /// LM response.
    pub lm_response: Vec<u8>,
    /// NT response.
    pub nt_response: Vec<u8>,
    /// Domain name.
    pub domain_name: String,
    /// User name.
    pub user_name: String,
    /// Workstation name.
    pub workstation: String,
    /// Encrypted random session key.
    pub encrypted_session_key: Vec<u8>,
    /// Negotiate flags.
    pub flags: NtlmFlags,
    /// Version (optional).
    pub version: Option<NtlmVersion>,
    /// MIC (message integrity code).
    pub mic: Option<[u8; 16]>,
}

impl AuthenticateMessage {
    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Minimum header without Version or MIC is 64 bytes.
        if data.len() < 64 {
            return None;
        }

        // Check signature
        if &data[..8] != NTLM_SIGNATURE {
            return None;
        }

        // Check message type
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if msg_type != NtlmMessageType::Authenticate as u32 {
            return None;
        }

        // LM response (offset 12)
        let lm_len = u16::from_le_bytes([data[12], data[13]]) as usize;
        let lm_offset = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        // NT response (offset 20)
        let nt_len = u16::from_le_bytes([data[20], data[21]]) as usize;
        let nt_offset = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;

        // Domain name (offset 28)
        let domain_len = u16::from_le_bytes([data[28], data[29]]) as usize;
        let domain_offset = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;

        // User name (offset 36)
        let user_len = u16::from_le_bytes([data[36], data[37]]) as usize;
        let user_offset = u32::from_le_bytes([data[40], data[41], data[42], data[43]]) as usize;

        // Workstation (offset 44)
        let ws_len = u16::from_le_bytes([data[44], data[45]]) as usize;
        let ws_offset = u32::from_le_bytes([data[48], data[49], data[50], data[51]]) as usize;

        // Encrypted session key (offset 52)
        let esk_len = u16::from_le_bytes([data[52], data[53]]) as usize;
        let esk_offset = u32::from_le_bytes([data[56], data[57], data[58], data[59]]) as usize;

        // Flags (offset 60)
        let flags = NtlmFlags(u32::from_le_bytes([data[60], data[61], data[62], data[63]]));

        // Version (offset 64)
        let version = if flags.has(NtlmFlags::NEGOTIATE_VERSION) && data.len() >= 72 {
            NtlmVersion::parse(&data[64..72])
        } else {
            None
        };

        // MIC (offset 72, 16 bytes) - only if present
        let mic = if data.len() >= 88 {
            let mut m = [0u8; 16];
            m.copy_from_slice(&data[72..88]);
            // Check if it's all zeros (no MIC)
            if m.iter().all(|&b| b == 0) {
                None
            } else {
                Some(m)
            }
        } else {
            None
        };

        // Extract payload fields
        let lm_response = if lm_len > 0 && lm_offset + lm_len <= data.len() {
            data[lm_offset..lm_offset + lm_len].to_vec()
        } else {
            Vec::new()
        };

        let nt_response = if nt_len > 0 && nt_offset + nt_len <= data.len() {
            data[nt_offset..nt_offset + nt_len].to_vec()
        } else {
            Vec::new()
        };

        let domain_name = if domain_len > 0 && domain_offset + domain_len <= data.len() {
            parse_string(&data[domain_offset..domain_offset + domain_len], flags.0)
                .unwrap_or_default()
        } else {
            String::new()
        };

        let user_name = if user_len > 0 && user_offset + user_len <= data.len() {
            parse_string(&data[user_offset..user_offset + user_len], flags.0).unwrap_or_default()
        } else {
            String::new()
        };

        let workstation = if ws_len > 0 && ws_offset + ws_len <= data.len() {
            parse_string(&data[ws_offset..ws_offset + ws_len], flags.0).unwrap_or_default()
        } else {
            String::new()
        };

        let encrypted_session_key = if esk_len > 0 && esk_offset + esk_len <= data.len() {
            data[esk_offset..esk_offset + esk_len].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            lm_response,
            nt_response,
            domain_name,
            user_name,
            workstation,
            encrypted_session_key,
            flags,
            version,
            mic,
        })
    }

    /// Check if this is an anonymous login attempt.
    pub fn is_anonymous(&self) -> bool {
        self.user_name.is_empty() && self.lm_response.is_empty() && self.nt_response.is_empty()
    }
}

/// NTLM version structure.
#[derive(Debug, Clone, Copy)]
pub struct NtlmVersion {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Build number.
    pub build: u16,
    /// NTLM revision.
    pub ntlm_revision: u8,
}

impl NtlmVersion {
    /// Current version (Windows 10/Server 2016 style).
    pub fn current() -> Self {
        Self {
            major: 10,
            minor: 0,
            build: 19041,
            ntlm_revision: 15,
        }
    }

    /// Parse from 8 bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            major: data[0],
            minor: data[1],
            build: u16::from_le_bytes([data[2], data[3]]),
            ntlm_revision: data[7],
        })
    }

    /// Serialize to 8 bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = self.major;
        buf[1] = self.minor;
        buf[2..4].copy_from_slice(&self.build.to_le_bytes());
        // bytes 4-6 are reserved
        buf[7] = self.ntlm_revision;
        buf
    }
}

/// Parse string from NTLM message (handles Unicode/OEM).
fn parse_string(data: &[u8], flags: u32) -> Option<String> {
    if flags & NtlmFlags::NEGOTIATE_UNICODE != 0 {
        // UTF-16LE
        if data.len() % 2 != 0 {
            return None;
        }
        let u16_vec: Vec<u16> = data
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&u16_vec).ok()
    } else {
        // OEM (ASCII)
        String::from_utf8(data.to_vec()).ok()
    }
}

/// Encode string for NTLM message.
fn encode_string(s: &str, flags: u32) -> Vec<u8> {
    if flags & NtlmFlags::NEGOTIATE_UNICODE != 0 {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    } else {
        s.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_message_build_parse() {
        let msg = NegotiateMessage::default();
        let bytes = msg.build();

        let parsed = NegotiateMessage::parse(&bytes).unwrap();
        assert!(parsed.flags.has(NtlmFlags::NEGOTIATE_UNICODE));
        assert!(parsed.flags.has(NtlmFlags::NEGOTIATE_NTLM));
    }

    #[test]
    fn test_challenge_message_build_parse() {
        let target_info = super::super::build_target_info(
            "DOMAIN",
            "SERVER",
            "domain.local",
            "server.domain.local",
            super::super::current_filetime(),
        );

        let msg = ChallengeMessage::new(
            "SERVER",
            [1, 2, 3, 4, 5, 6, 7, 8],
            target_info,
            NtlmFlags::server_default(),
        );

        let bytes = msg.build();
        let parsed = ChallengeMessage::parse(&bytes).unwrap();

        assert_eq!(parsed.target_name, "SERVER");
        assert_eq!(parsed.server_challenge, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(!parsed.target_info.is_empty());
    }

    #[test]
    fn test_version() {
        let ver = NtlmVersion::current();
        let bytes = ver.to_bytes();
        let parsed = NtlmVersion::parse(&bytes).unwrap();

        assert_eq!(parsed.major, ver.major);
        assert_eq!(parsed.minor, ver.minor);
        assert_eq!(parsed.build, ver.build);
    }

    #[test]
    fn test_authenticate_parse_minimal_no_version_or_mic() {
        let mut buf = vec![0u8; 64];
        buf[..8].copy_from_slice(NTLM_SIGNATURE);
        buf[8..12].copy_from_slice(&(NtlmMessageType::Authenticate as u32).to_le_bytes());

        let parsed = AuthenticateMessage::parse(&buf);
        assert!(parsed.is_some());
    }

    #[test]
    fn test_authenticate_parse_with_version_without_mic() {
        let mut buf = vec![0u8; 72];
        buf[..8].copy_from_slice(NTLM_SIGNATURE);
        buf[8..12].copy_from_slice(&(NtlmMessageType::Authenticate as u32).to_le_bytes());

        // Include NEGOTIATE_VERSION flag so version bytes are parsed.
        let flags = NtlmFlags::NEGOTIATE_VERSION;
        buf[60..64].copy_from_slice(&flags.to_le_bytes());
        buf[64..72].copy_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);

        let parsed = AuthenticateMessage::parse(&buf).unwrap();
        assert!(parsed.version.is_some());
        assert!(parsed.mic.is_none());
    }

    #[test]
    fn test_string_encoding() {
        let s = "TestString";

        // Unicode
        let unicode = encode_string(s, NtlmFlags::NEGOTIATE_UNICODE);
        let parsed = parse_string(&unicode, NtlmFlags::NEGOTIATE_UNICODE).unwrap();
        assert_eq!(parsed, s);

        // OEM
        let oem = encode_string(s, 0);
        let parsed = parse_string(&oem, 0).unwrap();
        assert_eq!(parsed, s);
    }
}
