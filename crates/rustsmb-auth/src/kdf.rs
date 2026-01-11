//! SMB 3.0/3.1.1 Key Derivation Functions.
//!
//! Implements key derivation as specified in MS-SMB2 section 3.1.4.2 using
//! SP800-108 KDF in Counter Mode with HMAC-SHA256 as the PRF.
//!
//! # SMB 3.0 Key Derivation
//!
//! SMB 3.0 uses SP800-108 KDF in Counter Mode with HMAC-SHA256:
//!
//! ```text
//! K(i) = HMAC-SHA256(Key, i || Label || 0x00 || Context || L)
//! ```
//!
//! Where:
//! - Key = Session Key (from authentication)
//! - i = Counter (32-bit big-endian)
//! - Label = ASCII string identifying the key purpose
//! - Context = ASCII string with additional context
//! - L = Output length in bits (32-bit big-endian)
//!
//! # SMB 3.1.1 Key Derivation
//!
//! SMB 3.1.1 uses the pre-authentication integrity hash as the Context:
//!
//! ```text
//! Context = PreauthIntegrityHashValue
//! ```

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// SMB 3.0 key labels (WITHOUT null terminator - KDF adds 0x00 separator).
pub mod labels {
    /// Label for SMB 3.0 signing key.
    pub const SMB2_SIGNING: &[u8] = b"SMB2AESCMAC";

    /// Label for SMB 3.0 encryption key (client to server).
    pub const SMB2_ENCRYPTION: &[u8] = b"SMB2AESCCM";

    /// Label for SMB 3.0 decryption key (server to client).
    pub const SMB2_DECRYPTION: &[u8] = b"SMB2AESCCM";

    /// Label for SMB 3.1.1 signing key.
    pub const SMB2_SIGNING_311: &[u8] = b"SMBSigningKey";

    /// Label for SMB 3.1.1 encryption key.
    pub const SMB2_ENCRYPTION_311: &[u8] = b"SMBC2SCipherKey";

    /// Label for SMB 3.1.1 decryption key.
    pub const SMB2_DECRYPTION_311: &[u8] = b"SMBS2CCipherKey";

    /// Label for SMB 3.1.1 application key.
    pub const SMB2_APP_KEY_311: &[u8] = b"SMBAppKey";
}

/// SMB 3.0 context strings (WITHOUT null terminator - KDF adds 0x00 separator).
pub mod contexts {
    /// Context for signing key.
    pub const SIGN: &[u8] = b"SmbSign";

    /// Context for encryption key (server receives).
    pub const SERVER_IN: &[u8] = b"ServerIn ";

    /// Context for decryption key (server sends).
    pub const SERVER_OUT: &[u8] = b"ServerOut";
}

/// Derive a key using SP800-108 KDF in Counter Mode.
///
/// This implements the KDF used by SMB 3.0 as specified in MS-SMB2.
///
/// # Arguments
///
/// * `session_key` - The session key from authentication
/// * `label` - Label string (e.g., "SMB2AESCMAC")
/// * `context` - Context string (e.g., "SmbSign") or preauth hash for SMB 3.1.1
/// * `output_len` - Desired output length in bytes
///
/// # Returns
///
/// The derived key of the specified length.
pub fn sp800_108_kdf(
    session_key: &[u8],
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Vec<u8> {
    let mut result = Vec::with_capacity(output_len);
    let l_bits = (output_len * 8) as u32;
    let mut counter: u32 = 1;

    while result.len() < output_len {
        // K(i) = HMAC-SHA256(Key, i || Label || 0x00 || Context || L)
        let mut mac =
            HmacSha256::new_from_slice(session_key).expect("HMAC can take key of any size");

        // Counter (32-bit big-endian)
        mac.update(&counter.to_be_bytes());

        // Label (caller includes trailing NUL if desired)
        mac.update(label);

        // Context (caller includes trailing NUL if desired)
        mac.update(context);

        // Output length in bits (32-bit big-endian)
        mac.update(&l_bits.to_be_bytes());

        let block = mac.finalize().into_bytes();
        result.extend_from_slice(&block);
        counter += 1;
    }

    result.truncate(output_len);
    result
}

/// SMB session keys derived from authentication.
#[derive(Debug, Clone)]
pub struct SessionKeys {
    /// The base session key from authentication.
    pub session_key: Vec<u8>,
    /// Signing key (for message authentication).
    pub signing_key: Vec<u8>,
    /// Encryption key (for encrypting server-to-client messages).
    pub encryption_key: Vec<u8>,
    /// Decryption key (for decrypting client-to-server messages).
    pub decryption_key: Vec<u8>,
    /// Application key (SMB 3.1.1 only).
    pub application_key: Option<Vec<u8>>,
}

impl SessionKeys {
    /// Derive SMB 3.0 session keys.
    ///
    /// # Arguments
    ///
    /// * `session_key` - Base session key from NTLM/Kerberos authentication
    pub fn derive_smb3(session_key: &[u8]) -> Self {
        // Match smbprotocol/Windows behavior: label/context include trailing NUL and
        // SP800-108 adds the separator.
        let signing_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_SIGNING, b"\0"].concat(),
            &[contexts::SIGN, b"\0"].concat(),
            16,
        );

        // Server encrypts outbound traffic with ServerOut key, decrypts inbound with ServerIn.
        let encryption_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_ENCRYPTION, b"\0"].concat(),
            &[contexts::SERVER_OUT, b"\0"].concat(),
            16,
        );

        let decryption_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_DECRYPTION, b"\0"].concat(),
            &[contexts::SERVER_IN, b"\0"].concat(),
            16,
        );

        Self {
            session_key: session_key.to_vec(),
            signing_key,
            encryption_key,
            decryption_key,
            application_key: None,
        }
    }

    /// Derive SMB 3.1.1 session keys with pre-authentication integrity hash.
    ///
    /// # Arguments
    ///
    /// * `session_key` - Base session key from NTLM/Kerberos authentication
    /// * `preauth_hash` - Pre-authentication integrity hash value
    pub fn derive_smb311(session_key: &[u8], preauth_hash: &[u8]) -> Self {
        let signing_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_SIGNING_311, b"\0"].concat(),
            preauth_hash,
            16,
        );

        // Label names indicate direction: SMBS2C is server->client, SMBC2S is client->server.
        let encryption_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_DECRYPTION_311, b"\0"].concat(),
            preauth_hash,
            16,
        );

        let decryption_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_ENCRYPTION_311, b"\0"].concat(),
            preauth_hash,
            16,
        );

        let application_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_APP_KEY_311, b"\0"].concat(),
            preauth_hash,
            16,
        );

        Self {
            session_key: session_key.to_vec(),
            signing_key,
            encryption_key,
            decryption_key,
            application_key: Some(application_key),
        }
    }

    /// Derive keys for SMB 3.0.2 or 3.1.1 with 256-bit encryption.
    ///
    /// AES-256-GCM requires 32-byte keys.
    ///
    /// # Arguments
    ///
    /// * `session_key` - Base session key from NTLM/Kerberos authentication
    /// * `preauth_hash` - Pre-authentication integrity hash value (for SMB 3.1.1)
    pub fn derive_smb311_256(session_key: &[u8], preauth_hash: &[u8]) -> Self {
        let signing_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_SIGNING_311, b"\0"].concat(),
            preauth_hash,
            16,
        );

        // 256-bit keys for AES-256-GCM
        let encryption_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_DECRYPTION_311, b"\0"].concat(),
            preauth_hash,
            32,
        );

        let decryption_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_ENCRYPTION_311, b"\0"].concat(),
            preauth_hash,
            32,
        );

        let application_key = sp800_108_kdf(
            session_key,
            &[labels::SMB2_APP_KEY_311, b"\0"].concat(),
            preauth_hash,
            16,
        );

        Self {
            session_key: session_key.to_vec(),
            signing_key,
            encryption_key,
            decryption_key,
            application_key: Some(application_key),
        }
    }
}

/// SMB dialect for key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbDialect {
    /// SMB 3.0
    Smb300,
    /// SMB 3.0.2
    Smb302,
    /// SMB 3.1.1
    Smb311,
}

/// Key derivation context for a session.
#[derive(Debug, Clone)]
pub struct KeyDerivationContext {
    /// SMB dialect in use.
    pub dialect: SmbDialect,
    /// Pre-authentication integrity hash (SMB 3.1.1 only).
    pub preauth_hash: Option<Vec<u8>>,
    /// Whether AES-256 encryption is negotiated.
    pub use_aes256: bool,
}

impl KeyDerivationContext {
    /// Create context for SMB 3.0.
    pub fn smb30() -> Self {
        Self {
            dialect: SmbDialect::Smb300,
            preauth_hash: None,
            use_aes256: false,
        }
    }

    /// Create context for SMB 3.0.2.
    pub fn smb302() -> Self {
        Self {
            dialect: SmbDialect::Smb302,
            preauth_hash: None,
            use_aes256: false,
        }
    }

    /// Create context for SMB 3.1.1.
    pub fn smb311(preauth_hash: Vec<u8>) -> Self {
        Self {
            dialect: SmbDialect::Smb311,
            preauth_hash: Some(preauth_hash),
            use_aes256: false,
        }
    }

    /// Create context for SMB 3.1.1 with AES-256.
    pub fn smb311_aes256(preauth_hash: Vec<u8>) -> Self {
        Self {
            dialect: SmbDialect::Smb311,
            preauth_hash: Some(preauth_hash),
            use_aes256: true,
        }
    }

    /// Derive session keys for this context.
    pub fn derive_keys(&self, session_key: &[u8]) -> SessionKeys {
        match (self.dialect, &self.preauth_hash, self.use_aes256) {
            (SmbDialect::Smb300 | SmbDialect::Smb302, None, _) => {
                SessionKeys::derive_smb3(session_key)
            }
            (SmbDialect::Smb311, Some(hash), true) => {
                SessionKeys::derive_smb311_256(session_key, hash)
            }
            (SmbDialect::Smb311, Some(hash), false) => {
                SessionKeys::derive_smb311(session_key, hash)
            }
            // Fallback to SMB 3.0 style if no preauth hash
            _ => SessionKeys::derive_smb3(session_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp800_108_kdf() {
        let session_key = [0x01u8; 16];
        let derived = sp800_108_kdf(&session_key, b"TestLabel", b"TestContext", 16);
        assert_eq!(derived.len(), 16);

        // Same inputs should produce same output
        let derived2 = sp800_108_kdf(&session_key, b"TestLabel", b"TestContext", 16);
        assert_eq!(derived, derived2);

        // Different inputs should produce different output
        let derived3 = sp800_108_kdf(&session_key, b"OtherLabel", b"TestContext", 16);
        assert_ne!(derived, derived3);
    }

    #[test]
    fn test_kdf_output_length() {
        let session_key = [0x02u8; 16];

        // Test 16-byte output
        let k16 = sp800_108_kdf(&session_key, b"Test", b"Ctx", 16);
        assert_eq!(k16.len(), 16);

        // Test 32-byte output
        let k32 = sp800_108_kdf(&session_key, b"Test", b"Ctx", 32);
        assert_eq!(k32.len(), 32);

        // Note: SP800-108 includes output length in HMAC input,
        // so different output lengths produce completely different keys.
        // This is by design to prevent length extension attacks.
        assert_ne!(&k32[..16], &k16[..]);
    }

    #[test]
    fn test_session_keys_smb3() {
        let session_key = [0x03u8; 16];
        let keys = SessionKeys::derive_smb3(&session_key);

        assert_eq!(keys.session_key, session_key);
        assert_eq!(keys.signing_key.len(), 16);
        assert_eq!(keys.encryption_key.len(), 16);
        assert_eq!(keys.decryption_key.len(), 16);
        assert!(keys.application_key.is_none());

        // Keys should all be different
        assert_ne!(keys.signing_key, keys.encryption_key);
        assert_ne!(keys.encryption_key, keys.decryption_key);
    }

    #[test]
    fn test_session_keys_smb311() {
        let session_key = [0x04u8; 16];
        let preauth_hash = [0x05u8; 64];
        let keys = SessionKeys::derive_smb311(&session_key, &preauth_hash);

        assert_eq!(keys.signing_key.len(), 16);
        assert_eq!(keys.encryption_key.len(), 16);
        assert_eq!(keys.decryption_key.len(), 16);
        assert!(keys.application_key.is_some());
        assert_eq!(keys.application_key.as_ref().unwrap().len(), 16);
    }

    #[test]
    fn test_session_keys_smb311_256() {
        let session_key = [0x06u8; 16];
        let preauth_hash = [0x07u8; 64];
        let keys = SessionKeys::derive_smb311_256(&session_key, &preauth_hash);

        // Signing key is still 16 bytes
        assert_eq!(keys.signing_key.len(), 16);
        // Encryption/decryption keys are 32 bytes for AES-256
        assert_eq!(keys.encryption_key.len(), 32);
        assert_eq!(keys.decryption_key.len(), 32);
    }

    #[test]
    fn test_key_derivation_context() {
        let session_key = [0x08u8; 16];

        // SMB 3.0
        let ctx30 = KeyDerivationContext::smb30();
        let keys30 = ctx30.derive_keys(&session_key);
        assert_eq!(keys30.encryption_key.len(), 16);

        // SMB 3.1.1
        let preauth = vec![0x09u8; 64];
        let ctx311 = KeyDerivationContext::smb311(preauth.clone());
        let keys311 = ctx311.derive_keys(&session_key);
        assert!(keys311.application_key.is_some());

        // Different preauth should give different keys
        assert_ne!(keys30.signing_key, keys311.signing_key);
    }

    #[test]
    fn test_smb3_directional_keys_use_correct_contexts() {
        let session_key = [0x09u8; 16];
        let expected_enc = sp800_108_kdf(
            &session_key,
            &[labels::SMB2_ENCRYPTION, b"\0"].concat(),
            &[contexts::SERVER_OUT, b"\0"].concat(),
            16,
        );
        let expected_dec = sp800_108_kdf(
            &session_key,
            &[labels::SMB2_DECRYPTION, b"\0"].concat(),
            &[contexts::SERVER_IN, b"\0"].concat(),
            16,
        );

        let keys = SessionKeys::derive_smb3(&session_key);
        assert_eq!(keys.encryption_key, expected_enc);
        assert_eq!(keys.decryption_key, expected_dec);
    }

    #[test]
    fn test_smb311_directional_keys_use_correct_labels() {
        let session_key = [0x0au8; 16];
        let preauth_hash = [0x0bu8; 64];

        let expected_enc = sp800_108_kdf(
            &session_key,
            &[labels::SMB2_DECRYPTION_311, b"\0"].concat(),
            &preauth_hash,
            16,
        );
        let expected_dec = sp800_108_kdf(
            &session_key,
            &[labels::SMB2_ENCRYPTION_311, b"\0"].concat(),
            &preauth_hash,
            16,
        );

        let keys = SessionKeys::derive_smb311(&session_key, &preauth_hash);
        assert_eq!(keys.encryption_key, expected_enc);
        assert_eq!(keys.decryption_key, expected_dec);
    }

    #[test]
    fn test_kdf_deterministic() {
        // Verify KDF produces consistent results
        let session_key = b"0123456789abcdef";
        let label = labels::SMB2_SIGNING;
        let context = contexts::SIGN;

        let k1 = sp800_108_kdf(session_key, label, context, 16);
        let k2 = sp800_108_kdf(session_key, label, context, 16);
        assert_eq!(k1, k2);
    }
}
