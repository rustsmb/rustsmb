//! SMB 3.1.1 Pre-Authentication Integrity Hash.
//!
//! Implements the pre-authentication integrity mechanism as specified in
//! MS-SMB2 section 3.1.4.3.
//!
//! # Overview
//!
//! SMB 3.1.1 uses a running hash of negotiate and session setup messages
//! to bind the session key to the negotiation transcript. This prevents
//! certain downgrade and man-in-the-middle attacks.
//!
//! # Hash Computation
//!
//! The pre-auth integrity hash is computed as:
//!
//! ```text
//! PreauthHash\[n+1\] = SHA-512(PreauthHash\[n\] || Message)
//! ```
//!
//! Where:
//! - `PreauthHash[0]` = all zeros (64 bytes)
//! - Message = SMB2 message including header and body

use sha2::{Digest, Sha512};

/// Pre-authentication integrity hash size (SHA-512 = 64 bytes).
pub const PREAUTH_HASH_SIZE: usize = 64;

/// Pre-authentication integrity hash algorithm ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PreauthHashAlgorithm {
    /// SHA-512 (the only supported algorithm).
    Sha512 = 0x0001,
}

impl TryFrom<u16> for PreauthHashAlgorithm {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::Sha512),
            _ => Err(()),
        }
    }
}

/// Pre-authentication integrity hash context.
///
/// Maintains the running hash state during negotiation and session setup.
#[derive(Debug, Clone)]
pub struct PreauthIntegrityHash {
    /// Current hash value.
    hash: [u8; PREAUTH_HASH_SIZE],
    /// Number of messages hashed.
    message_count: u32,
    /// Algorithm in use.
    algorithm: PreauthHashAlgorithm,
}

impl Default for PreauthIntegrityHash {
    fn default() -> Self {
        Self::new()
    }
}

impl PreauthIntegrityHash {
    /// Create a new pre-authentication integrity hash context.
    ///
    /// Initializes with zero hash value.
    pub fn new() -> Self {
        Self {
            hash: [0u8; PREAUTH_HASH_SIZE],
            message_count: 0,
            algorithm: PreauthHashAlgorithm::Sha512,
        }
    }

    /// Create from an existing hash value.
    ///
    /// Used when restoring state from storage.
    pub fn from_hash(hash: [u8; PREAUTH_HASH_SIZE]) -> Self {
        Self {
            hash,
            message_count: 0,
            algorithm: PreauthHashAlgorithm::Sha512,
        }
    }

    /// Get the current hash value.
    pub fn value(&self) -> &[u8; PREAUTH_HASH_SIZE] {
        &self.hash
    }

    /// Get the hash as a Vec for convenience.
    pub fn to_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    /// Get the number of messages that have been hashed.
    pub fn message_count(&self) -> u32 {
        self.message_count
    }

    /// Get the algorithm in use.
    pub fn algorithm(&self) -> PreauthHashAlgorithm {
        self.algorithm
    }

    /// Update the hash with a message.
    ///
    /// Computes: `Hash[n+1] = SHA-512(Hash[n] || Message)`
    ///
    /// # Arguments
    ///
    /// * `message` - The complete SMB2 message (header + body)
    pub fn update(&mut self, message: &[u8]) {
        let mut hasher = Sha512::new();
        hasher.update(self.hash);
        hasher.update(message);
        let result = hasher.finalize();
        self.hash.copy_from_slice(&result);
        self.message_count += 1;
    }

    /// Update with multiple messages in sequence.
    ///
    /// # Arguments
    ///
    /// * `messages` - Iterator of messages to hash
    pub fn update_many<'a>(&mut self, messages: impl IntoIterator<Item = &'a [u8]>) {
        for message in messages {
            self.update(message);
        }
    }

    /// Fork the hash context.
    ///
    /// Creates a copy of the current state for use in session setup.
    /// The connection-level hash continues separately from session-level.
    pub fn fork(&self) -> Self {
        self.clone()
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.hash = [0u8; PREAUTH_HASH_SIZE];
        self.message_count = 0;
    }
}

/// Connection-level pre-authentication context.
///
/// Tracks the hash during negotiate phase.
#[derive(Debug, Clone)]
pub struct ConnectionPreauthContext {
    /// Hash context.
    hash: PreauthIntegrityHash,
    /// Whether negotiate is complete.
    negotiate_complete: bool,
    /// Salt for connection (from negotiate context).
    salt: Option<Vec<u8>>,
}

impl Default for ConnectionPreauthContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPreauthContext {
    /// Create a new connection preauth context.
    pub fn new() -> Self {
        Self {
            hash: PreauthIntegrityHash::new(),
            negotiate_complete: false,
            salt: None,
        }
    }

    /// Set the connection salt (from PREAUTH_INTEGRITY_CAPABILITIES).
    pub fn set_salt(&mut self, salt: Vec<u8>) {
        self.salt = Some(salt);
    }

    /// Get the salt.
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    /// Update with negotiate request.
    pub fn update_negotiate_request(&mut self, message: &[u8]) {
        self.hash.update(message);
    }

    /// Update with negotiate response.
    pub fn update_negotiate_response(&mut self, message: &[u8]) {
        self.hash.update(message);
        self.negotiate_complete = true;
    }

    /// Check if negotiate phase is complete.
    pub fn is_negotiate_complete(&self) -> bool {
        self.negotiate_complete
    }

    /// Get the hash value after negotiate.
    pub fn negotiate_hash(&self) -> Option<&[u8; PREAUTH_HASH_SIZE]> {
        if self.negotiate_complete {
            Some(self.hash.value())
        } else {
            None
        }
    }

    /// Fork for session setup.
    ///
    /// Creates a session-level preauth context starting from the
    /// connection-level hash after negotiate.
    pub fn fork_for_session(&self) -> SessionPreauthContext {
        SessionPreauthContext {
            hash: self.hash.fork(),
            session_complete: false,
        }
    }
}

/// Session-level pre-authentication context.
///
/// Tracks the hash during session setup phase.
#[derive(Debug, Clone)]
pub struct SessionPreauthContext {
    /// Hash context (forked from connection after negotiate).
    hash: PreauthIntegrityHash,
    /// Whether session setup is complete.
    session_complete: bool,
}

impl SessionPreauthContext {
    /// Create from an existing connection context.
    pub fn from_connection(conn: &ConnectionPreauthContext) -> Self {
        conn.fork_for_session()
    }

    /// Update with session setup request.
    pub fn update_session_request(&mut self, message: &[u8]) {
        if !self.session_complete {
            self.hash.update(message);
        }
    }

    /// Update with session setup response.
    pub fn update_session_response(&mut self, message: &[u8]) {
        if !self.session_complete {
            self.hash.update(message);
        }
    }

    /// Mark session setup as complete.
    pub fn complete(&mut self) {
        self.session_complete = true;
    }

    /// Check if session setup is complete.
    pub fn is_complete(&self) -> bool {
        self.session_complete
    }

    /// Get the final preauth hash for key derivation.
    ///
    /// This value is used as the Context parameter in SMB 3.1.1 KDF.
    pub fn final_hash(&self) -> &[u8; PREAUTH_HASH_SIZE] {
        self.hash.value()
    }

    /// Get the hash value as a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.hash.to_vec()
    }
}

/// Parse PREAUTH_INTEGRITY_CAPABILITIES negotiate context.
///
/// # Arguments
///
/// * `data` - Context data (after context header)
///
/// # Returns
///
/// * `(algorithms, salt)` - Supported hash algorithms and salt value
pub fn parse_preauth_integrity_caps(data: &[u8]) -> Option<(Vec<PreauthHashAlgorithm>, Vec<u8>)> {
    if data.len() < 6 {
        return None;
    }

    let hash_count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let salt_length = u16::from_le_bytes([data[2], data[3]]) as usize;

    let algs_end = 4 + hash_count * 2;
    if data.len() < algs_end + salt_length {
        return None;
    }

    let mut algorithms = Vec::with_capacity(hash_count);
    for i in 0..hash_count {
        let offset = 4 + i * 2;
        let alg_id = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if let Ok(alg) = PreauthHashAlgorithm::try_from(alg_id) {
            algorithms.push(alg);
        }
    }

    let salt = data[algs_end..algs_end + salt_length].to_vec();

    Some((algorithms, salt))
}

/// Build PREAUTH_INTEGRITY_CAPABILITIES negotiate context.
///
/// # Arguments
///
/// * `algorithms` - Supported hash algorithms
/// * `salt` - Salt value (typically 32 random bytes)
///
/// # Returns
///
/// * Context data bytes
pub fn build_preauth_integrity_caps(algorithms: &[PreauthHashAlgorithm], salt: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + algorithms.len() * 2 + salt.len());

    // HashAlgorithmCount
    buf.extend_from_slice(&(algorithms.len() as u16).to_le_bytes());

    // SaltLength
    buf.extend_from_slice(&(salt.len() as u16).to_le_bytes());

    // HashAlgorithms
    for alg in algorithms {
        buf.extend_from_slice(&(*alg as u16).to_le_bytes());
    }

    // Salt
    buf.extend_from_slice(salt);

    buf
}

/// Generate a random salt for PREAUTH_INTEGRITY_CAPABILITIES.
pub fn generate_preauth_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preauth_hash_initial() {
        let hash = PreauthIntegrityHash::new();
        assert_eq!(hash.value(), &[0u8; 64]);
        assert_eq!(hash.message_count(), 0);
    }

    #[test]
    fn test_preauth_hash_update() {
        let mut hash = PreauthIntegrityHash::new();

        // Update with a message
        hash.update(b"test message");
        assert_ne!(hash.value(), &[0u8; 64]);
        assert_eq!(hash.message_count(), 1);

        let hash1 = *hash.value();

        // Update with another message
        hash.update(b"another message");
        assert_ne!(hash.value(), &hash1);
        assert_eq!(hash.message_count(), 2);
    }

    #[test]
    fn test_preauth_hash_deterministic() {
        let mut hash1 = PreauthIntegrityHash::new();
        let mut hash2 = PreauthIntegrityHash::new();

        hash1.update(b"message1");
        hash1.update(b"message2");

        hash2.update(b"message1");
        hash2.update(b"message2");

        assert_eq!(hash1.value(), hash2.value());
    }

    #[test]
    fn test_preauth_hash_fork() {
        let mut hash = PreauthIntegrityHash::new();
        hash.update(b"message1");

        let mut forked = hash.fork();

        // Continue original
        hash.update(b"message2a");

        // Continue fork with different message
        forked.update(b"message2b");

        // They should now be different
        assert_ne!(hash.value(), forked.value());
    }

    #[test]
    fn test_connection_context() {
        let mut conn = ConnectionPreauthContext::new();

        assert!(!conn.is_negotiate_complete());
        assert!(conn.negotiate_hash().is_none());

        // Simulate negotiate
        conn.update_negotiate_request(b"negotiate request");
        assert!(!conn.is_negotiate_complete());

        conn.update_negotiate_response(b"negotiate response");
        assert!(conn.is_negotiate_complete());
        assert!(conn.negotiate_hash().is_some());
    }

    #[test]
    fn test_session_context() {
        let mut conn = ConnectionPreauthContext::new();
        conn.update_negotiate_request(b"negotiate request");
        conn.update_negotiate_response(b"negotiate response");

        let mut session = conn.fork_for_session();
        assert!(!session.is_complete());

        // Simulate session setup
        session.update_session_request(b"session setup request 1");
        session.update_session_response(b"session setup response 1");
        session.update_session_request(b"session setup request 2");
        session.update_session_response(b"session setup response 2");

        session.complete();
        assert!(session.is_complete());

        // Final hash should be available
        let final_hash = session.final_hash();
        assert_ne!(final_hash, &[0u8; 64]);
    }

    #[test]
    fn test_preauth_caps_roundtrip() {
        let algorithms = vec![PreauthHashAlgorithm::Sha512];
        let salt = vec![0x01, 0x02, 0x03, 0x04];

        let encoded = build_preauth_integrity_caps(&algorithms, &salt);
        let (parsed_algs, parsed_salt) = parse_preauth_integrity_caps(&encoded).unwrap();

        assert_eq!(parsed_algs, algorithms);
        assert_eq!(parsed_salt, salt);
    }

    #[test]
    fn test_preauth_caps_multiple_algorithms() {
        let algorithms = vec![PreauthHashAlgorithm::Sha512];
        let salt = generate_preauth_salt();

        let encoded = build_preauth_integrity_caps(&algorithms, &salt);
        let (parsed_algs, parsed_salt) = parse_preauth_integrity_caps(&encoded).unwrap();

        assert_eq!(parsed_algs.len(), 1);
        assert_eq!(parsed_salt.len(), 32);
    }

    #[test]
    fn test_preauth_algorithm() {
        assert_eq!(
            PreauthHashAlgorithm::try_from(0x0001),
            Ok(PreauthHashAlgorithm::Sha512)
        );
        assert!(PreauthHashAlgorithm::try_from(0x0000).is_err());
        assert!(PreauthHashAlgorithm::try_from(0x0002).is_err());
    }

    #[test]
    fn test_session_forked_from_connection() {
        let mut conn = ConnectionPreauthContext::new();
        conn.update_negotiate_request(b"negotiate request");
        conn.update_negotiate_response(b"negotiate response");

        // Fork for two different sessions
        let session1 = conn.fork_for_session();
        let session2 = conn.fork_for_session();

        // They should start with the same hash
        assert_eq!(session1.final_hash(), session2.final_hash());
    }
}
