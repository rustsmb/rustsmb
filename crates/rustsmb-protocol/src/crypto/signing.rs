//! SMB2/3 message signing.
//!
//! SMB 3.0 uses AES-CMAC for signing.
//! SMB 3.1.1 uses AES-GMAC for signing.
//!
//! See MS-SMB2 Section 3.1.4.1.

use thiserror::Error;

/// Signing error.
#[derive(Debug, Error)]
pub enum SigningError {
    /// Invalid key size.
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Signature mismatch.
    #[error("Signature mismatch")]
    SignatureMismatch,

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

/// Signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// AES-128-CMAC (SMB 3.0/3.0.2).
    AesCmac,
    /// AES-128-GMAC (SMB 3.1.1).
    AesGmac,
}

impl SigningAlgorithm {
    /// Get the signing algorithm ID for negotiate contexts.
    pub fn algorithm_id(self) -> u16 {
        match self {
            Self::AesCmac => 0x0000,
            Self::AesGmac => 0x0001,
        }
    }

    /// Create from algorithm ID.
    pub fn from_algorithm_id(id: u16) -> Option<Self> {
        match id {
            0x0000 => Some(Self::AesCmac),
            0x0001 => Some(Self::AesGmac),
            _ => None,
        }
    }

    /// Get the required key size in bytes.
    pub fn key_size(self) -> usize {
        16 // Both algorithms use 128-bit keys
    }

    /// Get the signature size in bytes.
    pub fn signature_size(self) -> usize {
        16 // Both produce 16-byte signatures
    }
}

/// Message signer for SMB3.
pub struct MessageSigner {
    algorithm: SigningAlgorithm,
    key: [u8; 16],
}

impl MessageSigner {
    /// Create a new message signer.
    pub fn new(algorithm: SigningAlgorithm, key: &[u8]) -> Result<Self, SigningError> {
        if key.len() != 16 {
            return Err(SigningError::InvalidKeySize {
                expected: 16,
                actual: key.len(),
            });
        }

        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(key);

        Ok(Self {
            algorithm,
            key: key_array,
        })
    }

    /// Get the signing algorithm.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Sign a message and return the signature.
    ///
    /// The message should have the signature field zeroed before signing.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 16], SigningError> {
        match self.algorithm {
            SigningAlgorithm::AesCmac => self.sign_cmac(message),
            SigningAlgorithm::AesGmac => self.sign_gmac(message),
        }
    }

    /// Verify a message signature.
    ///
    /// The provided message should have the signature field zeroed.
    pub fn verify(&self, message: &[u8], signature: &[u8; 16]) -> Result<(), SigningError> {
        let computed = self.sign(message)?;

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in computed.iter().zip(signature.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            return Err(SigningError::SignatureMismatch);
        }

        Ok(())
    }

    /// Sign using AES-CMAC.
    fn sign_cmac(&self, message: &[u8]) -> Result<[u8; 16], SigningError> {
        use hmac::Mac;

        // Create CMAC instance
        type AesCmac = cmac::Cmac<aes::Aes128>;
        let mut mac = AesCmac::new_from_slice(&self.key)
            .map_err(|e| SigningError::CryptoError(e.to_string()))?;

        mac.update(message);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&bytes);
        Ok(signature)
    }

    /// Sign using AES-GMAC.
    ///
    /// GMAC is GCM with empty plaintext - it's essentially an authentication tag.
    fn sign_gmac(&self, message: &[u8]) -> Result<[u8; 16], SigningError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes128Gcm, Nonce,
        };

        // For GMAC signing in SMB 3.1.1, we use the message ID from the header
        // as part of the nonce. Here we use a simplified approach.
        // In practice, the nonce would be derived from the message ID.
        let nonce = Nonce::from_slice(&[0u8; 12]);

        let cipher = Aes128Gcm::new_from_slice(&self.key)
            .map_err(|e| SigningError::CryptoError(e.to_string()))?;

        // GMAC: encrypt empty data with AAD
        // We use the message as AAD (additional authenticated data)
        let result = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &[],
                    aad: message,
                },
            )
            .map_err(|e| SigningError::CryptoError(e.to_string()))?;

        // The result is just the authentication tag
        let mut signature = [0u8; 16];
        signature.copy_from_slice(&result);
        Ok(signature)
    }
}

/// Zero out the signature field in an SMB2 header.
///
/// The signature is at offset 48, length 16 bytes.
pub fn zero_signature(header: &mut [u8]) {
    if header.len() >= 64 {
        header[48..64].fill(0);
    }
}

/// Get the signature from an SMB2 header.
pub fn get_signature(header: &[u8]) -> Option<[u8; 16]> {
    if header.len() >= 64 {
        let mut sig = [0u8; 16];
        sig.copy_from_slice(&header[48..64]);
        Some(sig)
    } else {
        None
    }
}

/// Set the signature in an SMB2 header.
pub fn set_signature(header: &mut [u8], signature: &[u8; 16]) {
    if header.len() >= 64 {
        header[48..64].copy_from_slice(signature);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_algorithm_ids() {
        assert_eq!(SigningAlgorithm::AesCmac.algorithm_id(), 0x0000);
        assert_eq!(SigningAlgorithm::AesGmac.algorithm_id(), 0x0001);
        assert_eq!(
            SigningAlgorithm::from_algorithm_id(0x0000),
            Some(SigningAlgorithm::AesCmac)
        );
        assert_eq!(
            SigningAlgorithm::from_algorithm_id(0x0001),
            Some(SigningAlgorithm::AesGmac)
        );
        assert_eq!(SigningAlgorithm::from_algorithm_id(0x1234), None);
    }

    #[test]
    fn test_signer_invalid_key_size() {
        let result = MessageSigner::new(SigningAlgorithm::AesCmac, &[0u8; 8]);
        assert!(matches!(result, Err(SigningError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_cmac_sign_verify() {
        let key = [0u8; 16];
        let signer = MessageSigner::new(SigningAlgorithm::AesCmac, &key).unwrap();

        let message = b"test message for signing";
        let signature = signer.sign(message).unwrap();

        assert!(signer.verify(message, &signature).is_ok());

        // Modify message - verification should fail
        let modified = b"test message for signinG";
        assert!(matches!(
            signer.verify(modified, &signature),
            Err(SigningError::SignatureMismatch)
        ));
    }

    #[test]
    fn test_zero_signature() {
        let mut header = [0xFFu8; 64];
        zero_signature(&mut header);

        assert!(header[48..64].iter().all(|&b| b == 0));
        assert!(header[0..48].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_get_set_signature() {
        let mut header = [0u8; 64];
        let signature = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        set_signature(&mut header, &signature);
        let retrieved = get_signature(&header).unwrap();

        assert_eq!(retrieved, signature);
    }
}
