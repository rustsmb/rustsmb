//! SMB3 message encryption.
//!
//! SMB 3.0 uses AES-128-CCM for encryption.
//! SMB 3.1.1 can use AES-128-CCM, AES-128-GCM, AES-256-CCM, or AES-256-GCM.
//!
//! See MS-SMB2 Section 3.1.4.3.

use thiserror::Error;

use crate::transform::{EncryptionAlgorithm, Smb2TransformHeader, SMB2_TRANSFORM_HEADER_SIZE};

/// Encryption error.
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// Invalid key size.
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Invalid nonce size.
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize { expected: usize, actual: usize },

    /// Decryption failed (authentication tag mismatch).
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Buffer too small.
    #[error("Buffer too small: need {needed}, got {actual}")]
    BufferTooSmall { needed: usize, actual: usize },
}

/// Message encryptor for SMB3.
pub struct MessageEncryptor {
    algorithm: EncryptionAlgorithm,
    encryption_key: Vec<u8>,
    decryption_key: Vec<u8>,
}

impl MessageEncryptor {
    /// Create a new message encryptor.
    ///
    /// For SMB 3.0, both keys should be the same (Session.EncryptionKey).
    /// For SMB 3.1.1, separate encryption and decryption keys may be used.
    pub fn new(
        algorithm: EncryptionAlgorithm,
        encryption_key: &[u8],
        decryption_key: &[u8],
    ) -> Result<Self, EncryptionError> {
        let expected_size = algorithm.key_size();

        if encryption_key.len() != expected_size {
            return Err(EncryptionError::InvalidKeySize {
                expected: expected_size,
                actual: encryption_key.len(),
            });
        }

        if decryption_key.len() != expected_size {
            return Err(EncryptionError::InvalidKeySize {
                expected: expected_size,
                actual: decryption_key.len(),
            });
        }

        Ok(Self {
            algorithm,
            encryption_key: encryption_key.to_vec(),
            decryption_key: decryption_key.to_vec(),
        })
    }

    /// Create a new message encryptor with the same key for both directions.
    pub fn new_symmetric(
        algorithm: EncryptionAlgorithm,
        key: &[u8],
    ) -> Result<Self, EncryptionError> {
        Self::new(algorithm, key, key)
    }

    /// Get the encryption algorithm.
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Encrypt a message.
    ///
    /// Returns the transform header and encrypted data.
    pub fn encrypt(
        &self,
        session_id: u64,
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<(Smb2TransformHeader, Vec<u8>), EncryptionError> {
        let expected_nonce_size = self.algorithm.nonce_size();
        if nonce.len() != expected_nonce_size {
            return Err(EncryptionError::InvalidNonceSize {
                expected: expected_nonce_size,
                actual: nonce.len(),
            });
        }

        let (ciphertext, tag) = match self.algorithm {
            EncryptionAlgorithm::Aes128Gcm | EncryptionAlgorithm::Aes256Gcm => {
                self.encrypt_gcm(plaintext, nonce)?
            }
            EncryptionAlgorithm::Aes128Ccm | EncryptionAlgorithm::Aes256Ccm => {
                self.encrypt_ccm(plaintext, nonce)?
            }
        };

        // Build nonce field (16 bytes, with actual nonce at start)
        let mut nonce_field = [0u8; 16];
        nonce_field[..nonce.len()].copy_from_slice(nonce);

        // Build signature field from authentication tag
        let mut signature = [0u8; 16];
        signature.copy_from_slice(&tag);

        let header = Smb2TransformHeader {
            signature,
            nonce: nonce_field,
            original_message_size: plaintext.len() as u32,
            reserved: 0,
            flags: 0x0001, // Encrypted
            session_id,
        };

        Ok((header, ciphertext))
    }

    /// Decrypt a message.
    ///
    /// Takes the transform header and encrypted data, returns plaintext.
    pub fn decrypt(
        &self,
        header: &Smb2TransformHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce_size = self.algorithm.nonce_size();
        let nonce = &header.nonce[..nonce_size];

        match self.algorithm {
            EncryptionAlgorithm::Aes128Gcm | EncryptionAlgorithm::Aes256Gcm => {
                self.decrypt_gcm(ciphertext, nonce, &header.signature)
            }
            EncryptionAlgorithm::Aes128Ccm | EncryptionAlgorithm::Aes256Ccm => {
                self.decrypt_ccm(ciphertext, nonce, &header.signature)
            }
        }
    }

    /// Encrypt using AES-GCM.
    fn encrypt_gcm(&self, plaintext: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, [u8; 16]), EncryptionError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes128Gcm, Aes256Gcm, Nonce,
        };

        let nonce = Nonce::from_slice(nonce);

        match self.algorithm {
            EncryptionAlgorithm::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.encryption_key)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                let ciphertext_with_tag = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                // Split ciphertext and tag
                let (ciphertext, tag) = ciphertext_with_tag.split_at(plaintext.len());
                let mut tag_array = [0u8; 16];
                tag_array.copy_from_slice(tag);

                Ok((ciphertext.to_vec(), tag_array))
            }
            EncryptionAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                let ciphertext_with_tag = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                let (ciphertext, tag) = ciphertext_with_tag.split_at(plaintext.len());
                let mut tag_array = [0u8; 16];
                tag_array.copy_from_slice(tag);

                Ok((ciphertext.to_vec(), tag_array))
            }
            _ => Err(EncryptionError::CryptoError("Not a GCM algorithm".into())),
        }
    }

    /// Decrypt using AES-GCM.
    fn decrypt_gcm(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, EncryptionError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes128Gcm, Aes256Gcm, Nonce,
        };

        let nonce = Nonce::from_slice(nonce);

        // Append tag to ciphertext for decryption
        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(tag);

        match self.algorithm {
            EncryptionAlgorithm::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.decryption_key)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                cipher
                    .decrypt(nonce, ciphertext_with_tag.as_slice())
                    .map_err(|_| EncryptionError::DecryptionFailed)
            }
            EncryptionAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.decryption_key)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                cipher
                    .decrypt(nonce, ciphertext_with_tag.as_slice())
                    .map_err(|_| EncryptionError::DecryptionFailed)
            }
            _ => Err(EncryptionError::CryptoError("Not a GCM algorithm".into())),
        }
    }

    /// Encrypt using AES-CCM.
    fn encrypt_ccm(&self, plaintext: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, [u8; 16]), EncryptionError> {
        use ccm::{
            aead::{Aead, KeyInit},
            consts::{U11, U16},
            Ccm,
        };
        use aes::Aes128;

        type Aes128Ccm = Ccm<Aes128, U16, U11>;

        match self.algorithm {
            EncryptionAlgorithm::Aes128Ccm => {
                let cipher = Aes128Ccm::new_from_slice(&self.encryption_key)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                let nonce = ccm::aead::generic_array::GenericArray::from_slice(nonce);
                let ciphertext_with_tag = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                let (ciphertext, tag) = ciphertext_with_tag.split_at(plaintext.len());
                let mut tag_array = [0u8; 16];
                tag_array.copy_from_slice(tag);

                Ok((ciphertext.to_vec(), tag_array))
            }
            EncryptionAlgorithm::Aes256Ccm => {
                // AES-256-CCM would need a different type
                // For now, return an error as it's less commonly used
                Err(EncryptionError::CryptoError(
                    "AES-256-CCM not yet implemented".into(),
                ))
            }
            _ => Err(EncryptionError::CryptoError("Not a CCM algorithm".into())),
        }
    }

    /// Decrypt using AES-CCM.
    fn decrypt_ccm(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, EncryptionError> {
        use ccm::{
            aead::{Aead, KeyInit},
            consts::{U11, U16},
            Ccm,
        };
        use aes::Aes128;

        type Aes128Ccm = Ccm<Aes128, U16, U11>;

        let mut ciphertext_with_tag = ciphertext.to_vec();
        ciphertext_with_tag.extend_from_slice(tag);

        match self.algorithm {
            EncryptionAlgorithm::Aes128Ccm => {
                let cipher = Aes128Ccm::new_from_slice(&self.decryption_key)
                    .map_err(|e| EncryptionError::CryptoError(e.to_string()))?;

                let nonce = ccm::aead::generic_array::GenericArray::from_slice(nonce);
                cipher
                    .decrypt(nonce, ciphertext_with_tag.as_slice())
                    .map_err(|_| EncryptionError::DecryptionFailed)
            }
            EncryptionAlgorithm::Aes256Ccm => {
                Err(EncryptionError::CryptoError(
                    "AES-256-CCM not yet implemented".into(),
                ))
            }
            _ => Err(EncryptionError::CryptoError("Not a CCM algorithm".into())),
        }
    }
}

/// Generate a random nonce for encryption.
pub fn generate_nonce(algorithm: EncryptionAlgorithm) -> Vec<u8> {
    use rand::RngCore;

    let size = algorithm.nonce_size();
    let mut nonce = vec![0u8; size];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Calculate the total size of an encrypted message.
pub fn encrypted_message_size(plaintext_size: usize) -> usize {
    SMB2_TRANSFORM_HEADER_SIZE + plaintext_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryptor_invalid_key_size() {
        let result = MessageEncryptor::new_symmetric(EncryptionAlgorithm::Aes128Gcm, &[0u8; 8]);
        assert!(matches!(result, Err(EncryptionError::InvalidKeySize { .. })));
    }

    #[test]
    fn test_gcm_encrypt_decrypt() {
        let key = [0u8; 16];
        let encryptor =
            MessageEncryptor::new_symmetric(EncryptionAlgorithm::Aes128Gcm, &key).unwrap();

        let plaintext = b"Hello, SMB3 encryption!";
        let nonce = [1u8; 12];

        let (header, ciphertext) = encryptor.encrypt(0x123456789ABCDEF0, plaintext, &nonce).unwrap();

        assert_eq!(header.session_id, 0x123456789ABCDEF0);
        assert_eq!(header.original_message_size, plaintext.len() as u32);

        let decrypted = encryptor.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gcm_tampered_ciphertext() {
        let key = [0u8; 16];
        let encryptor =
            MessageEncryptor::new_symmetric(EncryptionAlgorithm::Aes128Gcm, &key).unwrap();

        let plaintext = b"Hello, SMB3 encryption!";
        let nonce = [1u8; 12];

        let (header, mut ciphertext) = encryptor.encrypt(0x123456789ABCDEF0, plaintext, &nonce).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        let result = encryptor.decrypt(&header, &ciphertext);
        assert!(matches!(result, Err(EncryptionError::DecryptionFailed)));
    }

    #[test]
    fn test_ccm_encrypt_decrypt() {
        let key = [0u8; 16];
        let encryptor =
            MessageEncryptor::new_symmetric(EncryptionAlgorithm::Aes128Ccm, &key).unwrap();

        let plaintext = b"Hello, SMB3 CCM encryption!";
        let nonce = [1u8; 11];

        let (header, ciphertext) = encryptor.encrypt(0x123456789ABCDEF0, plaintext, &nonce).unwrap();

        assert_eq!(header.session_id, 0x123456789ABCDEF0);
        assert_eq!(header.original_message_size, plaintext.len() as u32);

        let decrypted = encryptor.decrypt(&header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce_gcm = generate_nonce(EncryptionAlgorithm::Aes128Gcm);
        assert_eq!(nonce_gcm.len(), 12);

        let nonce_ccm = generate_nonce(EncryptionAlgorithm::Aes128Ccm);
        assert_eq!(nonce_ccm.len(), 11);
    }

    #[test]
    fn test_encrypted_message_size() {
        assert_eq!(encrypted_message_size(100), SMB2_TRANSFORM_HEADER_SIZE + 100);
    }
}
