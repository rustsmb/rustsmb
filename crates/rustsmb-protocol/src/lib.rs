//! SMB2/SMB3 protocol parsing and command handling.
//!
//! This crate implements the SMB2/SMB3 protocol as specified in MS-SMB2.
//!
//! # Modules
//!
//! - `header`: SMB2 packet header parsing (64 bytes)
//! - `transform`: SMB2 transform header for encrypted messages (52 bytes)
//! - `commands`: All 19 SMB2 commands with request/response structures
//! - `dialect`: Dialect negotiation helpers
//! - `crypto`: Message signing and encryption (SMB 3.0+)
//!
//! # Example
//!
//! ```rust
//! use rustsmb_protocol::{Smb2Header, Smb2Command, NegotiateRequest};
//! use binrw::BinRead;
//! use std::io::Cursor;
//!
//! // Parse a header
//! let header = Smb2Header::default();
//! assert_eq!(header.structure_size, 64);
//! ```

pub mod commands;
pub mod crypto;
pub mod dialect;
pub mod header;
pub mod transform;

// Re-export commonly used types
pub use commands::*;
pub use crypto::{
    encryption::{EncryptionError, MessageEncryptor},
    signing::{MessageSigner, SigningAlgorithm, SigningError},
};
pub use dialect::{DialectNegotiator, NegotiateContext, NegotiateContextType};
pub use header::{Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE, SMB2_MAGIC};
pub use transform::{
    EncryptionAlgorithm, Smb2TransformHeader, SMB2_TRANSFORM_HEADER_SIZE, SMB2_TRANSFORM_MAGIC,
};
