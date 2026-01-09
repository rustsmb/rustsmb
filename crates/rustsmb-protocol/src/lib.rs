//! SMB2/SMB3 protocol parsing and command handling.
//!
//! This crate implements the SMB2/SMB3 protocol as specified in MS-SMB2.

pub mod commands;
pub mod header;

pub use header::{Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE, SMB2_MAGIC};
