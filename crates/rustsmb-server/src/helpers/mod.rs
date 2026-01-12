//! Helper utilities for SMB2/SMB3 protocol handling.
//!
//! This module provides common utilities used across the server implementation:
//!
//! - **Time conversion**: Windows FILETIME ↔ Unix timestamp
//! - **String handling**: UTF-16LE parsing for SMB protocol strings
//! - **Info builders**: Binary response buffers for QUERY_INFO commands

pub mod info_builders;
pub mod strings;
pub mod time;

// Re-export commonly used functions
pub use info_builders::{
    build_directory_info, build_file_info, build_fs_info, build_security_info,
};
pub use strings::{decode_utf16le, extract_share_name, parse_utf16_string};
pub use time::{current_filetime, filetime_to_unix};
