//! String conversion utilities for SMB2/SMB3 protocol.
//!
//! SMB uses UTF-16LE encoding for strings. These helpers convert between
//! UTF-16LE byte arrays and Rust strings.

/// Parse a UTF-16LE byte slice into a String.
///
/// Stops at the first null terminator if present.
pub fn parse_utf16_string(bytes: &[u8]) -> String {
    // Ensure we have an even number of bytes
    let len = bytes.len() / 2;
    let mut chars: Vec<u16> = Vec::with_capacity(len);
    for i in 0..len {
        let lo = bytes[i * 2] as u16;
        let hi = bytes[i * 2 + 1] as u16;
        let c = lo | (hi << 8);
        // Stop at null terminator
        if c == 0 {
            break;
        }
        chars.push(c);
    }
    String::from_utf16_lossy(&chars)
}

/// Extract share name from UNC path (\\server\share).
///
/// Returns the share name portion of a UNC path, handling both
/// `\\server\share` and `\\server\share\path` formats.
pub fn extract_share_name(path: &str) -> String {
    let path = path.trim_start_matches('\\');
    if let Some(idx) = path.find('\\') {
        let after_server = &path[idx + 1..];
        if let Some(end) = after_server.find('\\') {
            after_server[..end].to_string()
        } else {
            after_server.to_string()
        }
    } else {
        path.to_string()
    }
}

/// Decode UTF-16LE bytes to a string.
///
/// Unlike `parse_utf16_string`, this does not stop at null terminators.
pub fn decode_utf16le(bytes: &[u8]) -> String {
    let u16_vec: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&u16_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_utf16_string_basic() {
        // "test" in UTF-16LE
        let bytes = [b't', 0, b'e', 0, b's', 0, b't', 0];
        let result = parse_utf16_string(&bytes);
        assert_eq!(result, "test", "Basic ASCII string");
    }

    #[test]
    fn test_parse_utf16_string_with_null() {
        // "hi" with null terminator and garbage after
        let bytes = [b'h', 0, b'i', 0, 0, 0, b'x', 0, b'y', 0];
        let result = parse_utf16_string(&bytes);
        assert_eq!(result, "hi", "Should stop at null terminator");
    }

    #[test]
    fn test_parse_utf16_string_empty() {
        // Empty string
        let bytes: [u8; 0] = [];
        let result = parse_utf16_string(&bytes);
        assert_eq!(result, "", "Empty input should return empty string");
    }

    #[test]
    fn test_parse_utf16_string_unicode() {
        // "日" (Japanese "day") in UTF-16LE: 0x65E5
        let bytes = [0xE5, 0x65];
        let result = parse_utf16_string(&bytes);
        assert_eq!(result, "日", "Unicode character should parse correctly");
    }

    #[test]
    fn test_extract_share_name_basic() {
        assert_eq!(extract_share_name(r"\\server\share"), "share");
        assert_eq!(extract_share_name(r"\\server\share\path"), "share");
        assert_eq!(extract_share_name(r"\\server\share\path\file"), "share");
    }

    #[test]
    fn test_extract_share_name_no_server() {
        // Edge case: just share name
        assert_eq!(extract_share_name("share"), "share");
    }

    #[test]
    fn test_decode_utf16le_basic() {
        // "test" in UTF-16LE
        let bytes = [b't', 0, b'e', 0, b's', 0, b't', 0];
        let result = decode_utf16le(&bytes);
        assert_eq!(result, "test");
    }

    #[test]
    fn test_decode_utf16le_with_null() {
        // Unlike parse_utf16_string, decode_utf16le doesn't stop at null
        let bytes = [b'h', 0, b'i', 0, 0, 0];
        let result = decode_utf16le(&bytes);
        assert_eq!(result, "hi\0");
    }
}
