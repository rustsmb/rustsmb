//! Time conversion utilities for SMB2/SMB3 protocol.
//!
//! Windows uses FILETIME format (100-nanosecond intervals since January 1, 1601).
//! These helpers convert between FILETIME and Unix timestamps.

use std::time::{SystemTime, UNIX_EPOCH};

/// Windows epoch is Jan 1, 1601; Unix epoch is Jan 1, 1970.
/// Difference is 11644473600 seconds.
const EPOCH_DIFF: u64 = 11644473600;

/// Number of 100-nanosecond intervals per second.
const TICKS_PER_SEC: u64 = 10_000_000;

/// Get current time as Windows FILETIME (100-nanosecond intervals since 1601).
pub fn current_filetime() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() + EPOCH_DIFF) * TICKS_PER_SEC + d.subsec_nanos() as u64 / 100)
        .unwrap_or(0)
}

/// Convert Windows FILETIME to Unix timestamp (seconds since 1970).
pub fn filetime_to_unix(filetime: u64) -> u64 {
    // Convert 100-nanosecond intervals to seconds and adjust epoch
    let seconds_since_1601 = filetime / TICKS_PER_SEC;
    seconds_since_1601.saturating_sub(EPOCH_DIFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_unix_conversion() {
        // Test known conversion: Jan 1, 2000 00:00:00 UTC
        // FILETIME: 125911584000000000 (100-nanosecond intervals since 1601)
        // Unix: 946684800 (seconds since 1970)
        let filetime_2000 = 125911584000000000u64;
        let unix_2000 = filetime_to_unix(filetime_2000);
        assert_eq!(unix_2000, 946684800, "Jan 1, 2000 should convert correctly");
    }

    #[test]
    fn test_filetime_to_unix_epoch() {
        // Unix epoch (Jan 1, 1970) as FILETIME
        // 11644473600 seconds * 10,000,000 = 116444736000000000
        let filetime_1970 = 116444736000000000u64;
        let unix_1970 = filetime_to_unix(filetime_1970);
        assert_eq!(unix_1970, 0, "Unix epoch should be 0");
    }

    #[test]
    fn test_filetime_to_unix_before_epoch() {
        // FILETIME before Unix epoch should saturate to 0
        let filetime_early = 100000000000000u64; // Before 1970
        let unix_early = filetime_to_unix(filetime_early);
        assert_eq!(unix_early, 0, "Pre-Unix-epoch time should saturate to 0");
    }

    #[test]
    fn test_current_filetime_reasonable() {
        // Verify current_filetime returns a reasonable value (after year 2000)
        let filetime = current_filetime();
        let unix = filetime_to_unix(filetime);

        // Unix timestamp for Jan 1, 2000 = 946684800
        assert!(unix > 946684800, "Current time should be after year 2000");

        // And before year 2100 = 4102444800
        assert!(unix < 4102444800, "Current time should be before year 2100");
    }
}
