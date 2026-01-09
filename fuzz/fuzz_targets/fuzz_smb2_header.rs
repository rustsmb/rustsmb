#![no_main]

use binrw::BinRead;
use libfuzzer_sys::fuzz_target;
use rustsmb_protocol::Smb2Header;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as an SMB2 header
    let mut cursor = Cursor::new(data);
    let _ = Smb2Header::read(&mut cursor);
});
