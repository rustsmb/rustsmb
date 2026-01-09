#![no_main]

use binrw::BinRead;
use libfuzzer_sys::fuzz_target;
use rustsmb_protocol::Smb2TransformHeader;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as a transform header (encryption envelope)
    let mut cursor = Cursor::new(data);
    let _ = Smb2TransformHeader::read(&mut cursor);
});
