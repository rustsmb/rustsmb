#![no_main]

use binrw::BinRead;
use libfuzzer_sys::fuzz_target;
use rustsmb_protocol::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse as read request
    let mut cursor = Cursor::new(data);
    let _ = ReadRequest::read(&mut cursor);

    // Try to parse as read response
    let mut cursor = Cursor::new(data);
    let _ = ReadResponse::read(&mut cursor);

    // Try to parse as write request
    let mut cursor = Cursor::new(data);
    let _ = WriteRequest::read(&mut cursor);

    // Try to parse as write response
    let mut cursor = Cursor::new(data);
    let _ = WriteResponse::read(&mut cursor);
});
