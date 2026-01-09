#![no_main]

use binrw::BinRead;
use libfuzzer_sys::fuzz_target;
use rustsmb_protocol::{CreateRequest, CreateResponse};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as create request
    let mut cursor = Cursor::new(data);
    let _ = CreateRequest::read(&mut cursor);

    // Try to parse arbitrary data as create response
    let mut cursor = Cursor::new(data);
    let _ = CreateResponse::read(&mut cursor);
});
