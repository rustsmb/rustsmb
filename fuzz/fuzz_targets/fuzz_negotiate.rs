#![no_main]

use binrw::BinRead;
use libfuzzer_sys::fuzz_target;
use rustsmb_protocol::{NegotiateRequest, NegotiateResponse};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as negotiate request
    let mut cursor = Cursor::new(data);
    let _ = NegotiateRequest::read(&mut cursor);

    // Try to parse arbitrary data as negotiate response
    let mut cursor = Cursor::new(data);
    let _ = NegotiateResponse::read(&mut cursor);
});
