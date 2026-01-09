//! Protocol parsing benchmarks for RustSMB.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustsmb_protocol::{Smb2Header, SMB2_HEADER_SIZE, SMB2_MAGIC};
use std::io::Cursor;

fn benchmark_header_parse(c: &mut Criterion) {
    // Create a valid SMB2 header buffer
    let mut buf = vec![0u8; SMB2_HEADER_SIZE];
    buf[0..4].copy_from_slice(&SMB2_MAGIC);
    buf[4..6].copy_from_slice(&64u16.to_le_bytes()); // structure_size

    c.bench_function("smb2_header_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _header: Smb2Header = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });
}

fn benchmark_header_write(c: &mut Criterion) {
    let header = Smb2Header::default();

    c.bench_function("smb2_header_write", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(SMB2_HEADER_SIZE);
            binrw::BinWrite::write_le(black_box(&header), &mut Cursor::new(&mut buf)).unwrap();
        })
    });
}

criterion_group!(benches, benchmark_header_parse, benchmark_header_write);
criterion_main!(benches);
