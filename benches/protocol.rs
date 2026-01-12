//! Protocol parsing and crypto benchmarks for RustSMB.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rustsmb_protocol::{
    CreateOplockLevel, CreateRequest, CreateResponse, NegotiateRequest, NegotiateResponse,
    ReadRequest, ReadResponse, Smb2Header, WriteRequest, WriteResponse, SMB2_HEADER_SIZE,
    SMB2_MAGIC,
};
use std::io::Cursor;

// ============================================================================
// Header Parsing Benchmarks
// ============================================================================

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

fn benchmark_header_roundtrip(c: &mut Criterion) {
    let header = Smb2Header::default();

    c.bench_function("smb2_header_roundtrip", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(SMB2_HEADER_SIZE);
            binrw::BinWrite::write_le(black_box(&header), &mut Cursor::new(&mut buf)).unwrap();
            let _parsed: Smb2Header = binrw::BinRead::read(&mut Cursor::new(&buf)).unwrap();
        })
    });
}

// ============================================================================
// Command Parsing Benchmarks
// ============================================================================

fn benchmark_negotiate_parse(c: &mut Criterion) {
    let req = NegotiateRequest::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&req, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("negotiate_request_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _req: NegotiateRequest = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });

    let resp = NegotiateResponse::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&resp, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("negotiate_response_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _resp: NegotiateResponse = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });
}

fn benchmark_create_parse(c: &mut Criterion) {
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: CreateOplockLevel::Exclusive,
        impersonation_level: 2, // Impersonation
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x001F01FF,
        file_attributes: 0x80,
        share_access: 0x07,
        create_disposition: 3,
        create_options: 0,
        name_offset: 0,
        name_length: 0,
        create_contexts_offset: 0,
        create_contexts_length: 0,
    };
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&req, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("create_request_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _req: CreateRequest = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });

    let resp = CreateResponse::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&resp, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("create_response_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _resp: CreateResponse = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });
}

fn benchmark_read_write_parse(c: &mut Criterion) {
    let read_req = ReadRequest::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&read_req, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("read_request_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _req: ReadRequest = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });

    let read_resp = ReadResponse::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&read_resp, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("read_response_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _resp: ReadResponse = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });

    let write_req = WriteRequest::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&write_req, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("write_request_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _req: WriteRequest = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });

    let write_resp = WriteResponse::default();
    let mut buf = Vec::new();
    binrw::BinWrite::write_le(&write_resp, &mut Cursor::new(&mut buf)).unwrap();

    c.bench_function("write_response_parse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(black_box(&buf));
            let _resp: WriteResponse = binrw::BinRead::read(&mut cursor).unwrap();
        })
    });
}

// ============================================================================
// Throughput Benchmarks
// ============================================================================

fn benchmark_header_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_throughput");

    for count in [100, 1000, 10000].iter() {
        let header = Smb2Header::default();
        let mut buf = Vec::with_capacity(SMB2_HEADER_SIZE);
        binrw::BinWrite::write_le(&header, &mut Cursor::new(&mut buf)).unwrap();

        // Create batch of headers
        let batch: Vec<Vec<u8>> = (0..*count).map(|_| buf.clone()).collect();

        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::new("parse", count), &batch, |b, batch| {
            b.iter(|| {
                for buf in batch.iter() {
                    let mut cursor = Cursor::new(black_box(buf));
                    let _header: Smb2Header = binrw::BinRead::read(&mut cursor).unwrap();
                }
            })
        });
    }

    group.finish();
}

fn benchmark_command_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("command_throughput");

    // Prepare read request buffer
    let read_req = ReadRequest::default();
    let mut read_buf = Vec::new();
    binrw::BinWrite::write_le(&read_req, &mut Cursor::new(&mut read_buf)).unwrap();

    for count in [100, 1000].iter() {
        let batch: Vec<Vec<u8>> = (0..*count).map(|_| read_buf.clone()).collect();

        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::new("read_request_batch", count),
            &batch,
            |b, batch| {
                b.iter(|| {
                    for buf in batch.iter() {
                        let mut cursor = Cursor::new(black_box(buf));
                        let _req: ReadRequest = binrw::BinRead::read(&mut cursor).unwrap();
                    }
                })
            },
        );
    }

    // Prepare write request buffer
    let write_req = WriteRequest::default();
    let mut write_buf = Vec::new();
    binrw::BinWrite::write_le(&write_req, &mut Cursor::new(&mut write_buf)).unwrap();

    for count in [100, 1000].iter() {
        let batch: Vec<Vec<u8>> = (0..*count).map(|_| write_buf.clone()).collect();

        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::new("write_request_batch", count),
            &batch,
            |b, batch| {
                b.iter(|| {
                    for buf in batch.iter() {
                        let mut cursor = Cursor::new(black_box(buf));
                        let _req: WriteRequest = binrw::BinRead::read(&mut cursor).unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Serialization Size Benchmarks
// ============================================================================

fn benchmark_message_sizes(c: &mut Criterion) {
    c.bench_function("serialize_full_message", |b| {
        let header = Smb2Header::default();
        let read_req = ReadRequest::default();

        b.iter(|| {
            // Simulate building a full SMB2 message
            let mut buf = Vec::with_capacity(128);

            // Write header
            binrw::BinWrite::write_le(black_box(&header), &mut Cursor::new(&mut buf)).unwrap();

            // Write request body
            binrw::BinWrite::write_le(black_box(&read_req), &mut Cursor::new(&mut buf)).unwrap();
        })
    });
}

// ============================================================================
// Main
// ============================================================================

criterion_group!(
    header_benches,
    benchmark_header_parse,
    benchmark_header_write,
    benchmark_header_roundtrip
);

criterion_group!(
    command_benches,
    benchmark_negotiate_parse,
    benchmark_create_parse,
    benchmark_read_write_parse
);

criterion_group!(
    throughput_benches,
    benchmark_header_throughput,
    benchmark_command_throughput,
    benchmark_message_sizes
);

criterion_main!(header_benches, command_benches, throughput_benches);
