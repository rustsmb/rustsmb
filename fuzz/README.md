# RustSMB Fuzz Testing

This directory contains fuzz targets for testing the SMB2/3 protocol parser using cargo-fuzz.

## Prerequisites

Fuzz testing requires:
- Rust nightly toolchain (>= 1.83.0)
- cargo-fuzz installed (`cargo install cargo-fuzz`)

## Setup

1. Install the nightly toolchain:
   ```bash
   rustup install nightly
   ```

2. Install cargo-fuzz:
   ```bash
   cargo install cargo-fuzz
   ```

## Available Fuzz Targets

| Target | Description |
|--------|-------------|
| `fuzz_smb2_header` | Fuzz the SMB2 header parser |
| `fuzz_negotiate` | Fuzz NEGOTIATE request/response parsing |
| `fuzz_create` | Fuzz CREATE request/response parsing |
| `fuzz_read_write` | Fuzz READ/WRITE request/response parsing |
| `fuzz_transform_header` | Fuzz the SMB2 transform (encryption) header |

## Running Fuzz Tests

From the project root:

```bash
# List available targets
cargo fuzz list

# Run a specific target
cargo fuzz run fuzz_smb2_header

# Run with a time limit (in seconds)
cargo fuzz run fuzz_smb2_header -- -max_total_time=300

# Run with multiple jobs
cargo fuzz run fuzz_smb2_header -- -jobs=4 -workers=4
```

## Corpus

Fuzz corpora are stored in `fuzz/corpus/<target_name>/`. You can seed the corpus
with valid SMB2 messages to improve fuzzing efficiency.

## Crashes

When a crash is found, it will be saved to `fuzz/artifacts/<target_name>/`. You can
reproduce the crash with:

```bash
cargo fuzz run fuzz_smb2_header fuzz/artifacts/fuzz_smb2_header/crash-<hash>
```

## Coverage

To generate coverage reports:

```bash
cargo fuzz coverage fuzz_smb2_header
```

## Minimizing Crashes

To minimize a crashing input:

```bash
cargo fuzz tmin fuzz_smb2_header fuzz/artifacts/fuzz_smb2_header/crash-<hash>
```
