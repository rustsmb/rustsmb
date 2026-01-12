# SMB Protocol Testing

This document describes how RustSMB is tested for SMB2/SMB3 protocol compliance.

## Overview

RustSMB uses multiple testing frameworks to ensure complete compliance with the MS-SMB2 specification:

1. **smbtorture** - Samba project's protocol torture tests
2. **Microsoft Protocol Test Suites** - Official conformance tests
3. **smbprotocol** - Python-based integration tests

## Quick Start

### Running smbtorture Tests

```bash
# Install smbtorture (Ubuntu/Debian)
sudo apt-get install samba-testsuite

# Or build from source (macOS/Linux)
./tests/scripts/install_smbtorture.sh

# Run via shell script (builds server and runs tests)
./tests/scripts/smbtorture.sh all

# Or run against an external server
./tests/scripts/run_smbtorture.sh localhost test testuser testpass
```

### Running Python Tests

```bash
# Install dependencies
pip install -r tests/python/requirements.txt

# Start RustSMB server (in another terminal)
cargo run -- --listen 127.0.0.1:445

# Run tests
cd tests/python && pytest -v
```

### Running MS Protocol Tests

```bash
# Setup (one-time)
./tests/ms-protocol/setup.sh

# Run tests (requires running server)
./tests/ms-protocol/run_tests.sh
```

## Test Categories

### Core Protocol (All 19 Commands)

| Command | smbtorture | MS Test Suite | Python Tests |
|---------|------------|---------------|--------------|
| NEGOTIATE | smb2.connect | Negotiate | test_negotiate.py |
| SESSION_SETUP | smb2.session | Session | test_session.py |
| LOGOFF | smb2.session | Session | test_session.py |
| TREE_CONNECT | smb2.tcon | TreeConnect | conftest.py |
| TREE_DISCONNECT | smb2.tcon | TreeConnect | conftest.py |
| CREATE | smb2.create | Create | test_create.py |
| CLOSE | smb2.create | Create | test_create.py |
| FLUSH | smb2.write | ReadWrite | - |
| READ | smb2.read | ReadWrite | test_read_write.py |
| WRITE | smb2.write | ReadWrite | test_read_write.py |
| LOCK | smb2.lock | Lock | - |
| IOCTL | smb2.ioctl | IOCTL | - |
| CANCEL | smb2.notify | - | - |
| ECHO | smb2.connect | - | - |
| QUERY_DIRECTORY | smb2.dir | QueryDirectory | - |
| CHANGE_NOTIFY | smb2.notify | ChangeNotify | - |
| QUERY_INFO | smb2.getinfo | QueryInfo | - |
| SET_INFO | smb2.setinfo | SetInfo | - |
| OPLOCK_BREAK | smb2.oplock | Lease | - |

### Advanced Features

| Feature | smbtorture | MS Test Suite | Python Tests |
|---------|------------|---------------|--------------|
| Leases (V1/V2) | smb2.lease | Lease | test_leases.py |
| Durable Handles V1 | smb2.durable-open | DurableHandle | - |
| Durable Handles V2 | smb2.durable-v2-open | DurableHandle | - |
| Persistent Handles | smb2.durable-v2-open | DurableHandle | - |
| Compound Requests | smb2.compound | Compound | - |
| Credit Management | smb2.credits | Credit | - |
| Message Signing | smb2.session | Signing | - |
| Encryption | smb2.session | Encryption | - |
| Multi-channel | smb2.multichannel | MultiChannel | - |

## smbtorture Test Suites

smbtorture provides the most comprehensive protocol-level testing. Here are the key test suites:

| Suite | Description | Tests |
|-------|-------------|-------|
| `smb2.connect` | Connection establishment, NEGOTIATE | Basic connectivity |
| `smb2.session` | SESSION_SETUP, authentication | NTLM, guest, binding |
| `smb2.tcon` | TREE_CONNECT operations | Share access |
| `smb2.create` | File creation, contexts | All create dispositions |
| `smb2.read` | Read operations | Offsets, large reads |
| `smb2.lock` | Byte-range locking | Exclusive, shared locks |
| `smb2.lease` | Lease handling | R, RH, RW, RWH leases |
| `smb2.oplock` | Opportunistic locks | Level 1, level 2, batch |
| `smb2.durable-open` | Durable handles v1 | Reconnect, timeout |
| `smb2.durable-v2-open` | Durable handles v2 | Persistent handles |
| `smb2.compound` | Compound requests | Related, unrelated |
| `smb2.credits` | Credit management | Multi-credit ops |
| `smb2.acls` | Access control lists | DACL, SACL |
| `smb2.streams` | Alternate data streams | ADS operations |

### Running Specific Test Suite

```bash
# Run specific suite
./tests/scripts/smbtorture.sh smb2.lease

# Or directly with smbtorture
smbtorture //localhost/test -Utestuser%testpass smb2.lease
```

## Microsoft Protocol Test Suites

The Microsoft Protocol Test Suites provide the most authoritative conformance testing, with 2000+ test cases.

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| BVT | ~100 | Basic verification tests |
| Negotiate | ~50 | Dialect negotiation |
| Session | ~30 | Session management |
| TreeConnect | ~20 | Share access |
| Create | ~100 | File operations |
| ReadWrite | ~40 | Data transfer |
| Lock | ~30 | File locking |
| Lease | ~80 | Lease management |
| DurableHandle | ~60 | Durable handles |
| Encryption | ~40 | SMB3 encryption |
| Signing | ~20 | Message signing |
| Compound | ~25 | Compound requests |

### Running by Category

```bash
# Run BVT (quick sanity check)
./tests/ms-protocol/run_tests.sh BVT

# Run lease tests
./tests/ms-protocol/run_tests.sh Lease

# Run all tests
./tests/ms-protocol/run_tests.sh All
```

## Python Test Suite

The Python tests using `smbprotocol` provide easy-to-read integration tests that are useful for debugging specific scenarios.

### Test Files

| File | Tests |
|------|-------|
| `test_negotiate.py` | Dialect negotiation, capabilities |
| `test_session.py` | Authentication, session management |
| `test_create.py` | File/directory creation, close |
| `test_read_write.py` | Data transfer operations |
| `test_leases.py` | Lease requests, conflicts |

### Environment Variables

```bash
# Configure test server
export RUSTSMB_SERVER=192.168.1.10
export RUSTSMB_PORT=445
export RUSTSMB_SHARE=test
export RUSTSMB_USER=testuser
export RUSTSMB_PASSWORD=testpass
```

## CI Integration

All tests run automatically in GitHub Actions. See `.github/workflows/ci.yml`.

### CI Test Jobs

1. **smbtorture-test**: Runs smbtorture against RustSMB
2. **python-smb-test**: Runs Python smbprotocol tests
3. **ms-protocol-test**: Runs MS Protocol Test Suites (optional)

## Debugging Test Failures

### Enable Verbose Logging

```bash
# Server-side logging
RUST_LOG=debug cargo run -- --listen 127.0.0.1:445

# Trace-level for protocol details
RUST_LOG=rustsmb=trace cargo run -- --listen 127.0.0.1:445
```

### Capture Network Traffic

```bash
# Capture SMB traffic
sudo tcpdump -i lo -w smb.pcap port 445

# Analyze with Wireshark
wireshark smb.pcap
```

### Common Issues

1. **Authentication failures**
   - Check NTLM challenge/response in logs
   - Verify username/password are correct
   - Check if guest access is enabled

2. **Lease conflicts**
   - Check Redis state: `redis-cli KEYS "*lease*"`
   - Verify lease cleanup on close
   - Check for stale leases from crashed connections

3. **Signing errors**
   - Verify session key derivation
   - Check signing algorithm (AES-CMAC vs AES-GMAC)
   - Ensure consistent signing policy

4. **Share not found**
   - Verify share is configured in server
   - Check share permissions
   - Verify backend path exists

## Test Results

Test results are saved to the `test-results/` directory:

```
test-results/
├── smbtorture/
│   ├── smb2_session.log
│   ├── smb2_lease.log
│   └── summary.txt
├── ms-protocol/
│   └── TestResults.trx
└── python/
    └── pytest.xml
```

## References

- [MS-SMB2 Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [Samba smbtorture Wiki](https://wiki.samba.org/index.php/Writing_Torture_Tests)
- [Microsoft Protocol Test Suites](https://github.com/microsoft/WindowsProtocolTestSuites)
- [smbprotocol Python Library](https://github.com/jborean93/smbprotocol)
- [SMB Protocol Overview](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview)
