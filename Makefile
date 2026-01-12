.PHONY: all build check test clippy fmt clean doc bench install smbtorture-test smbtorture-build

# Default target
all: check test

# Build all crates in release mode
build:
	cargo build --workspace --release

# Build in debug mode
build-debug:
	cargo build --workspace

# Type check without building
check:
	cargo check --workspace

# Run all tests
test:
	cargo test --workspace

# Run tests with output
test-verbose:
	cargo test --workspace -- --nocapture

# Run clippy lints
clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting without modifying
fmt-check:
	cargo fmt --all -- --check

# Generate documentation
doc:
	cargo doc --workspace --no-deps

# Open documentation in browser
doc-open:
	cargo doc --workspace --no-deps --open

# Run benchmarks
bench:
	cargo bench

# Clean build artifacts
clean:
	cargo clean

# Install the binary
install:
	cargo install --path .

# Run the server (debug mode)
run:
	cargo run

# Run the server (release mode)
run-release:
	cargo run --release

# Full CI check (what CI runs)
ci: fmt-check clippy test
	@echo "CI checks passed!"

# Watch for changes and run tests
watch:
	cargo watch -x test

# Watch for changes and check
watch-check:
	cargo watch -x check

# Update dependencies
update:
	cargo update

# Show outdated dependencies
outdated:
	cargo outdated

# Security audit
audit:
	cargo audit

# Generate coverage report (requires cargo-tarpaulin)
coverage:
	cargo tarpaulin --workspace --out Html

# Build smbtorture test Docker image
smbtorture-build:
	docker build -f tests/Dockerfile.smbtorture -t rustsmb-smbtorture .

# Run smbtorture tests in Docker (builds image if needed)
smbtorture-test: smbtorture-build
	docker run --rm rustsmb-smbtorture

# Run specific smbtorture suite (e.g., make smbtorture-suite SUITE=smb2.connect)
smbtorture-suite: smbtorture-build
	docker run --rm rustsmb-smbtorture $(SUITE)

# Run smbtorture with debug output
smbtorture-debug: smbtorture-build
	docker run --rm -e RUST_LOG=debug rustsmb-smbtorture $(SUITE)

# Help
help:
	@echo "RustSMB Makefile targets:"
	@echo ""
	@echo "  all          - Run check and test (default)"
	@echo "  build        - Build all crates (release)"
	@echo "  build-debug  - Build all crates (debug)"
	@echo "  check        - Type check without building"
	@echo "  test         - Run all tests"
	@echo "  test-verbose - Run tests with output"
	@echo "  clippy       - Run clippy lints"
	@echo "  fmt          - Format code"
	@echo "  fmt-check    - Check formatting"
	@echo "  doc          - Generate documentation"
	@echo "  doc-open     - Generate and open documentation"
	@echo "  bench        - Run benchmarks"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install the binary"
	@echo "  run          - Run the server (debug)"
	@echo "  run-release  - Run the server (release)"
	@echo "  ci           - Run full CI checks"
	@echo "  watch        - Watch and run tests"
	@echo "  watch-check  - Watch and check"
	@echo "  update       - Update dependencies"
	@echo "  outdated     - Show outdated dependencies"
	@echo "  audit        - Security audit"
	@echo "  coverage     - Generate coverage report"
	@echo "  smbtorture-build - Build smbtorture Docker image"
	@echo "  smbtorture-test  - Run smbtorture tests in Docker"
	@echo "  smbtorture-suite - Run specific suite (SUITE=smb2.connect)"
	@echo "  smbtorture-debug - Run with debug logging"
	@echo "  help         - Show this help"
