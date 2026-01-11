#!/bin/bash
# Run Python tests against RustSMB server
# Usage: ./tests/scripts/run_python_tests.sh [pytest args]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PYTHON_TEST_DIR="$PROJECT_DIR/tests/python"

# Configuration
PORT="${RUSTSMB_PORT:-4450}"
SERVER="${RUSTSMB_SERVER:-127.0.0.1}"
SHARE="${RUSTSMB_SHARE:-test}"
USER="${RUSTSMB_USER:-testuser}"
PASS="${RUSTSMB_PASSWORD:-testpass}"

# Build server
echo "Building server..."
cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1 | tail -3

# Kill any existing server on our port
pkill -f "rustsmb --listen.*:$PORT" 2>/dev/null || true
sleep 1

# Start server in background
echo "Starting server on $SERVER:$PORT..."
RUST_LOG=info "$PROJECT_DIR/target/release/rustsmb" --listen "$SERVER:$PORT" > /tmp/rustsmb-test.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Server failed to start! Logs:"
    cat /tmp/rustsmb-test.log
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping server..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Run Python tests
echo ""
echo "Running Python tests..."
cd "$PYTHON_TEST_DIR"
RUSTSMB_SERVER="$SERVER" \
RUSTSMB_PORT="$PORT" \
RUSTSMB_SHARE="$SHARE" \
RUSTSMB_USER="$USER" \
RUSTSMB_PASSWORD="$PASS" \
python3.10 -m pytest "$@"

echo ""
echo "Tests completed!"
