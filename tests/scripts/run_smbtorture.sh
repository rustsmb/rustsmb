#!/bin/bash
# Run smbtorture tests with host server + Docker client
#
# This script:
#   1. Builds and starts the RustSMB server on the host
#   2. Runs smbtorture tests in Docker
#   3. Cleans up when done
#
# Usage:
#   ./run_smbtorture.sh [suite]       # Run tests (default: all)
#   ./run_smbtorture.sh smb2.connect  # Run specific suite
#   ./run_smbtorture.sh --build-only  # Just build, don't run tests
#
# Environment variables:
#   SMB_PORT        - Port for server (default: 4450)
#   RUST_LOG        - Server log level (default: info)
#   SKIP_BUILD      - Set to 1 to skip cargo build

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SUITE="${1:-all}"

# Configuration
PORT="${SMB_PORT:-4450}"
SHARE_PATH="/tmp/rustsmb-test-share"
DOCKER_IMAGE="smbtorture-client"
RESULTS_DIR="$PROJECT_ROOT/test-results/smbtorture"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Server PID for cleanup
SERVER_PID=""

cleanup() {
    echo ""
    echo "Cleaning up..."
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        echo "Server stopped"
    fi
}
trap cleanup EXIT INT TERM

echo "========================================"
echo "RustSMB smbtorture Test Runner"
echo "========================================"
echo ""

# Handle --build-only flag
if [ "$SUITE" = "--build-only" ]; then
    echo "Building server and Docker image only..."
    cd "$PROJECT_ROOT"
    cargo build --release --package rustsmb
    docker build -f tests/Dockerfile.smbtorture -t "$DOCKER_IMAGE" tests/
    echo -e "${GREEN}Build complete${NC}"
    exit 0
fi

# Step 1: Build server (unless SKIP_BUILD=1)
if [ "${SKIP_BUILD:-0}" != "1" ]; then
    echo "Building RustSMB server..."
    cd "$PROJECT_ROOT"
    cargo build --release --package rustsmb
    echo ""
fi

# Step 2: Build Docker image if needed
if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    echo "Building smbtorture Docker image..."
    docker build -f tests/Dockerfile.smbtorture -t "$DOCKER_IMAGE" tests/
    echo ""
fi

# Step 3: Prepare share directory
mkdir -p "$SHARE_PATH"
rm -rf "$SHARE_PATH"/*

# Step 4: Start server
echo "Starting RustSMB server on port $PORT..."
"$PROJECT_ROOT/target/release/rustsmb" \
    --listen "0.0.0.0:$PORT" \
    --share-path "$SHARE_PATH" \
    &
SERVER_PID=$!

# Wait for server to be ready
echo -n "Waiting for server... "
for i in $(seq 1 30); do
    if (echo >/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
        echo "ready (PID: $SERVER_PID)"
        break
    fi
    sleep 0.2
done

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Server failed to start${NC}"
    exit 1
fi

echo ""

# Step 5: Create results directory
mkdir -p "$RESULTS_DIR"

# Step 6: Run smbtorture in Docker
echo "Running smbtorture tests..."
echo ""

# Determine Docker host access method
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - use host.docker.internal
    HOST_FLAG="--add-host=host.docker.internal:host-gateway"
else
    # Linux - use host network
    HOST_FLAG="--network=host"
fi

docker run --rm \
    $HOST_FLAG \
    -e SMB_PORT="$PORT" \
    -v "$RESULTS_DIR:/app/test-results" \
    "$DOCKER_IMAGE" \
    "$SUITE"

EXIT_CODE=$?

echo ""
echo "Results saved to: $RESULTS_DIR"

exit $EXIT_CODE
