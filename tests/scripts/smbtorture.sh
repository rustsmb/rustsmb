#!/bin/bash
# smbtorture test runner for RustSMB
#
# Usage:
#   ./smbtorture.sh [suite|all]
#
# Examples:
#   ./smbtorture.sh              # Run all suites
#   ./smbtorture.sh all          # Run all suites
#   ./smbtorture.sh smb2.connect # Run specific suite
#
# Environment variables:
#   RUSTSMB_BIN     - Path to RustSMB server binary (default: ./target/release/rustsmb)
#   SMB_PORT        - Port to listen on (default: 445)
#   SMB_SHARE       - Share name (default: test)
#   SMB_SHARE_PATH  - Share directory path (default: /tmp/share)

set -e

SUITE="${1:-all}"
PORT="${SMB_PORT:-445}"
SHARE="${SMB_SHARE:-test}"
SHARE_PATH="${SMB_SHARE_PATH:-/tmp/share}"
SERVER_BIN="${RUSTSMB_BIN:-./target/release/rustsmb}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# All SMB2 test suites
SUITES=(
    "smb2.connect"
    "smb2.session"
    "smb2.tcon"
    "smb2.create"
    "smb2.read"
    "smb2.lock"
    "smb2.lease"
    "smb2.oplock"
    "smb2.durable-open"
    "smb2.durable-v2-open"
    "smb2.compound"
    "smb2.credits"
    "smb2.dir"
    "smb2.getinfo"
    "smb2.setinfo"
    "smb2.notify"
    "smb2.ioctl"
    "smb2.streams"
    "smb2.delete-on-close"
    "smb2.deny"
    "smb2.sharemode"
    "smb2.replay"
    "smb2.acls"
)

# Start the RustSMB server
echo "Starting RustSMB server on port $PORT..."
echo "Using binary: $SERVER_BIN"
mkdir -p "$SHARE_PATH"
"$SERVER_BIN" --listen "127.0.0.1:$PORT" --share-path "$SHARE_PATH" &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}Error: Server failed to start${NC}"
    exit 1
fi

echo "Server started (PID: $SERVER_PID)"
echo ""

# Function to run a single test suite
run_suite() {
    local suite=$1
    echo -n "Running $suite... "

    if smbtorture "//127.0.0.1/$SHARE" -N "$suite" > "/tmp/${suite//\./_}.log" 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi
}

# Run tests
FAILED=0
PASSED=0
TOTAL=0
FAILED_SUITES=()

if [ "$SUITE" = "all" ]; then
    echo "Running all SMB2 test suites..."
    echo "========================================"

    for suite in "${SUITES[@]}"; do
        if run_suite "$suite"; then
            ((PASSED++))
        else
            ((FAILED++))
            FAILED_SUITES+=("$suite")
        fi
        ((TOTAL++))
    done
else
    # Run single suite
    echo "Running suite: $SUITE"
    echo "========================================"

    if smbtorture "//127.0.0.1/$SHARE" -N "$SUITE"; then
        PASSED=1
    else
        FAILED=1
        FAILED_SUITES+=("$SUITE")
    fi
    TOTAL=1
fi

# Stop server
kill $SERVER_PID 2>/dev/null || true

# Print summary
echo ""
echo "========================================"
echo -e "Results: ${GREEN}$PASSED${NC}/${TOTAL} passed, ${RED}$FAILED${NC} failed"
echo "========================================"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed suites:"
    for suite in "${FAILED_SUITES[@]}"; do
        echo "  - $suite"
        echo "    Log: /tmp/${suite//\./_}.log"
    done

    # Show last few lines of failed logs
    echo ""
    echo "=== Failed test output ==="
    for suite in "${FAILED_SUITES[@]}"; do
        echo "--- $suite ---"
        tail -20 "/tmp/${suite//\./_}.log" 2>/dev/null || true
        echo ""
    done
fi

# Exit with failure if any tests failed
exit $FAILED
