#!/bin/bash
# smbtorture test runner - client only
#
# This script runs smbtorture tests against an SMB server.
# Designed to run inside Docker, connecting to a host SMB server.
#
# Usage:
#   ./smbtorture.sh [suite|all]
#
# Examples:
#   ./smbtorture.sh                    # Run all suites
#   ./smbtorture.sh all                # Run all suites
#   ./smbtorture.sh smb2.connect       # Run specific suite
#   ./smbtorture.sh smb2.durable-open  # Run durable handle tests
#
# Environment variables:
#   SMB_HOST        - Server hostname (default: host.docker.internal)
#   SMB_PORT        - Server port (default: 4450)
#   SMB_SHARE       - Share name (default: test)
#   SMB_USER        - Username for auth (default: testuser)
#   SMB_PASS        - Password for auth (default: testpass)
#   RESULTS_DIR     - Where to save logs (default: test-results/smbtorture)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Parse command line arguments
SUITE="${1:-all}"

# Configuration from environment
SERVER_HOST="${SMB_HOST:-host.docker.internal}"
PORT="${SMB_PORT:-4450}"
SHARE="${SMB_SHARE:-test}"
SMB_USER="${SMB_USER:-testuser}"
SMB_PASS="${SMB_PASS:-testpass}"
RESULTS_DIR="${RESULTS_DIR:-test-results/smbtorture}"

# Build auth flag
if [ -n "$SMB_USER" ]; then
    AUTH_FLAG="-U${SMB_USER}%${SMB_PASS}"
else
    AUTH_FLAG="-N"
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

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
    "smb2.multichannel"
)

# Wait for server to be ready
wait_for_server() {
    local max_attempts=30
    echo -n "Waiting for $SERVER_HOST:$PORT... "
    for i in $(seq 1 $max_attempts); do
        if timeout 1 bash -c "echo >/dev/tcp/$SERVER_HOST/$PORT" 2>/dev/null; then
            echo "ready"
            return 0
        fi
        sleep 0.5
    done
    echo "timeout"
    return 1
}

# Wait for server
if ! wait_for_server; then
    echo -e "${RED}Error: Cannot connect to SMB server at $SERVER_HOST:$PORT${NC}"
    echo "Make sure the RustSMB server is running on the host."
    exit 1
fi

# Function to run a single test suite
run_suite() {
    local suite=$1
    local logfile="$RESULTS_DIR/${suite//\./_}.log"

    echo -n "Running $suite... "

    if smbtorture "//$SERVER_HOST:$PORT/$SHARE" $AUTH_FLAG "$suite" > "$logfile" 2>&1; then
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

echo "========================================"
echo "smbtorture SMB2 Test Suite"
echo "Server: $SERVER_HOST:$PORT"
echo "Share: $SHARE"
echo "Auth: ${SMB_USER:-anonymous}"
echo "Results: $RESULTS_DIR"
echo "========================================"
echo ""

if [ "$SUITE" = "all" ]; then
    echo "Running all SMB2 test suites..."
    echo ""

    for suite in "${SUITES[@]}"; do
        if run_suite "$suite"; then
            ((++PASSED))
        else
            ((++FAILED))
            FAILED_SUITES+=("$suite")
        fi
        ((++TOTAL))
    done
else
    # Run single suite
    echo "Running suite: $SUITE"
    echo ""

    logfile="$RESULTS_DIR/${SUITE//\./_}.log"
    if smbtorture "//$SERVER_HOST:$PORT/$SHARE" $AUTH_FLAG "$SUITE" 2>&1 | tee "$logfile"; then
        PASSED=1
    else
        FAILED=1
        FAILED_SUITES+=("$SUITE")
    fi
    TOTAL=1
fi

# Print summary
echo ""
echo "========================================"
echo -e "Results: ${GREEN}$PASSED${NC}/${TOTAL} passed, ${RED}$FAILED${NC} failed"
echo "========================================"

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "Failed suites:"
    for suite in "${FAILED_SUITES[@]}"; do
        echo "  - $suite (see $RESULTS_DIR/${suite//\./_}.log)"
    done

    # Show last few lines of failed logs
    echo ""
    echo "=== Failed test output ==="
    for suite in "${FAILED_SUITES[@]}"; do
        echo "--- $suite ---"
        tail -20 "$RESULTS_DIR/${suite//\./_}.log" 2>/dev/null || true
        echo ""
    done
fi

# Generate summary file
cat > "$RESULTS_DIR/summary.txt" << EOF
smbtorture Test Results
=======================
Date: $(date)
Server: $SERVER_HOST:$PORT
Share: $SHARE
Auth: ${SMB_USER:-anonymous}

Results: $PASSED/$TOTAL passed ($FAILED failed)

Failed suites:
$(printf '%s\n' "${FAILED_SUITES[@]}")
EOF

# Exit with failure if any tests failed
exit $FAILED
