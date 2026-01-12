#!/bin/bash
# smbtorture test runner for RustSMB
#
# Usage:
#   ./smbtorture.sh [suite|all]                    # Start server and run tests
#   ./smbtorture.sh [suite|all] --external HOST    # Test external server
#
# Examples:
#   ./smbtorture.sh                    # Run all suites (starts local server)
#   ./smbtorture.sh all                # Run all suites (starts local server)
#   ./smbtorture.sh smb2.connect       # Run specific suite
#   ./smbtorture.sh all --external localhost:445   # Test external server
#   ./smbtorture.sh smb2.session --external 192.168.1.10 --user testuser --pass secret
#
# Environment variables:
#   RUSTSMB_BIN     - Path to RustSMB server binary (default: ./target/release/rustsmb)
#   SMB_PORT        - Port to listen on (default: 445)
#   SMB_SHARE       - Share name (default: test)
#   SMB_SHARE_PATH  - Share directory path (default: /tmp/share)
#   SMB_USER        - Username for auth (empty = anonymous)
#   SMB_PASS        - Password for auth
#   RESULTS_DIR     - Where to save logs (default: test-results/smbtorture)
#   RUST_LOG        - Log level for server (default: info)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Parse command line arguments
SUITE=""
EXTERNAL_HOST=""
EXTERNAL_PORT=""
CLI_USER=""
CLI_PASS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --external)
            EXTERNAL_HOST="$2"
            # Parse host:port if provided
            if [[ "$EXTERNAL_HOST" == *:* ]]; then
                EXTERNAL_PORT="${EXTERNAL_HOST##*:}"
                EXTERNAL_HOST="${EXTERNAL_HOST%%:*}"
            fi
            shift 2
            ;;
        --user)
            CLI_USER="$2"
            shift 2
            ;;
        --pass)
            CLI_PASS="$2"
            shift 2
            ;;
        --help|-h)
            head -24 "$0" | tail -22
            exit 0
            ;;
        *)
            SUITE="$1"
            shift
            ;;
    esac
done

# Defaults
SUITE="${SUITE:-all}"
PORT="${EXTERNAL_PORT:-${SMB_PORT:-445}}"
SHARE="${SMB_SHARE:-test}"
SHARE_PATH="${SMB_SHARE_PATH:-/tmp/share}"
SERVER_BIN="${RUSTSMB_BIN:-./target/release/rustsmb}"
RESULTS_DIR="${RESULTS_DIR:-test-results/smbtorture}"
SMB_USER="${CLI_USER:-${SMB_USER:-}}"
SMB_PASS="${CLI_PASS:-${SMB_PASS:-}}"

# Determine server host
if [ -n "$EXTERNAL_HOST" ]; then
    SERVER_HOST="$EXTERNAL_HOST"
    EXTERNAL_MODE=true
else
    SERVER_HOST="127.0.0.1"
    EXTERNAL_MODE=false
fi

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

# Server PID (global for cleanup)
SERVER_PID=""

# Cleanup function - ensures server is killed on any exit
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# Wait for port to be available
wait_for_port() {
    local host=$1
    local port=$2
    local max_attempts=30

    echo -n "Waiting for $host:$port... "
    for i in $(seq 1 $max_attempts); do
        # Use bash's built-in /dev/tcp (more portable than nc)
        if (echo >/dev/tcp/"$host"/"$port") 2>/dev/null; then
            echo "ready"
            return 0
        fi
        sleep 0.1
    done
    echo "timeout"
    return 1
}

# Start local server if not in external mode
if [ "$EXTERNAL_MODE" = false ]; then
    echo "Starting RustSMB server on port $PORT..."
    echo "Using binary: $SERVER_BIN"

    # Create and clean share directory
    mkdir -p "$SHARE_PATH"

    # Start server in background
    "$SERVER_BIN" --listen "127.0.0.1:$PORT" --share-path "$SHARE_PATH" &
    SERVER_PID=$!

    # Wait for server to be ready
    if ! wait_for_port "127.0.0.1" "$PORT"; then
        echo -e "${RED}Error: Server failed to start${NC}"
        exit 1
    fi

    echo "Server started (PID: $SERVER_PID)"
else
    echo "Using external server: $SERVER_HOST:$PORT"
fi

echo ""

# Function to run a single test suite
run_suite() {
    local suite=$1
    local logfile="$RESULTS_DIR/${suite//\./_}.log"

    echo -n "Running $suite... "

    if smbtorture "//$SERVER_HOST/$SHARE" $AUTH_FLAG "$suite" > "$logfile" 2>&1; then
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
    echo ""

    logfile="$RESULTS_DIR/${SUITE//\./_}.log"
    if smbtorture "//$SERVER_HOST/$SHARE" $AUTH_FLAG "$SUITE" 2>&1 | tee "$logfile"; then
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
