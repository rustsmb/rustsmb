#!/bin/bash
# Run ALL smbtorture SMB2 tests against RustSMB
#
# Usage:
#   ./tests/scripts/run_smbtorture.sh [server] [share] [user] [pass]
#
# Examples:
#   ./tests/scripts/run_smbtorture.sh localhost test testuser testpass
#   ./tests/scripts/run_smbtorture.sh 192.168.1.10 share admin secret
#
# Or run tests/scripts/smbtorture.sh which starts its own server:
#   ./tests/scripts/smbtorture.sh all

set -e

SERVER="${1:-localhost}"
SHARE="${2:-test}"
USER="${3:-testuser}"
PASS="${4:-testpass}"
RESULTS_DIR="${RESULTS_DIR:-test-results/smbtorture}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if smbtorture is installed
if ! command -v smbtorture &> /dev/null; then
    echo -e "${RED}Error: smbtorture not found${NC}"
    echo "Install with: sudo apt-get install samba-testsuite"
    exit 1
fi

mkdir -p "$RESULTS_DIR"

# Function to run test suite and capture results
run_suite() {
    local suite=$1
    local logfile="$RESULTS_DIR/${suite//\./_}.log"

    echo -n "Running $suite... "

    if smbtorture "//$SERVER/$SHARE" -U"$USER%$PASS" "$suite" > "$logfile" 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi
}

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

echo "========================================"
echo "smbtorture SMB2 Test Suite"
echo "Server: $SERVER"
echo "Share: $SHARE"
echo "User: $USER"
echo "Results: $RESULTS_DIR"
echo "========================================"
echo ""

FAILED=0
PASSED=0
TOTAL=0
FAILED_SUITES=()

for suite in "${SUITES[@]}"; do
    if run_suite "$suite"; then
        ((PASSED++))
    else
        ((FAILED++))
        FAILED_SUITES+=("$suite")
    fi
    ((TOTAL++))
done

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
fi

# Generate summary file
cat > "$RESULTS_DIR/summary.txt" << EOF
smbtorture Test Results
=======================
Date: $(date)
Server: $SERVER
Share: $SHARE

Results: $PASSED/$TOTAL passed ($FAILED failed)

Failed suites:
$(printf '%s\n' "${FAILED_SUITES[@]}")
EOF

# Exit with failure if any tests failed
[ $FAILED -eq 0 ]
