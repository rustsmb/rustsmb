#!/bin/bash
# Run Microsoft Protocol Test Suites against RustSMB
#
# Usage:
#   ./tests/ms-protocol/run_tests.sh [category]
#
# Categories:
#   - BVT: Basic Verification Tests (quick sanity check)
#   - Negotiate: Dialect negotiation tests
#   - Session: Session management tests
#   - TreeConnect: Share connection tests
#   - Create: File creation tests
#   - ReadWrite: Read/write operation tests
#   - Lock: File locking tests
#   - Lease: Lease management tests
#   - DurableHandle: Durable handle tests
#   - Compound: Compound request tests
#   - All: Run all tests (default)
#
# Examples:
#   ./tests/ms-protocol/run_tests.sh BVT
#   ./tests/ms-protocol/run_tests.sh Lease
#   ./tests/ms-protocol/run_tests.sh All

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/WindowsProtocolTestSuites"
TEST_DIR="$REPO_DIR/TestSuites/FileServer"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/../../test-results/ms-protocol}"
CATEGORY="${1:-All}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "Microsoft Protocol Test Suites"
echo "Category: $CATEGORY"
echo "========================================"

# Check if test suite is set up
if [ ! -d "$TEST_DIR" ]; then
    echo -e "${RED}Error: Test suite not found${NC}"
    echo "Run ./tests/ms-protocol/setup.sh first"
    exit 1
fi

mkdir -p "$RESULTS_DIR"

# Copy configuration
cp "$SCRIPT_DIR/FileServer.ptfconfig" "$TEST_DIR/src/MS-SMB2/TestSuite/MS-SMB2_ServerTestSuite.ptfconfig" 2>/dev/null || true

# Build filter based on category
FILTER=""
case $CATEGORY in
    BVT)
        FILTER="Category=BVT"
        ;;
    Negotiate)
        FILTER="FullyQualifiedName~Negotiate"
        ;;
    Session)
        FILTER="FullyQualifiedName~Session"
        ;;
    TreeConnect)
        FILTER="FullyQualifiedName~TreeConnect"
        ;;
    Create)
        FILTER="FullyQualifiedName~Create"
        ;;
    ReadWrite)
        FILTER="FullyQualifiedName~Read|FullyQualifiedName~Write"
        ;;
    Lock)
        FILTER="FullyQualifiedName~Lock"
        ;;
    Lease)
        FILTER="FullyQualifiedName~Lease"
        ;;
    DurableHandle)
        FILTER="FullyQualifiedName~DurableHandle"
        ;;
    Compound)
        FILTER="FullyQualifiedName~Compound"
        ;;
    All)
        FILTER=""
        ;;
    *)
        echo -e "${YELLOW}Unknown category: $CATEGORY${NC}"
        echo "Using as custom filter..."
        FILTER="$CATEGORY"
        ;;
esac

# Run tests
cd "$TEST_DIR"

echo "Running tests..."
echo ""

if [ -n "$FILTER" ]; then
    dotnet test src/MS-SMB2/TestSuite/MS-SMB2_ServerTestSuite.csproj \
        --configuration Release \
        --filter "$FILTER" \
        --logger "trx;LogFileName=$RESULTS_DIR/TestResults.trx" \
        --logger "console;verbosity=normal" \
        2>&1 | tee "$RESULTS_DIR/test_output.log"
else
    dotnet test src/MS-SMB2/TestSuite/MS-SMB2_ServerTestSuite.csproj \
        --configuration Release \
        --logger "trx;LogFileName=$RESULTS_DIR/TestResults.trx" \
        --logger "console;verbosity=normal" \
        2>&1 | tee "$RESULTS_DIR/test_output.log"
fi

RESULT=$?

echo ""
echo "========================================"
if [ $RESULT -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed${NC}"
fi
echo "Results saved to: $RESULTS_DIR"
echo "========================================"

exit $RESULT
