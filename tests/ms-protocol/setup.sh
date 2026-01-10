#!/bin/bash
# Setup Microsoft Protocol Test Suites for RustSMB testing
#
# This script downloads and builds the Microsoft Protocol Test Suites
# for testing SMB2/SMB3 protocol conformance.
#
# Requirements:
#   - .NET 8 SDK
#   - Git
#
# Usage:
#   ./tests/ms-protocol/setup.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR/WindowsProtocolTestSuites"

echo "========================================"
echo "Microsoft Protocol Test Suites Setup"
echo "========================================"

# Check for .NET SDK
if ! command -v dotnet &> /dev/null; then
    echo "Installing .NET 8 SDK..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux installation
        wget https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh
        chmod +x /tmp/dotnet-install.sh
        /tmp/dotnet-install.sh --channel 8.0
        export PATH="$HOME/.dotnet:$PATH"
        export DOTNET_ROOT="$HOME/.dotnet"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS installation
        brew install --cask dotnet-sdk
    else
        echo "Error: Please install .NET 8 SDK manually"
        echo "Visit: https://dotnet.microsoft.com/download/dotnet/8.0"
        exit 1
    fi
fi

echo ".NET version: $(dotnet --version)"

# Clone test suite repository
if [ -d "$REPO_DIR" ]; then
    echo "Updating existing repository..."
    cd "$REPO_DIR"
    git pull
else
    echo "Cloning WindowsProtocolTestSuites..."
    git clone --depth 1 https://github.com/microsoft/WindowsProtocolTestSuites.git "$REPO_DIR"
fi

# Build FileServer test suite
echo "Building FileServer test suite..."
cd "$REPO_DIR/TestSuites/FileServer"

# Restore NuGet packages
dotnet restore src/FileServer.sln

# Build the solution
dotnet build src/FileServer.sln --configuration Release

echo ""
echo "========================================"
echo "Setup complete!"
echo ""
echo "Test suite location: $REPO_DIR/TestSuites/FileServer"
echo ""
echo "Next steps:"
echo "1. Configure test settings in:"
echo "   $SCRIPT_DIR/FileServer.ptfconfig"
echo ""
echo "2. Run tests with:"
echo "   ./tests/ms-protocol/run_tests.sh"
echo "========================================"
