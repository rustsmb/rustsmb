#!/bin/bash
# Download and compile smbtorture from Samba source
# This script builds smbtorture in the tests directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(dirname "$SCRIPT_DIR")"
SAMBA_DIR="$TESTS_DIR/samba"
INSTALL_DIR="$TESTS_DIR/smbtorture-bin"

# Samba version to build
SAMBA_VERSION="${SAMBA_VERSION:-4.19.4}"

echo "=== smbtorture Build Script ==="
echo "Samba version: $SAMBA_VERSION"
echo "Build directory: $SAMBA_DIR"
echo "Install directory: $INSTALL_DIR"
echo ""

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)
        echo "Detected: Linux"
        DEPS_CMD="sudo apt-get install -y build-essential python3-dev libgnutls28-dev libgpgme-dev libjansson-dev libarchive-dev libacl1-dev libldap2-dev libpam0g-dev liblmdb-dev libpopt-dev pkg-config flex bison perl python3-markdown python3-dnspython"
        ;;
    Darwin)
        echo "Detected: macOS"
        DEPS_CMD="brew install gnutls gpgme jansson libarchive lmdb popt flex bison perl python@3"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Install dependencies
install_deps() {
    echo "Installing build dependencies..."
    eval "$DEPS_CMD"
}

# Download Samba source
download_samba() {
    echo "Downloading Samba $SAMBA_VERSION..."

    if [ -d "$SAMBA_DIR" ]; then
        echo "Samba directory exists, skipping download"
        return
    fi

    TARBALL="samba-${SAMBA_VERSION}.tar.gz"
    URL="https://download.samba.org/pub/samba/stable/${TARBALL}"

    cd "$TESTS_DIR"
    curl -LO "$URL"
    tar xzf "$TARBALL"
    mv "samba-${SAMBA_VERSION}" samba
    rm "$TARBALL"
}

# Configure and build smbtorture only
build_smbtorture() {
    echo "Configuring Samba (smbtorture only)..."

    cd "$SAMBA_DIR"

    # Configure for minimal build with smbtorture
    # We only need the torture tests, not the full server
    ./configure \
        --prefix="$INSTALL_DIR" \
        --without-ad-dc \
        --without-ads \
        --without-ldap \
        --without-pam \
        --disable-python \
        --bundled-libraries=ALL \
        --private-libraries=ALL

    echo "Building smbtorture..."

    # Build only smbtorture and its dependencies
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) bin/smbtorture

    echo "Installing smbtorture..."
    mkdir -p "$INSTALL_DIR/bin"
    cp bin/smbtorture "$INSTALL_DIR/bin/"

    # Copy required shared libraries
    mkdir -p "$INSTALL_DIR/lib"
    if [ "$OS" = "Linux" ]; then
        ldd bin/smbtorture | grep "=>" | awk '{print $3}' | while read lib; do
            if [[ "$lib" == "$SAMBA_DIR"* ]]; then
                cp "$lib" "$INSTALL_DIR/lib/" 2>/dev/null || true
            fi
        done
    elif [ "$OS" = "Darwin" ]; then
        otool -L bin/smbtorture | tail -n +2 | awk '{print $1}' | while read lib; do
            if [[ "$lib" == "$SAMBA_DIR"* ]] || [[ "$lib" == @* ]]; then
                cp "$lib" "$INSTALL_DIR/lib/" 2>/dev/null || true
            fi
        done
    fi
}

# Create wrapper script
create_wrapper() {
    echo "Creating smbtorture wrapper..."

    cat > "$INSTALL_DIR/smbtorture" << 'EOF'
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LD_LIBRARY_PATH="$SCRIPT_DIR/lib:$LD_LIBRARY_PATH"
export DYLD_LIBRARY_PATH="$SCRIPT_DIR/lib:$DYLD_LIBRARY_PATH"
exec "$SCRIPT_DIR/bin/smbtorture" "$@"
EOF
    chmod +x "$INSTALL_DIR/smbtorture"
}

# Verify installation
verify() {
    echo ""
    echo "Verifying installation..."

    if [ -x "$INSTALL_DIR/smbtorture" ]; then
        echo "smbtorture installed successfully!"
        echo ""
        echo "Location: $INSTALL_DIR/smbtorture"
        echo ""
        echo "To use smbtorture:"
        echo "  $INSTALL_DIR/smbtorture --help"
        echo ""
        echo "To run tests against RustSMB:"
        echo "  $INSTALL_DIR/smbtorture //127.0.0.1:4450/test -N smb2.session"
        echo ""
        echo "Add to PATH (optional):"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        return 0
    else
        echo "ERROR: smbtorture installation failed!"
        return 1
    fi
}

# Clean build artifacts
clean() {
    echo "Cleaning build directory..."
    rm -rf "$SAMBA_DIR"
    echo "Done."
}

# Main
main() {
    case "${1:-build}" in
        deps)
            install_deps
            ;;
        download)
            download_samba
            ;;
        build)
            install_deps
            download_samba
            build_smbtorture
            create_wrapper
            verify
            ;;
        clean)
            clean
            ;;
        help|--help|-h)
            echo "Usage: $0 [deps|download|build|clean|help]"
            echo ""
            echo "Commands:"
            echo "  deps      Install build dependencies"
            echo "  download  Download Samba source"
            echo "  build     Full build (default)"
            echo "  clean     Remove build artifacts"
            echo "  help      Show this help"
            echo ""
            echo "Environment variables:"
            echo "  SAMBA_VERSION  Samba version to build (default: 4.19.4)"
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run '$0 help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
