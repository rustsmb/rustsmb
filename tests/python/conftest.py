"""
Pytest configuration and fixtures for RustSMB testing.

This module provides fixtures for connecting to and testing
the RustSMB server using the smbprotocol library.
"""

import os
import uuid
import subprocess
import time
import socket
import pytest
from contextlib import contextmanager

import smbprotocol
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


# Test configuration from environment variables
SMB_SERVER = os.environ.get("RUSTSMB_SERVER", "127.0.0.1")
SMB_PORT = int(os.environ.get("RUSTSMB_PORT", "445"))
SMB_SHARE = os.environ.get("RUSTSMB_SHARE", "test")
SMB_USER = os.environ.get("RUSTSMB_USER", "testuser")
SMB_PASSWORD = os.environ.get("RUSTSMB_PASSWORD", "testpass")
SMB_DOMAIN = os.environ.get("RUSTSMB_DOMAIN", "WORKGROUP")

# Whether to start a local server for testing
START_LOCAL_SERVER = os.environ.get("RUSTSMB_START_SERVER", "false").lower() == "true"


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait for a port to become available."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (socket.timeout, socket.error):
            time.sleep(0.1)
    return False


@pytest.fixture(scope="session")
def server_addr() -> str:
    """Return the SMB server address."""
    return SMB_SERVER


@pytest.fixture(scope="session")
def server_port() -> int:
    """Return the SMB server port."""
    return SMB_PORT


@pytest.fixture(scope="session")
def share_name() -> str:
    """Return the test share name."""
    return SMB_SHARE


@pytest.fixture(scope="session")
def credentials() -> tuple:
    """Return test credentials as (username, password, domain)."""
    return (SMB_USER, SMB_PASSWORD, SMB_DOMAIN)


@pytest.fixture(scope="function")
def connection(server_addr: str, server_port: int):
    """
    Create an SMB connection to the test server.

    This fixture provides a connected SMB connection that is automatically
    disconnected after the test completes.
    """
    conn = Connection(
        uuid.uuid4(),
        server_addr,
        server_port,
    )
    conn.connect()
    yield conn
    conn.disconnect()


@pytest.fixture(scope="function")
def session(connection: Connection, credentials: tuple):
    """
    Create an authenticated SMB session.

    This fixture provides an authenticated session that is automatically
    logged off after the test completes.
    """
    username, password, domain = credentials
    sess = Session(
        connection,
        username=username,
        password=password,
        domain=domain,
        require_encryption=False,
    )
    sess.connect()
    yield sess
    sess.disconnect()


@pytest.fixture(scope="function")
def tree(session: Session, share_name: str):
    """
    Create a tree connection to the test share.

    This fixture provides a tree connection that is automatically
    disconnected after the test completes.
    """
    tree = TreeConnect(
        session,
        f"\\\\{session.connection.server_name}\\{share_name}",
    )
    tree.connect()
    yield tree
    tree.disconnect()


@pytest.fixture(scope="function")
def unique_filename() -> str:
    """Generate a unique filename for test files."""
    return f"test_{uuid.uuid4().hex[:8]}.txt"


@pytest.fixture(scope="function")
def unique_dirname() -> str:
    """Generate a unique directory name for test directories."""
    return f"testdir_{uuid.uuid4().hex[:8]}"


# Dialect constants for reference
class Dialects:
    SMB2_002 = "2.0.2"
    SMB2_1 = "2.1"
    SMB3_0 = "3.0"
    SMB3_0_2 = "3.0.2"
    SMB3_1_1 = "3.1.1"


# Lease state constants
class LeaseState:
    NONE = 0x00
    READ_CACHING = 0x01
    HANDLE_CACHING = 0x02
    WRITE_CACHING = 0x04
    READ_HANDLE = READ_CACHING | HANDLE_CACHING
    READ_WRITE = READ_CACHING | WRITE_CACHING
    READ_WRITE_HANDLE = READ_CACHING | WRITE_CACHING | HANDLE_CACHING


# Helper functions for tests
def create_test_file(tree, filename: str, content: bytes = b"test content") -> None:
    """Create a test file on the share."""
    from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
    from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel

    file_open = Open(tree, filename)
    file_open.create(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.GENERIC_WRITE | FilePipePrinterAccessMask.GENERIC_READ,
        0,
        ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
        CreateDisposition.FILE_OVERWRITE_IF,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
    )
    file_open.write(content, 0)
    file_open.close()


def delete_test_file(tree, filename: str) -> None:
    """Delete a test file from the share."""
    from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
    from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel
    from smbprotocol.file_info import FileDispositionInformation

    try:
        file_open = Open(tree, filename)
        file_open.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.DELETE,
            0,
            ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
        )
        file_open.close()
    except Exception:
        pass  # File may not exist


def read_test_file(tree, filename: str) -> bytes:
    """Read content from a test file."""
    from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
    from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel

    file_open = Open(tree, filename)
    file_open.create(
        ImpersonationLevel.Impersonation,
        FilePipePrinterAccessMask.GENERIC_READ,
        0,
        ShareAccess.FILE_SHARE_READ,
        CreateDisposition.FILE_OPEN,
        CreateOptions.FILE_NON_DIRECTORY_FILE,
    )
    content = file_open.read(0, 1024 * 1024)  # Read up to 1MB
    file_open.close()
    return content
