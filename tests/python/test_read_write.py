"""
Tests for SMB READ and WRITE commands.

These tests verify data transfer operations.
"""

import os
import pytest
from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel

from conftest import create_test_file, delete_test_file, read_test_file


class TestRead:
    """Tests for READ command."""

    def test_read_small_file(self, tree, unique_filename):
        """Test reading a small file."""
        content = b"Hello, World!"
        create_test_file(tree, unique_filename, content)

        try:
            result = read_test_file(tree, unique_filename)
            assert result == content
        finally:
            delete_test_file(tree, unique_filename)

    def test_read_empty_file(self, tree, unique_filename):
        """Test reading an empty file returns END_OF_FILE per MS-SMB2 3.3.5.12."""
        from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
        from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel
        from smbprotocol.exceptions import EndOfFile

        create_test_file(tree, unique_filename, b"")

        try:
            # Per MS-SMB2 3.3.5.12: "If BytesRead is zero and Length is not zero,
            # the server MUST fail the request with STATUS_END_OF_FILE."
            file_open = Open(tree, unique_filename)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            try:
                with pytest.raises(EndOfFile):
                    file_open.read(0, 1024)  # Read with length > 0 should raise EndOfFile
            finally:
                file_open.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_read_at_offset(self, tree, unique_filename):
        """Test reading from a specific offset."""
        content = b"0123456789ABCDEF"
        create_test_file(tree, unique_filename, content)

        try:
            file_open = Open(tree, unique_filename)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Read from offset 10
            result = file_open.read(10, 6)
            assert result == b"ABCDEF"
            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_read_partial(self, tree, unique_filename):
        """Test reading partial content."""
        content = b"0123456789"
        create_test_file(tree, unique_filename, content)

        try:
            file_open = Open(tree, unique_filename)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Read only 5 bytes
            result = file_open.read(0, 5)
            assert result == b"01234"
            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)


class TestWrite:
    """Tests for WRITE command."""

    def test_write_new_file(self, tree, unique_filename):
        """Test writing to a new file."""
        content = b"Test content"

        file_open = Open(tree, unique_filename)
        try:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            bytes_written = file_open.write(content, 0)
            assert bytes_written == len(content)
            file_open.close()

            # Verify content
            result = read_test_file(tree, unique_filename)
            assert result == content
        finally:
            delete_test_file(tree, unique_filename)

    def test_write_at_offset(self, tree, unique_filename):
        """Test writing at a specific offset."""
        initial = b"0000000000"
        create_test_file(tree, unique_filename, initial)

        try:
            file_open = Open(tree, unique_filename)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Write "XXXX" at offset 3
            file_open.write(b"XXXX", 3)
            file_open.close()

            # Verify content
            result = read_test_file(tree, unique_filename)
            assert result == b"000XXXX000"
        finally:
            delete_test_file(tree, unique_filename)

    def test_write_append(self, tree, unique_filename):
        """Test appending to a file."""
        initial = b"Hello"
        create_test_file(tree, unique_filename, initial)

        try:
            file_open = Open(tree, unique_filename)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Append ", World!"
            file_open.write(b", World!", len(initial))
            file_open.close()

            # Verify content
            result = read_test_file(tree, unique_filename)
            assert result == b"Hello, World!"
        finally:
            delete_test_file(tree, unique_filename)

    def test_write_large_data(self, tree, unique_filename):
        """Test writing larger data (64KB)."""
        content = os.urandom(64 * 1024)  # 64KB of random data

        file_open = Open(tree, unique_filename)
        try:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            bytes_written = file_open.write(content, 0)
            assert bytes_written == len(content)
            file_open.close()

            # Verify content
            result = read_test_file(tree, unique_filename)
            assert result == content
        finally:
            delete_test_file(tree, unique_filename)


class TestReadWrite:
    """Combined read/write tests."""

    def test_read_after_write(self, tree, unique_filename):
        """Test reading immediately after writing."""
        file_open = Open(tree, unique_filename)
        try:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Write
            content = b"Test data"
            file_open.write(content, 0)

            # Read back
            result = file_open.read(0, len(content))
            assert result == content

            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_multiple_writes(self, tree, unique_filename):
        """Test multiple sequential writes."""
        file_open = Open(tree, unique_filename)
        try:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Multiple writes
            file_open.write(b"AAA", 0)
            file_open.write(b"BBB", 3)
            file_open.write(b"CCC", 6)

            # Read all
            result = file_open.read(0, 9)
            assert result == b"AAABBBCCC"

            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)
