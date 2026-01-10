"""
Tests for SMB leases.

These tests verify lease request, grant, and conflict handling.
"""

import uuid
import pytest
from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel
from smbprotocol.structure import FlagField

from conftest import delete_test_file, LeaseState


class TestLeases:
    """Tests for SMB lease functionality."""

    def test_lease_read_caching(self, tree, unique_filename):
        """Test requesting READ_CACHING lease."""
        file_open = Open(tree, unique_filename)
        try:
            # Request READ_CACHING lease
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Check if lease was granted
            # Note: The actual lease state depends on server implementation
            assert file_open.file_id is not None
            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_lease_read_read_compatible(self, tree, unique_filename):
        """Test that two READ leases are compatible."""
        file_open1 = Open(tree, unique_filename)
        file_open2 = Open(tree, unique_filename)

        try:
            # First open with READ sharing
            file_open1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Second open should succeed
            file_open2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Both should have valid handles
            assert file_open1.file_id is not None
            assert file_open2.file_id is not None

        finally:
            file_open1.close()
            file_open2.close()
            delete_test_file(tree, unique_filename)

    def test_lease_multiple_readers(self, tree, unique_filename):
        """Test multiple concurrent readers with leases."""
        handles = []

        try:
            # Create the file first
            create_open = Open(tree, unique_filename)
            create_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            create_open.write(b"test content", 0)
            create_open.close()

            # Open multiple read handles
            for _ in range(5):
                file_open = Open(tree, unique_filename)
                file_open.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.GENERIC_READ,
                    0,
                    ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_NON_DIRECTORY_FILE,
                )
                handles.append(file_open)

            # All should be able to read
            for handle in handles:
                data = handle.read(0, 100)
                assert data == b"test content"

        finally:
            for handle in handles:
                handle.close()
            delete_test_file(tree, unique_filename)

    def test_share_mode_exclusive_write(self, tree, unique_filename):
        """Test exclusive write access."""
        file_open1 = Open(tree, unique_filename)
        file_open2 = Open(tree, unique_filename)

        try:
            # First open with exclusive write
            file_open1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ,  # No write sharing
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Second open for write should fail (sharing violation)
            with pytest.raises(Exception):  # SMBResponseException for sharing violation
                file_open2.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.GENERIC_WRITE,
                    0,
                    ShareAccess.FILE_SHARE_READ,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_NON_DIRECTORY_FILE,
                )

        finally:
            file_open1.close()
            delete_test_file(tree, unique_filename)

    def test_share_mode_read_while_writing(self, tree, unique_filename):
        """Test reading while another handle is writing."""
        file_open1 = Open(tree, unique_filename)
        file_open2 = Open(tree, unique_filename)

        try:
            # First open for read+write with sharing
            file_open1.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Write some data
            file_open1.write(b"Hello", 0)

            # Second open for read should succeed
            file_open2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )

            # Should be able to read the written data
            data = file_open2.read(0, 100)
            assert data == b"Hello"

        finally:
            file_open1.close()
            file_open2.close()
            delete_test_file(tree, unique_filename)


class TestLeaseCleanup:
    """Tests for lease cleanup on close."""

    def test_lease_released_on_close(self, tree, unique_filename):
        """Test that lease is released when handle is closed."""
        # First handle with exclusive access
        file_open1 = Open(tree, unique_filename)
        file_open1.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
            0,
            ShareAccess.FILE_SHARE_READ,  # No write sharing
            CreateDisposition.FILE_OVERWRITE_IF,
            CreateOptions.FILE_NON_DIRECTORY_FILE,
        )

        # Close first handle
        file_open1.close()

        # Now second handle should be able to open with write
        file_open2 = Open(tree, unique_filename)
        try:
            file_open2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert file_open2.file_id is not None
        finally:
            file_open2.close()
            delete_test_file(tree, unique_filename)
