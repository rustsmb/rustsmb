"""
Tests for SMB CREATE and CLOSE commands.

These tests verify file and directory creation, opening, and closing.
"""

import uuid
import pytest
from smbprotocol.open import Open, CreateDisposition, FilePipePrinterAccessMask
from smbprotocol.open import ShareAccess, CreateOptions, ImpersonationLevel
from smbprotocol.exceptions import SMBResponseException

from conftest import create_test_file, delete_test_file


class TestCreate:
    """Tests for CREATE command."""

    def test_create_new_file(self, tree, unique_filename):
        """Test creating a new file."""
        file_open = Open(tree, unique_filename)
        try:
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_CREATE,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert file_open.file_id is not None
        finally:
            file_open.close()
            delete_test_file(tree, unique_filename)

    def test_create_overwrite_if(self, tree, unique_filename):
        """Test creating file with FILE_OVERWRITE_IF."""
        file_open = Open(tree, unique_filename)
        try:
            # First create
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            file_open.close()

            # Second create should also succeed
            file_open2 = Open(tree, unique_filename)
            file_open2.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                0,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            file_open2.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_create_open_existing(self, tree, unique_filename):
        """Test opening existing file with FILE_OPEN."""
        # Create file first
        create_test_file(tree, unique_filename, b"test content")

        try:
            # Open existing file
            file_open = Open(tree, unique_filename)
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )
            assert file_open.file_id is not None
            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_create_directory(self, tree, unique_dirname):
        """Test creating a directory."""
        dir_open = Open(tree, unique_dirname)
        try:
            dir_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_CREATE,
                CreateOptions.FILE_DIRECTORY_FILE,
            )
            assert dir_open.file_id is not None
        finally:
            dir_open.close()
            # Clean up directory
            try:
                delete_dir = Open(tree, unique_dirname)
                delete_dir.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.DELETE,
                    0,
                    ShareAccess.FILE_SHARE_DELETE,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE,
                )
                delete_dir.close()
            except Exception:
                pass

    def test_create_nonexistent_file_open(self, tree):
        """Test opening non-existent file with FILE_OPEN fails."""
        file_open = Open(tree, f"nonexistent_{uuid.uuid4().hex}.txt")
        with pytest.raises(SMBResponseException):
            file_open.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ,
                0,
                ShareAccess.FILE_SHARE_READ,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE,
            )


class TestClose:
    """Tests for CLOSE command."""

    def test_close_file(self, tree, unique_filename):
        """Test closing a file."""
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

            # Close should succeed
            file_open.close()
        finally:
            delete_test_file(tree, unique_filename)

    def test_close_multiple_handles(self, tree, unique_filename):
        """Test closing multiple handles to same file."""
        create_test_file(tree, unique_filename, b"test")

        try:
            # Open multiple handles
            handles = []
            for _ in range(3):
                file_open = Open(tree, unique_filename)
                file_open.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.GENERIC_READ,
                    0,
                    ShareAccess.FILE_SHARE_READ,
                    CreateDisposition.FILE_OPEN,
                    CreateOptions.FILE_NON_DIRECTORY_FILE,
                )
                handles.append(file_open)

            # Close all handles
            for handle in handles:
                handle.close()
        finally:
            delete_test_file(tree, unique_filename)
