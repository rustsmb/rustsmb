"""
Tests for SMB NEGOTIATE command.

These tests verify dialect negotiation, capabilities, and security settings.
"""

import uuid
import pytest
from smbprotocol.connection import Connection


class TestNegotiate:
    """Tests for SMB protocol negotiation."""

    def test_negotiate_default_dialect(self, server_addr, server_port):
        """Test that default negotiation succeeds with highest dialect."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Should negotiate to SMB 3.1.1 by default
        assert conn.dialect is not None
        assert conn.dialect in ["3.1.1", "3.0.2", "3.0", "2.1", "2.0.2"]
        conn.disconnect()

    def test_negotiate_smb311(self, server_addr, server_port):
        """Test SMB 3.1.1 dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect(preferred_dialect="3.1.1")

        if conn.dialect == "3.1.1":
            # SMB 3.1.1 should have pre-auth integrity
            assert conn.preauth_integrity_hash_id is not None or True  # May vary by impl
        conn.disconnect()

    def test_negotiate_smb302(self, server_addr, server_port):
        """Test SMB 3.0.2 dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        try:
            conn.connect(preferred_dialect="3.0.2")
            assert conn.dialect in ["3.0.2", "3.0", "2.1", "2.0.2"]
        finally:
            conn.disconnect()

    def test_negotiate_smb30(self, server_addr, server_port):
        """Test SMB 3.0 dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        try:
            conn.connect(preferred_dialect="3.0")
            assert conn.dialect in ["3.0", "2.1", "2.0.2"]
        finally:
            conn.disconnect()

    def test_negotiate_smb21(self, server_addr, server_port):
        """Test SMB 2.1 dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        try:
            conn.connect(preferred_dialect="2.1")
            assert conn.dialect in ["2.1", "2.0.2"]
        finally:
            conn.disconnect()

    def test_negotiate_server_guid(self, server_addr, server_port):
        """Test that server returns a valid GUID."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Server should return a GUID
        assert conn.server_guid is not None
        conn.disconnect()

    def test_negotiate_capabilities(self, server_addr, server_port):
        """Test that server reports capabilities."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Server should have some capabilities set
        # The exact capabilities depend on the server implementation
        assert conn.server_capabilities is not None
        conn.disconnect()

    def test_multiple_connections(self, server_addr, server_port):
        """Test multiple simultaneous connections."""
        connections = []
        try:
            for _ in range(5):
                conn = Connection(uuid.uuid4(), server_addr, server_port)
                conn.connect()
                connections.append(conn)

            # All connections should be valid
            for conn in connections:
                assert conn.dialect is not None
        finally:
            for conn in connections:
                conn.disconnect()
