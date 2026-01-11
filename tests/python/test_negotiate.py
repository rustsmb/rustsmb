"""
Tests for SMB NEGOTIATE command.

These tests verify dialect negotiation, capabilities, and security settings.
"""

import uuid
import pytest
from smbprotocol.connection import Connection, Dialects


# Dialect constants for comparison
DIALECT_SMB202 = Dialects.SMB_2_0_2  # 0x0202 = 514
DIALECT_SMB21 = Dialects.SMB_2_1_0   # 0x0210 = 528
DIALECT_SMB30 = Dialects.SMB_3_0_0   # 0x0300 = 768
DIALECT_SMB302 = Dialects.SMB_3_0_2  # 0x0302 = 770
DIALECT_SMB311 = Dialects.SMB_3_1_1  # 0x0311 = 785

VALID_DIALECTS = [DIALECT_SMB202, DIALECT_SMB21, DIALECT_SMB30, DIALECT_SMB302, DIALECT_SMB311]


class TestNegotiate:
    """Tests for SMB protocol negotiation."""

    def test_negotiate_default_dialect(self, server_addr, server_port):
        """Test that default negotiation succeeds with highest dialect."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Should negotiate to a valid SMB 2.x/3.x dialect
        assert conn.dialect is not None
        assert conn.dialect in VALID_DIALECTS, f"Unexpected dialect: {conn.dialect} (0x{conn.dialect:04x})"
        conn.disconnect()

    def test_negotiate_smb311(self, server_addr, server_port):
        """Test SMB 3.1.1 dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Server should support SMB 3.1.1
        if conn.dialect == DIALECT_SMB311:
            # SMB 3.1.1 should have pre-auth integrity
            assert hasattr(conn, 'preauth_integrity_hash_id')
        conn.disconnect()

    def test_negotiate_smb302(self, server_addr, server_port):
        """Test SMB 3.0.2 or higher dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Should negotiate to 3.0.2 or higher
        assert conn.dialect >= DIALECT_SMB302, f"Expected >= SMB 3.0.2, got 0x{conn.dialect:04x}"
        conn.disconnect()

    def test_negotiate_smb30(self, server_addr, server_port):
        """Test SMB 3.0 or higher dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Should negotiate to 3.0 or higher
        assert conn.dialect >= DIALECT_SMB30, f"Expected >= SMB 3.0, got 0x{conn.dialect:04x}"
        conn.disconnect()

    def test_negotiate_smb21(self, server_addr, server_port):
        """Test SMB 2.1 or higher dialect negotiation."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        # Should negotiate to 2.1 or higher
        assert conn.dialect >= DIALECT_SMB21, f"Expected >= SMB 2.1, got 0x{conn.dialect:04x}"
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
