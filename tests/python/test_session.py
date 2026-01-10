"""
Tests for SMB SESSION_SETUP and LOGOFF commands.

These tests verify authentication, session management, and security.
"""

import uuid
import pytest
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBAuthenticationError


class TestSessionSetup:
    """Tests for SMB session setup."""

    def test_session_setup_valid_credentials(self, connection, credentials):
        """Test session setup with valid credentials."""
        username, password, domain = credentials
        session = Session(
            connection,
            username=username,
            password=password,
            domain=domain,
            require_encryption=False,
        )
        session.connect()

        assert session.session_id is not None
        assert session.session_id > 0
        session.disconnect()

    def test_session_setup_guest(self, server_addr, server_port):
        """Test guest session setup."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        try:
            session = Session(
                conn,
                username="",
                password="",
                require_encryption=False,
            )
            session.connect()
            # Guest login should succeed or fail gracefully
            session.disconnect()
        except SMBAuthenticationError:
            # Guest login may be disabled
            pass
        finally:
            conn.disconnect()

    def test_session_multiple_sessions(self, connection, credentials):
        """Test multiple sessions on same connection."""
        username, password, domain = credentials

        sessions = []
        try:
            for _ in range(3):
                session = Session(
                    connection,
                    username=username,
                    password=password,
                    domain=domain,
                    require_encryption=False,
                )
                session.connect()
                sessions.append(session)

            # All sessions should have unique IDs
            session_ids = [s.session_id for s in sessions]
            assert len(set(session_ids)) == len(session_ids)
        finally:
            for session in sessions:
                session.disconnect()

    def test_session_logoff(self, connection, credentials):
        """Test session logoff."""
        username, password, domain = credentials
        session = Session(
            connection,
            username=username,
            password=password,
            domain=domain,
            require_encryption=False,
        )
        session.connect()
        session_id = session.session_id

        # Logoff should succeed
        session.disconnect()

        # Creating a new session should work after logoff
        session2 = Session(
            connection,
            username=username,
            password=password,
            domain=domain,
            require_encryption=False,
        )
        session2.connect()
        assert session2.session_id != session_id
        session2.disconnect()


class TestAuthentication:
    """Tests for authentication methods."""

    def test_ntlm_authentication(self, server_addr, server_port, credentials):
        """Test NTLM authentication."""
        username, password, domain = credentials

        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        try:
            session = Session(
                conn,
                username=username,
                password=password,
                domain=domain,
                require_encryption=False,
            )
            session.connect()
            assert session.session_id is not None
            session.disconnect()
        finally:
            conn.disconnect()

    def test_invalid_credentials(self, server_addr, server_port):
        """Test authentication with invalid credentials."""
        conn = Connection(uuid.uuid4(), server_addr, server_port)
        conn.connect()

        try:
            session = Session(
                conn,
                username="invalid_user_xyz",
                password="wrong_password_123",
                require_encryption=False,
            )
            # Should raise authentication error
            with pytest.raises((SMBAuthenticationError, Exception)):
                session.connect()
        finally:
            conn.disconnect()
