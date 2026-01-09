//! Connection state tracking.

use rustsmb_core::SmbDialect;
use std::net::SocketAddr;

/// Connection state (per TCP connection).
///
/// Note: This is local state that exists only while the connection is active.
/// Session data is stored in the StateStore for HA support.
#[derive(Debug)]
pub struct Connection {
    /// Unique connection ID.
    pub id: u64,
    /// Client address.
    pub peer_addr: SocketAddr,
    /// Negotiated dialect.
    pub dialect: Option<SmbDialect>,
    /// Connection state.
    pub state: ConnectionState,
    /// Signing required.
    pub signing_required: bool,
    /// Encryption required.
    pub encryption_required: bool,
    /// Max transaction size.
    pub max_transact_size: u32,
    /// Max read size.
    pub max_read_size: u32,
    /// Max write size.
    pub max_write_size: u32,
    /// Credits available.
    pub credits: u16,
    /// Client GUID.
    pub client_guid: [u8; 16],
    /// Pre-auth integrity hash (SMB 3.1.1).
    pub preauth_hash: Option<[u8; 64]>,
}

impl Connection {
    /// Create a new connection.
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        Self {
            id,
            peer_addr,
            dialect: None,
            state: ConnectionState::AwaitingNegotiate,
            signing_required: false,
            encryption_required: false,
            max_transact_size: 8 * 1024 * 1024,
            max_read_size: 8 * 1024 * 1024,
            max_write_size: 8 * 1024 * 1024,
            credits: 1,
            client_guid: [0; 16],
            preauth_hash: None,
        }
    }

    /// Check if connection is negotiated.
    pub fn is_negotiated(&self) -> bool {
        self.dialect.is_some()
    }

    /// Transition to negotiated state.
    pub fn negotiate(&mut self, dialect: SmbDialect) {
        self.dialect = Some(dialect);
        self.state = ConnectionState::Negotiated;
    }

    /// Transition to session active state.
    pub fn session_active(&mut self) {
        self.state = ConnectionState::SessionActive;
    }
}

/// Connection state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, awaiting NEGOTIATE.
    AwaitingNegotiate,
    /// Negotiate complete, awaiting SESSION_SETUP.
    Negotiated,
    /// At least one session authenticated.
    SessionActive,
    /// Connection being torn down.
    Disconnecting,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::AwaitingNegotiate
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_state() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let mut conn = Connection::new(1, addr);

        assert!(!conn.is_negotiated());
        assert_eq!(conn.state, ConnectionState::AwaitingNegotiate);

        conn.negotiate(SmbDialect::Smb311);
        assert!(conn.is_negotiated());
        assert_eq!(conn.dialect, Some(SmbDialect::Smb311));
        assert_eq!(conn.state, ConnectionState::Negotiated);
    }
}
