//! Connection state tracking.
//!
//! Each TCP connection has local state that exists only while the connection
//! is active. Session data is stored in the StateStore for HA support.

use crate::async_request::{AsyncRequestConfig, AsyncRequestTracker};
use crate::compound::{CompoundContext, CompoundQueue};
use crate::credits::{CreditConfig, CreditManager};
use rustsmb_core::SmbDialect;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Maximum sessions per connection.
pub const DEFAULT_MAX_SESSIONS_PER_CONNECTION: usize = 64;

/// Connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Maximum sessions per connection.
    pub max_sessions: usize,
    /// Credit configuration.
    pub credit_config: CreditConfig,
    /// Async request configuration.
    pub async_config: AsyncRequestConfig,
    /// Maximum compound commands per request.
    pub max_compound_commands: usize,
    /// Default max transaction size.
    pub max_transact_size: u32,
    /// Default max read size.
    pub max_read_size: u32,
    /// Default max write size.
    pub max_write_size: u32,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS_PER_CONNECTION,
            credit_config: CreditConfig::default(),
            async_config: AsyncRequestConfig::default(),
            max_compound_commands: 64,
            max_transact_size: 8 * 1024 * 1024,
            max_read_size: 8 * 1024 * 1024,
            max_write_size: 8 * 1024 * 1024,
        }
    }
}

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
    /// Client GUID.
    pub client_guid: [u8; 16],
    /// Pre-auth integrity hash (SMB 3.1.1).
    pub preauth_hash: Option<[u8; 64]>,
    /// Credit manager.
    pub credits: CreditManager,
    /// Async request tracker.
    pub async_requests: AsyncRequestTracker,
    /// Compound request queue.
    pub compound_queue: CompoundQueue,
    /// Active session IDs on this connection.
    session_ids: HashSet<u64>,
    /// Message ID counter.
    next_message_id: AtomicU64,
    /// Connection creation time.
    created: Instant,
    /// Last activity time.
    last_activity: Instant,
    /// Configuration.
    config: ConnectionConfig,
}

impl Connection {
    /// Create a new connection with default configuration.
    pub fn new(id: u64, peer_addr: SocketAddr) -> Self {
        Self::with_config(id, peer_addr, ConnectionConfig::default())
    }

    /// Create a new connection with custom configuration.
    pub fn with_config(id: u64, peer_addr: SocketAddr, config: ConnectionConfig) -> Self {
        let now = Instant::now();
        Self {
            id,
            peer_addr,
            dialect: None,
            state: ConnectionState::AwaitingNegotiate,
            signing_required: false,
            encryption_required: false,
            max_transact_size: config.max_transact_size,
            max_read_size: config.max_read_size,
            max_write_size: config.max_write_size,
            client_guid: [0; 16],
            preauth_hash: None,
            credits: CreditManager::with_config(config.credit_config.clone()),
            async_requests: AsyncRequestTracker::with_config(config.async_config.clone()),
            compound_queue: CompoundQueue::new(config.max_compound_commands),
            session_ids: HashSet::with_capacity(config.max_sessions.min(16)),
            next_message_id: AtomicU64::new(0),
            created: now,
            last_activity: now,
            config,
        }
    }

    /// Check if connection is negotiated.
    #[inline]
    pub fn is_negotiated(&self) -> bool {
        self.dialect.is_some()
    }

    /// Check if connection supports multi-credit operations.
    ///
    /// Multi-credit operations are available in SMB 2.1 and later.
    /// Per MS-SMB2 3.3.5.2.5, credit charge validation only applies when
    /// the connection supports multi-credit operations.
    #[inline]
    pub fn supports_multi_credit(&self) -> bool {
        matches!(
            self.dialect,
            Some(SmbDialect::Smb210 | SmbDialect::Smb300 | SmbDialect::Smb302 | SmbDialect::Smb311)
        )
    }

    /// Check if connection supports multi-channel operations.
    ///
    /// Multi-channel is available in SMB 3.x dialects only.
    /// Per MS-SMB2 3.3.5.5 line 14522, session binding requires
    /// IsMultiChannelCapable = TRUE, which is only for SMB 3.x.
    #[inline]
    pub fn is_multi_channel_capable(&self) -> bool {
        matches!(
            self.dialect,
            Some(SmbDialect::Smb300 | SmbDialect::Smb302 | SmbDialect::Smb311)
        )
    }

    /// Get client GUID as hex string (for lease tracking).
    #[inline]
    pub fn client_guid_string(&self) -> String {
        use std::fmt::Write;
        self.client_guid
            .iter()
            .fold(String::with_capacity(32), |mut s, b| {
                let _ = write!(s, "{:02x}", b);
                s
            })
    }

    /// Transition to negotiated state.
    pub fn negotiate(&mut self, dialect: SmbDialect) {
        self.dialect = Some(dialect);
        self.state = ConnectionState::Negotiated;
        self.touch();
    }

    /// Transition to session active state.
    pub fn session_active(&mut self) {
        self.state = ConnectionState::SessionActive;
        self.touch();
    }

    /// Start disconnection.
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnecting;
    }

    /// Check if connection is disconnecting or closed.
    #[inline]
    pub fn is_disconnecting(&self) -> bool {
        self.state == ConnectionState::Disconnecting
    }

    /// Add a session to this connection.
    ///
    /// Returns `false` if at session limit.
    pub fn add_session(&mut self, session_id: u64) -> bool {
        if self.session_ids.len() >= self.config.max_sessions {
            return false;
        }
        self.session_ids.insert(session_id);
        if self.state == ConnectionState::Negotiated {
            self.state = ConnectionState::SessionActive;
        }
        self.touch();
        true
    }

    /// Remove a session from this connection.
    pub fn remove_session(&mut self, session_id: u64) {
        self.session_ids.remove(&session_id);
        // Cancel any async requests for this session
        self.async_requests.cancel_session(session_id);
        if self.session_ids.is_empty() && self.state == ConnectionState::SessionActive {
            self.state = ConnectionState::Negotiated;
        }
        self.touch();
    }

    /// Check if a session exists on this connection.
    #[inline]
    pub fn has_session(&self, session_id: u64) -> bool {
        self.session_ids.contains(&session_id)
    }

    /// Get the number of active sessions.
    #[inline]
    pub fn session_count(&self) -> usize {
        self.session_ids.len()
    }

    /// Get all session IDs.
    pub fn session_ids(&self) -> impl Iterator<Item = &u64> {
        self.session_ids.iter()
    }

    /// Get the next message ID (for async responses).
    pub fn next_message_id(&self) -> u64 {
        self.next_message_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Validate and consume credits for a request.
    ///
    /// Returns the actual credits consumed, or an error.
    pub fn consume_credits(&self, credit_charge: u16) -> Option<u16> {
        self.credits.consume(credit_charge)
    }

    /// Grant credits in a response.
    pub fn grant_credits(&self, requested: u16, is_async: bool) -> u16 {
        let to_grant = self.credits.calculate_grant(requested, is_async);
        self.credits.grant(to_grant)
    }

    /// Start a compound request.
    pub fn start_compound(
        &mut self,
        context: CompoundContext,
        first_message_id: u64,
    ) -> Option<u64> {
        self.compound_queue.start(context, first_message_id)
    }

    /// Get a mutable reference to a pending compound.
    pub fn get_compound_mut(&mut self, id: u64) -> Option<&mut crate::compound::PendingCompound> {
        self.compound_queue.get_mut(id)
    }

    /// Complete a compound request.
    pub fn complete_compound(&mut self, id: u64) -> Option<crate::compound::PendingCompound> {
        self.compound_queue.complete(id)
    }

    /// Update last activity time.
    #[inline]
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get connection age.
    pub fn age(&self) -> std::time::Duration {
        self.created.elapsed()
    }

    /// Get idle duration since last activity.
    pub fn idle_duration(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }

    /// Check if connection has been idle too long.
    pub fn is_idle(&self, timeout: std::time::Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Clean up expired async requests.
    pub fn cleanup_expired_async(&mut self) -> Vec<crate::async_request::AsyncRequest> {
        self.async_requests.cleanup_expired()
    }
}

/// Connection state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Initial state, awaiting NEGOTIATE.
    #[default]
    AwaitingNegotiate,
    /// Negotiate complete, awaiting SESSION_SETUP.
    Negotiated,
    /// At least one session authenticated.
    SessionActive,
    /// Connection being torn down.
    Disconnecting,
}

impl ConnectionState {
    /// Check if this state allows new requests.
    #[inline]
    pub fn accepts_requests(&self) -> bool {
        !matches!(self, ConnectionState::Disconnecting)
    }

    /// Check if negotiate has completed.
    #[inline]
    pub fn is_post_negotiate(&self) -> bool {
        matches!(
            self,
            ConnectionState::Negotiated | ConnectionState::SessionActive
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    #[test]
    fn test_connection_state() {
        let mut conn = Connection::new(1, test_addr());

        assert!(!conn.is_negotiated());
        assert_eq!(conn.state, ConnectionState::AwaitingNegotiate);

        conn.negotiate(SmbDialect::Smb311);
        assert!(conn.is_negotiated());
        assert_eq!(conn.dialect, Some(SmbDialect::Smb311));
        assert_eq!(conn.state, ConnectionState::Negotiated);
    }

    #[test]
    fn test_session_management() {
        let mut conn = Connection::new(1, test_addr());
        conn.negotiate(SmbDialect::Smb311);

        // Add session transitions to SessionActive
        assert!(conn.add_session(100));
        assert_eq!(conn.state, ConnectionState::SessionActive);
        assert!(conn.has_session(100));
        assert_eq!(conn.session_count(), 1);

        // Add another session
        assert!(conn.add_session(101));
        assert_eq!(conn.session_count(), 2);

        // Remove session
        conn.remove_session(100);
        assert!(!conn.has_session(100));
        assert_eq!(conn.session_count(), 1);

        // Remove last session transitions back to Negotiated
        conn.remove_session(101);
        assert_eq!(conn.session_count(), 0);
        assert_eq!(conn.state, ConnectionState::Negotiated);
    }

    #[test]
    fn test_max_sessions() {
        let config = ConnectionConfig {
            max_sessions: 2,
            ..Default::default()
        };
        let mut conn = Connection::with_config(1, test_addr(), config);
        conn.negotiate(SmbDialect::Smb311);

        assert!(conn.add_session(1));
        assert!(conn.add_session(2));
        assert!(!conn.add_session(3)); // Should fail
        assert_eq!(conn.session_count(), 2);
    }

    #[test]
    fn test_credits() {
        use crate::credits::DEFAULT_INITIAL_CREDITS;

        let conn = Connection::new(1, test_addr());

        // Initial credits (256 by default for SMB compatibility)
        assert_eq!(conn.credits.available(), DEFAULT_INITIAL_CREDITS);

        // Grant more credits
        let granted = conn.grant_credits(10, false);
        assert!(granted > 0);

        // Consume credits
        assert!(conn.consume_credits(1).is_some());
    }

    #[test]
    fn test_disconnect_state() {
        let mut conn = Connection::new(1, test_addr());
        conn.negotiate(SmbDialect::Smb311);

        assert!(conn.state.accepts_requests());
        conn.disconnect();
        assert!(!conn.state.accepts_requests());
        assert!(conn.is_disconnecting());
    }

    #[test]
    fn test_idle_tracking() {
        let conn = Connection::new(1, test_addr());

        // Should not be idle immediately
        assert!(!conn.is_idle(std::time::Duration::from_secs(60)));

        // Age and idle_duration should be very small
        assert!(conn.age() < std::time::Duration::from_secs(1));
        assert!(conn.idle_duration() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn test_state_checks() {
        assert!(ConnectionState::Negotiated.is_post_negotiate());
        assert!(ConnectionState::SessionActive.is_post_negotiate());
        assert!(!ConnectionState::AwaitingNegotiate.is_post_negotiate());
        assert!(!ConnectionState::Disconnecting.is_post_negotiate());
    }

    #[test]
    fn test_session_iteration() {
        let mut conn = Connection::new(1, test_addr());
        conn.negotiate(SmbDialect::Smb311);

        // Add sessions
        conn.add_session(100);
        conn.add_session(200);
        conn.add_session(300);

        // Collect session IDs
        let sessions: Vec<u64> = conn.session_ids().copied().collect();
        assert_eq!(sessions.len(), 3);
        assert!(sessions.contains(&100));
        assert!(sessions.contains(&200));
        assert!(sessions.contains(&300));
    }

    #[test]
    fn test_duplicate_session() {
        let mut conn = Connection::new(1, test_addr());
        conn.negotiate(SmbDialect::Smb311);

        // Add session
        assert!(conn.add_session(100));
        assert_eq!(conn.session_count(), 1);

        // Adding same session ID should fail (returns false) or be idempotent
        // depending on implementation - HashSet silently ignores duplicates
        let result = conn.add_session(100);
        // HashSet returns false for insert when already exists
        assert!(!result || conn.session_count() == 1);
    }

    #[test]
    fn test_session_cleanup_on_disconnect() {
        let mut conn = Connection::new(1, test_addr());
        conn.negotiate(SmbDialect::Smb311);

        // Add multiple sessions
        conn.add_session(100);
        conn.add_session(200);
        conn.add_session(300);
        assert_eq!(conn.session_count(), 3);

        // Disconnect
        conn.disconnect();
        assert!(conn.is_disconnecting());

        // Sessions should still be tracked (for cleanup by handler)
        // The connection tracks them until handler cleans up
        assert_eq!(conn.session_count(), 3);
    }

    #[test]
    fn test_session_state_transitions() {
        let mut conn = Connection::new(1, test_addr());

        // Initial state
        assert_eq!(conn.state, ConnectionState::AwaitingNegotiate);

        // After negotiate
        conn.negotiate(SmbDialect::Smb311);
        assert_eq!(conn.state, ConnectionState::Negotiated);

        // After first session
        conn.add_session(1);
        assert_eq!(conn.state, ConnectionState::SessionActive);

        // More sessions don't change state
        conn.add_session(2);
        assert_eq!(conn.state, ConnectionState::SessionActive);

        // Remove one session, still have others
        conn.remove_session(1);
        assert_eq!(conn.state, ConnectionState::SessionActive);

        // Remove last session
        conn.remove_session(2);
        assert_eq!(conn.state, ConnectionState::Negotiated);
    }

    #[test]
    fn test_many_sessions() {
        let config = ConnectionConfig {
            max_sessions: 1000,
            ..Default::default()
        };
        let mut conn = Connection::with_config(1, test_addr(), config);
        conn.negotiate(SmbDialect::Smb311);

        // Add many sessions
        for i in 1..=100 {
            assert!(conn.add_session(i), "Should be able to add session {}", i);
        }
        assert_eq!(conn.session_count(), 100);

        // Remove half of them
        for i in 1..=50 {
            conn.remove_session(i);
        }
        assert_eq!(conn.session_count(), 50);

        // Verify remaining sessions
        for i in 51..=100 {
            assert!(conn.has_session(i), "Should still have session {}", i);
        }
    }

    #[test]
    fn test_session_ids_after_removal() {
        let mut conn = Connection::new(1, test_addr());
        conn.negotiate(SmbDialect::Smb311);

        // Add sessions
        conn.add_session(100);
        conn.add_session(200);
        conn.add_session(300);

        // Remove middle session
        conn.remove_session(200);

        // Check iteration
        let sessions: Vec<u64> = conn.session_ids().copied().collect();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.contains(&100));
        assert!(!sessions.contains(&200));
        assert!(sessions.contains(&300));
    }
}
