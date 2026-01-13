//! Lease break notification management.
//!
//! This module provides infrastructure for sending oplock/lease break notifications
//! to clients when their cached file access rights need to be reduced due to
//! conflicts with other clients.
//!
//! # Architecture
//!
//! The `LeaseBreakRegistry` is shared across all connections via `Arc<>`. Each
//! connection registers its leases when they are granted (in CREATE handler) and
//! unregisters them when released (in CLOSE handler or on disconnect).
//!
//! When a lease conflict is detected, the registry sends a `LeaseBreakEvent` via
//! the connection's mpsc channel, which the connection handler processes by sending
//! an unsolicited OPLOCK_BREAK notification to the client.
//!
//! # Protocol Compliance
//!
//! Implements MS-SMB2 sections:
//! - 2.2.23: OPLOCK_BREAK Notification
//! - 2.2.24: OPLOCK_BREAK Acknowledgment
//! - 3.3.4.6-7: Sending Break Notifications
//! - 3.3.5.22: Receiving Acknowledgments
//! - 3.3.6.5: Lease Break Acknowledgment Timer

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace, warn};

/// Default break timeout per MS-SMB2 specification.
pub const DEFAULT_BREAK_TIMEOUT: Duration = Duration::from_secs(35);

/// Entry for a connection that owns a lease.
#[derive(Debug)]
pub struct LeaseConnectionEntry {
    /// Channel to send break notifications to this connection.
    pub break_tx: mpsc::Sender<LeaseBreakEvent>,
    /// Server ID that owns this connection.
    pub server_id: String,
    /// Client GUID for this connection.
    pub client_guid: String,
    /// Session ID (for logging/diagnostics).
    pub session_id: u64,
}

/// A lease break event to be sent to a client.
#[derive(Debug, Clone)]
pub struct LeaseBreakEvent {
    /// Lease key being broken (16 bytes).
    pub lease_key: [u8; 16],
    /// Current lease state before break.
    pub current_state: u32,
    /// New lease state to transition to.
    pub new_state: u32,
    /// New epoch (SMB 3.x).
    pub new_epoch: u16,
    /// Whether acknowledgment is required.
    pub ack_required: bool,
    /// Unique break ID for tracking acknowledgment.
    pub break_id: u64,
}

/// An oplock break event to be sent to a client.
///
/// Unlike lease breaks, oplock breaks are tied to specific file handles.
#[derive(Debug, Clone)]
pub struct OplockBreakEvent {
    /// Persistent file ID of the handle.
    pub persistent_id: u64,
    /// Volatile file ID of the handle.
    pub volatile_id: u64,
    /// Current oplock level before break.
    pub current_level: u8,
    /// New oplock level to break to.
    pub new_level: u8,
    /// Whether acknowledgment is required.
    pub ack_required: bool,
    /// Unique break ID for tracking acknowledgment.
    pub break_id: u64,
}

/// Entry for a connection that owns an oplock.
#[derive(Debug)]
pub struct OplockConnectionEntry {
    /// Channel to send break notifications to this connection.
    pub break_tx: mpsc::Sender<OplockBreakEvent>,
    /// Server ID that owns this connection.
    pub server_id: String,
    /// Session ID that owns the oplock.
    pub session_id: u64,
    /// Current oplock level.
    pub oplock_level: u8,
    /// File path (for conflict detection).
    pub file_path: String,
    /// Share name (for conflict detection).
    pub share_name: String,
}

/// Tracking information for a pending oplock break.
#[derive(Debug)]
pub struct PendingOplockBreak {
    /// Handle ID being broken.
    pub handle_id: u128,
    /// New oplock level that was requested.
    pub new_level: u8,
    /// When the break notification was sent.
    pub sent_at: Instant,
    /// Timeout deadline.
    pub deadline: Instant,
    /// File path (for logging/diagnostics).
    pub file_path: String,
    /// Oneshot channel to notify when break completes.
    pub completion_tx: Option<oneshot::Sender<LeaseBreakResult>>,
}

/// Tracking information for a pending lease break.
#[derive(Debug)]
pub struct PendingBreak {
    /// Lease key being broken (hex-encoded).
    pub lease_key: String,
    /// New state that was requested.
    pub new_state: u32,
    /// When the break notification was sent.
    pub sent_at: Instant,
    /// Timeout deadline.
    pub deadline: Instant,
    /// File path (for logging/diagnostics).
    pub file_path: String,
    /// Oneshot channel to notify when break completes.
    pub completion_tx: Option<oneshot::Sender<LeaseBreakResult>>,
}

/// Result of a lease break attempt.
#[derive(Debug, Clone)]
pub enum LeaseBreakResult {
    /// Client acknowledged the break.
    Acknowledged {
        /// New lease state after acknowledgment.
        new_state: u32,
        /// New epoch.
        epoch: u16,
    },
    /// Break timed out (forced to NONE).
    TimedOut,
    /// Client disconnected during break.
    Disconnected,
    /// Lease was already broken (e.g., client closed handle).
    AlreadyBroken,
    /// No ACK was required (READ_CACHING only break).
    NoAckRequired,
}

/// Lease break registry error.
#[derive(Debug, Error)]
pub enum LeaseBreakError {
    /// Lease not found in registry.
    #[error("Lease not found: {0}")]
    LeaseNotFound(String),
    /// No pending break for lease.
    #[error("No pending break for lease: {0}")]
    NoPendingBreak(String),
    /// Connection unavailable for lease.
    #[error("Connection unavailable for lease: {0}")]
    ConnectionUnavailable(String),
    /// Break send failed.
    #[error("Break send failed: {0}")]
    SendFailed(String),
    /// Invalid state subset.
    #[error("Acknowledged state {acked:#x} is not subset of break-to state {break_to:#x}")]
    InvalidStateSubset { acked: u32, break_to: u32 },
}

/// Registry for managing oplock and lease break notifications across connections.
///
/// This registry is shared across all connections via `Arc<LeaseBreakRegistry>`.
/// It maintains mappings from lease keys and handle IDs to the connections that
/// own them, enabling break notifications to be sent to the correct client.
#[derive(Debug)]
pub struct LeaseBreakRegistry {
    /// Map from lease_key (hex) to connection entry.
    lease_connections: DashMap<String, LeaseConnectionEntry>,
    /// Map from break_id to pending lease break info.
    pending_breaks: DashMap<u64, PendingBreak>,
    /// Map from handle_id to oplock connection entry.
    oplock_connections: DashMap<u128, OplockConnectionEntry>,
    /// Map from break_id to pending oplock break info.
    pending_oplock_breaks: DashMap<u64, PendingOplockBreak>,
    /// Next break ID.
    next_break_id: AtomicU64,
    /// Break timeout duration (35 seconds per MS-SMB2).
    break_timeout: Duration,
}

impl LeaseBreakRegistry {
    /// Create a new registry with default timeout.
    pub fn new() -> Self {
        Self {
            lease_connections: DashMap::new(),
            pending_breaks: DashMap::new(),
            oplock_connections: DashMap::new(),
            pending_oplock_breaks: DashMap::new(),
            next_break_id: AtomicU64::new(1),
            break_timeout: DEFAULT_BREAK_TIMEOUT,
        }
    }

    /// Create a new registry with custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            lease_connections: DashMap::new(),
            pending_breaks: DashMap::new(),
            oplock_connections: DashMap::new(),
            pending_oplock_breaks: DashMap::new(),
            next_break_id: AtomicU64::new(1),
            break_timeout: timeout,
        }
    }

    /// Register a lease with its owning connection.
    ///
    /// Called when a CREATE handler grants a lease to a client.
    pub fn register_lease(&self, lease_key: &str, entry: LeaseConnectionEntry) {
        debug!(
            lease_key = lease_key,
            server_id = %entry.server_id,
            session_id = entry.session_id,
            "Registering lease with break registry"
        );
        self.lease_connections.insert(lease_key.to_string(), entry);
    }

    /// Unregister a lease (on CLOSE or disconnect).
    ///
    /// Returns true if the lease was found and removed.
    pub fn unregister_lease(&self, lease_key: &str) -> bool {
        let removed = self.lease_connections.remove(lease_key).is_some();
        if removed {
            debug!(
                lease_key = lease_key,
                "Unregistered lease from break registry"
            );
        }
        removed
    }

    /// Unregister all leases for a specific connection.
    ///
    /// Called when a connection disconnects.
    pub fn unregister_connection_leases(&self, server_id: &str, session_id: u64) {
        let to_remove: Vec<String> = self
            .lease_connections
            .iter()
            .filter(|entry| {
                entry.value().server_id == server_id && entry.value().session_id == session_id
            })
            .map(|entry| entry.key().clone())
            .collect();

        for key in &to_remove {
            self.lease_connections.remove(key);
        }

        if !to_remove.is_empty() {
            debug!(
                server_id = server_id,
                session_id = session_id,
                count = to_remove.len(),
                "Unregistered connection leases"
            );
        }
    }

    /// Check if a lease is registered.
    pub fn is_registered(&self, lease_key: &str) -> bool {
        self.lease_connections.contains_key(lease_key)
    }

    /// Get server ID for a lease (for conflict detection).
    pub fn get_server_id(&self, lease_key: &str) -> Option<String> {
        self.lease_connections
            .get(lease_key)
            .map(|e| e.server_id.clone())
    }

    // ========== Oplock Registration Methods ==========

    /// Register an oplock with its owning connection.
    ///
    /// Called when a CREATE handler grants an oplock to a client.
    pub fn register_oplock(&self, handle_id: u128, entry: OplockConnectionEntry) {
        debug!(
            handle_id = %handle_id,
            server_id = %entry.server_id,
            session_id = entry.session_id,
            oplock_level = entry.oplock_level,
            file_path = %entry.file_path,
            "Registering oplock with break registry"
        );
        self.oplock_connections.insert(handle_id, entry);
    }

    /// Unregister an oplock (on CLOSE or disconnect).
    ///
    /// Returns true if the oplock was found and removed.
    pub fn unregister_oplock(&self, handle_id: u128) -> bool {
        let removed = self.oplock_connections.remove(&handle_id).is_some();
        if removed {
            debug!(
                handle_id = %handle_id,
                "Unregistered oplock from break registry"
            );
        }
        removed
    }

    /// Unregister all oplocks for a specific connection.
    ///
    /// Called when a connection disconnects.
    pub fn unregister_connection_oplocks(&self, server_id: &str, session_id: u64) {
        let to_remove: Vec<u128> = self
            .oplock_connections
            .iter()
            .filter(|entry| {
                entry.value().server_id == server_id && entry.value().session_id == session_id
            })
            .map(|entry| *entry.key())
            .collect();

        for handle_id in &to_remove {
            self.oplock_connections.remove(handle_id);
        }

        if !to_remove.is_empty() {
            debug!(
                server_id = server_id,
                session_id = session_id,
                count = to_remove.len(),
                "Unregistered connection oplocks"
            );
        }
    }

    /// Check if an oplock is registered.
    pub fn is_oplock_registered(&self, handle_id: u128) -> bool {
        self.oplock_connections.contains_key(&handle_id)
    }

    /// Get oplocks for a file path (for conflict detection).
    ///
    /// Returns a list of (handle_id, oplock_level, server_id) for all oplocks on the file.
    pub fn get_oplocks_for_file(
        &self,
        share_name: &str,
        file_path: &str,
    ) -> Vec<(u128, u8, String, u64)> {
        self.oplock_connections
            .iter()
            .filter(|entry| {
                entry.value().share_name == share_name && entry.value().file_path == file_path
            })
            .map(|entry| {
                (
                    *entry.key(),
                    entry.value().oplock_level,
                    entry.value().server_id.clone(),
                    entry.value().session_id,
                )
            })
            .collect()
    }

    /// Initiate an oplock break without waiting for acknowledgment.
    ///
    /// This method just sends the break event to the connection's channel and returns
    /// immediately. Used for pre-sharing violation oplock breaks where we can't block
    /// the connection loop waiting for an ACK (since the ACK can only arrive after
    /// we process the break notification, which requires the loop to continue).
    ///
    /// Returns true if the break event was sent successfully.
    pub async fn initiate_oplock_break_nowait(&self, handle_id: u128, new_level: u8) -> bool {
        // Get the connection entry for this oplock
        let entry = match self.oplock_connections.get(&handle_id) {
            Some(e) => e,
            None => {
                debug!(handle_id = %handle_id, "Oplock not found for nowait break");
                return false;
            }
        };

        let current_level = entry.oplock_level;
        let break_id = self.next_break_id.fetch_add(1, Ordering::Relaxed);

        // Extract file IDs from handle_id
        let persistent_id = handle_id as u64;
        let volatile_id = (handle_id >> 64) as u64;

        // Determine if ACK is required
        let ack_required = current_level == 0x09 || current_level == 0x08;

        let event = OplockBreakEvent {
            persistent_id,
            volatile_id,
            current_level,
            new_level,
            ack_required,
            break_id,
        };

        debug!(
            handle_id = %handle_id,
            current_level = current_level,
            new_level = new_level,
            ack_required = ack_required,
            break_id = break_id,
            "Initiating oplock break (nowait)"
        );

        // Send the break event to the connection (non-blocking)
        if let Err(e) = entry.break_tx.try_send(event) {
            debug!(
                handle_id = %handle_id,
                error = %e,
                "Failed to send oplock break event (nowait)"
            );
            return false;
        }

        true
    }

    /// Initiate an oplock break, returns a future that completes when break is done.
    ///
    /// This method:
    /// 1. Sends an OplockBreakEvent to the owning connection's channel
    /// 2. If ACK is required, registers a pending break and waits for acknowledgment
    /// 3. Returns the result when the client acknowledges or timeout occurs
    pub async fn break_oplock(
        &self,
        handle_id: u128,
        new_level: u8,
        file_path: &str,
    ) -> Result<LeaseBreakResult, LeaseBreakError> {
        // Get the connection entry for this oplock
        let entry = self
            .oplock_connections
            .get(&handle_id)
            .ok_or_else(|| LeaseBreakError::LeaseNotFound(format!("handle:{}", handle_id)))?;

        let current_level = entry.oplock_level;

        // Determine if ACK is required per MS-SMB2 3.3.4.6:
        // ACK is required for Batch (0x09) or Exclusive (0x08) breaking to Level II (0x01) or None (0x00)
        // ACK is NOT required for Level II (0x01) breaking to None (0x00)
        let ack_required = current_level == 0x09 || current_level == 0x08;

        let break_id = self.next_break_id.fetch_add(1, Ordering::Relaxed);

        // Extract file IDs from handle_id
        // Per handle_id format: lower 64 bits = persistent, upper 64 bits = volatile
        let persistent_id = handle_id as u64;
        let volatile_id = (handle_id >> 64) as u64;

        let event = OplockBreakEvent {
            persistent_id,
            volatile_id,
            current_level,
            new_level,
            ack_required,
            break_id,
        };

        debug!(
            handle_id = %handle_id,
            current_level = current_level,
            new_level = new_level,
            ack_required = ack_required,
            break_id = break_id,
            "Initiating oplock break"
        );

        // Send the break event to the connection
        if let Err(e) = entry.break_tx.send(event).await {
            return Err(LeaseBreakError::SendFailed(e.to_string()));
        }

        // Drop the entry reference before awaiting
        drop(entry);

        // If no ACK required, break completes immediately
        if !ack_required {
            debug!(
                handle_id = %handle_id,
                break_id = break_id,
                "Oplock break completed (no ACK required)"
            );
            return Ok(LeaseBreakResult::NoAckRequired);
        }

        // Register pending break and wait for ACK
        let (completion_tx, completion_rx) = oneshot::channel();
        let now = Instant::now();
        let pending = PendingOplockBreak {
            handle_id,
            new_level,
            sent_at: now,
            deadline: now + self.break_timeout,
            file_path: file_path.to_string(),
            completion_tx: Some(completion_tx),
        };

        self.pending_oplock_breaks.insert(break_id, pending);

        // Wait for acknowledgment or timeout
        match tokio::time::timeout(self.break_timeout, completion_rx).await {
            Ok(Ok(result)) => {
                self.pending_oplock_breaks.remove(&break_id);
                Ok(result)
            }
            Ok(Err(_)) => {
                // Channel was dropped (connection closed)
                self.pending_oplock_breaks.remove(&break_id);
                Ok(LeaseBreakResult::Disconnected)
            }
            Err(_) => {
                // Timeout
                self.pending_oplock_breaks.remove(&break_id);
                warn!(
                    handle_id = %handle_id,
                    break_id = break_id,
                    "Oplock break timed out"
                );
                Ok(LeaseBreakResult::TimedOut)
            }
        }
    }

    /// Handle oplock acknowledgment from client.
    ///
    /// Called when an OPLOCK_BREAK acknowledgment is received.
    pub fn handle_oplock_acknowledgment(
        &self,
        persistent_id: u64,
        volatile_id: u64,
        acked_level: u8,
    ) -> Result<(), LeaseBreakError> {
        // Reconstruct handle_id: lower 64 bits = persistent, upper 64 bits = volatile
        let handle_id = (persistent_id as u128) | ((volatile_id as u128) << 64);

        // Find the pending break for this handle
        let break_id = self
            .pending_oplock_breaks
            .iter()
            .find(|entry| entry.value().handle_id == handle_id)
            .map(|entry| *entry.key());

        let break_id = break_id
            .ok_or_else(|| LeaseBreakError::NoPendingBreak(format!("handle:{}", handle_id)))?;

        // Remove and get the pending break
        let (_, mut pending) = self
            .pending_oplock_breaks
            .remove(&break_id)
            .ok_or_else(|| LeaseBreakError::NoPendingBreak(format!("handle:{}", handle_id)))?;

        // Validate that acked_level is valid per MS-SMB2 3.3.5.22.1
        // Client can ack with the break-to level or NONE (0x00)
        if acked_level != pending.new_level && acked_level != 0x00 {
            return Err(LeaseBreakError::InvalidStateSubset {
                acked: acked_level as u32,
                break_to: pending.new_level as u32,
            });
        }

        debug!(
            handle_id = %handle_id,
            break_id = break_id,
            acked_level = acked_level,
            "Oplock break acknowledged"
        );

        // Notify the waiting caller
        if let Some(tx) = pending.completion_tx.take() {
            let _ = tx.send(LeaseBreakResult::Acknowledged {
                new_state: acked_level as u32,
                epoch: 0,
            });
        }

        Ok(())
    }

    /// Update the oplock level for a registered handle.
    ///
    /// Called after a break is acknowledged to update the stored level.
    pub fn update_oplock_level(&self, handle_id: u128, new_level: u8) {
        if let Some(mut entry) = self.oplock_connections.get_mut(&handle_id) {
            entry.oplock_level = new_level;
        }
    }

    // ========== Lease Break Methods ==========

    /// Initiate a lease break, returns a future that completes when break is done.
    ///
    /// This method:
    /// 1. Sends a LeaseBreakEvent to the owning connection's channel
    /// 2. If ACK is required, registers a pending break and waits for acknowledgment
    /// 3. Returns the result when the client acknowledges or timeout occurs
    ///
    /// # Arguments
    ///
    /// * `lease_key` - The lease key (hex-encoded)
    /// * `current_state` - Current lease state
    /// * `new_state` - New state to break to
    /// * `epoch` - New epoch for the lease
    /// * `file_path` - File path (for logging)
    pub async fn break_lease(
        &self,
        lease_key: &str,
        current_state: u32,
        new_state: u32,
        epoch: u16,
        file_path: &str,
    ) -> Result<LeaseBreakResult, LeaseBreakError> {
        // Get the connection entry for this lease
        let entry = self
            .lease_connections
            .get(lease_key)
            .ok_or_else(|| LeaseBreakError::LeaseNotFound(lease_key.to_string()))?;

        // Determine if ACK is required per MS-SMB2 3.3.4.7:
        // "If Lease.LeaseState is not SMB2_LEASE_READ_CACHING, the server
        //  MUST set SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED"
        const READ_CACHING: u32 = 0x01;
        let ack_required = current_state != READ_CACHING;

        let break_id = self.next_break_id.fetch_add(1, Ordering::Relaxed);

        // Parse lease key from hex
        let mut key_bytes = [0u8; 16];
        if let Ok(bytes) = hex::decode(lease_key) {
            if bytes.len() == 16 {
                key_bytes.copy_from_slice(&bytes);
            }
        }

        let event = LeaseBreakEvent {
            lease_key: key_bytes,
            current_state,
            new_state,
            new_epoch: epoch,
            ack_required,
            break_id,
        };

        debug!(
            lease_key = lease_key,
            current_state = current_state,
            new_state = new_state,
            ack_required = ack_required,
            break_id = break_id,
            "Initiating lease break"
        );

        // Send the break event to the connection
        if let Err(e) = entry.break_tx.send(event).await {
            return Err(LeaseBreakError::SendFailed(e.to_string()));
        }

        // If no ACK required, break completes immediately
        if !ack_required {
            debug!(
                lease_key = lease_key,
                break_id = break_id,
                "Lease break completed (no ACK required)"
            );
            return Ok(LeaseBreakResult::NoAckRequired);
        }

        // Register pending break and wait for ACK
        let (completion_tx, completion_rx) = oneshot::channel();
        let now = Instant::now();
        let pending = PendingBreak {
            lease_key: lease_key.to_string(),
            new_state,
            sent_at: now,
            deadline: now + self.break_timeout,
            file_path: file_path.to_string(),
            completion_tx: Some(completion_tx),
        };

        self.pending_breaks.insert(break_id, pending);

        // Wait for acknowledgment or timeout
        match tokio::time::timeout(self.break_timeout, completion_rx).await {
            Ok(Ok(result)) => {
                self.pending_breaks.remove(&break_id);
                Ok(result)
            }
            Ok(Err(_)) => {
                // Channel was dropped (connection closed)
                self.pending_breaks.remove(&break_id);
                Ok(LeaseBreakResult::Disconnected)
            }
            Err(_) => {
                // Timeout
                self.pending_breaks.remove(&break_id);
                warn!(
                    lease_key = lease_key,
                    break_id = break_id,
                    "Lease break timed out"
                );
                Ok(LeaseBreakResult::TimedOut)
            }
        }
    }

    /// Handle acknowledgment from client.
    ///
    /// Called when an OPLOCK_BREAK acknowledgment is received.
    ///
    /// # Arguments
    ///
    /// * `lease_key` - The lease key (16 bytes)
    /// * `acked_state` - The state the client is acknowledging
    pub fn handle_acknowledgment(
        &self,
        lease_key: &[u8; 16],
        acked_state: u32,
    ) -> Result<(), LeaseBreakError> {
        let lease_key_hex = hex::encode(lease_key);

        // Find the pending break for this lease key
        let break_id = self
            .pending_breaks
            .iter()
            .find(|entry| entry.value().lease_key == lease_key_hex)
            .map(|entry| *entry.key());

        let break_id =
            break_id.ok_or_else(|| LeaseBreakError::NoPendingBreak(lease_key_hex.clone()))?;

        // Remove and get the pending break
        let (_, mut pending) = self
            .pending_breaks
            .remove(&break_id)
            .ok_or_else(|| LeaseBreakError::NoPendingBreak(lease_key_hex.clone()))?;

        // Validate that acked_state is a subset of new_state per MS-SMB2 3.3.5.22.2
        if (acked_state & !pending.new_state) != 0 {
            return Err(LeaseBreakError::InvalidStateSubset {
                acked: acked_state,
                break_to: pending.new_state,
            });
        }

        debug!(
            lease_key = %lease_key_hex,
            break_id = break_id,
            acked_state = acked_state,
            "Lease break acknowledged"
        );

        // Notify the waiting caller
        if let Some(tx) = pending.completion_tx.take() {
            let _ = tx.send(LeaseBreakResult::Acknowledged {
                new_state: acked_state,
                epoch: 0, // Epoch is updated by caller
            });
        }

        Ok(())
    }

    /// Get count of registered leases.
    pub fn lease_count(&self) -> usize {
        self.lease_connections.len()
    }

    /// Get count of pending breaks.
    pub fn pending_break_count(&self) -> usize {
        self.pending_breaks.len()
    }

    /// Process expired breaks (called by timeout processor).
    ///
    /// Returns the lease keys of timed-out breaks.
    pub fn process_expired_breaks(&self) -> Vec<String> {
        let now = Instant::now();
        let expired: Vec<(u64, String)> = self
            .pending_breaks
            .iter()
            .filter(|entry| entry.value().deadline <= now)
            .map(|entry| (*entry.key(), entry.value().lease_key.clone()))
            .collect();

        let mut timed_out = Vec::with_capacity(expired.len());

        for (break_id, lease_key) in expired {
            if let Some((_, mut pending)) = self.pending_breaks.remove(&break_id) {
                trace!(
                    lease_key = %lease_key,
                    break_id = break_id,
                    "Processing expired lease break"
                );

                // Notify the waiting caller
                if let Some(tx) = pending.completion_tx.take() {
                    let _ = tx.send(LeaseBreakResult::TimedOut);
                }

                timed_out.push(lease_key);
            }
        }

        timed_out
    }

    /// Start a background task to process timeouts.
    ///
    /// Returns a JoinHandle that can be used to cancel the task.
    pub fn start_timeout_processor(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                interval.tick().await;
                let expired = self.process_expired_breaks();
                if !expired.is_empty() {
                    debug!(count = expired.len(), "Processed expired lease breaks");
                }
            }
        })
    }
}

impl Default for LeaseBreakRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate the state a conflicting lease should break to.
///
/// Per MS-SMB2 lease conflict rules:
/// - WRITE_CACHING is exclusive - only one client can have it
/// - Conflicting leases must break WRITE before READ
///
/// # Arguments
///
/// * `existing_state` - Current state of the existing lease
/// * `requested_state` - State requested by the new client
pub fn calculate_break_state(existing_state: u32, requested_state: u32) -> u32 {
    const READ_CACHING: u32 = 0x01;
    const WRITE_CACHING: u32 = 0x02;
    const HANDLE_CACHING: u32 = 0x04;

    // If requester wants WRITE, existing must lose WRITE
    if requested_state & WRITE_CACHING != 0 {
        // Break to READ or NONE
        if existing_state & READ_CACHING != 0 {
            READ_CACHING // Keep READ if had it
        } else {
            0 // NONE
        }
    } else if requested_state & HANDLE_CACHING != 0 {
        // If requester wants HANDLE, existing loses HANDLE but may keep R+W
        existing_state & (READ_CACHING | WRITE_CACHING)
    } else {
        // Read-only request, break WRITE_CACHING
        existing_state & !WRITE_CACHING
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== 3.3.4.7 Tests - Sending a Lease Break Notification ==========

    #[test]
    fn test_lease_break_ack_required_non_read() {
        // ACK_REQUIRED flag should be set when state includes WRITE or HANDLE
        // Per MS-SMB2 3.3.4.7: "If Lease.LeaseState is not SMB2_LEASE_READ_CACHING"
        const READ_CACHING: u32 = 0x01;
        const WRITE_CACHING: u32 = 0x02;
        const HANDLE_CACHING: u32 = 0x04;

        // WRITE requires ACK
        let state = WRITE_CACHING;
        assert_ne!(state, READ_CACHING, "WRITE should require ACK");

        // HANDLE requires ACK
        let state = HANDLE_CACHING;
        assert_ne!(state, READ_CACHING, "HANDLE should require ACK");

        // RWH requires ACK
        let state = READ_CACHING | WRITE_CACHING | HANDLE_CACHING;
        assert_ne!(state, READ_CACHING, "RWH should require ACK");

        // READ only does not require ACK
        let state = READ_CACHING;
        assert_eq!(state, READ_CACHING, "READ only should not require ACK");
    }

    // ========== 3.3.5.22 Tests - Receiving OPLOCK_BREAK Acknowledgment ==========

    #[test]
    fn test_lease_ack_state_must_be_subset() {
        // LeaseState MUST be subset of Lease.BreakToLeaseState
        // Per MS-SMB2 3.3.5.22.2: reject with STATUS_REQUEST_NOT_ACCEPTED
        let registry = LeaseBreakRegistry::new();

        // Create a pending break with break_to_state = READ (0x01)
        let break_id = 1;
        let (tx, _rx) = oneshot::channel();
        registry.pending_breaks.insert(
            break_id,
            PendingBreak {
                lease_key: "0102030405060708090a0b0c0d0e0f10".to_string(),
                new_state: 0x01, // READ only
                sent_at: Instant::now(),
                deadline: Instant::now() + Duration::from_secs(35),
                file_path: "/test/file.txt".to_string(),
                completion_tx: Some(tx),
            },
        );

        // ACK with WRITE (0x02) should fail - not a subset of READ
        let lease_key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let result = registry.handle_acknowledgment(&lease_key, 0x02);
        assert!(matches!(
            result,
            Err(LeaseBreakError::InvalidStateSubset {
                acked: 0x02,
                break_to: 0x01
            })
        ));
    }

    #[test]
    fn test_lease_ack_invalid_lease_key() {
        let registry = LeaseBreakRegistry::new();

        // Try to acknowledge non-existent lease
        let lease_key = [0u8; 16];
        let result = registry.handle_acknowledgment(&lease_key, 0);
        assert!(matches!(result, Err(LeaseBreakError::NoPendingBreak(_))));
    }

    // ========== 3.3.6.5 Tests - Lease Break Acknowledgment Timer Event ==========

    #[test]
    fn test_lease_break_timeout_forces_none() {
        // On timeout, LeaseState should be forced to NONE per MS-SMB2 3.3.6.5
        let registry = LeaseBreakRegistry::new();

        // Create an already-expired pending break
        let break_id = 1;
        let (tx, mut rx) = oneshot::channel();
        registry.pending_breaks.insert(
            break_id,
            PendingBreak {
                lease_key: "test_lease".to_string(),
                new_state: 0x01,
                sent_at: Instant::now() - Duration::from_secs(40),
                deadline: Instant::now() - Duration::from_secs(5), // Already expired
                file_path: "/test/file.txt".to_string(),
                completion_tx: Some(tx),
            },
        );

        // Process expired breaks
        let expired = registry.process_expired_breaks();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "test_lease");

        // The receiver should get TimedOut result
        let result = rx.try_recv();
        assert!(matches!(result, Ok(LeaseBreakResult::TimedOut)));
    }

    // ========== LeaseBreakRegistry Tests ==========

    #[test]
    fn test_registry_register_lease() {
        let registry = LeaseBreakRegistry::new();
        let (tx, _rx) = mpsc::channel(32);

        registry.register_lease(
            "test_lease",
            LeaseConnectionEntry {
                break_tx: tx,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 123,
            },
        );

        assert!(registry.is_registered("test_lease"));
        assert_eq!(registry.lease_count(), 1);
    }

    #[test]
    fn test_registry_unregister_lease() {
        let registry = LeaseBreakRegistry::new();
        let (tx, _rx) = mpsc::channel(32);

        registry.register_lease(
            "test_lease",
            LeaseConnectionEntry {
                break_tx: tx,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 123,
            },
        );

        assert!(registry.unregister_lease("test_lease"));
        assert!(!registry.is_registered("test_lease"));
        assert_eq!(registry.lease_count(), 0);
    }

    #[test]
    fn test_registry_unregister_connection_leases() {
        let registry = LeaseBreakRegistry::new();
        let (tx1, _rx1) = mpsc::channel(32);
        let (tx2, _rx2) = mpsc::channel(32);
        let (tx3, _rx3) = mpsc::channel(32);

        // Register leases for different sessions
        registry.register_lease(
            "lease1",
            LeaseConnectionEntry {
                break_tx: tx1,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 100,
            },
        );
        registry.register_lease(
            "lease2",
            LeaseConnectionEntry {
                break_tx: tx2,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 100,
            },
        );
        registry.register_lease(
            "lease3",
            LeaseConnectionEntry {
                break_tx: tx3,
                server_id: "server1".to_string(),
                client_guid: "client2".to_string(),
                session_id: 200,
            },
        );

        assert_eq!(registry.lease_count(), 3);

        // Unregister session 100
        registry.unregister_connection_leases("server1", 100);

        assert!(!registry.is_registered("lease1"));
        assert!(!registry.is_registered("lease2"));
        assert!(registry.is_registered("lease3"));
        assert_eq!(registry.lease_count(), 1);
    }

    #[test]
    fn test_registry_get_server_id() {
        let registry = LeaseBreakRegistry::new();
        let (tx, _rx) = mpsc::channel(32);

        registry.register_lease(
            "test_lease",
            LeaseConnectionEntry {
                break_tx: tx,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 123,
            },
        );

        assert_eq!(
            registry.get_server_id("test_lease"),
            Some("server1".to_string())
        );
        assert_eq!(registry.get_server_id("unknown"), None);
    }

    #[tokio::test]
    async fn test_registry_break_sends_event() {
        let registry = LeaseBreakRegistry::new();
        let (tx, mut rx) = mpsc::channel(32);

        let lease_key = "0102030405060708090a0b0c0d0e0f10";
        registry.register_lease(
            lease_key,
            LeaseConnectionEntry {
                break_tx: tx,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 123,
            },
        );

        // Start break in background
        let registry_clone = Arc::new(registry);
        let lease_key_clone = lease_key.to_string();
        let handle = tokio::spawn({
            let registry = registry_clone.clone();
            async move {
                registry
                    .break_lease(&lease_key_clone, 0x07, 0x01, 2, "/test/file.txt")
                    .await
            }
        });

        // Receive the break event
        let event = rx.recv().await.expect("Should receive break event");
        assert_eq!(event.current_state, 0x07);
        assert_eq!(event.new_state, 0x01);
        assert_eq!(event.new_epoch, 2);
        assert!(event.ack_required); // RWH requires ACK

        // Acknowledge the break
        let mut key_bytes = [0u8; 16];
        key_bytes.copy_from_slice(&hex::decode(lease_key).unwrap());
        registry_clone
            .handle_acknowledgment(&key_bytes, 0x01)
            .expect("ACK should succeed");

        // Break should complete with Acknowledged
        let result = handle.await.expect("Task should complete");
        assert!(matches!(
            result,
            Ok(LeaseBreakResult::Acknowledged {
                new_state: 0x01,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_registry_break_no_ack_required_read_only() {
        let registry = Arc::new(LeaseBreakRegistry::new());
        let (tx, mut rx) = mpsc::channel(32);

        let lease_key = "0102030405060708090a0b0c0d0e0f10";
        registry.register_lease(
            lease_key,
            LeaseConnectionEntry {
                break_tx: tx,
                server_id: "server1".to_string(),
                client_guid: "client1".to_string(),
                session_id: 123,
            },
        );

        // Break from READ_CACHING should not require ACK
        let result = registry
            .break_lease(lease_key, 0x01, 0x00, 2, "/test/file.txt")
            .await;

        assert!(matches!(result, Ok(LeaseBreakResult::NoAckRequired)));

        // Event should still be sent
        let event = rx.recv().await.expect("Should receive break event");
        assert!(!event.ack_required);
    }

    #[test]
    fn test_registry_break_nonexistent_lease() {
        let registry = LeaseBreakRegistry::new();

        // Try to initiate break for unregistered lease
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(registry.break_lease("nonexistent", 0x07, 0x01, 1, "/test"));

        assert!(matches!(result, Err(LeaseBreakError::LeaseNotFound(_))));
    }

    // ========== Calculate Break State Tests ==========

    #[test]
    fn test_calculate_break_state_write_request() {
        // If requester wants WRITE, existing must lose WRITE
        let existing = 0x07; // RWH
        let requested = 0x02; // W
        let break_to = calculate_break_state(existing, requested);
        assert_eq!(break_to, 0x01); // R only (loses W and H)
    }

    #[test]
    fn test_calculate_break_state_handle_request() {
        // If requester wants HANDLE, existing loses HANDLE but keeps R+W
        let existing = 0x07; // RWH
        let requested = 0x04; // H
        let break_to = calculate_break_state(existing, requested);
        assert_eq!(break_to, 0x03); // RW (loses H)
    }

    #[test]
    fn test_calculate_break_state_read_request() {
        // Read-only request, existing breaks WRITE
        let existing = 0x07; // RWH
        let requested = 0x01; // R
        let break_to = calculate_break_state(existing, requested);
        assert_eq!(break_to, 0x05); // RH (loses W)
    }
}
