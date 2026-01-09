//! Asynchronous request tracking.
//!
//! Some SMB2 operations (like CHANGE_NOTIFY and LOCK with wait) return
//! STATUS_PENDING and complete asynchronously later. This module tracks
//! such pending operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

/// Default maximum pending async requests per connection.
pub const DEFAULT_MAX_ASYNC_REQUESTS: usize = 256;

/// Default timeout for async requests.
pub const DEFAULT_ASYNC_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour

/// Async request configuration.
#[derive(Debug, Clone)]
pub struct AsyncRequestConfig {
    /// Maximum pending async requests.
    pub max_pending: usize,
    /// Default timeout for async operations.
    pub default_timeout: Duration,
    /// Whether to send interim responses.
    pub send_interim_response: bool,
}

impl Default for AsyncRequestConfig {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_ASYNC_REQUESTS,
            default_timeout: DEFAULT_ASYNC_TIMEOUT,
            send_interim_response: true,
        }
    }
}

/// Types of async operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncOperationType {
    /// CHANGE_NOTIFY operation.
    ChangeNotify,
    /// LOCK operation with wait flag.
    LockWait,
    /// OPLOCK/Lease break acknowledgment.
    OplockBreak,
    /// Large write operation.
    Write,
    /// Large read operation.
    Read,
    /// Other async operation.
    Other,
}

/// An async request waiting for completion.
#[derive(Debug)]
pub struct AsyncRequest {
    /// Unique async ID.
    pub async_id: u64,
    /// Original message ID.
    pub message_id: u64,
    /// Session ID.
    pub session_id: u64,
    /// Tree ID.
    pub tree_id: u32,
    /// File handle (if applicable).
    pub file_id: Option<(u128, u128)>,
    /// Operation type.
    pub operation: AsyncOperationType,
    /// When the request was created.
    pub created: Instant,
    /// Timeout duration.
    pub timeout: Duration,
    /// Command code.
    pub command: u16,
    /// Cancellation flag.
    cancelled: bool,
}

impl AsyncRequest {
    /// Check if this request has timed out.
    pub fn is_timed_out(&self) -> bool {
        self.created.elapsed() > self.timeout
    }

    /// Check if this request has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Cancel this request.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Get remaining time before timeout.
    pub fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.created.elapsed())
    }
}

/// Result of completing an async request.
#[derive(Debug)]
pub struct AsyncCompletion {
    /// The async request that completed.
    pub request: AsyncRequest,
    /// NT status code.
    pub status: u32,
    /// Response data (if any).
    pub data: Vec<u8>,
}

/// Tracker for async requests on a connection.
#[derive(Debug)]
pub struct AsyncRequestTracker {
    /// Pending requests by async ID.
    pending: HashMap<u64, AsyncRequest>,
    /// Mapping from message ID to async ID.
    message_to_async: HashMap<u64, u64>,
    /// Next async ID.
    next_async_id: AtomicU64,
    /// Configuration.
    config: AsyncRequestConfig,
    /// Completion notifiers.
    notifiers: HashMap<u64, oneshot::Sender<AsyncCompletion>>,
}

impl AsyncRequestTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::with_config(AsyncRequestConfig::default())
    }

    /// Create a new tracker with custom config.
    pub fn with_config(config: AsyncRequestConfig) -> Self {
        Self {
            pending: HashMap::with_capacity(config.max_pending.min(64)),
            message_to_async: HashMap::with_capacity(config.max_pending.min(64)),
            next_async_id: AtomicU64::new(1),
            config,
            notifiers: HashMap::new(),
        }
    }

    /// Register a new async request.
    ///
    /// Returns the async ID and a receiver for completion notification,
    /// or None if at capacity.
    pub fn register(
        &mut self,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        operation: AsyncOperationType,
        command: u16,
    ) -> Option<(u64, oneshot::Receiver<AsyncCompletion>)> {
        self.register_with_timeout(
            message_id,
            session_id,
            tree_id,
            operation,
            command,
            self.config.default_timeout,
        )
    }

    /// Register a new async request with custom timeout.
    pub fn register_with_timeout(
        &mut self,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        operation: AsyncOperationType,
        command: u16,
        timeout: Duration,
    ) -> Option<(u64, oneshot::Receiver<AsyncCompletion>)> {
        if self.pending.len() >= self.config.max_pending {
            warn!("Async request limit reached ({})", self.config.max_pending);
            return None;
        }

        let async_id = self.next_async_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();

        let request = AsyncRequest {
            async_id,
            message_id,
            session_id,
            tree_id,
            file_id: None,
            operation,
            created: Instant::now(),
            timeout,
            command,
            cancelled: false,
        };

        debug!(
            "Registered async request: id={}, message_id={}, op={:?}",
            async_id, message_id, operation
        );

        self.pending.insert(async_id, request);
        self.message_to_async.insert(message_id, async_id);
        self.notifiers.insert(async_id, tx);

        Some((async_id, rx))
    }

    /// Register with file ID.
    pub fn register_with_file(
        &mut self,
        message_id: u64,
        session_id: u64,
        tree_id: u32,
        file_id: (u128, u128),
        operation: AsyncOperationType,
        command: u16,
    ) -> Option<(u64, oneshot::Receiver<AsyncCompletion>)> {
        let result = self.register(message_id, session_id, tree_id, operation, command)?;

        if let Some(request) = self.pending.get_mut(&result.0) {
            request.file_id = Some(file_id);
        }

        Some(result)
    }

    /// Get a pending request by async ID.
    pub fn get(&self, async_id: u64) -> Option<&AsyncRequest> {
        self.pending.get(&async_id)
    }

    /// Get a pending request by message ID.
    pub fn get_by_message_id(&self, message_id: u64) -> Option<&AsyncRequest> {
        self.message_to_async
            .get(&message_id)
            .and_then(|id| self.pending.get(id))
    }

    /// Complete an async request.
    ///
    /// Removes the request and notifies any waiters.
    pub fn complete(&mut self, async_id: u64, status: u32, data: Vec<u8>) -> Option<AsyncRequest> {
        let request = self.pending.remove(&async_id)?;
        self.message_to_async.remove(&request.message_id);

        debug!(
            "Completing async request: id={}, status={:#x}",
            async_id, status
        );

        // Notify waiter
        if let Some(notifier) = self.notifiers.remove(&async_id) {
            let completion = AsyncCompletion {
                request: AsyncRequest {
                    async_id,
                    message_id: request.message_id,
                    session_id: request.session_id,
                    tree_id: request.tree_id,
                    file_id: request.file_id,
                    operation: request.operation,
                    created: request.created,
                    timeout: request.timeout,
                    command: request.command,
                    cancelled: request.cancelled,
                },
                status,
                data,
            };
            let _ = notifier.send(completion);

            Some(request)
        } else {
            Some(request)
        }
    }

    /// Cancel an async request by message ID.
    ///
    /// This is called when a CANCEL command is received.
    pub fn cancel_by_message_id(&mut self, message_id: u64) -> Option<AsyncRequest> {
        let async_id = self.message_to_async.get(&message_id).copied()?;
        self.cancel(async_id)
    }

    /// Cancel an async request by async ID.
    pub fn cancel(&mut self, async_id: u64) -> Option<AsyncRequest> {
        if let Some(request) = self.pending.get_mut(&async_id) {
            request.cancel();
            debug!("Cancelled async request: id={}", async_id);
        }

        // Complete with STATUS_CANCELLED
        self.complete(async_id, 0xC0000120, Vec::new())
    }

    /// Cancel all requests for a session (session logoff).
    pub fn cancel_session(&mut self, session_id: u64) -> Vec<AsyncRequest> {
        let to_cancel: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, r)| r.session_id == session_id)
            .map(|(id, _)| *id)
            .collect();

        to_cancel
            .into_iter()
            .filter_map(|id| self.cancel(id))
            .collect()
    }

    /// Cancel all requests for a tree (tree disconnect).
    pub fn cancel_tree(&mut self, session_id: u64, tree_id: u32) -> Vec<AsyncRequest> {
        let to_cancel: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, r)| r.session_id == session_id && r.tree_id == tree_id)
            .map(|(id, _)| *id)
            .collect();

        to_cancel
            .into_iter()
            .filter_map(|id| self.cancel(id))
            .collect()
    }

    /// Cancel all requests for a file handle.
    pub fn cancel_file(&mut self, file_id: (u128, u128)) -> Vec<AsyncRequest> {
        let to_cancel: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, r)| r.file_id == Some(file_id))
            .map(|(id, _)| *id)
            .collect();

        to_cancel
            .into_iter()
            .filter_map(|id| self.cancel(id))
            .collect()
    }

    /// Clean up timed out requests.
    ///
    /// Returns the expired requests.
    pub fn cleanup_expired(&mut self) -> Vec<AsyncRequest> {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, r)| r.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        trace!("Cleaning up {} expired async requests", expired.len());

        expired
            .into_iter()
            .filter_map(|id| self.complete(id, 0xC00000B5, Vec::new())) // STATUS_IO_TIMEOUT
            .collect()
    }

    /// Get the count of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Check if any requests are pending.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Get all pending requests for iteration.
    pub fn pending_iter(&self) -> impl Iterator<Item = &AsyncRequest> {
        self.pending.values()
    }

    /// Get CHANGE_NOTIFY requests for a specific directory.
    pub fn get_change_notify_for_file(
        &self,
        file_id: (u128, u128),
    ) -> impl Iterator<Item = &AsyncRequest> {
        self.pending.values().filter(move |r| {
            r.operation == AsyncOperationType::ChangeNotify && r.file_id == Some(file_id)
        })
    }
}

impl Default for AsyncRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_complete() {
        let mut tracker = AsyncRequestTracker::new();

        let (async_id, _rx) = tracker
            .register(100, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();

        assert!(tracker.get(async_id).is_some());
        assert!(tracker.get_by_message_id(100).is_some());
        assert_eq!(tracker.pending_count(), 1);

        let completed = tracker.complete(async_id, 0, Vec::new());
        assert!(completed.is_some());
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn test_cancel_by_message_id() {
        let mut tracker = AsyncRequestTracker::new();

        let (async_id, _rx) = tracker
            .register(100, 1, 2, AsyncOperationType::LockWait, 0x0A)
            .unwrap();

        let cancelled = tracker.cancel_by_message_id(100);
        assert!(cancelled.is_some());
        assert!(cancelled.unwrap().is_cancelled());
        assert_eq!(tracker.pending_count(), 0);

        // Double cancel should return None
        assert!(tracker.cancel(async_id).is_none());
    }

    #[test]
    fn test_cancel_session() {
        let mut tracker = AsyncRequestTracker::new();

        // Register requests for different sessions
        tracker
            .register(100, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();
        tracker
            .register(101, 1, 3, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();
        tracker
            .register(102, 2, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();

        assert_eq!(tracker.pending_count(), 3);

        // Cancel session 1
        let cancelled = tracker.cancel_session(1);
        assert_eq!(cancelled.len(), 2);
        assert_eq!(tracker.pending_count(), 1);

        // Session 2's request should remain
        assert!(tracker.get_by_message_id(102).is_some());
    }

    #[test]
    fn test_cancel_tree() {
        let mut tracker = AsyncRequestTracker::new();

        tracker
            .register(100, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();
        tracker
            .register(101, 1, 3, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();
        tracker
            .register(102, 1, 2, AsyncOperationType::LockWait, 0x0A)
            .unwrap();

        let cancelled = tracker.cancel_tree(1, 2);
        assert_eq!(cancelled.len(), 2);
        assert_eq!(tracker.pending_count(), 1);
    }

    #[test]
    fn test_max_pending() {
        let config = AsyncRequestConfig {
            max_pending: 2,
            ..Default::default()
        };
        let mut tracker = AsyncRequestTracker::with_config(config);

        assert!(tracker
            .register(100, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .is_some());
        assert!(tracker
            .register(101, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .is_some());

        // Third should fail
        assert!(tracker
            .register(102, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .is_none());
    }

    #[test]
    fn test_timeout_check() {
        let config = AsyncRequestConfig {
            default_timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let mut tracker = AsyncRequestTracker::with_config(config);

        tracker
            .register(100, 1, 2, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let expired = tracker.cleanup_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(tracker.pending_count(), 0);
    }

    #[test]
    fn test_register_with_file() {
        let mut tracker = AsyncRequestTracker::new();
        let file_id = (0x1234, 0x5678);

        let (async_id, _rx) = tracker
            .register_with_file(100, 1, 2, file_id, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();

        let request = tracker.get(async_id).unwrap();
        assert_eq!(request.file_id, Some(file_id));

        // Cancel by file should work
        let cancelled = tracker.cancel_file(file_id);
        assert_eq!(cancelled.len(), 1);
    }

    #[test]
    fn test_get_change_notify_for_file() {
        let mut tracker = AsyncRequestTracker::new();
        let file_id = (0x1234, 0x5678);

        tracker
            .register_with_file(100, 1, 2, file_id, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();
        tracker
            .register_with_file(101, 1, 2, file_id, AsyncOperationType::ChangeNotify, 0x0F)
            .unwrap();
        tracker
            .register_with_file(
                102,
                1,
                2,
                (0xAAAA, 0xBBBB),
                AsyncOperationType::ChangeNotify,
                0x0F,
            )
            .unwrap();

        let notify_count = tracker.get_change_notify_for_file(file_id).count();
        assert_eq!(notify_count, 2);
    }
}
