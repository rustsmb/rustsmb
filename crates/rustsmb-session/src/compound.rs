//! SMB2/3 compound request handling.
//!
//! Compound requests allow multiple SMB2 commands to be batched in a single
//! network packet, reducing round trips for common operation sequences.
//!
//! There are two types of compound requests:
//! - **Related**: Operations share session/tree/file context from previous operations
//! - **Unrelated**: Operations are independent and can execute in parallel

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of commands in a compound request.
pub const MAX_COMPOUND_COMMANDS: usize = 64;

/// Compound request context.
///
/// Tracks the context for processing a sequence of related compound commands.
#[derive(Debug, Clone)]
pub struct CompoundContext {
    /// Whether operations are related (share context).
    pub related: bool,
    /// Session ID from first request (or inherited).
    pub session_id: Option<u64>,
    /// Tree ID from first request (or inherited).
    pub tree_id: Option<u32>,
    /// File ID from previous CREATE (for related requests).
    pub file_id: Option<FileId>,
    /// Index of current command being processed.
    pub current_index: usize,
    /// Total commands in the compound.
    pub total_commands: usize,
    /// Results from previous commands (for error propagation).
    pub previous_results: Vec<CompoundResult>,
}

/// File ID for compound request context.
#[derive(Debug, Clone, Copy)]
pub struct FileId {
    /// Persistent portion of the file ID.
    pub persistent: u128,
    /// Volatile portion of the file ID.
    pub volatile: u128,
}

impl FileId {
    /// Sentinel value indicating "use file ID from previous CREATE".
    pub const RELATED_SENTINEL: u128 = u64::MAX as u128 | ((u64::MAX as u128) << 64);

    /// Create a new FileId.
    pub fn new(persistent: u128, volatile: u128) -> Self {
        Self {
            persistent,
            volatile,
        }
    }

    /// Check if this is the related sentinel value.
    pub fn is_related_sentinel(&self) -> bool {
        self.persistent == Self::RELATED_SENTINEL && self.volatile == Self::RELATED_SENTINEL
    }
}

/// Result of a single command in a compound request.
#[derive(Debug, Clone)]
pub struct CompoundResult {
    /// NT status code.
    pub status: u32,
    /// Was this command successful?
    pub success: bool,
    /// File ID if this was a CREATE command.
    pub file_id: Option<FileId>,
}

impl CompoundResult {
    /// Create a success result.
    pub fn success() -> Self {
        Self {
            status: 0, // STATUS_SUCCESS
            success: true,
            file_id: None,
        }
    }

    /// Create a success result with file ID.
    pub fn success_with_file(file_id: FileId) -> Self {
        Self {
            status: 0,
            success: true,
            file_id: Some(file_id),
        }
    }

    /// Create a failure result.
    pub fn failure(status: u32) -> Self {
        Self {
            status,
            success: false,
            file_id: None,
        }
    }
}

impl CompoundContext {
    /// Create context for unrelated requests.
    pub fn unrelated(total_commands: usize) -> Self {
        Self {
            related: false,
            session_id: None,
            tree_id: None,
            file_id: None,
            current_index: 0,
            total_commands,
            previous_results: Vec::with_capacity(total_commands),
        }
    }

    /// Create context for related requests.
    pub fn related(total_commands: usize) -> Self {
        Self {
            related: true,
            session_id: None,
            tree_id: None,
            file_id: None,
            current_index: 0,
            total_commands,
            previous_results: Vec::with_capacity(total_commands),
        }
    }

    /// Check if this is the first command.
    #[inline]
    pub fn is_first(&self) -> bool {
        self.current_index == 0
    }

    /// Check if this is the last command.
    #[inline]
    pub fn is_last(&self) -> bool {
        self.current_index + 1 >= self.total_commands
    }

    /// Get the effective session ID for a related request.
    ///
    /// For related requests after the first, session_id=0xFFFFFFFFFFFFFFFF
    /// means "use the session ID from the first request".
    pub fn resolve_session_id(&self, request_session_id: u64) -> Option<u64> {
        if !self.related || self.is_first() {
            return Some(request_session_id);
        }

        if request_session_id == u64::MAX {
            // Use inherited session ID
            self.session_id
        } else {
            Some(request_session_id)
        }
    }

    /// Get the effective tree ID for a related request.
    pub fn resolve_tree_id(&self, request_tree_id: u32) -> Option<u32> {
        if !self.related || self.is_first() {
            return Some(request_tree_id);
        }

        if request_tree_id == u32::MAX {
            // Use inherited tree ID
            self.tree_id
        } else {
            Some(request_tree_id)
        }
    }

    /// Get the effective file ID for a related request.
    pub fn resolve_file_id(&self, request_file_id: FileId) -> Option<FileId> {
        if !self.related {
            return Some(request_file_id);
        }

        if request_file_id.is_related_sentinel() {
            // Use file ID from previous CREATE
            self.file_id
        } else {
            Some(request_file_id)
        }
    }

    /// Update context after processing a command.
    pub fn advance(&mut self, result: CompoundResult) {
        // Capture session/tree ID from first successful command
        if self.is_first() && result.success {
            // These should have been set by the caller before processing
        }

        // Capture file ID from CREATE
        if result.success && result.file_id.is_some() {
            self.file_id = result.file_id;
        }

        self.previous_results.push(result);
        self.current_index += 1;
    }

    /// Set the session ID (typically from first request).
    pub fn set_session_id(&mut self, session_id: u64) {
        self.session_id = Some(session_id);
    }

    /// Set the tree ID (typically from first request).
    pub fn set_tree_id(&mut self, tree_id: u32) {
        self.tree_id = Some(tree_id);
    }

    /// Check if a previous command failed (for error propagation in related requests).
    pub fn has_previous_failure(&self) -> bool {
        self.previous_results.iter().any(|r| !r.success)
    }

    /// Get the last failure status (if any).
    pub fn last_failure_status(&self) -> Option<u32> {
        self.previous_results
            .iter()
            .rev()
            .find(|r| !r.success)
            .map(|r| r.status)
    }
}

/// Queue for managing pending compound requests.
#[derive(Debug)]
pub struct CompoundQueue {
    /// Pending compound operations.
    pending: VecDeque<PendingCompound>,
    /// Counter for generating compound IDs.
    next_id: AtomicU64,
    /// Maximum pending compounds.
    max_pending: usize,
}

/// A pending compound request.
#[derive(Debug)]
pub struct PendingCompound {
    /// Unique ID for this compound.
    pub id: u64,
    /// Context for the compound.
    pub context: CompoundContext,
    /// Message ID of the first request.
    pub first_message_id: u64,
}

impl CompoundQueue {
    /// Create a new compound queue.
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: VecDeque::with_capacity(max_pending.min(64)),
            next_id: AtomicU64::new(1),
            max_pending,
        }
    }

    /// Start a new compound request.
    pub fn start(&mut self, context: CompoundContext, first_message_id: u64) -> Option<u64> {
        if self.pending.len() >= self.max_pending {
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.pending.push_back(PendingCompound {
            id,
            context,
            first_message_id,
        });
        Some(id)
    }

    /// Get a pending compound by ID.
    pub fn get(&self, id: u64) -> Option<&PendingCompound> {
        self.pending.iter().find(|c| c.id == id)
    }

    /// Get a mutable pending compound by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut PendingCompound> {
        self.pending.iter_mut().find(|c| c.id == id)
    }

    /// Complete and remove a compound.
    pub fn complete(&mut self, id: u64) -> Option<PendingCompound> {
        if let Some(pos) = self.pending.iter().position(|c| c.id == id) {
            self.pending.remove(pos)
        } else {
            None
        }
    }

    /// Get the number of pending compounds.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

impl Default for CompoundQueue {
    fn default() -> Self {
        Self::new(64)
    }
}

/// Parse compound request boundaries from a message.
///
/// Returns the offsets of each command in the compound.
pub fn parse_compound_offsets(data: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut current = 0;

    while current < data.len() {
        offsets.push(current);

        // Need at least 64 bytes for SMB2 header
        if current + 64 > data.len() {
            break;
        }

        // NextCommand is at offset 20 in the header (4 bytes LE)
        let next_offset_pos = current + 20;
        if next_offset_pos + 4 > data.len() {
            break;
        }

        let next_command = u32::from_le_bytes([
            data[next_offset_pos],
            data[next_offset_pos + 1],
            data[next_offset_pos + 2],
            data[next_offset_pos + 3],
        ]);

        if next_command == 0 {
            // This is the last command
            break;
        }

        // NextCommand is relative to the start of the current header
        current += next_command as usize;
    }

    offsets
}

/// Calculate 8-byte alignment padding for compound messages.
#[inline]
pub fn compound_padding(offset: usize) -> usize {
    (8 - (offset % 8)) % 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compound_context_unrelated() {
        let ctx = CompoundContext::unrelated(3);
        assert!(!ctx.related);
        assert_eq!(ctx.total_commands, 3);
        assert!(ctx.is_first());
    }

    #[test]
    fn test_compound_context_related() {
        let mut ctx = CompoundContext::related(3);
        ctx.set_session_id(123);
        ctx.set_tree_id(456);

        // First request uses its own values
        assert_eq!(ctx.resolve_session_id(100), Some(100));
        assert_eq!(ctx.resolve_tree_id(200), Some(200));

        // Advance to second request
        ctx.advance(CompoundResult::success());

        // Sentinel value (u64::MAX) means use inherited
        assert_eq!(ctx.resolve_session_id(u64::MAX), Some(123));
        assert_eq!(ctx.resolve_tree_id(u32::MAX), Some(456));

        // Explicit value still works
        assert_eq!(ctx.resolve_session_id(999), Some(999));
    }

    #[test]
    fn test_file_id_sentinel() {
        let sentinel = FileId::new(FileId::RELATED_SENTINEL, FileId::RELATED_SENTINEL);
        assert!(sentinel.is_related_sentinel());

        let normal = FileId::new(1, 2);
        assert!(!normal.is_related_sentinel());
    }

    #[test]
    fn test_resolve_file_id() {
        let mut ctx = CompoundContext::related(2);

        // Set file ID from CREATE result
        let create_file_id = FileId::new(0x1234, 0x5678);
        ctx.advance(CompoundResult::success_with_file(create_file_id));

        // Next command with sentinel should get CREATE's file ID
        let sentinel = FileId::new(FileId::RELATED_SENTINEL, FileId::RELATED_SENTINEL);
        let resolved = ctx.resolve_file_id(sentinel);
        assert!(resolved.is_some());
        let resolved = resolved.unwrap();
        assert_eq!(resolved.persistent, 0x1234);
        assert_eq!(resolved.volatile, 0x5678);
    }

    #[test]
    fn test_compound_queue() {
        let mut queue = CompoundQueue::new(10);

        let ctx = CompoundContext::related(2);
        let id = queue.start(ctx, 100).unwrap();

        assert_eq!(queue.len(), 1);
        assert!(queue.get(id).is_some());

        let completed = queue.complete(id);
        assert!(completed.is_some());
        assert!(queue.is_empty());
    }

    #[test]
    fn test_compound_padding() {
        assert_eq!(compound_padding(0), 0);
        assert_eq!(compound_padding(1), 7);
        assert_eq!(compound_padding(7), 1);
        assert_eq!(compound_padding(8), 0);
        assert_eq!(compound_padding(64), 0);
        assert_eq!(compound_padding(65), 7);
    }

    #[test]
    fn test_previous_failure() {
        let mut ctx = CompoundContext::related(3);

        ctx.advance(CompoundResult::success());
        assert!(!ctx.has_previous_failure());

        ctx.advance(CompoundResult::failure(0xC0000001));
        assert!(ctx.has_previous_failure());
        assert_eq!(ctx.last_failure_status(), Some(0xC0000001));
    }

    #[test]
    fn test_parse_compound_offsets() {
        // Create a mock compound message with two commands
        // Each command has a 64-byte header
        let mut data = vec![0u8; 200];

        // First header: NextCommand = 100 (at offset 20)
        data[20..24].copy_from_slice(&100u32.to_le_bytes());

        // Second header: NextCommand = 0 (last command, at offset 100+20=120)
        // Already zeros

        let offsets = parse_compound_offsets(&data);
        assert_eq!(offsets, vec![0, 100]);
    }
}
