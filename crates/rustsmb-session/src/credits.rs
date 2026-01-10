//! SMB2/3 credit management.
//!
//! Credits are the flow control mechanism in SMB2/3. Each request consumes credits
//! and responses grant new credits. Multi-credit operations allow large transfers
//! without excessive round trips.

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use tracing::{debug, trace};

/// Default initial credits granted to a new connection.
/// Windows servers typically grant 256+ credits after NEGOTIATE.
pub const DEFAULT_INITIAL_CREDITS: u16 = 256;

/// Default maximum credits a connection can accumulate.
pub const DEFAULT_MAX_CREDITS: u16 = 8192;

/// Minimum credits to grant in any response to prevent client starvation.
pub const MIN_CREDITS_PER_RESPONSE: u16 = 1;

/// Credit manager configuration.
#[derive(Debug, Clone)]
pub struct CreditConfig {
    /// Initial credits granted after negotiation.
    pub initial_credits: u16,
    /// Maximum credits a connection can accumulate.
    pub max_credits: u16,
    /// Credits to grant per response (base amount).
    pub grant_per_response: u16,
    /// Whether to scale grants based on request type.
    pub adaptive_grants: bool,
}

impl Default for CreditConfig {
    fn default() -> Self {
        Self {
            initial_credits: DEFAULT_INITIAL_CREDITS,
            max_credits: DEFAULT_MAX_CREDITS,
            grant_per_response: 1,
            adaptive_grants: true,
        }
    }
}

/// Credit manager for a single connection.
///
/// Manages the credit balance for a connection, tracking how many credits
/// are available and consumed.
#[derive(Debug)]
pub struct CreditManager {
    /// Currently available credits.
    available: AtomicU16,
    /// Total credits ever granted.
    granted: AtomicU64,
    /// Total credits ever consumed.
    consumed: AtomicU64,
    /// Configuration.
    config: CreditConfig,
}

impl CreditManager {
    /// Create a new credit manager with default configuration.
    pub fn new() -> Self {
        Self::with_config(CreditConfig::default())
    }

    /// Create a new credit manager with custom configuration.
    pub fn with_config(config: CreditConfig) -> Self {
        Self {
            available: AtomicU16::new(config.initial_credits),
            granted: AtomicU64::new(config.initial_credits as u64),
            consumed: AtomicU64::new(0),
            config,
        }
    }

    /// Get the current available credits.
    #[inline]
    pub fn available(&self) -> u16 {
        self.available.load(Ordering::Acquire)
    }

    /// Get the total credits granted.
    #[inline]
    pub fn total_granted(&self) -> u64 {
        self.granted.load(Ordering::Relaxed)
    }

    /// Get the total credits consumed.
    #[inline]
    pub fn total_consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }

    /// Check if there are enough credits for a request.
    ///
    /// Returns `true` if the credit charge can be satisfied.
    #[inline]
    pub fn can_satisfy(&self, credit_charge: u16) -> bool {
        self.available() >= credit_charge.max(1)
    }

    /// Consume credits for a request.
    ///
    /// Returns the actual credits consumed, or `None` if insufficient credits.
    pub fn consume(&self, credit_charge: u16) -> Option<u16> {
        let charge = credit_charge.max(1); // Minimum 1 credit per request

        loop {
            let current = self.available.load(Ordering::Acquire);
            if current < charge {
                debug!(
                    "Insufficient credits: requested {}, available {}",
                    charge, current
                );
                return None;
            }

            let new_value = current - charge;
            if self
                .available
                .compare_exchange_weak(current, new_value, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.consumed.fetch_add(charge as u64, Ordering::Relaxed);
                trace!("Consumed {} credits, {} remaining", charge, new_value);
                return Some(charge);
            }
        }
    }

    /// Grant credits (typically when sending a response).
    ///
    /// Returns the actual credits granted (capped at max).
    pub fn grant(&self, credits: u16) -> u16 {
        if credits == 0 {
            return 0;
        }

        loop {
            let current = self.available.load(Ordering::Acquire);
            let max_grant = self.config.max_credits.saturating_sub(current);
            let actual_grant = credits.min(max_grant);

            if actual_grant == 0 {
                return 0;
            }

            let new_value = current + actual_grant;
            if self
                .available
                .compare_exchange_weak(current, new_value, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.granted
                    .fetch_add(actual_grant as u64, Ordering::Relaxed);
                trace!("Granted {} credits, {} available", actual_grant, new_value);
                return actual_grant;
            }
        }
    }

    /// Calculate credits to grant in a response.
    ///
    /// Uses adaptive grant logic based on current balance and request type.
    /// Always grants at least MIN_CREDITS_PER_RESPONSE to prevent client starvation.
    pub fn calculate_grant(&self, requested_credits: u16, is_async: bool) -> u16 {
        let current = self.available();
        let headroom = self.config.max_credits.saturating_sub(current);

        // If at max, can't grant more
        if headroom == 0 {
            return 0;
        }

        if !self.config.adaptive_grants {
            return self.config.grant_per_response.min(headroom);
        }

        let target = self.config.max_credits / 2; // Target 50% of max

        // Base grant - always at least 1
        let mut grant = self.config.grant_per_response.max(MIN_CREDITS_PER_RESPONSE);

        // If below target, grant more aggressively
        if current < target {
            // Grant enough to help client reach a comfortable level
            let deficit = target - current;
            grant = grant.saturating_add(deficit / 4);
        }

        // Honor client request within limits
        if requested_credits > 0 {
            grant = grant.max(requested_credits);
        }

        // Async operations get more credits (they may spawn multiple responses)
        if is_async {
            grant = grant.saturating_mul(2);
        }

        // Cap at remaining headroom, but ensure at least 1 if possible
        grant.min(headroom).max(MIN_CREDITS_PER_RESPONSE.min(headroom))
    }

    /// Calculate the credit charge for a multi-credit operation.
    ///
    /// Multi-credit operations use credits based on payload size.
    /// The formula is: ceiling((PayloadSize - 1) / 65536) + 1
    pub fn calculate_charge(payload_size: u32, max_payload_per_credit: u32) -> u16 {
        if payload_size == 0 {
            return 1;
        }

        let max_per = max_payload_per_credit.max(1);
        let charge = (payload_size.saturating_sub(1) / max_per) + 1;
        charge.min(u16::MAX as u32) as u16
    }

    /// Validate a credit charge from a request.
    ///
    /// Returns `Ok(actual_charge)` if valid, `Err` with reason if invalid.
    pub fn validate_charge(
        &self,
        credit_charge: u16,
        payload_size: u32,
        max_payload_per_credit: u32,
    ) -> Result<u16, CreditError> {
        let min_required = Self::calculate_charge(payload_size, max_payload_per_credit);
        let actual_charge = credit_charge.max(1);

        if actual_charge < min_required {
            return Err(CreditError::InsufficientCharge {
                provided: actual_charge,
                required: min_required,
            });
        }

        if !self.can_satisfy(actual_charge) {
            return Err(CreditError::InsufficientCredits {
                requested: actual_charge,
                available: self.available(),
            });
        }

        Ok(actual_charge)
    }

    /// Reset credit balance (e.g., after reconnect).
    pub fn reset(&self) {
        self.available
            .store(self.config.initial_credits, Ordering::Release);
        debug!("Credit balance reset to {}", self.config.initial_credits);
    }
}

impl Default for CreditManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors related to credit operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditError {
    /// Credit charge is less than required for payload.
    InsufficientCharge { provided: u16, required: u16 },
    /// Not enough credits available.
    InsufficientCredits { requested: u16, available: u16 },
}

impl std::fmt::Display for CreditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreditError::InsufficientCharge { provided, required } => {
                write!(
                    f,
                    "Insufficient credit charge: provided {}, required {}",
                    provided, required
                )
            }
            CreditError::InsufficientCredits {
                requested,
                available,
            } => {
                write!(
                    f,
                    "Insufficient credits: requested {}, available {}",
                    requested, available
                )
            }
        }
    }
}

impl std::error::Error for CreditError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_credits() {
        let manager = CreditManager::new();
        assert_eq!(manager.available(), DEFAULT_INITIAL_CREDITS);
    }

    #[test]
    fn test_consume_credits() {
        let config = CreditConfig {
            initial_credits: 10,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);

        assert!(manager.can_satisfy(5));
        assert_eq!(manager.consume(5), Some(5));
        assert_eq!(manager.available(), 5);
        assert_eq!(manager.total_consumed(), 5);
    }

    #[test]
    fn test_consume_insufficient_credits() {
        let config = CreditConfig {
            initial_credits: 5,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);

        assert!(!manager.can_satisfy(10));
        assert_eq!(manager.consume(10), None);
        assert_eq!(manager.available(), 5);
    }

    #[test]
    fn test_grant_credits() {
        let config = CreditConfig {
            initial_credits: 5,
            max_credits: 100,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);

        assert_eq!(manager.grant(10), 10);
        assert_eq!(manager.available(), 15);
        assert_eq!(manager.total_granted(), 15);
    }

    #[test]
    fn test_grant_capped_at_max() {
        let config = CreditConfig {
            initial_credits: 90,
            max_credits: 100,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);

        // Try to grant 20, but only 10 headroom
        assert_eq!(manager.grant(20), 10);
        assert_eq!(manager.available(), 100);
    }

    #[test]
    fn test_minimum_charge_is_one() {
        let config = CreditConfig {
            initial_credits: 10,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);

        // Credit charge of 0 should consume 1
        assert_eq!(manager.consume(0), Some(1));
        assert_eq!(manager.available(), 9);
    }

    #[test]
    fn test_calculate_charge() {
        // 64KB per credit
        let max_per_credit = 65536;

        assert_eq!(CreditManager::calculate_charge(0, max_per_credit), 1);
        assert_eq!(CreditManager::calculate_charge(1, max_per_credit), 1);
        assert_eq!(CreditManager::calculate_charge(65536, max_per_credit), 1);
        assert_eq!(CreditManager::calculate_charge(65537, max_per_credit), 2);
        assert_eq!(CreditManager::calculate_charge(131072, max_per_credit), 2);
        assert_eq!(CreditManager::calculate_charge(131073, max_per_credit), 3);
    }

    #[test]
    fn test_validate_charge() {
        let config = CreditConfig {
            initial_credits: 10,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);
        let max_per_credit = 65536;

        // Valid charge
        assert!(manager.validate_charge(2, 100000, max_per_credit).is_ok());

        // Insufficient charge for payload
        let err = manager.validate_charge(1, 100000, max_per_credit);
        assert!(matches!(err, Err(CreditError::InsufficientCharge { .. })));

        // Insufficient credits available
        let err = manager.validate_charge(20, 1000, max_per_credit);
        assert!(matches!(err, Err(CreditError::InsufficientCredits { .. })));
    }

    #[test]
    fn test_reset() {
        let config = CreditConfig {
            initial_credits: 10,
            ..Default::default()
        };
        let manager = CreditManager::with_config(config);

        manager.consume(5);
        assert_eq!(manager.available(), 5);

        manager.reset();
        assert_eq!(manager.available(), 10);
    }

    #[test]
    fn test_calculate_grant_adaptive() {
        let config = CreditConfig {
            initial_credits: 10,
            max_credits: 100,
            grant_per_response: 1,
            adaptive_grants: true,
        };
        let manager = CreditManager::with_config(config);

        // Below target (50), should grant more
        let grant = manager.calculate_grant(0, false);
        assert!(grant > 1); // Should be elevated due to being below target

        // Async operations get more
        let async_grant = manager.calculate_grant(0, true);
        assert!(async_grant > grant);
    }

    #[test]
    fn test_default_initial_credits_sufficient() {
        // Verify default initial credits are sufficient for typical SMB operations
        let manager = CreditManager::new();

        // Should have at least 256 credits initially (per Windows server behavior)
        assert!(
            manager.available() >= 256,
            "Initial credits should be at least 256, got {}",
            manager.available()
        );

        // Should be able to handle multiple operations without starvation
        for _ in 0..10 {
            assert!(
                manager.can_satisfy(1),
                "Should have credits for basic operations"
            );
            manager.consume(1);
        }

        // Still should have credits remaining
        assert!(
            manager.available() > 0,
            "Should have credits remaining after 10 operations"
        );
    }

    #[test]
    fn test_credits_after_negotiate_response() {
        // Simulate a fresh connection with credits granted by NEGOTIATE response
        let config = CreditConfig {
            initial_credits: DEFAULT_INITIAL_CREDITS,
            max_credits: DEFAULT_MAX_CREDITS,
            grant_per_response: 1,
            adaptive_grants: true,
        };
        let manager = CreditManager::with_config(config);

        // Client sends NEGOTIATE, server responds granting credits
        // The calculate_grant should return a reasonable amount
        let credits_to_grant = manager.calculate_grant(64, false); // Client requests 64

        // Should grant enough for follow-up operations
        assert!(
            credits_to_grant >= 64,
            "Should grant at least what client requested, got {}",
            credits_to_grant
        );

        // Grant the credits
        manager.grant(credits_to_grant);

        // Now client should be able to send SESSION_SETUP (uses 1 credit)
        assert!(
            manager.can_satisfy(1),
            "Should have credits for SESSION_SETUP"
        );
    }

    #[test]
    fn test_prevent_credit_starvation() {
        // Verify that even with 0 requested credits, we grant something
        let config = CreditConfig {
            initial_credits: 10,
            max_credits: 100,
            grant_per_response: 1,
            adaptive_grants: true,
        };
        let manager = CreditManager::with_config(config);

        // Even with 0 requested, should grant at least 1
        let grant = manager.calculate_grant(0, false);
        assert!(
            grant >= MIN_CREDITS_PER_RESPONSE,
            "Should grant at least MIN_CREDITS_PER_RESPONSE, got {}",
            grant
        );
    }

    #[test]
    fn test_consume_grant_cycle() {
        // Simulate a realistic request/response cycle
        let config = CreditConfig {
            initial_credits: 256,
            max_credits: 1000,
            grant_per_response: 1,
            adaptive_grants: true,
        };
        let manager = CreditManager::with_config(config);

        // After NEGOTIATE, grant credits (simulating first response)
        let first_grant = manager.calculate_grant(64, false);
        manager.grant(first_grant);
        let after_first_grant = manager.available();
        assert!(
            after_first_grant > 256,
            "Should have more credits after first grant: {}",
            after_first_grant
        );

        // Simulate 10 request/response cycles
        for i in 0..10 {
            // Client sends request, consuming 1 credit
            let consumed = manager.consume(1);
            assert!(
                consumed.is_some(),
                "Should be able to consume credit on iteration {}",
                i
            );

            // Server responds, granting credits
            let to_grant = manager.calculate_grant(1, false);
            manager.grant(to_grant);
        }

        // Should still have plenty of credits
        assert!(
            manager.available() > 100,
            "Should still have credits after 10 cycles: {}",
            manager.available()
        );
    }

    #[test]
    fn test_headroom_replenishes_after_consume() {
        // This tests the bug where credits couldn't be granted after hitting max
        let config = CreditConfig {
            initial_credits: 100,
            max_credits: 100, // Start at max
            grant_per_response: 10,
            adaptive_grants: false,
        };
        let manager = CreditManager::with_config(config);

        // At max, grant should return 0
        assert_eq!(manager.grant(10), 0, "No headroom when at max");

        // Consume some credits
        manager.consume(50);
        assert_eq!(manager.available(), 50);

        // Now should be able to grant again
        let granted = manager.grant(10);
        assert_eq!(granted, 10, "Should grant after consuming");
        assert_eq!(manager.available(), 60);
    }

    #[test]
    fn test_sustained_traffic_pattern() {
        // Simulate sustained client traffic where requests arrive continuously
        let config = CreditConfig {
            initial_credits: DEFAULT_INITIAL_CREDITS,
            max_credits: DEFAULT_MAX_CREDITS,
            grant_per_response: 1,
            adaptive_grants: true,
        };
        let manager = CreditManager::with_config(config);

        // Simulate 100 sequential requests (like listing a large directory)
        for i in 0..100 {
            // Each request consumes credits
            assert!(
                manager.consume(1).is_some(),
                "Failed to consume on iteration {}, available: {}",
                i,
                manager.available()
            );

            // Each response grants credits
            let to_grant = manager.calculate_grant(1, false);
            manager.grant(to_grant);
        }

        // Credits should remain healthy
        assert!(
            manager.available() >= 200,
            "Should maintain healthy credits: {}",
            manager.available()
        );
    }

    #[test]
    fn test_multi_credit_operations() {
        // Test operations that consume multiple credits (large reads/writes)
        let config = CreditConfig {
            initial_credits: 256,
            max_credits: 1000,
            grant_per_response: 1,
            adaptive_grants: true,
        };
        let manager = CreditManager::with_config(config);

        // Grant initial credits like after NEGOTIATE
        let first_grant = manager.calculate_grant(64, false);
        manager.grant(first_grant);

        // Large read consuming 8 credits (512KB / 64KB per credit)
        assert!(manager.consume(8).is_some(), "Should consume 8 credits");

        // Response grants credits back
        let granted = manager.calculate_grant(8, false);
        manager.grant(granted);

        // Should still have healthy balance
        assert!(
            manager.available() > 200,
            "Should have credits after multi-credit op: {}",
            manager.available()
        );
    }

    #[test]
    fn test_credit_tracking_statistics() {
        let manager = CreditManager::new();

        // Track initial stats
        let initial_granted = manager.total_granted();
        let initial_consumed = manager.total_consumed();

        // Initial credits count as granted
        assert_eq!(initial_granted, DEFAULT_INITIAL_CREDITS as u64);
        assert_eq!(initial_consumed, 0);

        // Consume and grant
        manager.consume(10);
        manager.grant(50);

        // Check stats updated
        assert_eq!(manager.total_consumed(), 10);
        assert_eq!(
            manager.total_granted(),
            DEFAULT_INITIAL_CREDITS as u64 + 50
        );
    }
}
