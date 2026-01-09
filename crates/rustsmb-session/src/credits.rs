//! SMB2/3 credit management.
//!
//! Credits are the flow control mechanism in SMB2/3. Each request consumes credits
//! and responses grant new credits. Multi-credit operations allow large transfers
//! without excessive round trips.

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use tracing::{debug, trace};

/// Default initial credits granted to a new connection.
pub const DEFAULT_INITIAL_CREDITS: u16 = 1;

/// Default maximum credits a connection can accumulate.
pub const DEFAULT_MAX_CREDITS: u16 = 8192;

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
    pub fn calculate_grant(&self, requested_credits: u16, is_async: bool) -> u16 {
        if !self.config.adaptive_grants {
            return self.config.grant_per_response;
        }

        let current = self.available();
        let target = self.config.max_credits / 2; // Target 50% of max

        // Base grant
        let mut grant = self.config.grant_per_response;

        // If below target, grant more
        if current < target {
            grant = grant.saturating_add((target - current) / 4);
        }

        // Honor client request within limits
        if requested_credits > 0 {
            grant = grant.max(requested_credits);
        }

        // Async operations get more credits (they may spawn multiple responses)
        if is_async {
            grant = grant.saturating_mul(2);
        }

        // Cap at remaining headroom
        let headroom = self.config.max_credits.saturating_sub(current);
        grant.min(headroom)
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
}
