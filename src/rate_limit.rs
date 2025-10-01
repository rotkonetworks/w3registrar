use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of attempts allowed within the time window
    pub max_attempts: u32,
    /// Time window for rate limiting in seconds
    pub window_seconds: u64,
    /// Cooldown period after max attempts reached in seconds
    pub cooldown_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,        // 5 attempts
            window_seconds: 300,     // 5 minute window
            cooldown_seconds: 900,   // 15 minute cooldown after max attempts
        }
    }
}

/// Tracks attempts for a specific key
#[derive(Debug, Clone)]
struct AttemptRecord {
    attempts: Vec<Instant>,
    blocked_until: Option<Instant>,
}

impl AttemptRecord {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            blocked_until: None,
        }
    }

    /// Check if currently blocked
    fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            blocked_until > Instant::now()
        } else {
            false
        }
    }

    /// Clean up old attempts outside the window
    fn cleanup_old_attempts(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.attempts.retain(|&attempt| attempt > cutoff);
    }

    /// Add a new attempt and check if limit exceeded
    fn add_attempt(&mut self, config: &RateLimitConfig) -> Result<()> {
        let now = Instant::now();
        let window = Duration::from_secs(config.window_seconds);

        // Check if currently blocked
        if self.is_blocked() {
            let remaining = self.blocked_until.unwrap() - now;
            return Err(anyhow!(
                "Too many attempts. Please wait {} seconds before trying again",
                remaining.as_secs()
            ));
        }

        // Clean up old attempts
        self.cleanup_old_attempts(window);

        // Check if we're at the limit
        if self.attempts.len() >= config.max_attempts as usize {
            // Block for cooldown period
            self.blocked_until = Some(now + Duration::from_secs(config.cooldown_seconds));
            warn!(
                "Rate limit exceeded. Blocking for {} seconds",
                config.cooldown_seconds
            );
            return Err(anyhow!(
                "Rate limit exceeded. Too many validation attempts. Please wait {} minutes",
                config.cooldown_seconds / 60
            ));
        }

        // Record the attempt
        self.attempts.push(now);
        info!(
            "Token validation attempt recorded. {} of {} attempts used",
            self.attempts.len(),
            config.max_attempts
        );

        Ok(())
    }

    /// Get remaining attempts
    fn remaining_attempts(&self, config: &RateLimitConfig) -> u32 {
        let window = Duration::from_secs(config.window_seconds);
        let mut temp = self.clone();
        temp.cleanup_old_attempts(window);

        if temp.attempts.len() >= config.max_attempts as usize {
            0
        } else {
            config.max_attempts - temp.attempts.len() as u32
        }
    }
}

/// Rate limiter for token validation attempts
#[derive(Clone)]
pub struct TokenRateLimiter {
    records: Arc<RwLock<HashMap<String, AttemptRecord>>>,
    config: RateLimitConfig,
}

impl TokenRateLimiter {
    /// Create a new rate limiter with default config
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create a new rate limiter with custom config
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Build a key for rate limiting based on network, account, and field
    fn build_key(network: &str, account: &str, field: &str) -> String {
        format!("{}|{}|{}", network, account, field)
    }

    /// Check and record a token validation attempt
    pub async fn check_and_record_attempt(
        &self,
        network: &str,
        account: &str,
        field: &str,
    ) -> Result<()> {
        let key = Self::build_key(network, account, field);
        let mut records = self.records.write().await;

        let record = records.entry(key.clone()).or_insert_with(AttemptRecord::new);
        record.add_attempt(&self.config)?;

        Ok(())
    }

    /// Get the number of remaining attempts for a key
    pub async fn get_remaining_attempts(
        &self,
        network: &str,
        account: &str,
        field: &str,
    ) -> u32 {
        let key = Self::build_key(network, account, field);
        let records = self.records.read().await;

        if let Some(record) = records.get(&key) {
            record.remaining_attempts(&self.config)
        } else {
            self.config.max_attempts
        }
    }

    /// Check if a key is currently blocked
    pub async fn is_blocked(
        &self,
        network: &str,
        account: &str,
        field: &str,
    ) -> bool {
        let key = Self::build_key(network, account, field);
        let records = self.records.read().await;

        if let Some(record) = records.get(&key) {
            record.is_blocked()
        } else {
            false
        }
    }

    /// Reset attempts for a specific key (e.g., after successful validation)
    pub async fn reset_attempts(
        &self,
        network: &str,
        account: &str,
        field: &str,
    ) {
        let key = Self::build_key(network, account, field);
        let mut records = self.records.write().await;
        records.remove(&key);
        info!("Rate limit reset for {}", key);
    }

    /// Clean up expired records (should be called periodically)
    pub async fn cleanup_expired(&self) {
        let mut records = self.records.write().await;
        let window = Duration::from_secs(self.config.window_seconds);

        records.retain(|_key, record| {
            record.cleanup_old_attempts(window);
            // Keep if has recent attempts or is still blocked
            !record.attempts.is_empty() || record.is_blocked()
        });

        info!("Cleaned up rate limiter. {} records remaining", records.len());
    }
}

/// Global rate limiter instance
static RATE_LIMITER: once_cell::sync::OnceCell<TokenRateLimiter> = once_cell::sync::OnceCell::new();

/// Initialize the global rate limiter
pub fn init_rate_limiter(config: Option<RateLimitConfig>) {
    let config = config.unwrap_or_default();
    let _ = RATE_LIMITER.set(TokenRateLimiter::with_config(config));
}

/// Get the global rate limiter instance
pub fn get_rate_limiter() -> &'static TokenRateLimiter {
    RATE_LIMITER.get().expect("Rate limiter not initialized")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = RateLimitConfig {
            max_attempts: 3,
            window_seconds: 60,
            cooldown_seconds: 120,
        };

        let limiter = TokenRateLimiter::with_config(config);

        // First 3 attempts should succeed
        for i in 1..=3 {
            let result = limiter.check_and_record_attempt("paseo", "account1", "email").await;
            assert!(result.is_ok(), "Attempt {} should succeed", i);
        }

        // 4th attempt should fail
        let result = limiter.check_and_record_attempt("paseo", "account1", "email").await;
        assert!(result.is_err(), "4th attempt should be rate limited");

        // Check that it's blocked
        assert!(limiter.is_blocked("paseo", "account1", "email").await);

        // Different field should work
        let result = limiter.check_and_record_attempt("paseo", "account1", "discord").await;
        assert!(result.is_ok(), "Different field should not be rate limited");

        // Reset and try again
        limiter.reset_attempts("paseo", "account1", "email").await;
        let result = limiter.check_and_record_attempt("paseo", "account1", "email").await;
        assert!(result.is_ok(), "Should work after reset");
    }
}