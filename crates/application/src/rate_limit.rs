//! In-memory rate limiter for peer operations.
//!
//! # Security
//! Prevents connection flooding and discovery DoS.
//! Uses peer fingerprint as rate limit key to prevent
//! distributed exhaustion across multiple addresses.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::time::{Duration, Instant};

/// Default window for rate limiting.
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Default max attempts per window.
const DEFAULT_MAX_ATTEMPTS: usize = 5;

/// Simple sliding-window rate limiter.
///
/// # Performance
/// O(n) cleanup on check where n = attempts in window.
/// For n ≤ 5 and 200 peers, this is negligible.
///
/// # Thread Safety
/// `Mutex` is acceptable here because operations are O(n) with small n
/// and contention is rare (human-scale peer interactions).
pub struct RateLimiter {
    state: Mutex<HashMap<String, Vec<Instant>>>,
    window: Duration,
    max_attempts: usize,
}

impl RateLimiter {
    /// Create a rate limiter with default settings.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            window: DEFAULT_WINDOW,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Create with custom window and max attempts.
    pub fn with_config(window: Duration, max_attempts: usize) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            window,
            max_attempts,
        }
    }

    /// Check if operation is allowed for the given key.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entries = state.entry(key.to_string()).or_default();

        // Remove expired entries
        let cutoff = now - self.window;
        entries.retain(|t| *t > cutoff);

        if entries.len() >= self.max_attempts {
            false
        } else {
            entries.push(now);
            true
        }
    }

    /// Reset rate limit for a key (e.g., after successful trust).
    pub fn reset(&self, key: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.remove(key);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn allows_within_limit() {
        let limiter = RateLimiter::with_config(Duration::from_secs(10), 3);
        assert!(limiter.check("peer_a"));
        assert!(limiter.check("peer_a"));
        assert!(limiter.check("peer_a"));
    }

    #[tokio::test]
    async fn blocks_over_limit() {
        let limiter = RateLimiter::with_config(Duration::from_secs(10), 2);
        assert!(limiter.check("peer_b"));
        assert!(limiter.check("peer_b"));
        assert!(!limiter.check("peer_b"));
    }

    #[tokio::test]
    async fn reset_clears_limit() {
        let limiter = RateLimiter::with_config(Duration::from_secs(10), 1);
        assert!(limiter.check("peer_c"));
        assert!(!limiter.check("peer_c"));
        limiter.reset("peer_c");
        assert!(limiter.check("peer_c"));
    }

    #[tokio::test]
    async fn window_expires_old_entries() {
        let limiter = RateLimiter::with_config(Duration::from_millis(50), 2);
        assert!(limiter.check("peer_d"));
        assert!(limiter.check("peer_d"));
        assert!(!limiter.check("peer_d"));
        sleep(Duration::from_millis(60)).await;
        assert!(limiter.check("peer_d"));
    }
}