//! Peer connection status and availability tracking.
//! 
//! # Security
//! - `Online` status is ONLY set by local network layer, never by peer claim
//! - `last_seen` prevents indefinite stale "online" states

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Timeout after which an online peer is considered stale.
/// 
/// # Performance
/// 30 seconds balances responsiveness with reduced status churn.
pub const ONLINE_TIMEOUT_SECONDS: i64 = 30;

/// Peer availability status.
/// 
/// # Invariants
/// - Transitions are monotonic in time (last_seen never decreases)
/// - `Online` implies `last_seen` within `ONLINE_TIMEOUT_SECONDS`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Peer is currently reachable.
    /// Set exclusively by local heartbeat/connection layer.
    Online {
        /// When peer was last confirmed reachable.
        last_seen: DateTime<Utc>,
    },
    
    /// Peer was recently online but hasn't been seen.
    /// Transitional state before Offline.
    Away {
        /// When peer was last seen.
        last_seen: DateTime<Utc>,
    },
    
    /// Peer is not reachable.
    Offline {
        /// When peer was last known to be online (if ever).
        last_seen: Option<DateTime<Utc>>,
    },
    
    /// Peer is explicitly blocked by local user.
    /// Overrides all other status considerations.
    Blocked,
}

impl PeerStatus {
    /// Create a new Online status with current timestamp.
    pub fn online_now() -> Self {
        Self::Online {
            last_seen: Utc::now(),
        }
    }

    /// Create Offline status with no prior history.
    pub fn offline() -> Self {
        Self::Offline { last_seen: None }
    }

    /// Create Blocked status.
    pub fn blocked() -> Self {
        Self::Blocked
    }

    /// Update status based on current time and timeout rules.
    /// 
    /// # Performance
    /// O(1) — single timestamp comparison.
    pub fn refresh(self) -> Self {
        match self {
            Self::Online { last_seen } => {
                let elapsed = Utc::now() - last_seen;
                if elapsed > Duration::seconds(ONLINE_TIMEOUT_SECONDS) {
                    Self::Away { last_seen }
                } else {
                    self
                }
            }
            Self::Away { last_seen } => {
                let elapsed = Utc::now() - last_seen;
                // Consider away for 5 minutes, then offline
                if elapsed > Duration::seconds(ONLINE_TIMEOUT_SECONDS + 300) {
                    Self::Offline { last_seen: Some(last_seen) }
                } else {
                    self
                }
            }
            other => other,
        }
    }

    /// Check if peer is currently considered online.
    pub fn is_online(&self) -> bool {
        matches!(self, Self::Online { .. })
    }

    /// Check if peer is blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked)
    }

    /// Get last seen timestamp if available.
    pub fn last_seen(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Online { last_seen } | Self::Away { last_seen } => Some(*last_seen),
            Self::Offline { last_seen } => *last_seen,
            Self::Blocked => None,
        }
    }
}

impl fmt::Display for PeerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Online { last_seen } => {
                write!(f, "Online (last seen {})", last_seen.format("%H:%M:%S"))
            }
            Self::Away { last_seen } => {
                write!(f, "Away (last seen {})", last_seen.format("%H:%M:%S"))
            }
            Self::Offline { .. } => write!(f, "Offline"),
            Self::Blocked => write!(f, "Blocked"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_status_detected() {
        let status = PeerStatus::online_now();
        assert!(status.is_online());
    }

    #[test]
    fn refresh_expires_online() {
        // Simulate old online status by creating Away and checking transition
        let old_time = Utc::now() - Duration::seconds(ONLINE_TIMEOUT_SECONDS + 1);
        let status = PeerStatus::Online { last_seen: old_time };
        let refreshed = status.refresh();
        assert!(matches!(refreshed, PeerStatus::Away { .. }));
    }

    #[test]
    fn blocked_overrides_online() {
        let status = PeerStatus::blocked();
        assert!(status.is_blocked());
        assert!(!status.is_online());
    }

    #[test]
    fn offline_has_no_last_seen() {
        let status = PeerStatus::offline();
        assert_eq!(status.last_seen(), None);
    }

    #[test]
    fn display_format_no_panic() {
        let status = PeerStatus::online_now();
        let _ = format!("{}", status);
    }
}