//! Application-level error types.
//!
//! # Security
//! - `user_message()` provides sanitized strings safe for UI display.
//! - Internal details (peer addresses, key state) are never exposed.

use thiserror::Error;

/// Result alias for application operations.
pub type ApplicationResult<T> = Result<T, ApplicationError>;

/// Core application error enum.
#[derive(Error, Debug, Clone)]
pub enum ApplicationError {
    /// Input validation failure.
    #[error("validation failed: {field} — {reason}")]
    Validation {
        /// Field that failed validation.
        field: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Domain layer error (wrapped opaque).
    #[error("domain error")]
    Domain,

    /// Network communication failure.
    #[error("network error")]
    Network,

    /// Persistence storage failure.
    #[error("storage error")]
    Persistence,

    /// Cryptographic operation failure.
    #[error("security error")]
    Security,

    /// Peer has not been cryptographically verified.
    #[error("peer not verified")]
    PeerNotVerified,

    /// Peer not found in local store.
    #[error("peer not found")]
    PeerNotFound,

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Operation exceeded deadline.
    #[error("operation timed out")]
    Timeout,

    /// Operation cancelled (shutdown or explicit).
    #[error("operation cancelled")]
    Cancelled,

    /// Internal invariant violation (bug).
    #[error("internal error")]
    Internal,
}

impl ApplicationError {
    /// Sanitized message safe for display to end users.
    ///
    /// # Security
    /// Never includes internal state, peer addresses, or key material.
    pub fn user_message(&self) -> String {
        match self {
            Self::Validation { field, reason } => format!("Invalid {}: {}", field, reason),
            Self::Domain => "A data error occurred. Please retry.".into(),
            Self::Network => "Network unavailable. Check your LAN connection.".into(),
            Self::Persistence => "Failed to save data. Storage may be full.".into(),
            Self::Security => "Security check failed. Verify peer fingerprint.".into(),
            Self::PeerNotVerified => "Peer is not trusted. Verify identity out-of-band.".into(),
            Self::PeerNotFound => "Peer not found. Discover peers first.".into(),
            Self::RateLimited => "Too many attempts. Please wait.".into(),
            Self::Timeout => "Operation timed out. Please retry.".into(),
            Self::Cancelled => "Operation was cancelled.".into(),
            Self::Internal => "An unexpected error occurred.".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_message_never_leaks_internals() {
        let err = ApplicationError::Security;
        let msg = err.user_message();
        assert!(!msg.contains("key"));
        assert!(!msg.contains("private"));
        assert!(!msg.contains("0x"));
    }

    #[test]
    fn validation_message_includes_context() {
        let err = ApplicationError::Validation {
            field: "display_name".into(),
            reason: "too long".into(),
        };
        assert_eq!(err.user_message(), "Invalid display_name: too long");
    }
}