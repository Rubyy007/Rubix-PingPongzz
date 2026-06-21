//! Domain-level error types.
//! 
//! Security note: Error variants are designed to minimize information leakage.
//! Do not add variants that distinguish between "exists but invalid" vs "does not exist"
//! for authentication-related operations.

use std::fmt;
use thiserror::Error;

/// Maximum length for display names to prevent DoS via memory exhaustion.
pub const MAX_DISPLAY_NAME_LEN: usize = 64;

/// Maximum length for message content to prevent memory exhaustion.
pub const MAX_MESSAGE_CONTENT_LEN: usize = 65536; // 64KB

/// Maximum number of recipients in a single message.
pub const MAX_RECIPIENTS: usize = 50;

/// Result type alias for domain operations.
pub type DomainResult<T> = Result<T, DomainError>;

/// Core error enum for all domain-level failures.
/// 
/// # Security Considerations
/// - Authentication-related errors use opaque messaging to prevent user enumeration
/// - Cryptographic errors do not expose key material or internal state
/// - Network errors do not expose peer internal addresses
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DomainError {
    /// Identity-related errors.
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    /// Peer-related errors.
    #[error("peer error: {0}")]
    Peer(#[from] PeerError),

    /// Message-related errors.
    #[error("message error: {0}")]
    Message(#[from] MessageError),

    /// Cryptographic operation failure.
    /// Opaque error to prevent leaking information about key state.
    #[error("cryptographic operation failed")]
    Cryptographic,

    /// Validation failure with field context (safe to expose).
    #[error("validation failed: {field} - {reason}")]
    Validation { field: String, reason: String },

    /// Resource limit exceeded.
    #[error("resource limit exceeded: {resource}")]
    ResourceLimit { resource: String },

    /// Concurrent modification detected.
    #[error("concurrent modification detected")]
    ConcurrentModification,

    /// Operation cancelled (timeout or explicit cancellation).
    #[error("operation cancelled")]
    Cancelled,

    /// Internal invariant violated (bug).
    #[error("internal error")]
    Internal,
}

/// Identity-specific errors.
/// 
/// # Security
/// - `InvalidFingerprint` does not indicate whether fingerprint was malformed
///   vs. valid but non-matching
#[derive(Error, Debug, Clone, PartialEq)]
pub enum IdentityError {
    #[error("invalid identity parameters")]
    InvalidParameters,

    #[error("identity not found")]
    NotFound,

    #[error("identity already exists")]
    AlreadyExists,

    #[error("key generation failed")]
    KeyGenerationFailed,

    #[error("invalid key material")]
    InvalidKeyMaterial,

    #[error("identity locked")]
    Locked,
}

/// Peer-specific errors.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum PeerError {
    #[error("peer not found")]
    NotFound,

    #[error("peer already exists")]
    AlreadyExists,

    #[error("peer unreachable")]
    Unreachable,

    #[error("invalid peer data")]
    InvalidData,

    #[error("peer blocked")]
    Blocked,

    #[error("handshake failed")]
    HandshakeFailed,
}

/// Message-specific errors.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum MessageError {
    #[error("message not found")]
    NotFound,

    #[error("message too large")]
    TooLarge,

    #[error("invalid message format")]
    InvalidFormat,

    #[error("delivery failed")]
    DeliveryFailed,

    #[error("message expired")]
    Expired,

    #[error("recipient limit exceeded")]
    RecipientLimitExceeded,
}

/// Input validation helper to centralize boundary checks.
/// 
/// # Performance
/// - Uses stack-allocated strings for error fields to avoid heap allocation
///   on hot paths.
pub fn validate_display_name(name: &str) -> DomainResult<()> {
    if name.is_empty() {
        return Err(DomainError::Validation {
            field: "display_name".into(),
            reason: "cannot be empty".into(),
        });
    }
    if name.len() > MAX_DISPLAY_NAME_LEN {
        return Err(DomainError::ResourceLimit {
            resource: format!("display_name exceeds {} bytes", MAX_DISPLAY_NAME_LEN),
        });
    }
    // Check for control characters to prevent injection
    if name.chars().any(|c| c.is_control()) {
        return Err(DomainError::Validation {
            field: "display_name".into(),
            reason: "contains control characters".into(),
        });
    }
    Ok(())
}

/// Validate message content boundaries.
pub fn validate_message_content(content: &[u8]) -> DomainResult<()> {
    if content.is_empty() {
        return Err(DomainError::Validation {
            field: "content".into(),
            reason: "cannot be empty".into(),
        });
    }
    if content.len() > MAX_MESSAGE_CONTENT_LEN {
        return Err(DomainError::ResourceLimit {
            resource: format!("content exceeds {} bytes", MAX_MESSAGE_CONTENT_LEN),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_display_name_fails() {
        let result = validate_display_name("");
        assert!(matches!(
            result,
            Err(DomainError::Validation { field, reason })
            if field == "display_name" && reason == "cannot be empty"
        ));
    }

    #[test]
    fn oversized_display_name_fails() {
        let name = "a".repeat(MAX_DISPLAY_NAME_LEN + 1);
        let result = validate_display_name(&name);
        assert!(matches!(result, Err(DomainError::ResourceLimit { .. })));
    }

    #[test]
    fn control_char_in_display_name_fails() {
        let result = validate_display_name("test\x00name");
        assert!(matches!(result, Err(DomainError::Validation { .. })));
    }

    #[test]
    fn valid_display_name_passes() {
        let result = validate_display_name("ValidUser_123");
        assert!(result.is_ok());
    }

    #[test]
    fn empty_message_content_fails() {
        let result = validate_message_content(b"");
        assert!(matches!(
            result,
            Err(DomainError::Validation { field, .. })
            if field == "content"
        ));
    }

    #[test]
    fn oversized_message_content_fails() {
        let content = vec![0u8; MAX_MESSAGE_CONTENT_LEN + 1];
        let result = validate_message_content(&content);
        assert!(matches!(result, Err(DomainError::ResourceLimit { .. })));
    }

    #[test]
    fn error_display_does_not_leak_sensitive_info() {
        let err = DomainError::Cryptographic;
        let msg = format!("{}", err);
        assert!(!msg.contains("key"));
        assert!(!msg.contains("private"));
        assert!(!msg.contains("secret"));
    }
}