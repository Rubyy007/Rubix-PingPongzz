//! Security-specific error types.
//! All errors are convertible to `DomainError`.

use rubix_domain::errors::DomainError;
use thiserror::Error;

/// Result type for security operations.
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Security crate error enum.
///
/// # Security
/// - Error messages never contain key material or raw bytes
/// - Cryptographic failures are opaque to prevent oracle attacks
/// - Timeout and cancellation are distinguished from handshake failures
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SecurityError {
    /// Key pair generation failed.
    #[error("key generation failed")]
    KeyGeneration,

    /// Invalid public key: {0}
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature – verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Fingerprint mismatch – identity verification failed.
    #[error("fingerprint mismatch")]
    FingerprintMismatch,

    /// Handshake failed: {0}
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Handshake timed out after {0} seconds.
    #[error("handshake timed out after {0}s")]
    HandshakeTimeout(u64),

    /// Handshake cancelled by caller.
    #[error("handshake cancelled")]
    HandshakeCancelled,

    /// Identity binding failed: {0}
    #[error("identity binding failed: {0}")]
    IdentityBindingFailed(String),

    /// Replay detected: {0}
    #[error("replay detected: {0}")]
    ReplayDetected(String),

    /// Decryption failed – generic error, no details to avoid oracle.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Encryption failed – generic error.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Storage error: {0}
    #[error("storage error: {0}")]
    Storage(String),

    /// Invalid passphrase – decryption failed.
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Serialization error: {0}
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Randomness generation failed.
    #[error("randomness generation failed")]
    RandomnessFailed,

    /// Message too large: {size} bytes, max {max}
    #[error("message too large: {size} bytes, max {max}")]
    MessageTooLarge {
        /// Actual size of the message.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Transport is closed.
    #[error("transport closed")]
    TransportClosed,

    /// Internal invariant violated: {0}
    #[error("internal invariant violated: {0}")]
    Internal(String),
}

impl From<SecurityError> for DomainError {
    fn from(err: SecurityError) -> Self {
        use rubix_domain::errors::{IdentityError, PeerError};
        match err {
            SecurityError::FingerprintMismatch => {
                DomainError::Identity(IdentityError::InvalidKeyMaterial)
            }
            SecurityError::HandshakeFailed(_) | SecurityError::HandshakeTimeout(_) => {
                DomainError::Peer(PeerError::HandshakeFailed)
            }
            SecurityError::HandshakeCancelled => DomainError::Cancelled,
            SecurityError::InvalidPassphrase => DomainError::Identity(IdentityError::Locked),
            SecurityError::MessageTooLarge { .. } => {
                DomainError::Message(rubix_domain::errors::MessageError::TooLarge)
            }
            SecurityError::TransportClosed => DomainError::Peer(PeerError::Unreachable),
            _ => DomainError::Cryptographic,
        }
    }
}