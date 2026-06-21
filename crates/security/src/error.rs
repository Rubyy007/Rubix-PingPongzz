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
    #[error("key generation failed")]
    KeyGeneration,

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("fingerprint mismatch")]
    FingerprintMismatch,

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("handshake timed out after {0}s")]
    HandshakeTimeout(u64),

    #[error("handshake cancelled")]
    HandshakeCancelled,

    #[error("identity binding failed: {0}")]
    IdentityBindingFailed(String),

    #[error("replay detected: {0}")]
    ReplayDetected(String),

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("randomness generation failed")]
    RandomnessFailed,

    #[error("message too large: {size} bytes, max {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("transport closed")]
    TransportClosed,

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