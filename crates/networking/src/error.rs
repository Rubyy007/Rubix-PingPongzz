//! Network-specific error types.

use thiserror::Error;

/// Result type for network operations.
pub type NetworkResult<T> = Result<T, NetworkError>;

/// Network crate error enum.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum NetworkError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("connection timeout: {0}")]
    ConnectionTimeout(String),

    #[error("bind failed: {0}")]
    BindFailed(String),

    #[error("accept failed: {0}")]
    AcceptFailed(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("handshake timeout after {0}s")]
    HandshakeTimeout(u64),

    #[error("handshake cancelled")]
    HandshakeCancelled,

    #[error("identity mismatch: {0}")]
    IdentityMismatch(String),

    #[error("peer rejected: {0}")]
    PeerRejected(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("peer not trusted: {0}")]
    PeerNotTrusted(String),

    #[error("peer not connected: {0}")]
    PeerNotConnected(String),

    #[error("peer limit exceeded: max {0}")]
    PeerLimitExceeded(usize),

    #[error("connection limit exceeded: max {0}")]
    ConnectionLimitExceeded(usize),

    #[error("already connected to: {0}")]
    AlreadyConnected(String),

    #[error("invalid peer data: {0}")]
    InvalidPeerData(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("receive failed: {0}")]
    RecvFailed(String),

    #[error("frame too large: {size} bytes, max {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("connection closed")]
    ConnectionClosed,

    #[error("transport closed: {0}")]
    TransportClosed(String),

    #[error("message too large: {size} bytes, max {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("mDNS error: {0}")]
    MdnsError(String),

    #[error("UDP error: {0}")]
    UdpError(String),

    #[error("internal error: {0}")]
    Internal(String),
}