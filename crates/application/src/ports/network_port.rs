//! Network port — abstraction over TCP/UDP/mDNS operations.
//!
//! # Security
//! - Implementations must verify peer fingerprints during handshake.
//! - `connect` returns peer only after successful Noise handshake.
//! - All sends are over established encrypted channels.

use async_trait::async_trait;
use domain::identity::{Fingerprint, Identity};
use domain::peer::Peer;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::mpsc;

/// Opaque connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub uuid::Uuid);

/// A peer discovered via LAN advertisement (mDNS/UDP beacon).
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Advertised fingerprint.
    pub fingerprint: Fingerprint,
    /// Advertised display name.
    pub display_name: String,
    /// Advertised addresses.
    pub addresses: Vec<String>,
    /// Ed25519 public key.
    pub ed25519_public: [u8; 32],
    /// X25519 public key.
    pub x25519_public: [u8; 32],
}

/// An incoming encrypted message from the network.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// Sender fingerprint (from transport layer).
    pub sender_fingerprint: Fingerprint,
    /// Ciphertext payload.
    pub ciphertext: Vec<u8>,
    /// When received by transport.
    pub received_at: chrono::DateTime<chrono::Utc>,
}

/// Network operation errors.
#[derive(Error, Debug, Clone)]
pub enum NetworkError {
    /// Connection refused by peer.
    #[error("connection refused")]
    ConnectionRefused,

    /// Connection attempt timed out.
    #[error("connection timeout")]
    Timeout,

    /// Cryptographic handshake failed.
    #[error("handshake failed")]
    HandshakeFailed,

    /// Peer disconnected unexpectedly.
    #[error("peer disconnected")]
    PeerDisconnected,

    /// Send buffer full or backpressure exceeded.
    #[error("send backpressure")]
    Backpressure,

    /// Discovery broadcast/listen failure.
    #[error("discovery failed: {0}")]
    DiscoveryFailed(String),

    /// Internal network error.
    #[error("internal network error")]
    Internal,
}

/// Network infrastructure port.
#[async_trait]
pub trait NetworkPort: Send + Sync {
    /// Establish encrypted connection to a peer.
    ///
    /// # Security
    /// Implementations must:
    /// 1. Open TCP connection to `addr`.
    /// 2. Perform Noise handshake with X25519 + Ed25519 identity binding.
    /// 3. Verify returned fingerprint matches `expected_fingerprint` if provided.
    /// 4. Return `Peer` only after successful verification.
    ///
    /// # Performance
    /// Must complete within 5 seconds or return `Timeout`.
    async fn connect(
        &self,
        addr: SocketAddr,
        expected_fingerprint: Option<&Fingerprint>,
    ) -> Result<(ConnectionId, Peer), NetworkError>;

    /// Close an active connection.
    async fn disconnect(&self, conn_id: ConnectionId) -> Result<(), NetworkError>;

    /// Send encrypted data to a connected peer.
    ///
    /// # Security
    /// `ciphertext` must already be AEAD-encrypted. This method only transports.
    async fn send_to_peer(
        &self,
        conn_id: ConnectionId,
        ciphertext: &[u8],
    ) -> Result<(), NetworkError>;

    /// Broadcast local presence via mDNS/UDP beacon.
    async fn broadcast_presence(&self, identity: &Identity) -> Result<(), NetworkError>;

    /// Discover peers on LAN for the specified duration.
    ///
    /// Returns all unique peers heard within `timeout`.
    async fn discover_peers(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Vec<DiscoveredPeer>, NetworkError>;

    /// Subscribe to incoming encrypted messages.
    ///
    /// Returns a channel that yields messages as they arrive.
    /// Channel must be bounded (backpressure).
    async fn subscribe_incoming(&self) -> mpsc::Receiver<IncomingMessage>;
}