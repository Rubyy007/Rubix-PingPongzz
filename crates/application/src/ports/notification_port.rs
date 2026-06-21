//! Notification port — abstraction over OS notification APIs.

use async_trait::async_trait;
use domain::identity::Fingerprint;
use domain::peer::Peer;
use thiserror::Error;

/// Notification errors.
#[derive(Error, Debug, Clone)]
pub enum NotificationError {
    #[error("notification unavailable")]
    Unavailable,
    #[error("internal error")]
    Internal,
}

/// Notification infrastructure port.
#[async_trait]
pub trait NotificationPort: Send + Sync {
    /// Notify user of incoming message.
    ///
    /// `preview` is truncated plaintext (≤ 100 chars) for privacy.
    async fn notify_message_received(
        &self,
        sender_fp: &Fingerprint,
        preview: &str,
    ) -> Result<(), NotificationError>;

    /// Notify user that a peer came online.
    async fn notify_peer_connected(&self, peer: &Peer) -> Result<(), NotificationError>;

    /// Notify user that a peer went offline.
    async fn notify_peer_disconnected(
        &self,
        fingerprint: &Fingerprint,
    ) -> Result<(), NotificationError>;

    /// Notify user of identity reset completion.
    async fn notify_identity_reset(&self, new_fp: &Fingerprint) -> Result<(), NotificationError>;
}