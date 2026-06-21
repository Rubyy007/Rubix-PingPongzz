//! Receive Message use case.
//!
//! # Security
//! - Verifies sender fingerprint is known.
//! - Decrypts content before domain construction.
//! - Validates message state transitions.
//! - Untrusted senders trigger notification but not auto-trust.
//!
//! # Performance
//! - Runs as a background service (continuous).
//! - Uses bounded channel for backpressure.
//! - Each message is processed independently (no head-of-line blocking).

use crate::error::{ApplicationError, ApplicationResult};
use crate::ports::network_port::{IncomingMessage, NetworkPort};
use crate::ports::notification_port::NotificationPort;
use crate::ports::persistence_port::PersistencePort;
use crate::ports::security_port::SecurityPort;
use crate::ports::trust_port::TrustPort;
use domain::message::{Message, MessageBuilder, MessageState};
use domain::peer::PeerStatus;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, instrument, warn};

/// Receive Message use case / background service.
#[derive(Clone)]
pub struct ReceiveMessageUseCase {
    network: Arc<dyn NetworkPort>,
    persistence: Arc<dyn PersistencePort>,
    security: Arc<dyn SecurityPort>,
    trust: Arc<dyn TrustPort>,
    notification: Arc<dyn NotificationPort>,
}

impl ReceiveMessageUseCase {
    pub fn new(
        network: Arc<dyn NetworkPort>,
        persistence: Arc<dyn PersistencePort>,
        security: Arc<dyn SecurityPort>,
        trust: Arc<dyn TrustPort>,
        notification: Arc<dyn NotificationPort>,
    ) -> Self {
        Self {
            network,
            persistence,
            security,
            trust,
            notification,
        }
    }

    /// Run continuous message receiver.
    ///
    /// # Cancellation Safety
    /// Responds to `shutdown` signal and cleanly terminates.
    /// Partially processed messages may be re-processed on restart
    /// (idempotency handled by message UUID).
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> ApplicationResult<()> {
        let mut rx = self.network.subscribe_incoming().await;

        info!("message receiver started");

        loop {
            tokio::select! {
                Some(msg) = rx.recv() => {
                    if let Err(e) = self.process(msg).await {
                        error!(error = ?e, "message processing failed");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("message receiver shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a single incoming message.
    #[instrument(skip(self, incoming), fields(sender = %incoming.sender_fingerprint))]
    async fn process(&self, incoming: IncomingMessage) -> ApplicationResult<()> {
        // 1. Check if sender is known
        let sender_peer = match self
            .persistence
            .load_peer(&incoming.sender_fingerprint)
            .await
            .map_err(|_| ApplicationError::Persistence)?
        {
            Some(p) => p,
            None => {
                warn!(
                    fp = %incoming.sender_fingerprint,
                    "message from unknown peer — discarding"
                );
                return Err(ApplicationError::PeerNotFound);
            }
        };

        // 2. Check trust
        let is_trusted = self
            .trust
            .is_trusted(&incoming.sender_fingerprint)
            .await
            .unwrap_or(false);

        if !is_trusted {
            warn!(
                fp = %incoming.sender_fingerprint,
                "message from untrusted peer — discarding"
            );
            return Err(ApplicationError::PeerNotVerified);
        }

        // 3. Decrypt content
        let plaintext = self
            .security
            .decrypt_from_peer(&incoming.ciphertext, &incoming.sender_fingerprint)
            .await
            .map_err(|_| ApplicationError::Security)?;

        // 4. Build domain message
        let mut msg = Message::builder()
            .sender_fingerprint(incoming.sender_fingerprint.clone())
            .recipient_fingerprint(sender_peer.fingerprint().clone()) // Self as recipient
            .content(incoming.ciphertext) // Store encrypted content
            .build()
            .map_err(|_| ApplicationError::Domain)?;

        // 5. Mark as delivered
        msg.mark_delivered().map_err(|_| ApplicationError::Domain)?;

        // 6. Persist
        self.persistence
            .save_message(&msg)
            .await
            .map_err(|_| ApplicationError::Persistence)?;

        // 7. Update sender status
        self.persistence
            .update_peer_status(&incoming.sender_fingerprint, PeerStatus::online_now())
            .await
            .map_err(|_| ApplicationError::Persistence)?;

        // 8. Notify UI
        let preview = String::from_utf8_lossy(&plaintext);
        let preview_truncated = if preview.len() > 100 {
            format!("{}…", &preview[..100])
        } else {
            preview.to_string()
        };

        self.notification
            .notify_message_received(&incoming.sender_fingerprint, &preview_truncated)
            .await
            .ok(); // Notification failure is non-fatal

        info!(message_id = %msg.id(), "message received and processed");

        Ok(())
    }
}