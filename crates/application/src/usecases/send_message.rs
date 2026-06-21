//! Send Message use case.
//!
//! # Security
//! - Validates recipient fingerprint before any network operation.
//! - Encrypts content before Domain entity construction.
//! - Persists before sending (write-through) to prevent loss.
//! - Retries with exponential backoff on transient failures.
//!
//! # Performance
//! - Encryption is the dominant cost: O(n) for n = content bytes.
//! - Network send is async non-blocking.
//! - Persistence write is awaited before send to ensure durability.

use crate::dto::message_dto::{MessageResponse, SendMessageRequest};
use crate::error::{ApplicationError, ApplicationResult};
use crate::ports::network_port::{ConnectionId, NetworkError, NetworkPort};
use crate::ports::notification_port::NotificationPort;
use crate::ports::persistence_port::PersistencePort;
use crate::ports::security_port::SecurityError;
use crate::ports::security_port::SecurityPort;
use crate::rate_limit::RateLimiter;
use async_trait::async_trait;
use domain::identity::{Fingerprint, Identity};
use domain::message::{ContentType, Message, MessageBuilder, MessageState};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, warn};

/// Max retries for message delivery.
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff.
const BASE_BACKOFF_MS: u64 = 500;

/// Max message content size (enforced before encryption).
const MAX_CONTENT_BYTES: usize = 65536;

/// Send Message use case.
#[derive(Clone)]
pub struct SendMessageUseCase {
    identity: Arc<tokio::sync::RwLock<Identity>>,
    network: Arc<dyn NetworkPort>,
    persistence: Arc<dyn PersistencePort>,
    security: Arc<dyn SecurityPort>,
    notification: Arc<dyn NotificationPort>,
    rate_limiter: Arc<RateLimiter>,
}

impl SendMessageUseCase {
    /// Create a new use case with injected ports.
    pub fn new(
        identity: Arc<tokio::sync::RwLock<Identity>>,
        network: Arc<dyn NetworkPort>,
        persistence: Arc<dyn PersistencePort>,
        security: Arc<dyn SecurityPort>,
        notification: Arc<dyn NotificationPort>,
    ) -> Self {
        Self {
            identity,
            network,
            persistence,
            security,
            notification,
            rate_limiter: Arc::new(RateLimiter::new()),
        }
    }

    /// Execute the send message flow.
    ///
    /// # Cancellation Safety
    /// Safe to cancel at await points. Partial state (saved message with Failed state)
    /// is recoverable on restart.
    #[instrument(skip(self, request), fields(recipient = %request.recipient_fingerprint))]
    pub async fn execute(&self, request: SendMessageRequest) -> ApplicationResult<MessageResponse> {
        // 1. Validate input
        self.validate_request(&request)?;

        // 2. Parse recipient fingerprint
        let recipient_fp = Fingerprint::from_hex(&request.recipient_fingerprint)
            .map_err(|e| ApplicationError::Validation {
                field: "recipient_fingerprint".into(),
                reason: e.to_string(),
            })?;

        // 3. Rate limit check
        let rate_key = format!("send:{}", recipient_fp.to_formatted_string());
        if !self.rate_limiter.check(&rate_key) {
            return Err(ApplicationError::RateLimited);
        }

        // 4. Load sender identity
        let identity = self.identity.read().await.clone();

        // 5. Encrypt content
        let plaintext = request.content.into_bytes();
        let ciphertext = self
            .security
            .encrypt_for_peer(&plaintext, &recipient_fp)
            .await
            .map_err(|_| ApplicationError::Security)?;

        // 6. Build domain message
        let mut msg = Message::builder()
            .sender_fingerprint(identity.fingerprint().clone())
            .recipient_fingerprint(recipient_fp.clone())
            .content(ciphertext.clone())
            .content_type(request.content_type.into())
            .build()
            .map_err(|_| ApplicationError::Domain)?;

        // 7. Persist before send (write-through durability)
        self.persistence
            .save_message(&msg)
            .await
            .map_err(|_| ApplicationError::Persistence)?;

        // 8. Send with retry
        let send_result = self.send_with_retry(&mut msg, &recipient_fp, &ciphertext).await;

        // 9. Persist final state
        self.persistence
            .save_message(&msg)
            .await
            .map_err(|_| ApplicationError::Persistence)?;

        // 10. Build response with preview
        let preview = String::from_utf8_lossy(&plaintext);
        let response = MessageResponse::from_message(&msg, &preview);

        match send_result {
            Ok(_) => {
                info!(message_id = %msg.id(), "message sent successfully");
                Ok(response)
            }
            Err(e) => {
                warn!(message_id = %msg.id(), error = ?e, "message delivery failed");
                // Still return response so UI can show failed state
                Ok(response)
            }
        }
    }

    /// Validate request boundaries.
    fn validate_request(&self, request: &SendMessageRequest) -> ApplicationResult<()> {
        if request.recipient_fingerprint.is_empty() {
            return Err(ApplicationError::Validation {
                field: "recipient_fingerprint".into(),
                reason: "cannot be empty".into(),
            });
        }
        if request.content.is_empty() {
            return Err(ApplicationError::Validation {
                field: "content".into(),
                reason: "cannot be empty".into(),
            });
        }
        if request.content.len() > MAX_CONTENT_BYTES {
            return Err(ApplicationError::Validation {
                field: "content".into(),
                reason: format!("exceeds {} bytes", MAX_CONTENT_BYTES),
            });
        }
        Ok(())
    }

    /// Send with exponential backoff retry.
    ///
    /// On final failure, marks message as Failed(retryable=true).
    #[instrument(skip(self, msg, ciphertext), fields(message_id = %msg.id()))]
    async fn send_with_retry(
        &self,
        msg: &mut Message,
        recipient_fp: &Fingerprint,
        ciphertext: &[u8],
    ) -> ApplicationResult<()> {
        // First, mark as Sending
        msg.transition_state(MessageState::Sending)
            .map_err(|_| ApplicationError::Domain)?;

        // Try to find or establish connection
        // Note: In a full implementation, we'd query network for existing connection
        // For now, we attempt direct send (network port handles connection internally)
        let conn_id = self
            .network
            .connect(
                self.resolve_address(recipient_fp).await?,
                Some(recipient_fp),
            )
            .await
            .map_err(|_| ApplicationError::Network)?;

        for attempt in 0..=MAX_RETRIES {
            match self.network.send_to_peer(conn_id.0, ciphertext).await {
                Ok(_) => {
                    msg.mark_sent().map_err(|_| ApplicationError::Domain)?;
                    return Ok(());
                }
                Err(NetworkError::PeerDisconnected) if attempt < MAX_RETRIES => {
                    debug!(attempt, "peer disconnected, retrying...");
                }
                Err(NetworkError::Backpressure) if attempt < MAX_RETRIES => {
                    debug!(attempt, "backpressure, backing off...");
                }
                Err(_) if attempt < MAX_RETRIES => {
                    debug!(attempt, "send failed, will retry");
                }
                Err(e) => {
                    error!(attempt, error = ?e, "send failed permanently");
                    msg.mark_failed(true).map_err(|_| ApplicationError::Domain)?;
                    return Err(ApplicationError::Network);
                }
            }

            let backoff = Duration::from_millis(BASE_BACKOFF_MS * 2_u64.pow(attempt));
            sleep(backoff).await;
        }

        unreachable!()
    }

    /// Resolve peer fingerprint to a network address.
    ///
    /// # Performance
    /// Loads from persistence — O(1) with proper indexing.
    async fn resolve_address(
        &self,
        fingerprint: &Fingerprint,
    ) -> ApplicationResult<SocketAddr> {
        let peer = self
            .persistence
            .load_peer(fingerprint)
            .await
            .map_err(|_| ApplicationError::Persistence)?
            .ok_or(ApplicationError::PeerNotFound)?;

        let addr_str = peer
            .addresses()
            .first()
            .ok_or_else(|| ApplicationError::Validation {
                field: "peer_address".into(),
                reason: "peer has no known addresses".into(),
            })?;

        addr_str
            .parse()
            .map_err(|_| ApplicationError::Validation {
                field: "peer_address".into(),
                reason: "invalid address format".into(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::network_port::{DiscoveredPeer, IncomingMessage, NetworkPort};
    use crate::ports::notification_port::NotificationPort;
    use crate::ports::persistence_port::PersistencePort;
    use crate::ports::security_port::SecurityPort;
    use domain::identity::Fingerprint;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    struct MockSecurity;
    #[async_trait]
    impl SecurityPort for MockSecurity {
        async fn generate_identity(&self, _: &str) -> Result<Identity, SecurityError> {
            unimplemented!()
        }
        async fn derive_fingerprint(
            &self,
            _: &[u8; 32],
            _: &[u8; 32],
        ) -> Result<Fingerprint, SecurityError> {
            unimplemented!()
        }
        async fn encrypt_for_peer(
            &self,
            plaintext: &[u8],
            _: &Fingerprint,
        ) -> Result<Vec<u8>, SecurityError> {
            Ok(plaintext.to_vec())
        }
        async fn decrypt_from_peer(
            &self,
            ciphertext: &[u8],
            _: &Fingerprint,
        ) -> Result<Vec<u8>, SecurityError> {
            Ok(ciphertext.to_vec())
        }
        async fn sign_data(&self, _: &[u8]) -> Result<Vec<u8>, SecurityError> {
            Ok(vec![1, 2, 3])
        }
        async fn verify_signature(
            &self,
            _: &[u8],
            _: &[u8],
            _: &Fingerprint,
        ) -> Result<bool, SecurityError> {
            Ok(true)
        }
        async fn load_identity(&self) -> Result<Option<Identity>, SecurityError> {
            unimplemented!()
        }
        async fn save_identity(&self, _: &Identity) -> Result<(), SecurityError> {
            Ok(())
        }
    }

    struct MockPersistence {
        peers: Mutex<Vec<Peer>>,
        messages: Mutex<Vec<Message>>,
    }
    #[async_trait]
    impl PersistencePort for MockPersistence {
        async fn save_message(&self, msg: &Message) -> Result<(), crate::ports::persistence_port::PersistenceError> {
            self.messages.lock().unwrap().push(msg.clone());
            Ok(())
        }
        async fn load_messages(
            &self,
            _: &Fingerprint,
            _: usize,
            _: usize,
        ) -> Result<Vec<Message>, crate::ports::persistence_port::PersistenceError> {
            Ok(vec![])
        }
        async fn save_peer(&self, peer: &Peer) -> Result<(), crate::ports::persistence_port::PersistenceError> {
            self.peers.lock().unwrap().push(peer.clone());
            Ok(())
        }
        async fn load_peer(
            &self,
            fp: &Fingerprint,
        ) -> Result<Option<Peer>, crate::ports::persistence_port::PersistenceError> {
            Ok(self.peers.lock().unwrap().iter().find(|p| p.fingerprint() == fp).cloned())
        }
        async fn load_peers(&self) -> Result<Vec<Peer>, crate::ports::persistence_port::PersistenceError> {
            Ok(self.peers.lock().unwrap().clone())
        }
        async fn update_peer_status(
            &self,
            _: &Fingerprint,
            _: PeerStatus,
        ) -> Result<(), crate::ports::persistence_port::PersistenceError> {
            Ok(())
        }
        async fn delete_peer(
            &self,
            _: &Fingerprint,
        ) -> Result<(), crate::ports::persistence_port::PersistenceError> {
            Ok(())
        }
    }

    struct MockNetwork;
    #[async_trait]
    impl NetworkPort for MockNetwork {
        async fn connect(
            &self,
            _: SocketAddr,
            _: Option<&Fingerprint>,
        ) -> Result<(ConnectionId, Peer), NetworkError> {
            unimplemented!()
        }
        async fn disconnect(&self, _: ConnectionId) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn send_to_peer(
            &self,
            _: ConnectionId,
            _: &[u8],
        ) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn broadcast_presence(&self, _: &Identity) -> Result<(), NetworkError> {
            Ok(())
        }
        async fn discover_peers(
            &self,
            _: std::time::Duration,
        ) -> Result<Vec<DiscoveredPeer>, NetworkError> {
            Ok(vec![])
        }
        async fn subscribe_incoming(&self) -> mpsc::Receiver<IncomingMessage> {
            mpsc::channel(1).1
        }
    }

    struct MockNotification;
    #[async_trait]
    impl NotificationPort for MockNotification {
        async fn notify_message_received(
            &self,
            _: &Fingerprint,
            _: &str,
        ) -> Result<(), crate::ports::notification_port::NotificationError> {
            Ok(())
        }
        async fn notify_peer_connected(
            &self,
            _: &Peer,
        ) -> Result<(), crate::ports::notification_port::NotificationError> {
            Ok(())
        }
        async fn notify_peer_disconnected(
            &self,
            _: &Fingerprint,
        ) -> Result<(), crate::ports::notification_port::NotificationError> {
            Ok(())
        }
        async fn notify_identity_reset(
            &self,
            _: &Fingerprint,
        ) -> Result<(), crate::ports::notification_port::NotificationError> {
            Ok(())
        }
    }

    fn test_identity() -> Identity {
        Identity::builder()
            .display_name("TestUser")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(Fingerprint::from_bytes(&[0xAA; 20]).unwrap())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn empty_content_fails_validation() {
        let uc = SendMessageUseCase::new(
            Arc::new(tokio::sync::RwLock::new(test_identity())),
            Arc::new(MockNetwork),
            Arc::new(MockPersistence {
                peers: Mutex::new(vec![]),
                messages: Mutex::new(vec![]),
            }),
            Arc::new(MockSecurity),
            Arc::new(MockNotification),
        );

        let req = SendMessageRequest {
            recipient_fingerprint: "A1B2C3D4E5F67890123456789ABCDEF011223344".into(),
            content: "".into(),
            content_type: crate::dto::message_dto::ContentTypeDto::Text,
        };

        let result = uc.execute(req).await;
        assert!(matches!(result, Err(ApplicationError::Validation { field, .. }) if field == "content"));
    }

    #[tokio::test]
    async fn valid_message_saves_and_returns() {
        let peer = Peer::builder()
            .display_name("Recipient")
            .fingerprint(Fingerprint::from_bytes(&[0xBB; 20]).unwrap())
            .ed25519_public([0x03; 32])
            .x25519_public([0x04; 32])
            .address("127.0.0.1:8080")
            .build()
            .unwrap();

        let persistence = Arc::new(MockPersistence {
            peers: Mutex::new(vec![peer]),
            messages: Mutex::new(vec![]),
        });

        let uc = SendMessageUseCase::new(
            Arc::new(tokio::sync::RwLock::new(test_identity())),
            Arc::new(MockNetwork),
            persistence.clone(),
            Arc::new(MockSecurity),
            Arc::new(MockNotification),
        );

        let req = SendMessageRequest {
            recipient_fingerprint: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            content: "Hello secure world".into(),
            content_type: crate::dto::message_dto::ContentTypeDto::Text,
        };

        let result = uc.execute(req).await;
        assert!(result.is_ok());

        let msgs = persistence.messages.lock().unwrap();
        assert_eq!(msgs.len(), 1);
    }
}