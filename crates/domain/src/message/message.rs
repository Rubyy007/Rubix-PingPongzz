//! Message entity for chat communication.
//! 
//! # Security
//! - Content is opaque bytes (encrypted at rest and in transit)
//! - Sender binding via fingerprint, not mutable display name
//! - Message ID prevents replay attacks
//! - Timestamps are monotonic within a conversation

use crate::errors::{DomainError, DomainResult, validate_message_content};
use crate::identity::Fingerprint;
use crate::message::message_state::MessageState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum number of recipients in a single message.
pub const MAX_RECIPIENTS: usize = 50;

/// A chat message.
/// 
/// # Invariants
/// - `id` is globally unique
/// - `sender_fingerprint` is immutable (binds to cryptographic identity)
/// - `content` is non-empty and within size limits
/// - `recipient_fingerprints` has 1-50 entries
/// - `state` tracks delivery lifecycle
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    id: Uuid,
    sender_fingerprint: Fingerprint,
    recipient_fingerprints: Vec<Fingerprint>,
    content: Vec<u8>, // Encrypted content - opaque to domain
    content_type: ContentType,
    state: MessageState,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    delivered_at: Option<DateTime<Utc>>,
    read_at: Option<DateTime<Utc>>,
}

/// Type of message content for UI rendering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// Plain text content.
    #[default]
    Text,
    /// Image content.
    Image,
    /// File or document content.
    File,
    /// Voice or audio content.
    Voice,
}

/// Builder for Message construction with validation.
#[derive(Default)]
pub struct MessageBuilder {
    sender_fingerprint: Option<Fingerprint>,
    recipient_fingerprints: Vec<Fingerprint>,
    content: Option<Vec<u8>>,
    content_type: ContentType,
}

impl MessageBuilder {
    /// Create a new message builder with Text as the default content type.
    pub fn new() -> Self {
        Self {
            content_type: ContentType::Text,
            ..Default::default()
        }
    }

    /// Set the sender's fingerprint (cryptographic identity).
    pub fn sender_fingerprint(mut self, fp: Fingerprint) -> Self {
        self.sender_fingerprint = Some(fp);
        self
    }

    /// Add a recipient fingerprint to this message.
    pub fn recipient_fingerprint(mut self, fp: Fingerprint) -> Self {
        self.recipient_fingerprints.push(fp);
        self
    }

    /// Replace all recipients with the provided fingerprints.
    pub fn recipient_fingerprints(mut self, fps: Vec<Fingerprint>) -> Self {
        self.recipient_fingerprints = fps;
        self
    }

    /// Set the message content (encrypted bytes).
    pub fn content(mut self, content: Vec<u8>) -> Self {
        self.content = Some(content);
        self
    }

    /// Set the content type for UI rendering.
    pub fn content_type(mut self, ct: ContentType) -> Self {
        self.content_type = ct;
        self
    }

    /// Validate and construct the Message.
    ///
    /// Returns Err if any required field is missing or validation fails.
    pub fn build(self) -> DomainResult<Message> {
        let sender_fingerprint = self.sender_fingerprint.ok_or_else(|| DomainError::Validation {
            field: "sender_fingerprint".into(),
            reason: "required".into(),
        })?;

        if self.recipient_fingerprints.is_empty() {
            return Err(DomainError::Validation {
                field: "recipient_fingerprints".into(),
                reason: "at least one recipient required".into(),
            });
        }

        if self.recipient_fingerprints.len() > MAX_RECIPIENTS {
            return Err(DomainError::ResourceLimit {
                resource: format!("recipients exceed {}", MAX_RECIPIENTS),
            });
        }

        // Deduplicate recipients
        let mut recipients = self.recipient_fingerprints;
        recipients.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        recipients.dedup();

        let content = self.content.ok_or_else(|| DomainError::Validation {
            field: "content".into(),
            reason: "required".into(),
        })?;
        validate_message_content(&content)?;

        let now = Utc::now();

        Ok(Message {
            id: Uuid::new_v4(),
            sender_fingerprint,
            recipient_fingerprints: recipients,
            content,
            content_type: self.content_type,
            state: MessageState::Pending,
            created_at: now,
            sent_at: None,
            delivered_at: None,
            read_at: None,
        })
    }
}

impl Message {
    /// Create a new MessageBuilder for constructing Message instances.
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }

    /// Get the message's globally unique identifier.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the sender's cryptographic fingerprint.
    pub fn sender_fingerprint(&self) -> &Fingerprint {
        &self.sender_fingerprint
    }

    /// Get the list of recipient fingerprints.
    pub fn recipient_fingerprints(&self) -> &[Fingerprint] {
        &self.recipient_fingerprints
    }

    /// Get the encrypted message content.
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Get the content type for UI rendering.
    pub fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Get the current delivery state of the message.
    pub fn state(&self) -> &MessageState {
        &self.state
    }

    /// Get the timestamp when the message was created.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get the timestamp when the message was sent (if sent).
    pub fn sent_at(&self) -> Option<DateTime<Utc>> {
        self.sent_at
    }

    /// Get the timestamp when the message was delivered (if delivered).
    pub fn delivered_at(&self) -> Option<DateTime<Utc>> {
        self.delivered_at
    }

    /// Get the timestamp when the message was read by the recipient.
    pub fn read_at(&self) -> Option<DateTime<Utc>> {
        self.read_at
    }

    /// Transition message state.
    /// 
    /// # Security
    /// Enforces valid state machine transitions.
    pub fn transition_state(&mut self, new_state: MessageState) -> DomainResult<()> {
        let current = self.state.clone();
        self.state = current.transition_to(new_state).map_err(|e| {
            DomainError::Validation {
                field: "message_state".into(),
                reason: e.to_string(),
            }
        })?;

        // Update timestamps based on new state
        match &self.state {
            MessageState::Sent { sent_at } => self.sent_at = Some(*sent_at),
            MessageState::Delivered { delivered_at } => self.delivered_at = Some(*delivered_at),
            MessageState::Read { read_at } => self.read_at = Some(*read_at),
            _ => {}
        }

        Ok(())
    }

    /// Check if this message is from a specific sender.
    pub fn is_from(&self, fingerprint: &Fingerprint) -> bool {
        self.sender_fingerprint.constant_time_eq(fingerprint)
    }

    /// Check if this message is addressed to a specific recipient.
    pub fn is_to(&self, fingerprint: &Fingerprint) -> bool {
        self.recipient_fingerprints.iter().any(|fp| fp.constant_time_eq(fingerprint))
    }

    /// Mark as sending (transition from Pending to Sending).
    pub fn mark_sending(&mut self) -> DomainResult<()> {
        self.transition_state(MessageState::Sending)
    }

    /// Mark as sent (transition from Sending to Sent).
    pub fn mark_sent(&mut self) -> DomainResult<()> {
        self.transition_state(MessageState::Sent { sent_at: Utc::now() })
    }

    /// Mark as delivered.
    pub fn mark_delivered(&mut self) -> DomainResult<()> {
        self.transition_state(MessageState::Delivered { delivered_at: Utc::now() })
    }

    /// Mark as read.
    pub fn mark_read(&mut self) -> DomainResult<()> {
        self.transition_state(MessageState::Read { read_at: Utc::now() })
    }

    /// Mark as failed.
    pub fn mark_failed(&mut self, retryable: bool) -> DomainResult<()> {
        self.transition_state(MessageState::Failed {
            failed_at: Utc::now(),
            retryable,
        })
    }

    /// Get content size in bytes.
    pub fn content_size(&self) -> usize {
        self.content.len()
    }

    /// Check if message is a group message (multiple recipients).
    pub fn is_group(&self) -> bool {
        self.recipient_fingerprints.len() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fingerprint(val: u8) -> Fingerprint {
        Fingerprint::from_bytes(&[val; 20]).unwrap()
    }

    fn valid_message() -> Message {
        Message::builder()
            .sender_fingerprint(test_fingerprint(0xAA))
            .recipient_fingerprint(test_fingerprint(0xBB))
            .content(b"Hello, secure world!".to_vec())
            .build()
            .unwrap()
    }

    #[test]
    fn builder_creates_message() {
        let msg = valid_message();
        assert_eq!(msg.content(), b"Hello, secure world!");
        assert_eq!(msg.content_type(), ContentType::Text);
        assert!(matches!(msg.state(), MessageState::Pending));
    }

    #[test]
    fn missing_sender_fails() {
        let result = Message::builder()
            .recipient_fingerprint(test_fingerprint(0xBB))
            .content(b"test".to_vec())
            .build();
        assert!(matches!(result, Err(DomainError::Validation { field, .. }) if field == "sender_fingerprint"));
    }

    #[test]
    fn missing_recipient_fails() {
        let result = Message::builder()
            .sender_fingerprint(test_fingerprint(0xAA))
            .content(b"test".to_vec())
            .build();
        assert!(matches!(result, Err(DomainError::Validation { field, .. }) if field == "recipient_fingerprints"));
    }

    #[test]
    fn too_many_recipients_fails() {
        let mut builder = Message::builder()
            .sender_fingerprint(test_fingerprint(0xAA))
            .content(b"test".to_vec());

        for i in 0..=MAX_RECIPIENTS {
            builder = builder.recipient_fingerprint(test_fingerprint(i as u8));
        }

        let result = builder.build();
        assert!(matches!(result, Err(DomainError::ResourceLimit { .. })));
    }

    #[test]
    fn empty_content_fails() {
        let result = Message::builder()
            .sender_fingerprint(test_fingerprint(0xAA))
            .recipient_fingerprint(test_fingerprint(0xBB))
            .content(b"".to_vec())
            .build();
        assert!(matches!(result, Err(DomainError::Validation { .. })));
    }

    #[test]
    fn state_transitions_work() {
        let mut msg = valid_message();
        
        // Pending -> Sending -> Sent -> Delivered -> Read
        msg.mark_sending().unwrap();
        assert!(matches!(msg.state(), MessageState::Sending));
        
        msg.mark_sent().unwrap();
        assert!(msg.state().is_sent());
        assert!(msg.sent_at().is_some());
        
        msg.mark_delivered().unwrap();
        assert!(msg.state().is_delivered());
        
        msg.mark_read().unwrap();
        assert!(msg.state().is_read());
    }

    #[test]
    fn invalid_transition_fails() {
        let mut msg = valid_message();
        let result = msg.mark_delivered(); // Can't deliver before sending
        assert!(result.is_err());
    }

    #[test]
    fn sender_check_uses_constant_time() {
        let msg = valid_message();
        assert!(msg.is_from(&test_fingerprint(0xAA)));
        assert!(!msg.is_from(&test_fingerprint(0xBB)));
    }

    #[test]
    fn recipient_deduplication() {
        let msg = Message::builder()
            .sender_fingerprint(test_fingerprint(0xAA))
            .recipient_fingerprint(test_fingerprint(0xBB))
            .recipient_fingerprint(test_fingerprint(0xBB)) // duplicate
            .recipient_fingerprint(test_fingerprint(0xCC))
            .content(b"test".to_vec())
            .build()
            .unwrap();

        assert_eq!(msg.recipient_fingerprints().len(), 2);
    }

    #[test]
    fn group_message_detection() {
        let msg = Message::builder()
            .sender_fingerprint(test_fingerprint(0xAA))
            .recipient_fingerprint(test_fingerprint(0xBB))
            .recipient_fingerprint(test_fingerprint(0xCC))
            .content(b"test".to_vec())
            .build()
            .unwrap();

        assert!(msg.is_group());
    }

    #[test]
    fn serialization_roundtrip() {
        let msg = valid_message();
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&json).unwrap();
        
        assert_eq!(msg.id(), deserialized.id());
        assert_eq!(msg.content(), deserialized.content());
        assert_eq!(msg.sender_fingerprint().as_bytes(), deserialized.sender_fingerprint().as_bytes());
    }
}