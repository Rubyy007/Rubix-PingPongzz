//! Message DTOs for UI communication.
//!
//! # Security
//! - `content` in `SendMessageRequest` is **plaintext** (encrypted by use case).
//! - `content_preview` in `MessageResponse` is truncated to prevent UI memory bloat.

use domain::message::{ContentType, Message, MessageState};
use serde::{Deserialize, Serialize};

/// Maximum length of content preview sent to UI.
const MAX_PREVIEW_LEN: usize = 256;

/// Request to send a message.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendMessageRequest {
    /// Recipient fingerprint in hex format.
    pub recipient_fingerprint: String,
    /// Plaintext content (encrypted before domain construction).
    pub content: String,
    /// Content type for UI rendering.
    pub content_type: ContentTypeDto,
}

/// Message response for UI display.
#[derive(Debug, Clone, Serialize)]
pub struct MessageResponse {
    /// Message UUID.
    pub id: String,
    /// Sender fingerprint hex.
    pub sender_fingerprint: String,
    /// Recipient fingerprint(s) hex.
    pub recipient_fingerprints: Vec<String>,
    /// Content type.
    pub content_type: ContentTypeDto,
    /// Delivery state.
    pub state: MessageStateDto,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// When sent (if applicable).
    pub sent_at: Option<String>,
    /// When delivered (if applicable).
    pub delivered_at: Option<String>,
    /// When read (if applicable).
    pub read_at: Option<String>,
    /// Truncated plaintext preview (decrypted by use case).
    pub content_preview: String,
}

/// Content type for UI serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentTypeDto {
    /// Plain or formatted text.
    Text,
    /// Image data.
    Image,
    /// Arbitrary file.
    File,
    /// Voice message.
    Voice,
}

impl From<ContentType> for ContentTypeDto {
    fn from(ct: ContentType) -> Self {
        match ct {
            ContentType::Text => Self::Text,
            ContentType::Image => Self::Image,
            ContentType::File => Self::File,
            ContentType::Voice => Self::Voice,
        }
    }
}

impl From<ContentTypeDto> for ContentType {
    fn from(ct: ContentTypeDto) -> Self {
        match ct {
            ContentTypeDto::Text => Self::Text,
            ContentTypeDto::Image => Self::Image,
            ContentTypeDto::File => Self::File,
            ContentTypeDto::Voice => Self::Voice,
        }
    }
}

/// Message state for UI serialization.
#[derive(Debug, Clone, Serialize)]
pub enum MessageStateDto {
    /// Not yet sent.
    Pending,
    /// Transmission in progress.
    Sending,
    /// Transmitted to recipient device.
    Sent { at: String },
    /// Recipient device confirmed receipt.
    Delivered { at: String },
    /// Recipient opened message.
    Read { at: String },
    /// Delivery failed.
    Failed { at: String, retryable: bool },
}

impl From<&MessageState> for MessageStateDto {
    fn from(state: &MessageState) -> Self {
        use domain::message::MessageState as S;
        match state {
            S::Pending => Self::Pending,
            S::Sending => Self::Sending,
            S::Sent { sent_at } => Self::Sent {
                at: sent_at.to_rfc3339(),
            },
            S::Delivered { delivered_at } => Self::Delivered {
                at: delivered_at.to_rfc3339(),
            },
            S::Read { read_at } => Self::Read {
                at: read_at.to_rfc3339(),
            },
            S::Failed { failed_at, retryable } => Self::Failed {
                at: failed_at.to_rfc3339(),
                retryable: *retryable,
            },
        }
    }
}

impl MessageResponse {
    /// Build a response from a domain Message with decrypted preview.
    ///
    /// # Security
    /// `content_preview` is truncated to `MAX_PREVIEW_LEN` to prevent
    /// UI memory exhaustion on large messages.
    pub fn from_message(msg: &Message, content_preview: &str) -> Self {
        let preview = if content_preview.len() > MAX_PREVIEW_LEN {
            format!("{}…", &content_preview[..MAX_PREVIEW_LEN])
        } else {
            content_preview.to_string()
        };

        Self {
            id: msg.id().to_string(),
            sender_fingerprint: msg.sender_fingerprint().to_formatted_string(),
            recipient_fingerprints: msg
                .recipient_fingerprints()
                .iter()
                .map(|fp| fp.to_formatted_string())
                .collect(),
            content_type: msg.content_type().into(),
            state: msg.state().into(),
            created_at: msg.created_at().to_rfc3339(),
            sent_at: msg.sent_at().map(|t| t.to_rfc3339()),
            delivered_at: msg.delivered_at().map(|t| t.to_rfc3339()),
            read_at: msg.read_at().map(|t| t.to_rfc3339()),
            content_preview: preview,
        }
    }
}