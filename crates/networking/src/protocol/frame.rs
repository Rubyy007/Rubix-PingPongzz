//! Application-level message frame types.
//!
//! These are the plaintext payloads that get encrypted by Noise transport.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of message frame.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FrameType {
    /// Chat message from peer.
    Chat,
    /// Acknowledgment of receipt.
    Ack,
    /// Heartbeat / keepalive.
    Heartbeat,
    /// Peer discovery info (sent over UDP or mDNS).
    PeerInfo,
    /// Request to establish connection.
    ConnectRequest,
    /// Response to connection request.
    ConnectResponse,
}

/// A framed message for transport over encrypted channels.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageFrame {
    /// Unique message ID for deduplication and ACK tracking.
    pub id: Uuid,
    /// Type of message.
    pub frame_type: FrameType,
    /// Sender fingerprint (redundant but useful for routing).
    pub sender: String,
    /// Unix timestamp (seconds) for ordering and replay detection.
    pub timestamp: u64,
    /// Serialized payload (content depends on frame_type).
    pub payload: Vec<u8>,
}

impl MessageFrame {
    /// Create a new chat message frame.
    pub fn chat(sender: impl Into<String>, content: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            frame_type: FrameType::Chat,
            sender: sender.into(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            payload: content,
        }
    }

    /// Create a heartbeat frame.
    pub fn heartbeat(sender: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            frame_type: FrameType::Heartbeat,
            sender: sender.into(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            payload: vec![],
        }
    }

    /// Create an ACK frame for a given message ID.
    pub fn ack(sender: impl Into<String>, message_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            frame_type: FrameType::Ack,
            sender: sender.into(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            payload: message_id.as_bytes().to_vec(),
        }
    }

    /// Serialize to bytes (for encryption).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes (after decryption).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_frame_roundtrip() {
        let frame = MessageFrame::chat("Alice", b"hello".to_vec());
        let bytes = frame.to_bytes();
        let decoded = MessageFrame::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.frame_type, FrameType::Chat);
        assert_eq!(decoded.payload, b"hello");
        assert_eq!(decoded.sender, "Alice");
    }

    #[test]
    fn heartbeat_frame() {
        let frame = MessageFrame::heartbeat("Bob");
        assert_eq!(frame.frame_type, FrameType::Heartbeat);
        assert!(frame.payload.is_empty());
    }

    #[test]
    fn ack_frame() {
        let msg_id = Uuid::new_v4();
        let frame = MessageFrame::ack("Alice", msg_id);
        assert_eq!(frame.frame_type, FrameType::Ack);
        assert_eq!(frame.payload, msg_id.as_bytes().to_vec());
    }
}