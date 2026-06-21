//! Application-level message content types.
//!
//! Defines the payloads for Chat, PeerInfo, and other frame types.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Content of a chat message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatContent {
    /// Plaintext message body.
    pub text: String,
    /// Optional reply-to message ID.
    pub reply_to: Option<Uuid>,
}

/// Content of a peer discovery announcement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfoContent {
    /// Human-readable display name.
    pub display_name: String,
    /// Ed25519 public key (32 bytes, hex encoded).
    pub ed25519_public: String,
    /// X25519 public key (32 bytes, hex encoded).
    pub x25519_public: String,
    /// Fingerprint for verification.
    pub fingerprint: String,
    /// TCP port for direct connections.
    pub tcp_port: u16,
    /// Protocol version for compatibility.
    pub protocol_version: u16,
}

/// Content of a connection request/response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectContent {
    /// Whether the connection is accepted.
    pub accepted: bool,
    /// Optional reason if rejected.
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_content_serde() {
        let content = ChatContent {
            text: "Hello!".into(),
            reply_to: Some(Uuid::new_v4()),
        };
        let json = serde_json::to_string(&content).unwrap();
        let decoded: ChatContent = serde_json::from_str(&json).unwrap();
        assert_eq!(content, decoded);
    }

    #[test]
    fn peer_info_content() {
        let info = PeerInfoContent {
            display_name: "Alice".into(),
            ed25519_public: "aabbccdd".into(),
            x25519_public: "11223344".into(),
            fingerprint: "A1B2-C3D4".into(),
            tcp_port: 7878,
            protocol_version: 1,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Alice"));
    }
}