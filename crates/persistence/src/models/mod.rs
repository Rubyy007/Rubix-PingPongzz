use serde::{Deserialize, Serialize};

use rubix_domain::{Fingerprint, Peer, PeerBuilder, Message};

/// Persistent representation of a Peer row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerModel {
	pub id: String,
	pub display_name: String,
	pub fingerprint: String,
	pub ed25519_public: Vec<u8>,
	pub x25519_public: Vec<u8>,
	/// JSON array of address strings
	pub addresses: String,
	/// JSON-serialized PeerStatus
	pub status: String,
	pub verified: i32,
	pub first_seen: i64,
	pub last_seen: i64,
}

impl From<&Peer> for PeerModel {
	fn from(p: &Peer) -> Self {
		let addresses_json = match serde_json::to_string(p.addresses()) {
			Ok(s) => s,
			Err(_) => "[]".into(),
		};
		let status_json = match serde_json::to_string(p.status()) {
			Ok(s) => s,
			Err(_) => "null".into(),
		};

		Self {
			id: p.id().to_string(),
			display_name: p.display_name().to_string(),
			fingerprint: p.fingerprint().to_string(),
			ed25519_public: p.ed25519_public().to_vec(),
			x25519_public: p.x25519_public().to_vec(),
			addresses: addresses_json,
			status: status_json,
			verified: if p.is_verified() { 1 } else { 0 },
			first_seen: p.first_seen().timestamp(),
			last_seen: p.last_seen().timestamp(),
		}
	}
}

impl TryFrom<PeerModel> for Peer {
	type Error = rubix_domain::DomainError;

	fn try_from(m: PeerModel) -> Result<Self, Self::Error> {
		// Parse fingerprint
		let fp = Fingerprint::from_hex(&m.fingerprint)?;

		// Parse public keys
		if m.ed25519_public.len() != rubix_domain::ED25519_PUBLIC_KEY_LEN {
			return Err(rubix_domain::DomainError::Validation { field: "ed25519_public".into(), reason: "invalid length".into() });
		}
		let mut ed = [0u8; rubix_domain::ED25519_PUBLIC_KEY_LEN];
		ed.copy_from_slice(&m.ed25519_public);

		if m.x25519_public.len() != rubix_domain::X25519_PUBLIC_KEY_LEN {
			return Err(rubix_domain::DomainError::Validation { field: "x25519_public".into(), reason: "invalid length".into() });
		}
		let mut x = [0u8; rubix_domain::X25519_PUBLIC_KEY_LEN];
		x.copy_from_slice(&m.x25519_public);

		// Parse addresses
		let addresses: Vec<String> = serde_json::from_str(&m.addresses)
			.map_err(|_| rubix_domain::DomainError::Validation { field: "addresses".into(), reason: "invalid json".into() })?;

		// Build peer
		let peer = Peer::builder()
			.display_name(m.display_name)
			.fingerprint(fp)
			.ed25519_public(ed)
			.x25519_public(x)
			.addresses(addresses)
			.build()?;

		Ok(peer)
	}
}

/// Persistent representation of a Message row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageModel {
	pub id: String,
	pub sender_fingerprint: String,
	/// JSON array of recipient fingerprint strings
	pub recipient_fingerprints: String,
	pub content: Vec<u8>,
	pub content_type: String,
	/// JSON-serialized MessageState
	pub state: String,
	/// Full serialized Message JSON for exact reconstruction
	pub message_json: String,
	pub created_at: i64,
	pub sent_at: Option<i64>,
	pub delivered_at: Option<i64>,
	pub read_at: Option<i64>,
}

impl From<&Message> for MessageModel {
	fn from(m: &Message) -> Self {
		let recipients: Vec<String> = m.recipient_fingerprints().iter().map(|fp| fp.to_string()).collect();
		let recipients_json = match serde_json::to_string(&recipients) {
			Ok(s) => s,
			Err(_) => "[]".into(),
		};
		let state_json = match serde_json::to_string(m.state()) {
			Ok(s) => s,
			Err(_) => "null".into(),
		};
		let message_json = match serde_json::to_string(m) {
			Ok(s) => s,
			Err(_) => String::new(),
		};

		Self {
			id: m.id().to_string(),
			sender_fingerprint: m.sender_fingerprint().to_string(),
			recipient_fingerprints: recipients_json,
			content: m.content().to_vec(),
			content_type: format!("{:?}", m.content_type()),
			state: state_json,
			message_json,
			created_at: m.created_at().timestamp(),
			sent_at: m.sent_at().map(|t| t.timestamp()),
			delivered_at: m.delivered_at().map(|t| t.timestamp()),
			read_at: m.read_at().map(|t| t.timestamp()),
		}
	}
}

impl TryFrom<MessageModel> for Message {
	type Error = rubix_domain::DomainError;

	fn try_from(m: MessageModel) -> Result<Self, Self::Error> {
		// Use full JSON to reconstruct exact Message state
		let msg: Message = serde_json::from_str(&m.message_json)
			.map_err(|_| rubix_domain::DomainError::Internal)?;
		Ok(msg)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn peer_roundtrip() {
		let fp = match Fingerprint::from_bytes(&[0xAA; 20]) {
			Ok(v) => v,
			Err(e) => panic!("fingerprint creation failed: {:?}", e),
		};

		let peer = match rubix_domain::peer::Peer::builder()
			.display_name("TestPeer")
			.fingerprint(fp)
			.ed25519_public([0x11; 32])
			.x25519_public([0x22; 32])
			.address("127.0.0.1:8080")
			.build()
		{
			Ok(p) => p,
			Err(e) => panic!("peer build failed: {:?}", e),
		};

		let model = PeerModel::from(&peer);
		let reconstructed = Peer::try_from(model).unwrap();
		assert_eq!(reconstructed.display_name(), peer.display_name());
	}

	#[test]
	fn message_roundtrip_via_json() {
		let sender_fp = match Fingerprint::from_bytes(&[0xAA; 20]) {
			Ok(v) => v,
			Err(e) => panic!("fingerprint creation failed: {:?}", e),
		};

		let recipient_fp = match Fingerprint::from_bytes(&[0xBB; 20]) {
			Ok(v) => v,
			Err(e) => panic!("fingerprint creation failed: {:?}", e),
		};

		let msg = match rubix_domain::message::Message::builder()
			.sender_fingerprint(sender_fp)
			.recipient_fingerprint(recipient_fp)
			.content(b"hello".to_vec())
			.build()
		{
			Ok(m) => m,
			Err(e) => panic!("message build failed: {:?}", e),
		};

		let model = MessageModel::from(&msg);
		let reconstructed = Message::try_from(model).unwrap();
		assert_eq!(reconstructed.id(), msg.id());
	}
}
