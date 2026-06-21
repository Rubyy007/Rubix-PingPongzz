//! Peer module exports.
//!
//! Contains remote peer entities and connection status tracking.
//!
//! # Security
//! - Peer verification status is ONLY set after successful Noise handshake
//! - Network addresses are untrusted until cryptographic verification completes

pub mod peer;
pub mod peer_status;

pub use peer::{Peer, PeerBuilder, MAX_PEER_ADDRESSES};
pub use peer_status::{PeerStatus, ONLINE_TIMEOUT_SECONDS};