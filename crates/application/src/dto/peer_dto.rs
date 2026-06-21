//! Peer DTOs for UI communication.

use domain::peer::{Peer, PeerStatus};
use serde::{Deserialize, Serialize};

/// Request to connect to a specific peer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectPeerRequest {
    /// Network address: `ipv4:port` or `[ipv6]:port`.
    pub address: String,
    /// Expected fingerprint for verification (hex).
    pub fingerprint: String,
}

/// Request to discover peers on LAN.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoverPeerRequest {
    /// How long to listen for advertisements (seconds).
    pub timeout_secs: u64,
    /// Maximum peers to return.
    pub max_results: usize,
}

impl Default for DiscoverPeerRequest {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            max_results: 200,
        }
    }
}

/// Peer information for UI display.
#[derive(Debug, Clone, Serialize)]
pub struct PeerResponse {
    /// Peer UUID.
    pub id: String,
    /// Display name.
    pub display_name: String,
    /// Fingerprint hex.
    pub fingerprint: String,
    /// Known network addresses.
    pub addresses: Vec<String>,
    /// Connection status.
    pub status: PeerStatusDto,
    /// Cryptographically verified.
    pub verified: bool,
    /// First seen timestamp.
    pub first_seen: String,
    /// Last seen timestamp.
    pub last_seen: String,
}

/// Peer status for UI serialization.
#[derive(Debug, Clone, Serialize)]
pub enum PeerStatusDto {
    /// Currently reachable.
    Online { last_seen: String },
    /// Recently online.
    Away { last_seen: String },
    /// Not reachable.
    Offline,
    /// Explicitly blocked.
    Blocked,
}

impl From<&PeerStatus> for PeerStatusDto {
    fn from(status: &PeerStatus) -> Self {
        use domain::peer::PeerStatus as S;
        match status {
            S::Online { last_seen } => Self::Online {
                last_seen: last_seen.to_rfc3339(),
            },
            S::Away { last_seen } => Self::Away {
                last_seen: last_seen.to_rfc3339(),
            },
            S::Offline { .. } => Self::Offline,
            S::Blocked => Self::Blocked,
        }
    }
}

impl PeerResponse {
    /// Build from domain Peer.
    pub fn from_peer(peer: &Peer) -> Self {
        Self {
            id: peer.id().to_string(),
            display_name: peer.display_name().to_string(),
            fingerprint: peer.fingerprint().to_formatted_string(),
            addresses: peer.addresses().to_vec(),
            status: peer.status().into(),
            verified: peer.is_verified(),
            first_seen: peer.first_seen().to_rfc3339(),
            last_seen: peer.last_seen().to_rfc3339(),
        }
    }
}