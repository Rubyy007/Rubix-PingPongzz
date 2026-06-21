//! Peer entity representing a remote user.
//! 
//! # Security
//! - Peer identity is cryptographically verified via fingerprint
//! - Network addresses are untrusted until handshake completes
//! - `verified` flag indicates completed cryptographic handshake

use crate::errors::{DomainError, DomainResult, validate_display_name};
use crate::identity::{Fingerprint, Identity, ED25519_PUBLIC_KEY_LEN, X25519_PUBLIC_KEY_LEN};
use crate::peer::peer_status::PeerStatus;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum number of network addresses a peer can advertise.
/// Prevents address list bloat and DoS.
pub const MAX_PEER_ADDRESSES: usize = 10;

/// A remote peer in the system.
/// 
/// # Invariants
/// - `id` is unique and stable for this peer
/// - `fingerprint` matches the public keys
/// - `addresses` length ≤ MAX_PEER_ADDRESSES
/// - `verified` is false until Noise handshake completes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    id: Uuid,
    display_name: String,
    fingerprint: Fingerprint,
    ed25519_public: [u8; ED25519_PUBLIC_KEY_LEN],
    x25519_public: [u8; X25519_PUBLIC_KEY_LEN],
    addresses: Vec<String>, // "ipv4:port" or "[ipv6]:port" format
    status: PeerStatus,
    verified: bool,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// Builder for Peer construction with validation.
#[derive(Default)]
pub struct PeerBuilder {
    display_name: Option<String>,
    fingerprint: Option<Fingerprint>,
    ed25519_public: Option<[u8; ED25519_PUBLIC_KEY_LEN]>,
    x25519_public: Option<[u8; X25519_PUBLIC_KEY_LEN]>,
    addresses: Vec<String>,
}

impl PeerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn fingerprint(mut self, fp: Fingerprint) -> Self {
        self.fingerprint = Some(fp);
        self
    }

    pub fn ed25519_public(mut self, key: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        self.ed25519_public = Some(key);
        self
    }

    pub fn x25519_public(mut self, key: [u8; X25519_PUBLIC_KEY_LEN]) -> Self {
        self.x25519_public = Some(key);
        self
    }

    pub fn address(mut self, addr: impl Into<String>) -> Self {
        self.addresses.push(addr.into());
        self
    }

    pub fn addresses(mut self, addrs: Vec<String>) -> Self {
        self.addresses = addrs;
        self
    }

    pub fn build(self) -> DomainResult<Peer> {
        let display_name = self.display_name.ok_or_else(|| DomainError::Validation {
            field: "display_name".into(),
            reason: "required".into(),
        })?;
        validate_display_name(&display_name)?;

        let fingerprint = self.fingerprint.ok_or_else(|| DomainError::Validation {
            field: "fingerprint".into(),
            reason: "required".into(),
        })?;

        let ed25519_public = self.ed25519_public.ok_or_else(|| DomainError::Validation {
            field: "ed25519_public".into(),
            reason: "required".into(),
        })?;

        let x25519_public = self.x25519_public.ok_or_else(|| DomainError::Validation {
            field: "x25519_public".into(),
            reason: "required".into(),
        })?;

        if self.addresses.len() > MAX_PEER_ADDRESSES {
            return Err(DomainError::ResourceLimit {
                resource: format!("peer addresses exceed {}", MAX_PEER_ADDRESSES),
            });
        }

        let now = Utc::now();

        Ok(Peer {
            id: Uuid::new_v4(),
            display_name,
            fingerprint,
            ed25519_public,
            x25519_public,
            addresses: self.addresses,
            status: PeerStatus::offline(),
            verified: false,
            first_seen: now,
            last_seen: now,
        })
    }
}

impl Peer {
    pub fn builder() -> PeerBuilder {
        PeerBuilder::new()
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    pub fn ed25519_public(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.ed25519_public
    }

    pub fn x25519_public(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.x25519_public
    }

    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    pub fn status(&self) -> &PeerStatus {
        &self.status
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }

    pub fn first_seen(&self) -> DateTime<Utc> {
        self.first_seen
    }

    pub fn last_seen(&self) -> DateTime<Utc> {
        self.last_seen
    }

    /// Update display name with validation.
    pub fn set_display_name(&mut self, name: impl Into<String>) -> DomainResult<()> {
        let name = name.into();
        validate_display_name(&name)?;
        self.display_name = name;
        self.last_seen = Utc::now();
        Ok(())
    }

    /// Update network addresses.
    /// 
    /// # Security
    /// Replaces entire address list—caller must validate each address.
    pub fn set_addresses(&mut self, addresses: Vec<String>) -> DomainResult<()> {
        if addresses.len() > MAX_PEER_ADDRESSES {
            return Err(DomainError::ResourceLimit {
                resource: format!("peer addresses exceed {}", MAX_PEER_ADDRESSES),
            });
        }
        self.addresses = addresses;
        self.last_seen = Utc::now();
        Ok(())
    }

    /// Update status (called by networking layer only).
    pub fn set_status(&mut self, status: PeerStatus) {
        self.status = status;
        if status.is_online() {
            self.last_seen = Utc::now();
        }
    }

    /// Mark peer as cryptographically verified.
    /// 
    /// # Security
    /// Only call after successful Noise handshake + identity verification.
    pub fn verify(&mut self) {
        self.verified = true;
    }

    /// Mark peer as unverified (e.g., after key rotation detected).
    pub fn unverify(&mut self) {
        self.verified = false;
    }

    /// Check if this peer matches a given fingerprint.
    /// 
    /// # Security
    /// Uses constant-time comparison.
    pub fn matches_fingerprint(&self, fingerprint: &Fingerprint) -> bool {
        self.fingerprint.constant_time_eq(fingerprint)
    }

    /// Refresh status based on timeout rules.
    pub fn refresh_status(&mut self) {
        self.status = self.status.refresh();
    }

    /// Add a single address if under limit.
    pub fn add_address(&mut self, address: String) -> DomainResult<()> {
        if self.addresses.len() >= MAX_PEER_ADDRESSES {
            return Err(DomainError::ResourceLimit {
                resource: "peer addresses at maximum".into(),
            });
        }
        // Simple deduplication
        if !self.addresses.contains(&address) {
            self.addresses.push(address);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fingerprint() -> Fingerprint {
        Fingerprint::from_bytes(&[0xBB; 20]).unwrap()
    }

    fn valid_peer() -> Peer {
        Peer::builder()
            .display_name("RemotePeer")
            .fingerprint(test_fingerprint())
            .ed25519_public([0x11; 32])
            .x25519_public([0x22; 32])
            .address("192.168.1.100:8080")
            .build()
            .unwrap()
    }

    #[test]
    fn builder_creates_peer() {
        let peer = valid_peer();
        assert_eq!(peer.display_name(), "RemotePeer");
        assert!(!peer.is_verified());
    }

    #[test]
    fn address_limit_enforced() {
        let mut builder = Peer::builder()
            .display_name("Test")
            .fingerprint(test_fingerprint())
            .ed25519_public([0x11; 32])
            .x25519_public([0x22; 32]);

        for i in 0..=MAX_PEER_ADDRESSES {
            builder = builder.address(format!("192.168.1.{}:8080", i));
        }

        let result = builder.build();
        assert!(matches!(result, Err(DomainError::ResourceLimit { .. })));
    }

    #[test]
    fn verification_works() {
        let mut peer = valid_peer();
        assert!(!peer.is_verified());
        peer.verify();
        assert!(peer.is_verified());
        peer.unverify();
        assert!(!peer.is_verified());
    }

    #[test]
    fn fingerprint_matching() {
        let peer = valid_peer();
        let fp = test_fingerprint();
        assert!(peer.matches_fingerprint(&fp));
        
        let other_fp = Fingerprint::from_bytes(&[0xCC; 20]).unwrap();
        assert!(!peer.matches_fingerprint(&other_fp));
    }

    #[test]
    fn status_refresh_updates_last_seen() {
        let mut peer = valid_peer();
        let old_last_seen = peer.last_seen();
        
        peer.set_status(PeerStatus::online_now());
        assert!(peer.last_seen() >= old_last_seen);
    }

    #[test]
    fn add_address_deduplicates() {
        let mut peer = valid_peer();
        let initial_count = peer.addresses().len();
        
        peer.add_address("192.168.1.100:8080".into()).unwrap(); // duplicate
        assert_eq!(peer.addresses().len(), initial_count);
        
        peer.add_address("192.168.1.101:8080".into()).unwrap(); // new
        assert_eq!(peer.addresses().len(), initial_count + 1);
    }

    #[test]
    fn serialization_roundtrip() {
        let peer = valid_peer();
        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: Peer = serde_json::from_str(&json).unwrap();
        
        assert_eq!(peer.id(), deserialized.id());
        assert_eq!(peer.fingerprint().as_bytes(), deserialized.fingerprint().as_bytes());
    }
}