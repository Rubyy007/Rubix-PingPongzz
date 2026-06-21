//! UDP discovery beacon format.
//!
//! # Protocol
//! Broadcast UDP packets on port 9876 containing peer identity info.
//! Used as fallback when mDNS is unavailable.
//!
//! # Security
//! - Contains only public keys and fingerprint (no secrets).
//! - Signed with Ed25519 to prevent spoofing.
//! - Timestamp prevents replay (+/- 60s window).

use rubix_domain::identity::fingerprint::Fingerprint;
use rubix_security::keys::ed25519::{Ed25519Keypair, Ed25519Signature};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// UDP discovery beacon.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    /// Protocol version.
    pub version: u16,
    /// Human-readable display name.
    pub display_name: String,
    /// Ed25519 public key (hex).
    pub ed25519_public: String,
    /// X25519 public key (hex).
    pub x25519_public: String,
    /// Peer fingerprint.
    pub fingerprint: String,
    /// TCP port for connections.
    pub tcp_port: u16,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Ed25519 signature of the above fields.
    pub signature: String,
}

/// Maximum age of a beacon before it's considered stale (seconds).
const BEACON_MAX_AGE_SECS: u64 = 60;

impl DiscoveryBeacon {
    /// Create a new signed beacon.
    pub fn create(
        identity: &Ed25519Keypair,
        x25519_public: &[u8; 32],
        tcp_port: u16,
        display_name: impl Into<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let fingerprint = rubix_security::fingerprint::derive::derive_fingerprint(
            &identity.public,
            &rubix_security::keys::x25519::X25519PublicKey(*x25519_public),
        )
        .unwrap_or_else(|_| Fingerprint::from_bytes(&[0u8; 20]).unwrap());

        let mut beacon = Self {
            version: 1,
            display_name: display_name.into(),
            ed25519_public: hex::encode(identity.public.as_bytes()),
            x25519_public: hex::encode(x25519_public),
            fingerprint: fingerprint.to_string(),
            tcp_port,
            timestamp,
            signature: String::new(),
        };

        let sig = identity.sign(&beacon.signature_payload());
        beacon.signature = hex::encode(sig.0);

        debug!("created discovery beacon for {}", beacon.fingerprint);
        beacon
    }

    /// Verify beacon signature and timestamp.
    ///
    /// # Returns
    /// - `Ok(())` if valid.
    /// - `Err` if signature invalid, timestamp stale, or fingerprint mismatch.
    pub fn verify(&self) -> Result<(), &'static str> {
        // Check timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.timestamp > now + BEACON_MAX_AGE_SECS {
            return Err("beacon timestamp in future");
        }
        if self.timestamp + BEACON_MAX_AGE_SECS < now {
            return Err("beacon too old");
        }

        // Verify fingerprint matches keys
        let ed25519_bytes = hex::decode(&self.ed25519_public).map_err(|_| "invalid ed25519 hex")?;
        let x25519_bytes = hex::decode(&self.x25519_public).map_err(|_| "invalid x25519 hex")?;

        let ed25519_pub = rubix_security::keys::ed25519::Ed25519PublicKey::from_bytes(&ed25519_bytes)
            .map_err(|_| "invalid ed25519 key")?;
        let x25519_pub = rubix_security::keys::x25519::X25519PublicKey::from_bytes(&x25519_bytes)
            .map_err(|_| "invalid x25519 key")?;

        let computed_fp = rubix_security::fingerprint::derive::derive_fingerprint(&ed25519_pub, &x25519_pub)
            .map_err(|_| "fingerprint derivation failed")?;

        let claimed_fp = Fingerprint::from_hex(&self.fingerprint)
            .map_err(|_| "invalid fingerprint")?;

        if !computed_fp.constant_time_eq(&claimed_fp) {
            return Err("fingerprint mismatch");
        }

        // Verify signature
        let sig_bytes = hex::decode(&self.signature).map_err(|_| "invalid signature hex")?;
        if sig_bytes.len() != 64 {
            return Err("invalid signature length");
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Ed25519Signature(sig_arr);

        ed25519_pub
            .verify(&self.signature_payload(), &signature)
            .map_err(|_| "signature verification failed")?;

        Ok(())
    }

    /// The data that is signed.
    fn signature_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&self.version.to_le_bytes());
        payload.extend_from_slice(self.display_name.as_bytes());
        payload.extend_from_slice(self.ed25519_public.as_bytes());
        payload.extend_from_slice(self.x25519_public.as_bytes());
        payload.extend_from_slice(self.fingerprint.as_bytes());
        payload.extend_from_slice(&self.tcp_port.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;

    #[test]
    fn beacon_create_and_verify() {
        let keys = IdentityKeys::generate().unwrap();
        let beacon = DiscoveryBeacon::create(
            &keys.ed25519,
            &keys.x25519.public.0,
            7878,
            "TestUser",
        );
        assert!(beacon.verify().is_ok());
    }

    #[test]
    fn beacon_tampered_signature_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let mut beacon = DiscoveryBeacon::create(
            &keys.ed25519,
            &keys.x25519.public.0,
            7878,
            "TestUser",
        );
        beacon.signature = "00".repeat(64);
        assert!(beacon.verify().is_err());
    }

    #[test]
    fn beacon_old_timestamp_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let mut beacon = DiscoveryBeacon::create(
            &keys.ed25519,
            &keys.x25519.public.0,
            7878,
            "TestUser",
        );
        beacon.timestamp -= BEACON_MAX_AGE_SECS + 1;
        // Need to re-sign with old timestamp
        let sig = keys.ed25519.sign(&beacon.signature_payload());
        beacon.signature = hex::encode(sig.0);
        assert!(beacon.verify().is_err());
    }
}