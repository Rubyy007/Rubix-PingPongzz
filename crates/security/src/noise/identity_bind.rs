//! Identity binding payload exchanged inside Noise handshake messages.
//!
//! # Security
//! - Ed25519 signature proves possession of the claimed secret key.
//! - Timestamp window (+/- 30s) limits replay of captured payloads.
//! - Fingerprint is independently derived from the embedded public keys and
//!   compared in constant time against any caller-supplied expectation — never
//!   trusted as transmitted.

use crate::error::{SecurityError, SecurityResult};
use crate::fingerprint::derive::derive_fingerprint;
use crate::keys::ed25519::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};
use crate::keys::x25519::X25519PublicKey;
use rubix_domain::identity::fingerprint::Fingerprint;
use rand::rngs::OsRng;
use rand::RngCore;
use chrono::Utc;
use subtle::ConstantTimeEq;

/// Identity binding payload exchanged inside Noise handshake messages.
#[derive(Clone, Debug)]
pub struct IdentityBindPayload {
    /// Version for future format changes.
    pub version: u8,
    /// Ed25519 public key bytes (32 bytes).
    pub ed25519_public: [u8; 32],
    /// X25519 public key bytes (32 bytes).
    pub x25519_public: [u8; 32],
    /// Unix timestamp (seconds) at creation time.
    pub timestamp: i64,
    /// Nonce to protect against simple replay (12 bytes).
    pub nonce: [u8; 12],
    /// Ed25519 signature over the canonical payload.
    pub signature: Ed25519Signature,
}

/// Verified identity extracted from an `IdentityBindPayload`.
#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
    /// Ed25519 public key of the remote peer.
    pub ed25519_public: Ed25519PublicKey,
    /// X25519 public key of the remote peer.
    pub x25519_public: X25519PublicKey,
    /// Fingerprint derived from both public keys.
    pub fingerprint: Fingerprint,
    /// Timestamp from the payload (for replay detection).
    pub timestamp: i64,
    /// Nonce from the payload.
    pub nonce: [u8; 12],
}

/// Allowed clock skew for identity payload timestamps (seconds).
const TIMESTAMP_SKEW_SECS: i64 = 30;
/// Domain separator for the signed payload to prevent cross-protocol replay.
const DOMAIN_SEPARATOR: &[u8] = b"rubix-identity-bind-v1";

impl IdentityBindPayload {
    /// Create a new signed identity bind payload from key material.
    pub fn create(
        ed25519: &Ed25519Keypair,
        x25519_public: &X25519PublicKey,
    ) -> SecurityResult<Self> {
        let ed_bytes = *ed25519.public.as_bytes();
        let x_bytes = *x25519_public.as_bytes();
        let timestamp = Utc::now().timestamp();
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let mut payload = IdentityBindPayload {
            version: 1,
            ed25519_public: ed_bytes,
            x25519_public: x_bytes,
            timestamp,
            nonce,
            signature: Ed25519Signature([0u8; 64]),
        };
        let sig = ed25519.sign(&payload.signature_payload());
        payload.signature = sig;
        Ok(payload)
    }

    /// Construct the canonical payload bytes that are signed.
    pub fn signature_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN_SEPARATOR.len() + 1 + 32 + 32 + 8 + 12);
        out.extend_from_slice(DOMAIN_SEPARATOR);
        out.push(self.version);
        out.extend_from_slice(&self.ed25519_public);
        out.extend_from_slice(&self.x25519_public);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Serialize to a fixed-size 149-byte array.
    pub(crate) fn to_bytes(&self) -> [u8; 149] {
        let mut out = [0u8; 149];
        out[0] = self.version;
        out[1..33].copy_from_slice(&self.ed25519_public);
        out[33..65].copy_from_slice(&self.x25519_public);
        out[65..73].copy_from_slice(&self.timestamp.to_le_bytes());
        out[73..85].copy_from_slice(&self.nonce);
        out[85..149].copy_from_slice(&self.signature.0);
        out
    }

    /// Deserialize from a fixed-size 149-byte array.
    pub(crate) fn from_bytes(bytes: &[u8]) -> SecurityResult<Self> {
        if bytes.len() != 149 {
            return Err(SecurityError::IdentityBindingFailed(format!(
                "invalid payload size: expected 149, got {}",
                bytes.len()
            )));
        }
        let mut ed25519_public = [0u8; 32];
        let mut x25519_public = [0u8; 32];
        let mut timestamp_bytes = [0u8; 8];
        let mut nonce = [0u8; 12];
        let mut signature = [0u8; 64];
        ed25519_public.copy_from_slice(&bytes[1..33]);
        x25519_public.copy_from_slice(&bytes[33..65]);
        timestamp_bytes.copy_from_slice(&bytes[65..73]);
        nonce.copy_from_slice(&bytes[73..85]);
        signature.copy_from_slice(&bytes[85..149]);
        Ok(Self {
            version: bytes[0],
            ed25519_public,
            x25519_public,
            timestamp: i64::from_le_bytes(timestamp_bytes),
            nonce,
            signature: Ed25519Signature(signature),
        })
    }

    /// Internal: shared validation logic for `verify` and `verify_unbound`.
    fn verify_signature_and_freshness(&self) -> SecurityResult<(Ed25519PublicKey, X25519PublicKey)> {
        if self.version != 1 {
            return Err(SecurityError::IdentityBindingFailed(
                format!("unsupported version {}", self.version)
            ));
        }
        let now = Utc::now().timestamp();
        let max_future = now.checked_add(TIMESTAMP_SKEW_SECS)
            .ok_or_else(|| SecurityError::Internal("timestamp overflow".into()))?;
        let min_past = now.checked_sub(TIMESTAMP_SKEW_SECS)
            .ok_or_else(|| SecurityError::Internal("timestamp underflow".into()))?;
        if self.timestamp > max_future {
            return Err(SecurityError::ReplayDetected("timestamp in future".into()));
        }
        if self.timestamp < min_past {
            return Err(SecurityError::ReplayDetected("timestamp too old".into()));
        }

        let ed_pub = Ed25519PublicKey::from_bytes(&self.ed25519_public)
            .map_err(|_| SecurityError::IdentityBindingFailed("invalid ed25519 key".into()))?;
        let x_pub = X25519PublicKey::from_bytes(&self.x25519_public)
            .map_err(|_| SecurityError::IdentityBindingFailed("invalid x25519 key".into()))?;

        ed_pub.verify(&self.signature_payload(), &self.signature)
            .map_err(|_| SecurityError::IdentityBindingFailed("signature verification failed".into()))?;

        Ok((ed_pub, x_pub))
    }

    /// Verify the payload against an expected fingerprint.
    ///
    /// Performs signature verification, timestamp window check, and
    /// fingerprint derivation with constant-time comparison against `expected_fp`.
    ///
    /// # Errors
    /// Returns `SecurityError::FingerprintMismatch` if the derived fingerprint
    /// does not match the expected one.
    pub fn verify(&self, expected_fp: &Fingerprint) -> SecurityResult<VerifiedIdentity> {
        let (ed_pub, x_pub) = self.verify_signature_and_freshness()?;
        let computed_fp = derive_fingerprint(&ed_pub, &x_pub)
            .map_err(|e| SecurityError::IdentityBindingFailed(format!("fingerprint derive: {}", e)))?;
        if !bool::from(computed_fp.as_bytes().ct_eq(expected_fp.as_bytes())) {
            return Err(SecurityError::FingerprintMismatch);
        }
        Ok(VerifiedIdentity {
            ed25519_public: ed_pub,
            x25519_public: x_pub,
            fingerprint: computed_fp,
            timestamp: self.timestamp,
            nonce: self.nonce,
        })
    }

    /// Verify payload without an expected fingerprint. Returns the computed fingerprint.
    ///
    /// # Security
    /// Use only when the peer's identity is not yet known (e.g., a responder
    /// before trust is established). The caller MUST independently check
    /// `VerifiedIdentity::fingerprint` against a trust store before treating
    /// the peer as authenticated.
    pub fn verify_unbound(&self) -> SecurityResult<VerifiedIdentity> {
        let (ed_pub, x_pub) = self.verify_signature_and_freshness()?;
        let computed_fp = derive_fingerprint(&ed_pub, &x_pub)
            .map_err(|e| SecurityError::IdentityBindingFailed(format!("fingerprint derive: {}", e)))?;
        Ok(VerifiedIdentity {
            ed25519_public: ed_pub,
            x25519_public: x_pub,
            fingerprint: computed_fp,
            timestamp: self.timestamp,
            nonce: self.nonce,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::identity_keys::IdentityKeys;

    #[test]
    fn create_and_verify_roundtrip() {
        let keys = IdentityKeys::generate().unwrap();
        let payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        let fp = keys.fingerprint().unwrap();
        let verified = payload.verify(&fp).unwrap();
        assert!(verified.fingerprint.constant_time_eq(&fp));
    }

    #[test]
    fn tampered_signature_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let mut payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        payload.signature.0[0] ^= 0xFF;
        let fp = keys.fingerprint().unwrap();
        let res = payload.verify(&fp);
        assert!(matches!(res, Err(SecurityError::IdentityBindingFailed(_))));
    }

    #[test]
    fn old_timestamp_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let mut payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        payload.timestamp -= TIMESTAMP_SKEW_SECS * 10;
        let sig = keys.ed25519.sign(&payload.signature_payload());
        payload.signature = sig;
        let fp = keys.fingerprint().unwrap();
        let res = payload.verify(&fp);
        assert!(matches!(res, Err(SecurityError::ReplayDetected(_))));
    }

    #[test]
    fn future_timestamp_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let mut payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        payload.timestamp += TIMESTAMP_SKEW_SECS * 10;
        let sig = keys.ed25519.sign(&payload.signature_payload());
        payload.signature = sig;
        let fp = keys.fingerprint().unwrap();
        let res = payload.verify(&fp);
        assert!(matches!(res, Err(SecurityError::ReplayDetected(_))));
    }

    #[test]
    fn wrong_expected_fingerprint_fails() {
        let keys = IdentityKeys::generate().unwrap();
        let other_keys = IdentityKeys::generate().unwrap();
        let payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        let wrong_fp = other_keys.fingerprint().unwrap();
        let res = payload.verify(&wrong_fp);
        assert!(matches!(res, Err(SecurityError::FingerprintMismatch)));
    }

    #[test]
    fn verify_unbound_succeeds() {
        let keys = IdentityKeys::generate().unwrap();
        let payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        let verified = payload.verify_unbound().unwrap();
        assert!(verified.fingerprint.constant_time_eq(&keys.fingerprint().unwrap()));
    }

    #[test]
    fn version_rejected_if_not_1() {
        let keys = IdentityKeys::generate().unwrap();
        let mut payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        payload.version = 2;
        let sig = keys.ed25519.sign(&payload.signature_payload());
        payload.signature = sig;
        let fp = keys.fingerprint().unwrap();
        let res = payload.verify(&fp);
        assert!(matches!(res, Err(SecurityError::IdentityBindingFailed(_))));
    }

    #[test]
    fn nonce_exact_length() {
        let keys = IdentityKeys::generate().unwrap();
        let payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        assert_eq!(payload.nonce.len(), 12);
    }

    #[test]
    fn binary_roundtrip() {
        let keys = IdentityKeys::generate().unwrap();
        let payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), 149);
        let restored = IdentityBindPayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.version, payload.version);
        assert_eq!(restored.ed25519_public, payload.ed25519_public);
        assert_eq!(restored.x25519_public, payload.x25519_public);
        assert_eq!(restored.timestamp, payload.timestamp);
        assert_eq!(restored.nonce, payload.nonce);
        assert_eq!(restored.signature.0, payload.signature.0);
    }
}