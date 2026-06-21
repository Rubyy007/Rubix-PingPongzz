use crate::error::{SecurityError, SecurityResult};
use crate::keys::ed25519::{Ed25519Keypair, Ed25519PublicKey, Ed25519Signature};
use crate::keys::x25519::X25519PublicKey;
use rubix_domain::identity::fingerprint::Fingerprint;
use rubix_security::fingerprint::derive::derive_fingerprint;
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;
use rand::RngCore;
use chrono::Utc;
use subtle::ConstantTimeEq;

/// Identity binding payload exchanged inside Noise handshake messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityBindPayload {
	/// Version for future format changes.
	pub version: u8,

	/// Ed25519 public key bytes (32 bytes).
	pub ed25519_public: Vec<u8>,

	/// X25519 public key bytes (32 bytes).
	pub x25519_public: Vec<u8>,

	/// Unix timestamp (seconds) at creation time.
	pub timestamp: i64,

	/// Nonce to protect against simple replay (12 bytes recommended).
	pub nonce: Vec<u8>,

	/// Ed25519 signature over the canonical payload.
	pub signature: Vec<u8>,
}

/// Verified identity extracted from an IdentityBindPayload.
#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
	pub ed25519_public: Ed25519PublicKey,
	pub x25519_public: X25519PublicKey,
	pub fingerprint: Fingerprint,
	pub timestamp: i64,
	pub nonce: Vec<u8>,
}

/// Allowed clock skew for identity payload timestamps (seconds).
const TIMESTAMP_SKEW_SECS: i64 = 30;

impl IdentityBindPayload {
	/// Create a new signed identity bind payload from key material.
	///
	/// Signs the canonical payload using the provided Ed25519 keypair.
	pub fn create(
		ed25519: &Ed25519Keypair,
		x25519_public: &X25519PublicKey,
	) -> SecurityResult<Self> {
		// Prepare fields
		let ed_bytes = ed25519.public.as_bytes();
		let x_bytes = x25519_public.as_bytes();

		let timestamp = Utc::now().timestamp();

		// Nonce: 12 bytes
		let mut nonce = vec![0u8; 12];
		OsRng.fill_bytes(&mut nonce);

		let mut payload = IdentityBindPayload {
			version: 1,
			ed25519_public: ed_bytes.to_vec(),
			x25519_public: x_bytes.to_vec(),
			timestamp,
			nonce,
			signature: Vec::new(),
		};

		let sig = ed25519.sign(&payload.signature_payload());
		payload.signature = sig.0.to_vec();
		Ok(payload)
	}

	/// Construct the canonical payload bytes that are signed.
	pub fn signature_payload(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(1 + 32 + 32 + 8 + self.nonce.len());
		out.push(self.version);
		out.extend_from_slice(&self.ed25519_public);
		out.extend_from_slice(&self.x25519_public);
		out.extend_from_slice(&self.timestamp.to_le_bytes());
		out.extend_from_slice(&self.nonce);
		out
	}

	/// Verify the payload against an expected fingerprint.
	///
	/// Performs signature verification, timestamp window check, and fingerprint
	/// derivation and constant-time comparison against `expected_fp`.
	pub fn verify(&self, expected_fp: &Fingerprint) -> SecurityResult<VerifiedIdentity> {
		// Basic length checks
		if self.ed25519_public.len() != 32 {
			return Err(SecurityError::IdentityBindingFailed("invalid ed25519 length".into()));
		}
		if self.x25519_public.len() != 32 {
			return Err(SecurityError::IdentityBindingFailed("invalid x25519 length".into()));
		}
		if self.nonce.len() < 8 {
			return Err(SecurityError::IdentityBindingFailed("nonce too short".into()));
		}
		if self.signature.len() != 64 {
			return Err(SecurityError::IdentityBindingFailed("invalid signature length".into()));
		}

		// Signature verification
		let ed_pub = Ed25519PublicKey::from_bytes(&self.ed25519_public)
			.map_err(|_| SecurityError::IdentityBindingFailed("invalid ed25519 key".into()))?;

		let mut sig_arr = [0u8; 64];
		sig_arr.copy_from_slice(&self.signature);
		let signature = Ed25519Signature(sig_arr);

		ed_pub.verify(&self.signature_payload(), &signature)
			.map_err(|_| SecurityError::IdentityBindingFailed("signature verification failed".into()))?;

		// Timestamp check
		let now = Utc::now().timestamp();
		if self.timestamp > now + TIMESTAMP_SKEW_SECS {
			return Err(SecurityError::ReplayDetected("timestamp in future".into()));
		}
		if self.timestamp + TIMESTAMP_SKEW_SECS < now {
			return Err(SecurityError::ReplayDetected("timestamp too old".into()));
		}

		// Derive fingerprint from provided public keys
		let x_pub = X25519PublicKey::from_bytes(&self.x25519_public)
			.map_err(|_| SecurityError::IdentityBindingFailed("invalid x25519 key".into()))?;

		let computed_fp = derive_fingerprint(&ed_pub, &x_pub)
			.map_err(|e| SecurityError::IdentityBindingFailed(format!("fingerprint derive: {}", e)))?;

		// Constant-time compare
		if !computed_fp.as_bytes().ct_eq(expected_fp.as_bytes()).into() {
			return Err(SecurityError::FingerprintMismatch);
		}

		Ok(VerifiedIdentity {
			ed25519_public: ed_pub,
			x25519_public: x_pub,
			fingerprint: computed_fp,
			timestamp: self.timestamp,
			nonce: self.nonce.clone(),
		})
	}

	/// Verify payload without an expected fingerprint. Returns the computed fingerprint.
	pub fn verify_unbound(&self) -> SecurityResult<VerifiedIdentity> {
		// Same checks except we don't compare to an expected fingerprint
		if self.ed25519_public.len() != 32 {
			return Err(SecurityError::IdentityBindingFailed("invalid ed25519 length".into()));
		}
		if self.x25519_public.len() != 32 {
			return Err(SecurityError::IdentityBindingFailed("invalid x25519 length".into()));
		}
		if self.nonce.len() < 8 {
			return Err(SecurityError::IdentityBindingFailed("nonce too short".into()));
		}
		if self.signature.len() != 64 {
			return Err(SecurityError::IdentityBindingFailed("invalid signature length".into()));
		}

		let ed_pub = Ed25519PublicKey::from_bytes(&self.ed25519_public)
			.map_err(|_| SecurityError::IdentityBindingFailed("invalid ed25519 key".into()))?;

		let mut sig_arr = [0u8; 64];
		sig_arr.copy_from_slice(&self.signature);
		let signature = Ed25519Signature(sig_arr);

		ed_pub.verify(&self.signature_payload(), &signature)
			.map_err(|_| SecurityError::IdentityBindingFailed("signature verification failed".into()))?;

		// Timestamp check
		let now = Utc::now().timestamp();
		if self.timestamp > now + TIMESTAMP_SKEW_SECS {
			return Err(SecurityError::ReplayDetected("timestamp in future".into()));
		}
		if self.timestamp + TIMESTAMP_SKEW_SECS < now {
			return Err(SecurityError::ReplayDetected("timestamp too old".into()));
		}

		let x_pub = X25519PublicKey::from_bytes(&self.x25519_public)
			.map_err(|_| SecurityError::IdentityBindingFailed("invalid x25519 key".into()))?;

		let computed_fp = derive_fingerprint(&ed_pub, &x_pub)
			.map_err(|e| SecurityError::IdentityBindingFailed(format!("fingerprint derive: {}", e)))?;

		Ok(VerifiedIdentity {
			ed25519_public: ed_pub,
			x25519_public: x_pub,
			fingerprint: computed_fp,
			timestamp: self.timestamp,
			nonce: self.nonce.clone(),
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
		// Tamper signature
		if !payload.signature.is_empty() {
			payload.signature[0] ^= 0xFF;
		}
		let fp = keys.fingerprint().unwrap();
		let res = payload.verify(&fp);
		assert!(matches!(res, Err(SecurityError::IdentityBindingFailed(_))));
	}

	#[test]
	fn old_timestamp_fails() {
		let keys = IdentityKeys::generate().unwrap();
		let mut payload = IdentityBindPayload::create(&keys.ed25519, keys.x25519_public()).unwrap();
		// Make timestamp very old
		payload.timestamp -= TIMESTAMP_SKEW_SECS * 10;
		// Re-sign to keep signature consistent with payload
		let sig = keys.ed25519.sign(&payload.signature_payload());
		payload.signature = sig.0.to_vec();

		let fp = keys.fingerprint().unwrap();
		let res = payload.verify(&fp);
		assert!(matches!(res, Err(SecurityError::ReplayDetected(_))));
	}
}
