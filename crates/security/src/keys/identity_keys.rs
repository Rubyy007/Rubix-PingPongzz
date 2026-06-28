//! Combined identity keypair (Ed25519 + X25519) and fingerprint.

use crate::error::{SecurityError, SecurityResult};
use crate::fingerprint::derive::derive_fingerprint;
use crate::keys::ed25519::{Ed25519Keypair, Ed25519PublicKey};
use crate::keys::x25519::{X25519Keypair, X25519PublicKey};
use rubix_domain::identity::Identity;
use rubix_domain::identity::fingerprint::Fingerprint;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Combined identity keys.
///
/// # Security
/// Deliberately **not** `Clone` — `Ed25519Keypair`/`X25519Keypair` hold secret
/// material that must never be duplicated in memory. Share ownership via
/// `Arc<IdentityKeys>` (cloning the `Arc`, never the keys).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeys {
    /// Ed25519 signing keypair. `pub(crate)` allows intra-crate access while
    /// remaining hidden from external crates.
    pub(crate) ed25519: Ed25519Keypair,
    /// X25519 Diffie-Hellman keypair.
    pub(crate) x25519: X25519Keypair,
}

impl IdentityKeys {
    /// Generate a new random identity key pair.
    pub fn generate() -> SecurityResult<Self> {
        let ed25519 = Ed25519Keypair::generate()?;
        let x25519 = X25519Keypair::generate()?;
        Ok(Self { ed25519, x25519 })
    }

    /// Construct from validated keypairs.
    ///
    /// # Safety
    /// Assumes `ed25519` and `x25519` are already internally consistent
    /// (verified by `Ed25519Keypair::from_parts` and `X25519Keypair::from_parts`).
    /// This function only bundles them; it does not re-derive or cross-check.
    pub fn from_parts(ed25519: Ed25519Keypair, x25519: X25519Keypair) -> SecurityResult<Self> {
        // Verify that the fingerprint is derivable (catches corrupted key material).
        let _ = derive_fingerprint(&ed25519.public, &x25519.public)
            .map_err(|e| SecurityError::Internal(format!("fingerprint derivation failed: {}", e)))?;
        Ok(Self { ed25519, x25519 })
    }

    /// Compute the fingerprint from the public keys.
    pub fn fingerprint(&self) -> SecurityResult<Fingerprint> {
        derive_fingerprint(&self.ed25519.public, &self.x25519.public)
    }

    /// Create a domain `Identity` from these keys and a display name.
    pub fn to_domain_identity(&self, display_name: &str) -> SecurityResult<Identity> {
        let fingerprint = self.fingerprint()?;
        Identity::builder()
            .display_name(display_name)
            .ed25519_public(self.ed25519.public.0)
            .x25519_public(self.x25519.public.0)
            .fingerprint(fingerprint)
            .build()
            .map_err(|e| SecurityError::Internal(format!("domain identity build failed: {}", e)))
    }

    /// Get the X25519 public key (for Noise handshake remote static key).
    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519.public
    }

    /// Get the Ed25519 public key (for identity binding).
    pub fn ed25519_public(&self) -> &Ed25519PublicKey {
        &self.ed25519.public
    }

    /// Compare two `IdentityKeys` by public material only.
    ///
    /// # Security
    /// Never compares secret key material.
    pub fn public_eq(&self, other: &IdentityKeys) -> bool {
        self.ed25519.public.0 == other.ed25519.public.0
            && self.x25519.public.0 == other.x25519.public.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_keys() {
        let keys = IdentityKeys::generate().unwrap();
        assert_eq!(keys.ed25519_public().0.len(), 32);
        assert_eq!(keys.x25519_public().0.len(), 32);
        let fp = keys.fingerprint().unwrap();
        assert_eq!(fp.as_bytes().len(), 20);
    }

    #[test]
    fn fingerprint_deterministic() {
        let keys = IdentityKeys::generate().unwrap();
        let fp1 = keys.fingerprint().unwrap();
        let fp2 = keys.fingerprint().unwrap();
        assert!(fp1.constant_time_eq(&fp2));
    }

    #[test]
    fn to_domain_identity_works() {
        let keys = IdentityKeys::generate().unwrap();
        let identity = keys.to_domain_identity("TestUser").unwrap();
        assert_eq!(identity.display_name(), "TestUser");
        assert!(keys.fingerprint().unwrap().constant_time_eq(identity.fingerprint()));
    }

    #[test]
    fn different_keys_different_fingerprints() {
        let keys1 = IdentityKeys::generate().unwrap();
        let keys2 = IdentityKeys::generate().unwrap();
        assert!(!keys1.fingerprint().unwrap().constant_time_eq(&keys2.fingerprint().unwrap()));
    }

    #[test]
    fn from_parts_works() {
        let ed = Ed25519Keypair::generate().unwrap();
        let x = X25519Keypair::generate().unwrap();
        let fp = derive_fingerprint(&ed.public, &x.public).unwrap();
        let rebuilt = IdentityKeys::from_parts(ed, x).unwrap();
        assert!(rebuilt.fingerprint().unwrap().constant_time_eq(&fp));
    }

    #[test]
    fn public_eq_matches() {
        let keys1 = IdentityKeys::generate().unwrap();
        let keys2 = IdentityKeys::generate().unwrap();
        assert!(keys1.public_eq(&keys1));
        assert!(!keys1.public_eq(&keys2));
    }
}