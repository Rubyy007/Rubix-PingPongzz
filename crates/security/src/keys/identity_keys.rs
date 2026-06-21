//! Combined identity keypair (Ed25519 + X25519) and fingerprint.

use crate::error::{SecurityError, SecurityResult};
use crate::fingerprint::derive::derive_fingerprint;
use crate::keys::ed25519::{Ed25519Keypair, Ed25519PublicKey};
use crate::keys::x25519::{X25519Keypair, X25519PublicKey};
use rubix_domain::identity::{Identity, IdentityBuilder};
use rubix_domain::identity::fingerprint::Fingerprint;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Combined identity keys.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct IdentityKeys {
    pub ed25519: Ed25519Keypair,
    pub x25519: X25519Keypair,
}

impl IdentityKeys {
    /// Generate a new random identity key pair.
    pub fn generate() -> SecurityResult<Self> {
        let ed25519 = Ed25519Keypair::generate()?;
        let x25519 = X25519Keypair::generate()?;
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
            .map_err(|e| SecurityError::Internal(format!("domain error: {}", e)))
    }

    /// Get the X25519 public key (for Noise handshake remote static key).
    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519.public
    }

    /// Get the Ed25519 public key (for identity binding).
    pub fn ed25519_public(&self) -> &Ed25519PublicKey {
        &self.ed25519.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_keys() {
        let keys = IdentityKeys::generate().unwrap();
        assert_eq!(keys.ed25519.public.0.len(), 32);
        assert_eq!(keys.x25519.public.0.len(), 32);
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
}