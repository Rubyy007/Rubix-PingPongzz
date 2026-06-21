//! X25519 key exchange primitives.

use crate::error::{SecurityError, SecurityResult};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

/// X25519 public key (32 bytes).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> SecurityResult<Self> {
        if bytes.len() != 32 {
            return Err(SecurityError::InvalidPublicKey(
                "X25519 public key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// X25519 secret key (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct X25519SecretKey(pub [u8; 32]);

/// X25519 keypair.
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct X25519Keypair {
    pub public: X25519PublicKey,
    pub secret: X25519SecretKey,
}

impl X25519Keypair {
    /// Generate a new random keypair using `StaticSecret` for persistence.
    pub fn generate() -> SecurityResult<Self> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = DalekPublic::from(&secret);
        let mut secret_bytes = [0u8; 32];
        let mut public_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(secret.as_bytes());
        public_bytes.copy_from_slice(public.as_bytes());
        Ok(Self {
            public: X25519PublicKey(public_bytes),
            secret: X25519SecretKey(secret_bytes),
        })
    }

    /// Perform Diffie-Hellman with a remote public key.
    ///
    /// # Security
    /// - Shared secret is zeroized after copying to result.
    /// - Uses constant-time scalar multiplication from dalek.
    pub fn diffie_hellman(&self, remote_public: &X25519PublicKey) -> [u8; 32] {
        let secret = StaticSecret::from(self.secret.0);
        let public = DalekPublic::from(remote_public.0);
        let shared = secret.diffie_hellman(&public);
        let mut result = [0u8; 32];
        result.copy_from_slice(shared.as_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_works() {
        let kp = X25519Keypair::generate().unwrap();
        assert_eq!(kp.public.0.len(), 32);
        assert_eq!(kp.secret.0.len(), 32);
    }

    #[test]
    fn dh_agreement() {
        let alice = X25519Keypair::generate().unwrap();
        let bob = X25519Keypair::generate().unwrap();
        let shared_a = alice.diffie_hellman(&bob.public);
        let shared_b = bob.diffie_hellman(&alice.public);
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn dh_with_different_keys() {
        let alice = X25519Keypair::generate().unwrap();
        let bob = X25519Keypair::generate().unwrap();
        let charlie = X25519Keypair::generate().unwrap();
        let shared_ab = alice.diffie_hellman(&bob.public);
        let shared_ac = alice.diffie_hellman(&charlie.public);
        assert_ne!(shared_ab, shared_ac);
    }
}