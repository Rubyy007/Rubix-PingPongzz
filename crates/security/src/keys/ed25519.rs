//! Ed25519 signing primitives.

use crate::error::{SecurityError, SecurityResult};
use ed25519_dalek::{Signer, Verifier, Signature as DalekSignature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ed25519 public key (32 bytes).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> SecurityResult<Self> {
        if bytes.len() != 32 {
            return Err(SecurityError::InvalidPublicKey(
                "Ed25519 public key must be 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> SecurityResult<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.0)
            .map_err(|_| SecurityError::InvalidPublicKey("invalid Ed25519 key".into()))?;
        let sig = DalekSignature::from_bytes(&signature.0)
            .map_err(|_| SecurityError::InvalidPublicKey("invalid signature".into()))?;
        verifying_key
            .verify(message, &sig)
            .map_err(|_| SecurityError::InvalidPublicKey("signature verification failed".into()))?;
        Ok(())
    }
}

/// Ed25519 secret key (32 bytes).
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Ed25519SecretKey(pub [u8; 32]);

/// Ed25519 signature (64 bytes).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Signature(pub [u8; 64]);

/// Ed25519 keypair.
#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Ed25519Keypair {
    pub public: Ed25519PublicKey,
    pub secret: Ed25519SecretKey,
}

impl Ed25519Keypair {
    pub fn generate() -> SecurityResult<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public = signing_key.verifying_key();
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public.as_bytes());
        let secret_bytes = signing_key.to_bytes();
        Ok(Self {
            public: Ed25519PublicKey(public_bytes),
            secret: Ed25519SecretKey(secret_bytes),
        })
    }

    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signing_key = SigningKey::from_bytes(&self.secret.0);
        let signature = signing_key.sign(message);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature.to_bytes().as_ref());
        Ed25519Signature(sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_works() {
        let kp = Ed25519Keypair::generate().unwrap();
        assert_eq!(kp.public.0.len(), 32);
        assert_eq!(kp.secret.0.len(), 32);
    }

    #[test]
    fn sign_verify_works() {
        let kp = Ed25519Keypair::generate().unwrap();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        assert!(kp.public.verify(msg, &sig).is_ok());
        // tamper message
        let bad_msg = b"goodbye";
        assert!(kp.public.verify(bad_msg, &sig).is_err());
    }
}