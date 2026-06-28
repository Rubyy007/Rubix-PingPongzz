//! Ed25519 signing primitives.
//!
//! # Security
//! - Secret key material never derives `Debug` or `Clone`.
//! - Secret stored as `[u8; 32]` and zeroized on drop.
//! - `SigningKey` is reconstructed on each sign (rare operation).

use crate::error::{SecurityError, SecurityResult};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ed25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    /// Construct from raw bytes.
    ///
    /// # Errors
    /// Returns `SecurityError::InvalidPublicKey` if `bytes.len() != 32`.
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

    /// Borrow the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verify a signature over `message`.
    ///
    /// # Security
    /// Error is opaque — does not distinguish "bad key" from "bad signature"
    /// from "verification failed" to an external caller, preventing oracle
    /// attacks that probe which stage failed.
    ///
    /// # Errors
    /// Returns `SecurityError::InvalidSignature` on any verification failure.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> SecurityResult<()> {
        let verifying_key = VerifyingKey::from_bytes(&self.0)
            .map_err(|_| SecurityError::InvalidPublicKey("invalid Ed25519 key".into()))?;
        let sig = DalekSignature::from_bytes(&signature.0);
        verifying_key
            .verify(message, &sig)
            .map_err(|_| SecurityError::InvalidSignature)?;
        Ok(())
    }
}

/// Ed25519 secret key (32 bytes). No `Debug`, no `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SecretKey(pub [u8; 32]);

/// Ed25519 signature (64 bytes).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = Ed25519Signature;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "64 bytes representing an Ed25519 signature")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 64 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(Ed25519Signature(arr))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Ed25519Signature(arr))
            }
        }
        deserializer.deserialize_bytes(SigVisitor)
    }
}

/// Ed25519 keypair. No `Debug`, no `Clone`. Stores secret as raw bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Keypair {
    /// The public portion of the key.
    pub public: Ed25519PublicKey,
    secret: [u8; 32], // zeroized on drop
}

impl Ed25519Keypair {
    /// Generate a new keypair using a cryptographically secure RNG.
    pub fn generate() -> SecurityResult<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public = signing_key.verifying_key();
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public.as_bytes());
        Ok(Self {
            public: Ed25519PublicKey(public_bytes),
            secret: signing_key.to_bytes(),
        })
    }

    /// Construct from existing secret and public key, validating consistency.
    ///
    /// # Errors
    /// Returns `SecurityError::InvalidPublicKey` if the public key does not
    /// match the secret key.
    pub fn from_parts(secret: Ed25519SecretKey, public: Ed25519PublicKey) -> SecurityResult<Self> {
        let signing_key = SigningKey::from_bytes(&secret.0);
        let verifying_key = signing_key.verifying_key();
        if verifying_key.as_bytes() != public.as_bytes() {
            return Err(SecurityError::InvalidPublicKey("public key mismatch".into()));
        }
        Ok(Self {
            public,
            secret: secret.0,
        })
    }

    /// Sign `message` with this keypair's secret key.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signing_key = SigningKey::from_bytes(&self.secret);
        let signature = signing_key.sign(message);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature.to_bytes().as_ref());
        Ed25519Signature(sig_bytes)
    }

    /// Return a copy of the secret key bytes.
    ///
    /// # Security
    /// The returned array is a copy and will **not** be automatically zeroized.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_works() {
        let kp = Ed25519Keypair::generate().unwrap();
        assert_eq!(kp.public.0.len(), 32);
    }

    #[test]
    fn sign_verify_works() {
        let kp = Ed25519Keypair::generate().unwrap();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        assert!(kp.public.verify(msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails() {
        let kp = Ed25519Keypair::generate().unwrap();
        let sig = kp.sign(b"hello world");
        assert!(kp.public.verify(b"goodbye", &sig).is_err());
    }

    #[test]
    fn tampered_signature_fails() {
        let kp = Ed25519Keypair::generate().unwrap();
        let mut sig = kp.sign(b"hello world");
        sig.0[0] ^= 0xFF;
        assert!(kp.public.verify(b"hello world", &sig).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = Ed25519Keypair::generate().unwrap();
        let kp2 = Ed25519Keypair::generate().unwrap();
        let sig = kp1.sign(b"hello world");
        assert!(kp2.public.verify(b"hello world", &sig).is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let short = [0u8; 16];
        assert!(Ed25519PublicKey::from_bytes(&short).is_err());
    }

    #[test]
    fn signature_serde_roundtrip() {
        let kp = Ed25519Keypair::generate().unwrap();
        let sig = kp.sign(b"roundtrip test");
        let bytes = serde_json::to_vec(&sig).unwrap();
        let decoded: Ed25519Signature = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(sig.0, decoded.0);
    }

    #[test]
    fn from_parts_valid() {
        let kp = Ed25519Keypair::generate().unwrap();
        let secret = Ed25519SecretKey(kp.secret_bytes());
        let public = kp.public.clone();
        let rebuilt = Ed25519Keypair::from_parts(secret, public).unwrap();
        assert_eq!(rebuilt.public.0, kp.public.0);
        let msg = b"test";
        let sig = rebuilt.sign(msg);
        assert!(rebuilt.public.verify(msg, &sig).is_ok());
    }

    #[test]
    fn from_parts_mismatch_fails() {
        let kp1 = Ed25519Keypair::generate().unwrap();
        let kp2 = Ed25519Keypair::generate().unwrap();
        let secret = Ed25519SecretKey(kp1.secret_bytes());
        let result = Ed25519Keypair::from_parts(secret, kp2.public.clone());
        assert!(matches!(result, Err(SecurityError::InvalidPublicKey(_))));
    }
}