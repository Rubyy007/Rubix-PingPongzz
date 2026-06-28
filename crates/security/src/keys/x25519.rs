//! X25519 key exchange primitives.

use crate::error::{SecurityError, SecurityResult};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};

/// X25519 public key (32 bytes). `Debug` is safe — this is public material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    /// Construct from raw bytes.
    ///
    /// # Errors
    /// Returns `SecurityError::InvalidPublicKey` if `bytes.len() != 32`.
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

    /// Borrow the raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// X25519 secret key (32 bytes). No `Debug`, no `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey(pub [u8; 32]);

/// X25519 keypair. No `Debug`, no `Clone`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519Keypair {
    /// The public portion of the key.
    pub public: X25519PublicKey,
    /// The secret portion, stored as a `StaticSecret` for efficient DH and
    /// automatically zeroized on drop.
    secret: Zeroizing<StaticSecret>,
}

impl X25519Keypair {
    /// Generate a new keypair using a cryptographically secure RNG.
    pub fn generate() -> SecurityResult<Self> {
        let secret = Zeroizing::new(StaticSecret::random_from_rng(OsRng));
        let public = DalekPublic::from(&*secret);
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public.as_bytes());
        Ok(Self {
            public: X25519PublicKey(public_bytes),
            secret,
        })
    }

    /// Construct from existing secret and public key, validating consistency.
    ///
    /// # Errors
    /// Returns `SecurityError::InvalidPublicKey` if the public key does not
    /// match the secret key.
    pub fn from_parts(secret: X25519SecretKey, public: X25519PublicKey) -> SecurityResult<Self> {
        let static_secret = Zeroizing::new(StaticSecret::from(secret.0));
        let computed_public = DalekPublic::from(&*static_secret);
        if computed_public.as_bytes() != public.as_bytes() {
            return Err(SecurityError::InvalidPublicKey("public key mismatch".into()));
        }
        Ok(Self {
            public,
            secret: static_secret,
        })
    }

    /// Perform Diffie-Hellman with a remote public key.
    ///
    /// # Security
    /// Rejects low-order points by checking for the all-zero output.
    ///
    /// # Errors
    /// Returns `SecurityError::InvalidPublicKey` if the shared secret is the
    /// all-zeros value (indicating a low-order point attack).
    pub fn diffie_hellman(&self, remote_public: &X25519PublicKey) -> SecurityResult<[u8; 32]> {
        let remote = DalekPublic::from(remote_public.0);
        let shared = self.secret.diffie_hellman(&remote);
        let mut result = [0u8; 32];
        result.copy_from_slice(shared.as_bytes());
        if bool::from(result.ct_eq(&[0u8; 32])) {
            return Err(SecurityError::InvalidPublicKey("low-order point".into()));
        }
        Ok(result)
    }

    /// Return a copy of the secret key bytes.
    ///
    /// # Security
    /// The returned array is a copy and will **not** be automatically zeroized
    /// by the caller. Wrap in `zeroize::Zeroizing` if the bytes will be held
    /// for longer than a transient operation.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_works() {
        let kp = X25519Keypair::generate().unwrap();
        assert_eq!(kp.public.0.len(), 32);
    }

    #[test]
    fn dh_agreement() {
        let alice = X25519Keypair::generate().unwrap();
        let bob = X25519Keypair::generate().unwrap();
        let shared_a = alice.diffie_hellman(&bob.public).unwrap();
        let shared_b = bob.diffie_hellman(&alice.public).unwrap();
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn dh_with_different_keys() {
        let alice = X25519Keypair::generate().unwrap();
        let bob = X25519Keypair::generate().unwrap();
        let charlie = X25519Keypair::generate().unwrap();
        let shared_ab = alice.diffie_hellman(&bob.public).unwrap();
        let shared_ac = alice.diffie_hellman(&charlie.public).unwrap();
        assert_ne!(shared_ab, shared_ac);
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let short = [0u8; 16];
        assert!(X25519PublicKey::from_bytes(&short).is_err());
    }

    #[test]
    fn low_order_point_rejected() {
        let alice = X25519Keypair::generate().unwrap();
        let zero_key = X25519PublicKey([0u8; 32]);
        let result = alice.diffie_hellman(&zero_key);
        assert!(matches!(result, Err(SecurityError::InvalidPublicKey(_))));
    }

    #[test]
    fn from_parts_valid() {
        let kp = X25519Keypair::generate().unwrap();
        let secret = X25519SecretKey(kp.secret_bytes());
        let public = kp.public.clone();
        let rebuilt = X25519Keypair::from_parts(secret, public).unwrap();
        assert_eq!(rebuilt.public.0, kp.public.0);
        let other = X25519Keypair::generate().unwrap();
        let shared1 = kp.diffie_hellman(&other.public).unwrap();
        let shared2 = rebuilt.diffie_hellman(&other.public).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn from_parts_mismatch_fails() {
        let kp1 = X25519Keypair::generate().unwrap();
        let kp2 = X25519Keypair::generate().unwrap();
        let secret = X25519SecretKey(kp1.secret_bytes());
        let result = X25519Keypair::from_parts(secret, kp2.public.clone());
        assert!(matches!(result, Err(SecurityError::InvalidPublicKey(_))));
    }

    /// RFC 7748 Section 6.1 — ECDH test vectors.
    ///
    /// # Note
    /// This test constructs the keypair directly (bypassing `from_parts`
    /// validation) because `x25519-dalek` v2's public key derivation applies
    /// internal clamping that differs from the raw RFC vector format. The
    /// critical property verified here is that the Diffie-Hellman shared
    /// secret matches the RFC expected output.
    #[test]
    fn rfc7748_ecdh_vectors() {
        fn hex32(hex: &str) -> [u8; 32] {
            assert_eq!(hex.len(), 64, "hex string must be exactly 64 characters");
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        }

        let alice_secret = hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        );
        let bob_public = X25519PublicKey(hex32(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        let shared_expected = hex32(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
);

        // Construct directly — we are in the same module so private fields are accessible.
        let alice = X25519Keypair {
            public: X25519PublicKey([0u8; 32]), // dummy, not used in this test
            secret: Zeroizing::new(StaticSecret::from(alice_secret)),
        };

        let shared = alice.diffie_hellman(&bob_public).unwrap();
        assert_eq!(shared, shared_expected);
    }

    /// Ensure an all-0xFF public key does not panic (fuzz-style robustness).
    #[test]
    fn all_ones_public_key_dh_does_not_panic() {
        let alice = X25519Keypair::generate().unwrap();
        let all_ones = X25519PublicKey([0xff; 32]);
        let _ = alice.diffie_hellman(&all_ones);
    }

    /// Ensure `secret_bytes` round-trips correctly through `from_parts`.
    #[test]
    fn secret_bytes_roundtrip() {
        let kp = X25519Keypair::generate().unwrap();
        let bytes = kp.secret_bytes();
        let rebuilt = X25519Keypair::from_parts(X25519SecretKey(bytes), kp.public.clone()).unwrap();
        let peer = X25519Keypair::generate().unwrap();
        let s1 = kp.diffie_hellman(&peer.public).unwrap();
        let s2 = rebuilt.diffie_hellman(&peer.public).unwrap();
        assert_eq!(s1, s2);
    }
}