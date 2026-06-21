//! Derive human-readable fingerprint from public keys.

use crate::error::{SecurityError, SecurityResult};
use crate::keys::ed25519::Ed25519PublicKey;
use crate::keys::x25519::X25519PublicKey;
use rubix_domain::identity::fingerprint::Fingerprint;

/// Derive a fingerprint from Ed25519 and X25519 public keys.
/// Uses BLAKE3-256 truncated to 160 bits (20 bytes).
///
/// # Security
/// - BLAKE3 provides strong collision resistance.
/// - Truncation to 160 bits gives ~2^80 birthday security, sufficient for
///   human out-of-band verification.
/// - Always returns `SecurityResult` — never panics.
pub fn derive_fingerprint(
    ed25519_pub: &Ed25519PublicKey,
    x25519_pub: &X25519PublicKey,
) -> SecurityResult<Fingerprint> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ed25519_pub.as_bytes());
    hasher.update(x25519_pub.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash.as_bytes()[..20]);
    Fingerprint::from_bytes(&bytes)
        .map_err(|e| SecurityError::Internal(format!("fingerprint construction failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::Ed25519Keypair;
    use crate::keys::x25519::X25519Keypair;

    #[test]
    fn fingerprint_stable() {
        let ed = Ed25519Keypair::generate().unwrap();
        let x = X25519Keypair::generate().unwrap();
        let fp1 = derive_fingerprint(&ed.public, &x.public).unwrap();
        let fp2 = derive_fingerprint(&ed.public, &x.public).unwrap();
        assert!(fp1.constant_time_eq(&fp2));
    }

    #[test]
    fn fingerprint_different_keys() {
        let ed1 = Ed25519Keypair::generate().unwrap();
        let x1 = X25519Keypair::generate().unwrap();
        let ed2 = Ed25519Keypair::generate().unwrap();
        let x2 = X25519Keypair::generate().unwrap();
        let fp1 = derive_fingerprint(&ed1.public, &x1.public).unwrap();
        let fp2 = derive_fingerprint(&ed2.public, &x2.public).unwrap();
        assert!(!fp1.constant_time_eq(&fp2));
    }

    #[test]
    fn fingerprint_length_correct() {
        let ed = Ed25519Keypair::generate().unwrap();
        let x = X25519Keypair::generate().unwrap();
        let fp = derive_fingerprint(&ed.public, &x.public).unwrap();
        assert_eq!(fp.as_bytes().len(), 20);
    }
}