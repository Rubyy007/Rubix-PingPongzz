//! Security port — abstraction over Noise, X25519, Ed25519 operations.

use async_trait::async_trait;
use domain::identity::{Fingerprint, Identity};
use thiserror::Error;

/// Security operation errors.
#[derive(Error, Debug, Clone)]
pub enum SecurityError {
    /// Key generation failure (entropy exhaustion).
    #[error("key generation failed")]
    KeyGenerationFailed,

    /// Encryption failure.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failure (bad ciphertext or wrong key).
    #[error("decryption failed")]
    DecryptionFailed,

    /// Signature verification failed.
    #[error("signature invalid")]
    SignatureInvalid,

    /// Fingerprint derivation error.
    #[error("fingerprint derivation failed")]
    FingerprintFailed,

    /// Secure storage failure.
    #[error("secure storage error")]
    StorageFailed,

    /// Internal cryptographic error.
    #[error("internal security error")]
    Internal,
}

/// Security infrastructure port.
#[async_trait]
pub trait SecurityPort: Send + Sync {
    /// Generate a new identity with fresh key pairs.
    ///
    /// # Security
    /// Uses cryptographically secure randomness (CSPRNG).
    /// Private keys are never exposed through this interface.
    async fn generate_identity(&self, display_name: &str) -> Result<Identity, SecurityError>;

    /// Derive fingerprint from public key material.
    async fn derive_fingerprint(
        &self,
        ed25519_pk: &[u8; 32],
        x25519_pk: &[u8; 32],
    ) -> Result<Fingerprint, SecurityError>;

    /// Encrypt plaintext for a specific peer.
    ///
    /// # Security
    /// Implementations must use AEAD with a fresh nonce per message.
    async fn encrypt_for_peer(
        &self,
        plaintext: &[u8],
        peer_fp: &Fingerprint,
    ) -> Result<Vec<u8>, SecurityError>;

    /// Decrypt ciphertext from a specific peer.
    async fn decrypt_from_peer(
        &self,
        ciphertext: &[u8],
        peer_fp: &Fingerprint,
    ) -> Result<Vec<u8>, SecurityError>;

    /// Sign data with local Ed25519 private key.
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityError>;

    /// Verify Ed25519 signature from a peer.
    async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
        peer_fp: &Fingerprint,
    ) -> Result<bool, SecurityError>;

    /// Load the current local identity from secure storage.
    async fn load_identity(&self) -> Result<Option<Identity>, SecurityError>;

    /// Save identity to secure storage.
    ///
    /// # Security
    /// Private keys must be encrypted at rest.
    async fn save_identity(&self, identity: &Identity) -> Result<(), SecurityError>;
}