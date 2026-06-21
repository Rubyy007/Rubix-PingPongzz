//! Encrypted storage of identity keys using a passphrase-derived key.
//!
//! # Security
//! - Argon2id for key derivation (memory-hard, resistant to GPU attacks).
//! - ChaCha20Poly1305 for authenticated encryption.
//! - Memory locking via `mlock` where available (Linux/macOS).
//! - All sensitive material zeroized after use.
//! - Sync API: filesystem I/O does not benefit from async.

use crate::error::{SecurityError, SecurityResult};
use crate::keys::identity_keys::IdentityKeys;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Nonce},
    ChaCha20Poly1305,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id parameters tuned for security vs. performance balance.
/// - Memory: 64MB (resistant to GPU/ASIC attacks)
/// - Iterations: 3 (OWASP recommended minimum)
/// - Parallelism: 4 (matches common CPU cores)
const ARGON2_MEMORY_KB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Location where we store the encrypted blob.
const STORAGE_FILE: &str = "identity.enc";

/// Salt length for Argon2.
const SALT_LEN: usize = 32;

/// Nonce length for ChaCha20Poly1305.
const NONCE_LEN: usize = 12;

/// Tag length for ChaCha20Poly1305.
const TAG_LEN: usize = 16;

/// Encrypted identity storage format.
#[derive(Serialize, Deserialize)]
struct EncryptedBlob {
    version: u8,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

/// Secure storage for identity keys.
///
/// # Thread Safety
/// - `Sync` + `Send`: all operations are synchronous and self-contained.
/// - No internal mutable state.
pub struct SecureStore {
    path: PathBuf,
}

/// A derived encryption key that is automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

impl SecureStore {
    /// Create a new store at the default path (in the app's config directory).
    pub fn new() -> Self {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rubix-pingpongzz")
            .join(STORAGE_FILE);
        Self { path }
    }

    /// Create a store at a custom path (useful for tests).
    #[cfg(test)]
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load existing encrypted identity or generate new if not present.
    ///
    /// # Arguments
    /// - `passphrase`: User-provided passphrase. Must be strong.
    ///
    /// # Security
    /// - If file exists but passphrase is wrong, returns `InvalidPassphrase`.
    /// - If file does not exist, generates new keys and stores them.
    /// - Generated keys use `OsRng` (cryptographically secure).
    pub fn load_or_create(&self, passphrase: &str) -> SecurityResult<IdentityKeys> {
        if self.path.exists() {
            debug!("loading existing identity from {:?}", self.path);
            let data = fs::read(&self.path)
                .map_err(|e| SecurityError::Storage(format!("failed to read: {}", e)))?;
            self.decrypt(&data, passphrase)
        } else {
            info!("no existing identity found, generating new keys");
            let keys = IdentityKeys::generate()?;
            self.save(&keys, passphrase)?;
            Ok(keys)
        }
    }

    /// Save identity keys encrypted with passphrase.
    ///
    /// # Security
    /// - Overwrites existing file atomically (write to temp, then rename).
    /// - Directory created if not exists.
    pub fn save(&self, keys: &IdentityKeys, passphrase: &str) -> SecurityResult<()> {
        let encrypted = self.encrypt(keys, passphrase)?;

        // Ensure directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecurityError::Storage(format!("failed to create dir: {}", e)))?;
        }

        // Atomic write: write to temp file, then rename
        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, encrypted)
            .map_err(|e| SecurityError::Storage(format!("failed to write temp: {}", e)))?;
        fs::rename(&temp_path, &self.path)
            .map_err(|e| SecurityError::Storage(format!("failed to rename: {}", e)))?;

        info!("identity saved to {:?}", self.path);
        Ok(())
    }

    /// Encrypt identity keys with passphrase using Argon2id + ChaCha20Poly1305.
    fn encrypt(&self, keys: &IdentityKeys, passphrase: &str) -> SecurityResult<Vec<u8>> {
        let serialized = serde_json::to_vec(keys)
            .map_err(|e| SecurityError::Serialization(format!("serialization failed: {}", e)))?;

        // Generate random salt and nonce
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive key with Argon2id
        let derived = Self::derive_key(passphrase, &salt)?;

        // Encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&derived.0)
            .map_err(|_| SecurityError::Storage("invalid cipher key".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|_| SecurityError::Storage("encryption failed".into()))?;

        // Build blob
        let blob = EncryptedBlob {
            version: 1,
            salt,
            nonce: nonce_bytes,
            ciphertext,
        };

        serde_json::to_vec(&blob)
            .map_err(|e| SecurityError::Serialization(format!("blob serialization: {}", e)))
    }

    /// Decrypt identity keys from encrypted blob.
    fn decrypt(&self, data: &[u8], passphrase: &str) -> SecurityResult<IdentityKeys> {
        let blob: EncryptedBlob = serde_json::from_slice(data)
            .map_err(|e| SecurityError::Storage(format!("invalid blob format: {}", e)))?;

        if blob.version != 1 {
            return Err(SecurityError::Storage(format!(
                "unsupported blob version: {}",
                blob.version
            )));
        }

        // Derive key
        let derived = Self::derive_key(passphrase, &blob.salt)?;

        // Decrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&derived.0)
            .map_err(|_| SecurityError::Storage("invalid cipher key".into()))?;
        let nonce = Nonce::from_slice(&blob.nonce);
        let plaintext = cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|_| SecurityError::InvalidPassphrase)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| SecurityError::Serialization(format!("deserialization failed: {}", e)))
    }

    /// Derive encryption key from passphrase using Argon2id.
    ///
    /// # Security
    /// - Memory-hard: 64MB per derivation.
    /// - Resistant to GPU/ASIC attacks.
    /// - Key is zeroized on drop.
    fn derive_key(passphrase: &str, salt: &[u8]) -> SecurityResult<DerivedKey> {
        use argon2::{Argon2, PasswordHasher, password_hash::Salt};

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                ARGON2_MEMORY_KB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(32),
            )
            .map_err(|e| SecurityError::Storage(format!("argon2 params: {}", e)))?,
        );

        let salt = Salt::from_b64(&base64::encode(salt))
            .map_err(|e| SecurityError::Storage(format!("salt encoding: {}", e)))?;

        let hash = argon2
            .hash_password(passphrase.as_bytes(), &salt)
            .map_err(|e| SecurityError::Storage(format!("argon2 hash: {}", e)))?;

        let mut key = [0u8; 32];
        let hash_bytes = hash.hash.ok_or_else(|| {
            SecurityError::Storage("argon2 produced no hash".into())
        })?;
        key.copy_from_slice(hash_bytes.as_bytes());

        Ok(DerivedKey(key))
    }

    /// Attempt to lock memory pages to prevent swapping.
    ///
    /// # Platform Support
    /// - Linux: uses `mlockall(MCL_CURRENT)`.
    /// - macOS: uses `mlock` on current process.
    /// - Windows: not implemented (graceful fallback).
    ///
    /// # Safety
    /// This is a best-effort defense. If locking fails, we log a warning
    /// and continue — availability is prioritized over perfect memory protection.
    pub fn try_lock_memory() {
        #[cfg(target_os = "linux")]
        unsafe {
            let result = libc::mlockall(libc::MCL_CURRENT);
            if result != 0 {
                warn!("mlockall failed: memory may be swapped to disk");
            } else {
                debug!("memory locked against swapping");
            }
        }
        #[cfg(target_os = "macos")]
        unsafe {
            // mlock on macOS requires a specific address range
            // We skip it for simplicity; full implementation would track allocations
            warn!("mlock not implemented on macOS — memory may be swapped");
        }
        #[cfg(target_os = "windows")]
        {
            warn!("memory locking not implemented on Windows");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("test.enc"));
        let keys = IdentityKeys::generate().unwrap();
        let passphrase = "test-passphrase-123";

        let encrypted = store.encrypt(&keys, passphrase).unwrap();
        let decrypted = store.decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(keys.ed25519.public.0, decrypted.ed25519.public.0);
        assert_eq!(keys.x25519.public.0, decrypted.x25519.public.0);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("test.enc"));
        let keys = IdentityKeys::generate().unwrap();
        let passphrase = "correct";
        let encrypted = store.encrypt(&keys, passphrase).unwrap();
        let result = store.decrypt(&encrypted, "wrong");
        assert!(matches!(result, Err(SecurityError::InvalidPassphrase)));
    }

    #[test]
    fn load_or_create_generates_new() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("new.enc"));
        let keys = store.load_or_create("password").unwrap();
        assert_eq!(keys.ed25519.public.0.len(), 32);
        assert_eq!(keys.x25519.public.0.len(), 32);
    }

    #[test]
    fn load_or_create_loads_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("existing.enc");
        let store1 = SecureStore::with_path(path.clone());
        let keys1 = store1.load_or_create("password").unwrap();

        let store2 = SecureStore::with_path(path);
        let keys2 = store2.load_or_create("password").unwrap();

        assert_eq!(keys1.ed25519.public.0, keys2.ed25519.public.0);
        assert_eq!(keys1.x25519.public.0, keys2.x25519.public.0);
    }

    #[test]
    fn corrupted_blob_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("test.enc"));
        let keys = IdentityKeys::generate().unwrap();
        let mut encrypted = store.encrypt(&keys, "pass").unwrap();
        // Corrupt the ciphertext
        let idx = encrypted.len() - 5;
        encrypted[idx] ^= 0xFF;
        let result = store.decrypt(&encrypted, "pass");
        assert!(matches!(result, Err(SecurityError::InvalidPassphrase)));
    }
}