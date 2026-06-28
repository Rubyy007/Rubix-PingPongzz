//! Encrypted storage of identity keys using a passphrase-derived key.
//!
//! # Security
//! - Argon2id for key derivation.
//! - ChaCha20Poly1305 for authenticated encryption.
//! - Plaintext buffers are zeroized.
//! - File permissions set to 0o600 on Unix.
//! - File size limited to prevent OOM.
//! - Orphaned temp files cleaned on initialization.

use crate::error::{SecurityError, SecurityResult};
use crate::keys::identity_keys::IdentityKeys;
use crate::keys::ed25519::Ed25519Keypair;
use crate::keys::x25519::X25519Keypair;
use crate::keys::ed25519::Ed25519SecretKey;
use crate::keys::x25519::X25519SecretKey;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use std::io;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Argon2id parameters: 64MB, 3 iterations, 4 parallelism.
const ARGON2_MEMORY_KB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const STORAGE_FILE: &str = "identity.enc";
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
/// Maximum allowed encrypted blob size (64 KB).
const MAX_STORE_SIZE: u64 = 65536;

/// Serializable representation of IdentityKeys (only for storage).
struct SerializableIdentity {
    ed25519_secret: [u8; 32],
    ed25519_public: [u8; 32],
    x25519_secret: [u8; 32],
    x25519_public: [u8; 32],
}

impl SerializableIdentity {
    fn to_bytes(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        out[0..32].copy_from_slice(&self.ed25519_secret);
        out[32..64].copy_from_slice(&self.ed25519_public);
        out[64..96].copy_from_slice(&self.x25519_secret);
        out[96..128].copy_from_slice(&self.x25519_public);
        out
    }

    fn from_bytes(bytes: &[u8]) -> SecurityResult<Self> {
        if bytes.len() != 128 {
            return Err(SecurityError::Storage(format!(
                "invalid identity size: expected 128, got {}",
                bytes.len()
            )));
        }
        let mut ed25519_secret = [0u8; 32];
        let mut ed25519_public = [0u8; 32];
        let mut x25519_secret = [0u8; 32];
        let mut x25519_public = [0u8; 32];
        ed25519_secret.copy_from_slice(&bytes[0..32]);
        ed25519_public.copy_from_slice(&bytes[32..64]);
        x25519_secret.copy_from_slice(&bytes[64..96]);
        x25519_public.copy_from_slice(&bytes[96..128]);
        Ok(Self {
            ed25519_secret,
            ed25519_public,
            x25519_secret,
            x25519_public,
        })
    }
}

impl From<&IdentityKeys> for SerializableIdentity {
    fn from(keys: &IdentityKeys) -> Self {
        SerializableIdentity {
            ed25519_secret: keys.ed25519.secret_bytes(),
            ed25519_public: keys.ed25519.public.0,
            x25519_secret: keys.x25519.secret_bytes(),
            x25519_public: keys.x25519.public.0,
        }
    }
}

impl TryFrom<SerializableIdentity> for IdentityKeys {
    type Error = SecurityError;
    fn try_from(value: SerializableIdentity) -> Result<Self, Self::Error> {
        let ed_secret = Ed25519SecretKey(value.ed25519_secret);
        let ed_public = crate::keys::ed25519::Ed25519PublicKey(value.ed25519_public);
        let ed_keypair = Ed25519Keypair::from_parts(ed_secret, ed_public)?;
        let x_secret = X25519SecretKey(value.x25519_secret);
        let x_public = crate::keys::x25519::X25519PublicKey(value.x25519_public);
        let x_keypair = X25519Keypair::from_parts(x_secret, x_public)?;
        IdentityKeys::from_parts(ed_keypair, x_keypair)
    }
}

/// Encrypted blob format.
struct EncryptedBlob {
    version: u8,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + 4 + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    fn from_bytes(bytes: &[u8]) -> SecurityResult<Self> {
        if bytes.len() < 1 + SALT_LEN + NONCE_LEN + 4 {
            return Err(SecurityError::Storage("blob too small".into()));
        }
        let version = bytes[0];
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        salt.copy_from_slice(&bytes[1..1 + SALT_LEN]);
        nonce.copy_from_slice(&bytes[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]);
        let ct_start = 1 + SALT_LEN + NONCE_LEN;
        let ct_len = u32::from_be_bytes([
            bytes[ct_start],
            bytes[ct_start + 1],
            bytes[ct_start + 2],
            bytes[ct_start + 3],
        ]) as usize;
        if bytes.len() < ct_start + 4 + ct_len {
            return Err(SecurityError::Storage("blob truncated".into()));
        }
        let ciphertext = bytes[ct_start + 4..ct_start + 4 + ct_len].to_vec();
        Ok(Self {
            version,
            salt,
            nonce,
            ciphertext,
        })
    }
}

/// Secure storage for encrypted identity keys.
pub struct SecureStore {
    path: PathBuf,
}

impl SecureStore {
    /// Create a new store at the default config directory.
    pub fn new() -> Self {
        let base = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rubix-pingpongzz");
        // Clean up orphaned temp files on start
        let _ = Self::cleanup_temp_files(&base);
        let path = base.join(STORAGE_FILE);
        Self { path }
    }

    /// Create a store at a custom path (useful for tests).
    ///
    /// Also cleans up orphaned `.tmp` files in the parent directory.
    #[cfg(test)]
    pub fn with_path(path: PathBuf) -> Self {
        let base = path.parent().unwrap_or(&path).to_path_buf();
        let _ = Self::cleanup_temp_files(&base);
        Self { path }
    }

    /// Clean up any leftover .tmp files from previous crashes.
    fn cleanup_temp_files(dir: &PathBuf) -> io::Result<()> {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "tmp" {
                        let _ = fs::remove_file(&path);
                        debug!("removed orphaned temp file {:?}", path);
                    }
                }
            }
        }
        Ok(())
    }

    /// Load existing identity. Returns `SecurityError::Storage("file not found")` if missing.
    pub fn load(&self, passphrase: &str) -> SecurityResult<IdentityKeys> {
        if !self.path.exists() {
            return Err(SecurityError::Storage("identity file not found".into()));
        }
        let metadata = fs::metadata(&self.path)
            .map_err(|e| SecurityError::Storage(format!("metadata: {}", e)))?;
        if metadata.len() > MAX_STORE_SIZE {
            return Err(SecurityError::Storage(format!(
                "file too large: {} bytes (max {})",
                metadata.len(), MAX_STORE_SIZE
            )));
        }
        let data = fs::read(&self.path)
            .map_err(|e| SecurityError::Storage(format!("read: {}", e)))?;
        self.decrypt(&data, passphrase)
    }

    /// Create new identity and save it. Fails if file already exists.
    pub fn create(&self, passphrase: &str) -> SecurityResult<IdentityKeys> {
        if self.path.exists() {
            return Err(SecurityError::Storage("identity already exists".into()));
        }
        let keys = IdentityKeys::generate()?;
        self.save(&keys, passphrase)?;
        Ok(keys)
    }

    /// Load or create (legacy – prefer load/create separately).
    pub fn load_or_create(&self, passphrase: &str) -> SecurityResult<IdentityKeys> {
        if self.path.exists() {
            self.load(passphrase)
        } else {
            self.create(passphrase)
        }
    }

    /// Save identity (encrypted).
    pub fn save(&self, keys: &IdentityKeys, passphrase: &str) -> SecurityResult<()> {
        let encrypted = self.encrypt(keys, passphrase)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecurityError::Storage(format!("create dir: {}", e)))?;
        }
        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, &encrypted)
            .map_err(|e| SecurityError::Storage(format!("write temp: {}", e)))?;
        fs::rename(&temp_path, &self.path)
            .map_err(|e| SecurityError::Storage(format!("rename: {}", e)))?;
        // Set permissions to 0o600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(perms) = fs::metadata(&self.path).and_then(|m| m.permissions()) {
                let mut new_perms = perms;
                new_perms.set_mode(0o600);
                if let Err(e) = fs::set_permissions(&self.path, new_perms) {
                    warn!("failed to set permissions: {}", e);
                }
            }
        }
        info!("identity saved");
        Ok(())
    }

    /// Encrypt identity keys.
    fn encrypt(&self, keys: &IdentityKeys, passphrase: &str) -> SecurityResult<Vec<u8>> {
        let serializable = SerializableIdentity::from(keys);
        let serialized = Zeroizing::new(serializable.to_bytes().to_vec());
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);
        let derived = Self::derive_key(passphrase, &salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&derived.0)
            .map_err(|_| SecurityError::Storage("invalid cipher key".into()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, serialized.as_ref())
            .map_err(|_| SecurityError::Storage("encryption failed".into()))?;
        let blob = EncryptedBlob {
            version: 1,
            salt,
            nonce: nonce_bytes,
            ciphertext,
        };
        Ok(blob.to_bytes())
    }

    /// Decrypt identity keys.
    fn decrypt(&self, data: &[u8], passphrase: &str) -> SecurityResult<IdentityKeys> {
        if data.len() as u64 > MAX_STORE_SIZE {
            return Err(SecurityError::Storage("blob too large".into()));
        }
        let blob = EncryptedBlob::from_bytes(data)?;
        if blob.version != 1 {
            return Err(SecurityError::Storage(format!(
                "unsupported version: {}",
                blob.version
            )));
        }
        let derived = Self::derive_key(passphrase, &blob.salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&derived.0)
            .map_err(|_| SecurityError::Storage("invalid cipher key".into()))?;
        let nonce = Nonce::from_slice(&blob.nonce);
        let plaintext = cipher
            .decrypt(nonce, blob.ciphertext.as_ref())
            .map_err(|_| SecurityError::InvalidPassphrase)?;
        let plaintext = Zeroizing::new(plaintext);
        let serializable = SerializableIdentity::from_bytes(&plaintext)?;
        IdentityKeys::try_from(serializable)
    }

    /// Derive key using Argon2id.
    fn derive_key(passphrase: &str, salt: &[u8]) -> SecurityResult<DerivedKey> {
        use argon2::Argon2;
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
        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| SecurityError::Storage(format!("argon2 hash: {}", e)))?;
        Ok(DerivedKey(key))
    }

    /// Attempt to lock already-allocated memory into RAM.
    ///
    /// # Security Warning
    /// `mlockall(MCL_CURRENT)` prevents currently allocated memory from being
    /// swapped to disk. It does **not** prevent future allocations from
    /// swapping; call this after all sensitive buffers are allocated.
    /// In containerized environments with low `ulimit -l` this may fail
    /// harmlessly.
    #[allow(unsafe_code)]
    pub fn try_lock_memory() {
        #[cfg(target_os = "linux")]
        unsafe {
            let result = libc::mlockall(libc::MCL_CURRENT);
            if result != 0 {
                warn!("mlockall failed: memory may be swapped");
            } else {
                debug!("memory locked (current)");
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            warn!("memory locking not fully supported on this platform");
        }
    }
}

impl Default for SecureStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Zeroizing key.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("test.enc"));
        let keys = IdentityKeys::generate().unwrap();
        let pass = "test";
        let encrypted = store.encrypt(&keys, pass).unwrap();
        let decrypted = store.decrypt(&encrypted, pass).unwrap();
        assert_eq!(keys.fingerprint().unwrap(), decrypted.fingerprint().unwrap());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("test.enc"));
        let keys = IdentityKeys::generate().unwrap();
        let enc = store.encrypt(&keys, "correct").unwrap();
        let res = store.decrypt(&enc, "wrong");
        assert!(matches!(res, Err(SecurityError::InvalidPassphrase)));
    }

    #[test]
    fn load_or_create_new() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = SecureStore::with_path(temp_dir.path().join("new.enc"));
        let keys = store.load_or_create("pass").unwrap();
        assert_eq!(keys.ed25519_public().0.len(), 32);
    }

    #[test]
    fn load_existing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("existing.enc");
        let store1 = SecureStore::with_path(path.clone());
        let keys1 = store1.load_or_create("pass").unwrap();
        let store2 = SecureStore::with_path(path);
        let keys2 = store2.load("pass").unwrap();
        assert_eq!(keys1.fingerprint().unwrap(), keys2.fingerprint().unwrap());
    }

    #[test]
    fn create_fails_if_exists() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("exists.enc");
        let store = SecureStore::with_path(path.clone());
        let _ = store.create("pass").unwrap();
        let res = store.create("pass2");
        assert!(matches!(res, Err(SecurityError::Storage(_))));
    }

    #[cfg(unix)]
    #[test]
    fn file_permissions_600() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("perm.enc");
        let store = SecureStore::with_path(path.clone());
        let keys = IdentityKeys::generate().unwrap();
        store.save(&keys, "pass").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode();
        // Mode may have extra bits, but we check that only owner has read/write.
        let owner_read_write = 0o600;
        assert_eq!(mode & 0o777, owner_read_write);
    }

    #[test]
    fn oversized_file_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("big.enc");
        // Write a huge file
        let data = vec![0u8; 100_000];
        std::fs::write(&path, &data).unwrap();
        let store = SecureStore::with_path(path);
        let res = store.load("pass");
        assert!(matches!(res, Err(SecurityError::Storage(_))));
    }

    #[test]
    fn cleanup_temp_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base = temp_dir.path().to_path_buf();
        let temp_file = base.join("test.tmp");
        std::fs::write(&temp_file, b"dummy").unwrap();
        let _ = SecureStore::cleanup_temp_files(&base);
        assert!(!temp_file.exists());
    }
}