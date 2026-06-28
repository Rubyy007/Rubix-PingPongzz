//! Secure transport after Noise handshake.
//!
//! # Security
//! - Encryption/decryption errors are deliberately opaque.
//! - `std::sync::Mutex` serializes access to the non-Sync `SnowTransport`.
//! - The returned plaintext `Vec<u8>` is **not** automatically zeroized.
//!   Callers must handle sensitive data appropriately.
//! - Message size is bounded to prevent unbounded allocation.

use crate::error::{SecurityError, SecurityResult};
use snow::TransportState as SnowTransport;
use std::sync::{Arc, Mutex};
use tracing::debug;

/// Maximum plaintext message size (1 MiB).
pub const MAX_TRANSPORT_MSG_SIZE: usize = 1_048_576;

/// AEAD authentication tag size for ChaCha20Poly1305.
const AEAD_TAG_SIZE: usize = 16;

/// Maximum ciphertext frame size (plaintext + AEAD tag).
pub const MAX_TRANSPORT_FRAME_SIZE: usize = MAX_TRANSPORT_MSG_SIZE + AEAD_TAG_SIZE;

/// Secure transport for encrypted messages, wrapping a completed Noise session.
///
/// # Thread Safety
/// `Transport` is `Clone`, `Send`, and `Sync`. Multiple tasks may hold
/// clones and call `encrypt`/`decrypt` concurrently; the mutex serializes
/// access to the underlying `SnowTransport` state machine.
#[derive(Clone, Debug)]
pub struct Transport {
    inner: Arc<Mutex<SnowTransport>>,
}

impl Transport {
    pub(crate) fn new(transport: SnowTransport) -> Self {
        Self {
            inner: Arc::new(Mutex::new(transport)),
        }
    }

    /// Encrypt a plaintext message into a ciphertext frame.
    ///
    /// # Errors
    /// - `SecurityError::MessageTooLarge` if `plaintext` exceeds `MAX_TRANSPORT_MSG_SIZE`.
    /// - `SecurityError::EncryptionFailed` if the Noise state machine rejects the message.
    pub fn encrypt(&self, plaintext: &[u8]) -> SecurityResult<Vec<u8>> {
        if plaintext.len() > MAX_TRANSPORT_MSG_SIZE {
            return Err(SecurityError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_TRANSPORT_MSG_SIZE,
            });
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::Internal("transport state corrupted".into()))?;
        let mut output = vec![0u8; plaintext.len() + AEAD_TAG_SIZE];
        let len = guard
            .write_message(plaintext, &mut output)
            .map_err(|_| SecurityError::EncryptionFailed)?;
        output.truncate(len);
        debug!(in_len = plaintext.len(), out_len = output.len(), "encrypted message");
        Ok(output)
    }

    /// Decrypt a ciphertext frame into the original plaintext.
    ///
    /// # Security
    /// The returned `Vec<u8>` contains decrypted plaintext. Callers should
    /// zeroize sensitive data after use.
    ///
    /// # Errors
    /// - `SecurityError::MessageTooLarge` if `ciphertext` exceeds `MAX_TRANSPORT_FRAME_SIZE`.
    /// - `SecurityError::DecryptionFailed` if authentication fails or the frame is malformed.
    pub fn decrypt(&self, ciphertext: &[u8]) -> SecurityResult<Vec<u8>> {
        if ciphertext.len() > MAX_TRANSPORT_FRAME_SIZE {
            return Err(SecurityError::MessageTooLarge {
                size: ciphertext.len(),
                max: MAX_TRANSPORT_FRAME_SIZE,
            });
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecurityError::Internal("transport state corrupted".into()))?;
        let mut output = vec![0u8; ciphertext.len()];
        let len = guard
            .read_message(ciphertext, &mut output)
            .map_err(|_| SecurityError::DecryptionFailed)?;
        output.truncate(len);
        debug!(in_len = ciphertext.len(), out_len = output.len(), "decrypted message");
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_constants_are_sane() {
        assert_eq!(MAX_TRANSPORT_MSG_SIZE, 1_048_576);
        assert_eq!(AEAD_TAG_SIZE, 16);
        assert_eq!(MAX_TRANSPORT_FRAME_SIZE, 1_048_592);
    }
}