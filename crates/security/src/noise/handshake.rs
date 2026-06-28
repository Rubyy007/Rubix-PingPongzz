//! Noise KK handshake with shared nonce replay cache.
//!
//! # Security
//! - Noise_KK_25519_ChaChaPoly_BLAKE2s provides mutual authentication.
//! - Ed25519 identity binding payload proves key ownership.
//! - Timestamp-based replay protection (+/-30s window).
//! - Nonce replay cache prevents duplicate payloads within the TTL window.
//! - Handshake timeout prevents half-open connections.
//! - Cancellation support via `tokio_util::sync::CancellationToken`.

use crate::error::{SecurityError, SecurityResult};
use crate::keys::identity_keys::IdentityKeys;
use crate::keys::x25519::X25519PublicKey;
use crate::noise::identity_bind::{IdentityBindPayload, VerifiedIdentity};
use crate::noise::transport::Transport;
use rubix_domain::identity::fingerprint::Fingerprint;
use snow::{Builder as SnowBuilder, HandshakeState};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Default handshake timeout in seconds.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const MAX_HANDSHAKE_MSG_SIZE: usize = 4096;
const NONCE_CACHE_TTL_SECS: u64 = 60;

/// Shared nonce cache to prevent replay attacks across all handshake instances.
///
/// # Thread Safety
/// Wrap in `Arc<Mutex<NonceCache>>` and share between all initiator/responder
/// handshakes. A per-handshake cache is ineffective because replay attacks
/// arrive on new TCP connections.
pub struct NonceCache {
    inner: HashSet<(Fingerprint, [u8; 12])>,
    order: VecDeque<(Fingerprint, [u8; 12], Instant)>,
    max_entries: usize,
}

impl NonceCache {
    /// Create a new cache with a maximum number of tracked entries.
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: HashSet::new(),
            order: VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }

    /// Check if `(fingerprint, nonce)` has been seen before, and insert it.
    ///
    /// Returns `false` if the nonce was already present (replay detected).
    pub fn check_and_insert(&mut self, fingerprint: &Fingerprint, nonce: &[u8; 12]) -> bool {
        let now = Instant::now();

        // Evict expired entries
        while let Some((_, _, time)) = self.order.front() {
            if time.elapsed() > Duration::from_secs(NONCE_CACHE_TTL_SECS) {
                let (fp, nonce, _) = self.order.pop_front().unwrap();
                self.inner.remove(&(fp, nonce));
            } else {
                break;
            }
        }

        let key = (fingerprint.clone(), *nonce);
        if self.inner.contains(&key) {
            return false;
        }

        // Evict oldest if at capacity
        if self.inner.len() >= self.max_entries {
            if let Some((fp, nonce, _)) = self.order.pop_front() {
                self.inner.remove(&(fp, nonce));
            }
        }

        self.inner.insert(key.clone());
        self.order.push_back((fingerprint.clone(), *nonce, now));
        true
    }
}

/// Wrapper for the Noise KK handshake with identity verification.
///
/// # Requirements
/// `Fingerprint` must implement `Clone`, `Hash`, and `Eq`.
pub struct NoiseHandshake {
    state: HandshakeState,
    our_identity: Arc<IdentityKeys>,
    remote_fingerprint: Option<Fingerprint>,
    verified_remote: Option<VerifiedIdentity>,
    nonce_cache: Arc<Mutex<NonceCache>>,
}

impl NoiseHandshake {
    /// Create a new handshake as an **initiator** with a fresh nonce cache.
    pub fn new_initiator(
        our_identity: Arc<IdentityKeys>,
        remote_fingerprint: Fingerprint,
        remote_x25519_public: &X25519PublicKey,
    ) -> SecurityResult<Self> {
        Self::new_initiator_with_cache(
            our_identity,
            remote_fingerprint,
            remote_x25519_public,
            Arc::new(Mutex::new(NonceCache::new(10000))),
        )
    }

    /// Create a new handshake as an **initiator** with a shared nonce cache.
    pub fn new_initiator_with_cache(
        our_identity: Arc<IdentityKeys>,
        remote_fingerprint: Fingerprint,
        remote_x25519_public: &X25519PublicKey,
        nonce_cache: Arc<Mutex<NonceCache>>,
    ) -> SecurityResult<Self> {
        let params = "Noise_KK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| SecurityError::HandshakeFailed(format!("invalid params: {}", e)))?;

        let static_private = our_identity.x25519.secret_bytes();
        let remote_static = remote_x25519_public.0;

        let builder = SnowBuilder::new(params)
            .local_private_key(&static_private)
            .remote_public_key(&remote_static);

        let state = builder
            .build_initiator()
            .map_err(|e| SecurityError::HandshakeFailed(format!("build initiator: {}", e)))?;

        info!("initiated KK handshake with fingerprint {}", remote_fingerprint);

        Ok(Self {
            state,
            our_identity,
            remote_fingerprint: Some(remote_fingerprint),
            verified_remote: None,
            nonce_cache,
        })
    }

    /// Create a new handshake as a **responder** with a fresh nonce cache.
    pub fn new_responder(
        our_identity: Arc<IdentityKeys>,
        remote_fingerprint: Fingerprint,
        remote_x25519_public: &X25519PublicKey,
    ) -> SecurityResult<Self> {
        Self::new_responder_with_cache(
            our_identity,
            remote_fingerprint,
            remote_x25519_public,
            Arc::new(Mutex::new(NonceCache::new(10000))),
        )
    }

    /// Create a new handshake as a **responder** with a shared nonce cache.
    pub fn new_responder_with_cache(
        our_identity: Arc<IdentityKeys>,
        remote_fingerprint: Fingerprint,
        remote_x25519_public: &X25519PublicKey,
        nonce_cache: Arc<Mutex<NonceCache>>,
    ) -> SecurityResult<Self> {
        let params = "Noise_KK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| SecurityError::HandshakeFailed(format!("invalid params: {}", e)))?;

        let static_private = our_identity.x25519.secret_bytes();
        let remote_static = remote_x25519_public.0;

        let builder = SnowBuilder::new(params)
            .local_private_key(&static_private)
            .remote_public_key(&remote_static);

        let state = builder
            .build_responder()
            .map_err(|e| SecurityError::HandshakeFailed(format!("build responder: {}", e)))?;

        info!("listening for KK handshake from fingerprint {}", remote_fingerprint);

        Ok(Self {
            state,
            our_identity,
            remote_fingerprint: Some(remote_fingerprint),
            verified_remote: None,
            nonce_cache,
        })
    }

    /// Read and decrypt an incoming Noise handshake message.
    ///
    /// # Errors
    /// Returns `SecurityError::HandshakeFailed` if the message is too large
    /// or the Noise state machine rejects it.
    pub fn read_message(&mut self, input: &[u8]) -> SecurityResult<Vec<u8>> {
        if input.len() > MAX_HANDSHAKE_MSG_SIZE {
            return Err(SecurityError::HandshakeFailed(format!(
                "message too large: {} bytes",
                input.len()
            )));
        }
        let mut output = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self
            .state
            .read_message(input, &mut output)
            .map_err(|e| SecurityError::HandshakeFailed(format!("read error: {}", e)))?;
        output.truncate(len);
        Ok(output)
    }

    /// Encrypt and write the next Noise handshake message.
    ///
    /// # Errors
    /// Returns `SecurityError::HandshakeFailed` if the Noise state machine
    /// rejects the payload.
    pub fn write_message(&mut self, payload: &[u8]) -> SecurityResult<Vec<u8>> {
        let mut output = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self
            .state
            .write_message(payload, &mut output)
            .map_err(|e| SecurityError::HandshakeFailed(format!("write error: {}", e)))?;
        output.truncate(len);
        Ok(output)
    }

    /// Check if the Noise handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Get the verified remote identity (available after successful handshake).
    pub fn verified_remote(&self) -> Option<&VerifiedIdentity> {
        self.verified_remote.as_ref()
    }

    /// Set the verified remote identity (called after payload verification).
    pub fn set_verified_remote(&mut self, identity: VerifiedIdentity) {
        self.verified_remote = Some(identity);
    }

    /// Consume the handshake into a secure transport.
    ///
    /// # Errors
    /// Returns `SecurityError::HandshakeFailed` if the handshake is incomplete.
    /// Returns `SecurityError::IdentityBindingFailed` if the remote identity
    /// was not verified.
    pub fn into_transport(self) -> SecurityResult<Transport> {
        if !self.is_complete() {
            return Err(SecurityError::HandshakeFailed(
                "handshake not complete".into(),
            ));
        }
        if self.verified_remote.is_none() {
            return Err(SecurityError::IdentityBindingFailed(
                "remote identity not verified".into(),
            ));
        }
        let transport_state = self
            .state
            .into_transport_mode()
            .map_err(|e| SecurityError::HandshakeFailed(format!("into transport: {}", e)))?;
        info!("handshake complete, transport established");
        Ok(Transport::new(transport_state))
    }

    /// Create the identity binding payload for the first handshake message.
    pub fn create_identity_payload(&self) -> SecurityResult<Vec<u8>> {
        let payload = IdentityBindPayload::create(
            &self.our_identity.ed25519,
            &self.our_identity.x25519.public,
        )?;
        Ok(payload.to_bytes().to_vec())
    }

    /// Parse and verify an identity binding payload from a decrypted handshake message.
    ///
    /// # Errors
    /// Returns `SecurityError::IdentityBindingFailed` if parsing or signature
    /// verification fails. Returns `SecurityError::ReplayDetected` if the nonce
    /// has been seen before.
    pub fn verify_identity_payload(
        &mut self,
        payload_bytes: &[u8],
    ) -> SecurityResult<VerifiedIdentity> {
        let payload = IdentityBindPayload::from_bytes(payload_bytes)
            .map_err(|e| SecurityError::IdentityBindingFailed(format!("parse: {}", e)))?;

        let expected_fp = self
            .remote_fingerprint
            .as_ref()
            .ok_or_else(|| SecurityError::Internal("no expected fingerprint".into()))?;

        let verified = payload.verify(expected_fp)?;

        let mut cache = self
            .nonce_cache
            .lock()
            .map_err(|_| SecurityError::Internal("nonce cache poisoned".into()))?;

        if !cache.check_and_insert(&verified.fingerprint, &verified.nonce) {
            return Err(SecurityError::ReplayDetected("duplicate nonce".into()));
        }

        Ok(verified)
    }
}

/// Send a length-prefixed message over the stream.
async fn send_message<S>(stream: &mut S, data: &[u8]) -> SecurityResult<()>
where
    S: tokio::io::AsyncWriteExt + Unpin,
{
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| SecurityError::HandshakeFailed(format!("send: {}", e)))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| SecurityError::HandshakeFailed(format!("send: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| SecurityError::HandshakeFailed(format!("flush: {}", e)))?;
    Ok(())
}

/// Receive a length-prefixed message from the stream.
///
/// # Security
/// Length is bounded to `MAX_HANDSHAKE_MSG_SIZE` before allocating the
/// receive buffer — prevents a malicious peer from forcing an unbounded
/// allocation via a forged length prefix (DoS).
async fn recv_message<S>(stream: &mut S) -> SecurityResult<Vec<u8>>
where
    S: tokio::io::AsyncReadExt + Unpin,
{
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| SecurityError::HandshakeFailed(format!("recv len: {}", e)))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_HANDSHAKE_MSG_SIZE {
        return Err(SecurityError::HandshakeFailed(format!(
            "message size {} exceeds max {}",
            len, MAX_HANDSHAKE_MSG_SIZE
        )));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| SecurityError::HandshakeFailed(format!("recv data: {}", e)))?;
    Ok(buf)
}

/// Execute a full initiator handshake with timeout and cancellation.
///
/// # Returns
/// - `Ok((Transport, VerifiedIdentity))` on success.
/// - `Err(SecurityError::HandshakeTimeout)` if timeout expires.
/// - `Err(SecurityError::HandshakeCancelled)` if cancelled.
pub async fn run_initiator_handshake<S>(
    handshake: NoiseHandshake,
    stream: &mut S,
    cancel: CancellationToken,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let timeout_duration = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let result = timeout(timeout_duration, async move {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                Err(SecurityError::HandshakeCancelled)
            }
            result = perform_initiator_handshake(handshake, stream) => {
                result
            }
        }
    })
    .await
    .map_err(|_| SecurityError::HandshakeTimeout(HANDSHAKE_TIMEOUT_SECS))?;
    result
}

async fn perform_initiator_handshake<S>(
    mut handshake: NoiseHandshake,
    stream: &mut S,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let identity_payload = handshake.create_identity_payload()?;
    let msg1 = handshake.write_message(&identity_payload)?;
    send_message(stream, &msg1).await?;
    debug!("initiator sent message 1");

    let msg2 = recv_message(stream).await?;
    let payload2 = handshake.read_message(&msg2)?;
    let verified = handshake.verify_identity_payload(&payload2)?;
    handshake.set_verified_remote(verified.clone());

    let transport = handshake.into_transport()?;
    Ok((transport, verified))
}

/// Execute a full responder handshake with timeout and cancellation.
///
/// # Returns
/// - `Ok((Transport, VerifiedIdentity))` on success.
/// - `Err(SecurityError::HandshakeTimeout)` if timeout expires.
/// - `Err(SecurityError::HandshakeCancelled)` if cancelled.
pub async fn run_responder_handshake<S>(
    handshake: NoiseHandshake,
    stream: &mut S,
    cancel: CancellationToken,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let timeout_duration = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let result = timeout(timeout_duration, async move {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                Err(SecurityError::HandshakeCancelled)
            }
            result = perform_responder_handshake(handshake, stream) => {
                result
            }
        }
    })
    .await
    .map_err(|_| SecurityError::HandshakeTimeout(HANDSHAKE_TIMEOUT_SECS))?;
    result
}

async fn perform_responder_handshake<S>(
    mut handshake: NoiseHandshake,
    stream: &mut S,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let msg1 = recv_message(stream).await?;
    let payload1 = handshake.read_message(&msg1)?;
    let initiator_verified = handshake.verify_identity_payload(&payload1)?;
    handshake.set_verified_remote(initiator_verified.clone());

    let identity_payload = handshake.create_identity_payload()?;
    let msg2 = handshake.write_message(&identity_payload)?;
    send_message(stream, &msg2).await?;
    debug!("responder sent message 2");

    let transport = handshake.into_transport()?;
    Ok((transport, initiator_verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::identity_keys::IdentityKeys;
    use tokio::io::duplex;
    use tokio::io::AsyncWriteExt;

    fn shared_cache() -> Arc<Mutex<NonceCache>> {
        Arc::new(Mutex::new(NonceCache::new(10000)))
    }

    #[tokio::test]
    async fn handshake_success() {
        let alice_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_keys = Arc::new(IdentityKeys::generate().unwrap());
        let alice_fp = alice_keys.fingerprint().unwrap();
        let bob_fp = bob_keys.fingerprint().unwrap();

        let (mut alice_stream, mut bob_stream) = duplex(4096);

        let cache = shared_cache();
        let alice_handshake = NoiseHandshake::new_initiator_with_cache(
            alice_keys.clone(),
            bob_fp.clone(),
            bob_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        let bob_handshake = NoiseHandshake::new_responder_with_cache(
            bob_keys.clone(),
            alice_fp.clone(),
            alice_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        let cancel = CancellationToken::new();

        let alice_future = run_initiator_handshake(alice_handshake, &mut alice_stream, cancel.clone());
        let bob_future = run_responder_handshake(bob_handshake, &mut bob_stream, cancel.clone());

        let ((alice_transport, alice_verified), (bob_transport, bob_verified)) =
            tokio::try_join!(alice_future, bob_future).unwrap();

        assert!(alice_verified.fingerprint.constant_time_eq(&bob_fp));
        assert!(bob_verified.fingerprint.constant_time_eq(&alice_fp));

        // Encryption round-trip (synchronous — no async overhead)
        let plaintext = b"hello";
        let encrypted = alice_transport.encrypt(plaintext).unwrap();
        let decrypted = bob_transport.decrypt(&encrypted).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn handshake_wrong_fingerprint_fails() {
        let alice_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_keys = Arc::new(IdentityKeys::generate().unwrap());
        let fake_keys = Arc::new(IdentityKeys::generate().unwrap());
        let fake_fp = fake_keys.fingerprint().unwrap();

        let (mut alice_stream, mut bob_stream) = duplex(4096);

        let cache = shared_cache();
        let alice_handshake = NoiseHandshake::new_initiator_with_cache(
            alice_keys.clone(),
            bob_keys.fingerprint().unwrap(),
            bob_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        let bob_handshake = NoiseHandshake::new_responder_with_cache(
            bob_keys.clone(),
            fake_fp,
            alice_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        let cancel = CancellationToken::new();

        let alice_future = run_initiator_handshake(alice_handshake, &mut alice_stream, cancel.clone());
        let bob_future = run_responder_handshake(bob_handshake, &mut bob_stream, cancel.clone());

        let results = tokio::try_join!(alice_future, bob_future);
        assert!(results.is_err());
        let err = results.unwrap_err();
        assert!(matches!(err, SecurityError::FingerprintMismatch));
    }

    #[tokio::test]
    async fn handshake_timeout() {
        let keys = Arc::new(IdentityKeys::generate().unwrap());
        let fp = keys.fingerprint().unwrap();

        let (mut stream, _other) = duplex(4096);
        let cache = shared_cache();
        let handshake = NoiseHandshake::new_initiator_with_cache(
            keys.clone(),
            fp,
            keys.x25519_public(),
            cache,
        )
        .unwrap();
        let cancel = CancellationToken::new();

        let result = run_initiator_handshake(handshake, &mut stream, cancel).await;
        assert!(matches!(result, Err(SecurityError::HandshakeTimeout(10))));
    }

    #[tokio::test]
    async fn handshake_cancellation() {
        let keys = Arc::new(IdentityKeys::generate().unwrap());
        let fp = keys.fingerprint().unwrap();

        let (mut stream, _other) = duplex(4096);
        let cache = shared_cache();
        let handshake = NoiseHandshake::new_initiator_with_cache(
            keys.clone(),
            fp,
            keys.x25519_public(),
            cache,
        )
        .unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = run_initiator_handshake(handshake, &mut stream, cancel).await;
        assert!(matches!(result, Err(SecurityError::HandshakeCancelled)));
    }

    #[tokio::test]
    async fn noise_message_bit_flip_fails() {
        let alice_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_keys = Arc::new(IdentityKeys::generate().unwrap());

        let (mut alice_stream, mut bob_stream) = duplex(4096);

        let cache = shared_cache();
        let mut alice = NoiseHandshake::new_initiator_with_cache(
            alice_keys.clone(),
            bob_keys.fingerprint().unwrap(),
            bob_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        let mut bob = NoiseHandshake::new_responder_with_cache(
            bob_keys.clone(),
            alice_keys.fingerprint().unwrap(),
            alice_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        // Alice sends msg1
        let payload = alice.create_identity_payload().unwrap();
        let msg1 = alice.write_message(&payload).unwrap();
        send_message(&mut alice_stream, &msg1).await.unwrap();

        // Bob receives it
        let received = recv_message(&mut bob_stream).await.unwrap();

        // Corrupt and try to read
        let mut corrupted = received;
        if !corrupted.is_empty() {
            corrupted[0] ^= 0xFF;
        }
        let result = bob.read_message(&corrupted);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn oversized_length_prefix_fails() {
        // Use a Cursor to provide the bad length prefix without blocking.
        let data = u32::MAX.to_be_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(data);
        let result = recv_message(&mut cursor).await;
        assert!(matches!(result, Err(SecurityError::HandshakeFailed(_))));
    }

    #[tokio::test]
    async fn handshake_wrong_x25519_key_fails() {
        let alice_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_keys = Arc::new(IdentityKeys::generate().unwrap());
        let charlie_keys = Arc::new(IdentityKeys::generate().unwrap());

        let (mut alice_stream, mut bob_stream) = duplex(4096);

        let cache = shared_cache();
        let alice_handshake = NoiseHandshake::new_initiator_with_cache(
            alice_keys.clone(),
            bob_keys.fingerprint().unwrap(),
            charlie_keys.x25519_public(), // wrong key
            cache.clone(),
        )
        .unwrap();

        let bob_handshake = NoiseHandshake::new_responder_with_cache(
            bob_keys.clone(),
            alice_keys.fingerprint().unwrap(),
            alice_keys.x25519_public(),
            cache.clone(),
        )
        .unwrap();

        let cancel = CancellationToken::new();

        let alice_future = run_initiator_handshake(alice_handshake, &mut alice_stream, cancel.clone());
        let bob_future = run_responder_handshake(bob_handshake, &mut bob_stream, cancel.clone());

        let results = tokio::try_join!(alice_future, bob_future);
        assert!(results.is_err());
    }

    #[tokio::test]
    async fn handshake_mid_stream_drop_fails() {
        let keys = Arc::new(IdentityKeys::generate().unwrap());
        let fp = keys.fingerprint().unwrap();

        let (mut alice_stream, bob_stream) = duplex(4096);
        let cache = shared_cache();
        let handshake = NoiseHandshake::new_initiator_with_cache(
            keys.clone(),
            fp,
            keys.x25519_public(),
            cache,
        )
        .unwrap();
        let cancel = CancellationToken::new();

        let alice_task = tokio::spawn(async move {
            run_initiator_handshake(handshake, &mut alice_stream, cancel).await
        });

        // Let Alice send msg1, then drop the peer's end
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(bob_stream);

        let result = alice_task.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn nonce_cache_rejects_duplicate() {
        let cache = Arc::new(Mutex::new(NonceCache::new(100)));
        let fp = IdentityKeys::generate().unwrap().fingerprint().unwrap();
        let nonce = [42u8; 12];

        {
            let mut c = cache.lock().unwrap();
            assert!(c.check_and_insert(&fp, &nonce));
            assert!(!c.check_and_insert(&fp, &nonce));
        }
    }
}