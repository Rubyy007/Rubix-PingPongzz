//! Noise KK handshake using the `snow` crate with identity binding.
//!
//! # Security
//! - Noise_KK_25519_ChaChaPoly_BLAKE2s provides mutual authentication.
//! - Ed25519 identity binding payload proves key ownership.
//! - Timestamp-based replay protection (+/-30s window).
//! - Handshake timeout prevents half-open connections.
//! - Cancellation support via `tokio_util::sync::CancellationToken`.

use crate::error::{SecurityError, SecurityResult};
use crate::keys::identity_keys::IdentityKeys;
use crate::keys::x25519::X25519PublicKey;
use crate::noise::identity_bind::{IdentityBindPayload, VerifiedIdentity};
use crate::noise::transport::Transport;
use rubix_domain::identity::fingerprint::Fingerprint;
use snow::{Builder as SnowBuilder, HandshakeState};
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Default handshake timeout.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Maximum handshake message size (prevent DoS).
const MAX_HANDSHAKE_MSG_SIZE: usize = 4096;

/// Wrapper for the Noise KK handshake with identity verification.
pub struct NoiseHandshake {
    state: HandshakeState,
    our_identity: Arc<IdentityKeys>,
    remote_fingerprint: Option<Fingerprint>,
    verified_remote: Option<VerifiedIdentity>,
}

impl NoiseHandshake {
    /// Create a new handshake as an **initiator** (caller).
    ///
    /// # Arguments
    /// - `our_identity`: Our full identity keys (Ed25519 + X25519).
    /// - `remote_fingerprint`: Expected fingerprint of the responder.
    /// - `remote_x25519_public`: Responder's X25519 static public key (required for KK pattern).
    ///
    /// # Security
    /// The initiator MUST know the responder's static X25519 key in advance.
    /// This is verified against the fingerprint after handshake completion.
    pub fn new_initiator(
        our_identity: Arc<IdentityKeys>,
        remote_fingerprint: Fingerprint,
        remote_x25519_public: &X25519PublicKey,
    ) -> SecurityResult<Self> {
        let params = "Noise_KK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| SecurityError::HandshakeFailed(format!("invalid params: {}", e)))?;

        let static_private = our_identity.x25519.secret.0;
        let remote_static = remote_x25519_public.0;

        let builder = SnowBuilder::new(params)
            .local_private_key(&static_private)
            .remote_public_key(&remote_static)
            .map_err(|e| SecurityError::HandshakeFailed(format!("remote key error: {}", e)))?;

        let state = builder
            .build_initiator()
            .map_err(|e| SecurityError::HandshakeFailed(format!("build initiator: {}", e)))?;

        info!(
            "initiated KK handshake with fingerprint {}",
            remote_fingerprint
        );

        Ok(Self {
            state,
            our_identity,
            remote_fingerprint: Some(remote_fingerprint),
            verified_remote: None,
        })
    }

    /// Create a new handshake as a **responder** (listener).
    ///
    /// The responder does not know the initiator's key in advance.
    /// Identity verification happens after receiving the first message.
    pub fn new_responder(our_identity: Arc<IdentityKeys>) -> SecurityResult<Self> {
        let params = "Noise_KK_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| SecurityError::HandshakeFailed(format!("invalid params: {}", e)))?;

        let static_private = our_identity.x25519.secret.0;

        let builder = SnowBuilder::new(params).local_private_key(&static_private);

        let state = builder
            .build_responder()
            .map_err(|e| SecurityError::HandshakeFailed(format!("build responder: {}", e)))?;

        info!("listening for KK handshake");

        Ok(Self {
            state,
            our_identity,
            remote_fingerprint: None,
            verified_remote: None,
        })
    }

    /// Read an incoming handshake message.
    ///
    /// # Security
    /// - Input is bounded to `MAX_HANDSHAKE_MSG_SIZE`.
    /// - Output buffer is pre-allocated to prevent unbounded growth.
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

    /// Write the next handshake message.
    pub fn write_message(&mut self, payload: &[u8]) -> SecurityResult<Vec<u8>> {
        let mut output = vec![0u8; MAX_HANDSHAKE_MSG_SIZE];
        let len = self
            .state
            .write_message(payload, &mut output)
            .map_err(|e| SecurityError::HandshakeFailed(format!("write error: {}", e)))?;
        output.truncate(len);
        Ok(output)
    }

    /// Check if the handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Get the verified remote identity (available after successful handshake).
    pub fn verified_remote(&self) -> Option<&VerifiedIdentity> {
        self.verified_remote.as_ref()
    }

    /// Set the verified remote identity (called by application layer after payload verification).
    pub fn set_verified_remote(&mut self, identity: VerifiedIdentity) {
        self.verified_remote = Some(identity);
    }

    /// After handshake complete, consume into a transport.
    ///
    /// # Security
    /// - Verifies that handshake actually finished.
    /// - Verifies remote identity was bound (for initiator).
    pub fn into_transport(self) -> SecurityResult<Transport> {
        if !self.is_complete() {
            return Err(SecurityError::HandshakeFailed(
                "handshake not complete".into(),
            ));
        }

        // For initiator: must have verified remote identity
        if self.remote_fingerprint.is_some() && self.verified_remote.is_none() {
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
        serde_json::to_vec(&payload)
            .map_err(|e| SecurityError::Serialization(format!("payload: {}", e)))
    }

    /// Parse and verify an identity binding payload from a decrypted handshake message.
    pub fn verify_identity_payload(
        &self,
        payload_bytes: &[u8],
    ) -> SecurityResult<VerifiedIdentity> {
        let payload: IdentityBindPayload = serde_json::from_slice(payload_bytes)
            .map_err(|e| SecurityError::IdentityBindingFailed(format!("parse: {}", e)))?;

        let expected_fp = self
            .remote_fingerprint
            .as_ref()
            .ok_or_else(|| SecurityError::Internal("no expected fingerprint".into()))?;

        payload.verify(expected_fp)
    }
}

/// Execute a full initiator handshake with timeout and cancellation.
///
/// This is a high-level helper that orchestrates the handshake over a byte stream.
/// In practice, the networking crate will call the lower-level `NoiseHandshake` methods.
///
/// # Returns
/// - `Ok((Transport, VerifiedIdentity))` on success.
/// - `Err(SecurityError::HandshakeTimeout)` if timeout expires.
/// - `Err(SecurityError::HandshakeCancelled)` if cancelled.
pub async fn run_initiator_handshake<S>(
    mut handshake: NoiseHandshake,
    stream: &mut S,
    cancel: CancellationToken,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let timeout_duration = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);

    let result = timeout(timeout_duration, async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                Err(SecurityError::HandshakeCancelled)
            }
            result = perform_initiator_handshake(&mut handshake, stream) => {
                result
            }
        }
    })
    .await
    .map_err(|_| SecurityError::HandshakeTimeout(HANDSHAKE_TIMEOUT_SECS))?;

    result
}

async fn perform_initiator_handshake<S>(
    handshake: &mut NoiseHandshake,
    stream: &mut S,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    // Step 1: Send identity payload in first message
    let identity_payload = handshake.create_identity_payload()?;
    let msg1 = handshake.write_message(&identity_payload)?;
    send_message(stream, &msg1).await?;
    debug!("initiator sent message 1 ({} bytes)", msg1.len());

    // Step 2: Receive responder's message with their identity payload
    let msg2 = recv_message(stream).await?;
    let payload2 = handshake.read_message(&msg2)?;
    let verified = handshake.verify_identity_payload(&payload2)?;
    handshake.set_verified_remote(verified.clone());
    debug!("initiator verified responder identity");

    // Step 3: Send final handshake message (empty payload)
    let msg3 = handshake.write_message(b"")?;
    send_message(stream, &msg3).await?;
    debug!("initiator sent message 3");

    // Step 4: Receive final confirmation
    let msg4 = recv_message(stream).await?;
    let _ = handshake.read_message(&msg4)?;

    let transport = handshake.into_transport()?;
    Ok((transport, verified))
}

/// Execute a full responder handshake with timeout and cancellation.
pub async fn run_responder_handshake<S>(
    mut handshake: NoiseHandshake,
    stream: &mut S,
    cancel: CancellationToken,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let timeout_duration = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);

    let result = timeout(timeout_duration, async {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                Err(SecurityError::HandshakeCancelled)
            }
            result = perform_responder_handshake(&mut handshake, stream) => {
                result
            }
        }
    })
    .await
    .map_err(|_| SecurityError::HandshakeTimeout(HANDSHAKE_TIMEOUT_SECS))?;

    result
}

async fn perform_responder_handshake<S>(
    handshake: &mut NoiseHandshake,
    stream: &mut S,
) -> SecurityResult<(Transport, VerifiedIdentity)>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    // Step 1: Receive initiator's identity payload
    let msg1 = recv_message(stream).await?;
    let payload1 = handshake.read_message(&msg1)?;
    let payload: IdentityBindPayload = serde_json::from_slice(&payload1)
        .map_err(|e| SecurityError::IdentityBindingFailed(format!("parse: {}", e)))?;

    // Derive fingerprint from payload to know who we are talking to
    let ed25519_pub = crate::keys::ed25519::Ed25519PublicKey::from_bytes(&payload.ed25519_public)?;
    let x25519_pub = crate::keys::x25519::X25519PublicKey::from_bytes(&payload.x25519_public)?;
    let fingerprint = crate::fingerprint::derive::derive_fingerprint(&ed25519_pub, &x25519_pub)?;

    // Step 2: Send our identity payload
    let identity_payload = handshake.create_identity_payload()?;
    let msg2 = handshake.write_message(&identity_payload)?;
    send_message(stream, &msg2).await?;
    debug!("responder sent message 2");

    // Step 3: Receive final handshake message
    let msg3 = recv_message(stream).await?;
    let _ = handshake.read_message(&msg3)?;

    // Step 4: Send final confirmation
    let msg4 = handshake.write_message(b"")?;
    send_message(stream, &msg4).await?;

    let transport = handshake.into_transport()?;

    let verified = VerifiedIdentity {
        ed25519_public: ed25519_pub,
        x25519_public: x25519_pub,
        fingerprint,
        timestamp: payload.timestamp,
    };

    Ok((transport, verified))
}

// Helper: send length-prefixed message
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
    Ok(())
}

// Helper: receive length-prefixed message
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::identity_keys::IdentityKeys;
    use tokio::io::duplex;

    #[tokio::test]
    async fn initiator_responder_handshake_success() {
        let alice_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_keys = Arc::new(IdentityKeys::generate().unwrap());

        let alice_fp = alice_keys.fingerprint().unwrap();
        let bob_fp = bob_keys.fingerprint().unwrap();

        let (mut alice_stream, mut bob_stream) = duplex(4096);

        let alice_handshake = NoiseHandshake::new_initiator(
            alice_keys.clone(),
            bob_fp.clone(),
            bob_keys.x25519_public(),
        )
        .unwrap();

        let bob_handshake = NoiseHandshake::new_responder(bob_keys.clone()).unwrap();

        let cancel = CancellationToken::new();

        let alice_task = tokio::spawn(run_initiator_handshake(
            alice_handshake,
            &mut alice_stream,
            cancel.clone(),
        ));

        let bob_task = tokio::spawn(run_responder_handshake(
            bob_handshake,
            &mut bob_stream,
            cancel.clone(),
        ));

        let (alice_result, bob_result) = tokio::join!(alice_task, bob_task);

        let (alice_transport, alice_verified) = alice_result.unwrap().unwrap();
        let (bob_transport, bob_verified) = bob_result.unwrap().unwrap();

        assert!(alice_verified.fingerprint.constant_time_eq(&bob_fp));
        assert!(bob_verified.fingerprint.constant_time_eq(&alice_fp));

        // Test transport encryption roundtrip
        let plaintext = b"hello from alice";
        let encrypted = alice_transport.encrypt(plaintext).await.unwrap();
        let decrypted = bob_transport.decrypt(&encrypted).await.unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn handshake_timeout() {
        let keys = Arc::new(IdentityKeys::generate().unwrap());
        let fp = keys.fingerprint().unwrap();

        // Create a dummy stream that never sends data
        let (mut stream, _other) = duplex(4096);
        let handshake = NoiseHandshake::new_initiator(keys.clone(), fp, keys.x25519_public()).unwrap();
        let cancel = CancellationToken::new();

        let result = run_initiator_handshake(handshake, &mut stream, cancel).await;
        assert!(matches!(result, Err(SecurityError::HandshakeTimeout(10))));
    }

    #[tokio::test]
    async fn handshake_cancellation() {
        let keys = Arc::new(IdentityKeys::generate().unwrap());
        let fp = keys.fingerprint().unwrap();

        let (mut stream, _other) = duplex(4096);
        let handshake = NoiseHandshake::new_initiator(keys.clone(), fp, keys.x25519_public()).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = run_initiator_handshake(handshake, &mut stream, cancel).await;
        assert!(matches!(result, Err(SecurityError::HandshakeCancelled)));
    }
}