//! Encrypted TCP connection wrapper.
//!
//! Combines a TCP stream with a Noise transport for transparent encryption.
//!
//! # Security
//! - All reads/writes are encrypted/decrypted via Noise transport.
//! - Connection tracks peer fingerprint for identity verification.
//! - Graceful close ensures transport state is cleaned up.

use rubix_security::noise::transport::{Transport, TransportState};
use rubix_domain::identity::fingerprint::Fingerprint;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, trace, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::protocol::codec::EncryptedFrameCodec;

/// An active encrypted connection to a peer.
pub struct EncryptedConnection {
    stream: TcpStream,
    transport: Transport,
    peer_fingerprint: Fingerprint,
    codec: EncryptedFrameCodec,
}

impl EncryptedConnection {
    /// Create a new encrypted connection.
    ///
    /// # Arguments
    /// - `stream`: Established TCP stream.
    /// - `transport`: Noise transport after successful handshake.
    /// - `peer_fingerprint`: Verified fingerprint of the peer.
    pub fn new(
        stream: TcpStream,
        transport: Transport,
        peer_fingerprint: Fingerprint,
    ) -> Self {
        Self {
            stream,
            transport,
            peer_fingerprint,
            codec: EncryptedFrameCodec::new(),
        }
    }

    /// Send an encrypted message frame.
    ///
    /// # Arguments
    /// - `data`: Raw message bytes to encrypt and send.
    ///
    /// # Errors
    /// - `NetworkError::TransportClosed` if connection is closed.
    /// - `NetworkError::EncryptionFailed` on crypto failure.
    /// - `NetworkError::SendFailed` on TCP write failure.
    pub async fn send(&mut self, data: &[u8]) -> NetworkResult<()> {
        trace!(
            "sending {} bytes to {}",
            data.len(),
            self.peer_fingerprint
        );

        // 1. Encrypt via Noise transport
        let encrypted = self.transport.encrypt(data).await.map_err(|e| {
            match e {
                rubix_security::error::SecurityError::TransportClosed => {
                    NetworkError::TransportClosed(self.peer_fingerprint.to_string())
                }
                rubix_security::error::SecurityError::MessageTooLarge { size, max } => {
                    NetworkError::MessageTooLarge { size, max }
                }
                _ => NetworkError::EncryptionFailed(format!("{}", e)),
            }
        })?;

        // 2. Encode with length prefix
        let frame = self.codec.encode(&encrypted);

        // 3. Send over TCP
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| NetworkError::SendFailed(format!("{}", e)))?;

        debug!("sent {} bytes encrypted to {}", data.len(), self.peer_fingerprint);
        Ok(())
    }

    /// Receive and decrypt a message frame.
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` with decrypted plaintext.
    ///
    /// # Errors
    /// - `NetworkError::TransportClosed` if connection is closed.
    /// - `NetworkError::DecryptionFailed` on corrupted or tampered data.
    /// - `NetworkError::RecvFailed` on TCP read failure.
    pub async fn recv(&mut self) -> NetworkResult<Vec<u8>> {
        // 1. Read length-prefixed frame
        let encrypted = self.codec.decode(&mut self.stream).await?;

        // 2. Decrypt via Noise transport
        let plaintext = self.transport.decrypt(&encrypted).await.map_err(|e| {
            match e {
                rubix_security::error::SecurityError::TransportClosed => {
                    NetworkError::TransportClosed(self.peer_fingerprint.to_string())
                }
                _ => NetworkError::DecryptionFailed(format!("{}", e)),
            }
        })?;

        trace!(
            "received {} bytes decrypted from {}",
            plaintext.len(),
            self.peer_fingerprint
        );
        Ok(plaintext)
    }

    /// Get the peer's verified fingerprint.
    pub fn peer_fingerprint(&self) -> &Fingerprint {
        &self.peer_fingerprint
    }

    /// Check if the transport is still active.
    pub async fn is_active(&self) -> bool {
        self.transport.state().await == TransportState::Active
    }

    /// Gracefully close the connection.
    pub async fn close(&mut self) {
        debug!("closing connection to {}", self.peer_fingerprint);
        self.transport.close().await;
        let _ = self.stream.shutdown().await;
    }

    /// Get a reference to the underlying TCP stream (for advanced use).
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;
    use rubix_security::noise::handshake::NoiseHandshake;
    use std::sync::Arc;
    use tokio::io::duplex;

    // Helper: create a pair of connected transports for testing
    async fn create_test_connection_pair() -> (EncryptedConnection, EncryptedConnection) {
        let alice_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_keys = Arc::new(IdentityKeys::generate().unwrap());
        let bob_fp = bob_keys.fingerprint().unwrap();
        let alice_fp = alice_keys.fingerprint().unwrap();

        // Use duplex streams to simulate TCP
        let (alice_stream, bob_stream) = tokio::io::duplex(4096);

        // Handshake
        let mut alice_hs = NoiseHandshake::new_initiator(
            alice_keys.clone(),
            bob_fp.clone(),
            bob_keys.x25519_public(),
        ).unwrap();

        let mut bob_hs = NoiseHandshake::new_responder(bob_keys.clone()).unwrap();

        let payload1 = alice_hs.create_identity_payload().unwrap();
        let msg1 = alice_hs.write_message(&payload1).unwrap();
        let _ = bob_hs.read_message(&msg1).unwrap();

        let payload2 = bob_hs.create_identity_payload().unwrap();
        let msg2 = bob_hs.write_message(&payload2).unwrap();
        let _ = alice_hs.read_message(&msg2).unwrap();

        let msg3 = alice_hs.write_message(b"").unwrap();
        let _ = bob_hs.read_message(&msg3).unwrap();

        let msg4 = bob_hs.write_message(b"").unwrap();
        let _ = alice_hs.read_message(&msg4).unwrap();

        let alice_transport = alice_hs.into_transport().unwrap();
        let bob_transport = bob_hs.into_transport().unwrap();

        // Convert duplex to TcpStream-like (we use a wrapper for testing)
        // In real code, these would be actual TcpStreams
        let alice_conn = EncryptedConnection::new(
            // We need to adapt duplex to TcpStream - this is a test limitation
            // In production, these are real TCP connections
            todo!("use actual TcpStream in integration tests"),
            alice_transport,
            bob_fp,
        );

        let bob_conn = EncryptedConnection::new(
            todo!("use actual TcpStream in integration tests"),
            bob_transport,
            alice_fp,
        );

        (alice_conn, bob_conn)
    }
}