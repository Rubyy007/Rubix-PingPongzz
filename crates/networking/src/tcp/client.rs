//! TCP client for initiating encrypted connections.
//!
//! # Security
//! - Verifies remote identity via Noise KK + Ed25519 binding.
//! - 10-second handshake timeout prevents half-open connections.
//! - CancellationToken allows graceful shutdown.

use rubix_security::{
    keys::identity_keys::IdentityKeys,
    noise::{
        handshake::{run_initiator_handshake, NoiseHandshake},
        transport::Transport,
        identity_bind::VerifiedIdentity,
    },
};
use rubix_domain::identity::fingerprint::Fingerprint;
use rubix_domain::peer::Peer;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::tcp::connection::EncryptedConnection;

/// TCP client for connecting to peers.
pub struct TcpClient {
    our_identity: Arc<IdentityKeys>,
}

impl TcpClient {
    /// Create a new TCP client with our identity keys.
    pub fn new(our_identity: Arc<IdentityKeys>) -> Self {
        Self { our_identity }
    }

    /// Connect to a peer and perform Noise handshake.
    ///
    /// # Arguments
    /// - `peer`: Target peer with fingerprint and X25519 public key.
    /// - `cancel`: Cancellation token for graceful shutdown.
    ///
    /// # Returns
    /// - `Ok(EncryptedConnection)` on successful handshake.
    /// - `Err(NetworkError::HandshakeTimeout)` if handshake exceeds 10s.
    /// - `Err(NetworkError::HandshakeCancelled)` if cancelled.
    /// - `Err(NetworkError::IdentityMismatch)` if peer identity verification fails.
    ///
    /// # Security
    /// - Noise KK pattern ensures mutual authentication.
    /// - Ed25519 identity binding prevents key substitution.
    /// - Timeout prevents resource exhaustion from slow peers.
    pub async fn connect(
        &self,
        ip: std::net::IpAddr,
        port: u16,
        remote_fingerprint: &Fingerprint,
        remote_x25519: &rubix_security::keys::x25519::X25519PublicKey,
        cancel: CancellationToken,
    ) -> NetworkResult<EncryptedConnection> {
        let addr = format!("{}:{}", ip, port);
        info!("connecting to peer {} at {}", remote_fingerprint, addr);

        // 1. Establish TCP connection
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| NetworkError::ConnectionTimeout(addr.clone()))?
        .map_err(|e| NetworkError::ConnectionFailed(format!("{}: {}", addr, e)))?;

        debug!("TCP connected to {}", addr);

        // 2. Get peer's X25519 public key
        let remote_x25519 = remote_x25519;

        // 3. Create Noise handshake
        let handshake = NoiseHandshake::new_initiator(
            self.our_identity.clone(),
            remote_fingerprint.clone(),
            remote_x25519,
        )
        .map_err(|e| NetworkError::HandshakeFailed(format!("initiator setup: {}", e)))?;

        // 4. Run handshake with timeout and cancellation
        let (transport, verified) = run_initiator_handshake(
            handshake,
            &mut { let s = stream.try_clone().map_err(|e| NetworkError::Internal(format!("stream clone: {}", e)))?; s },
            cancel,
        )
        .await
        .map_err(|e| match e {
            rubix_security::error::SecurityError::HandshakeTimeout(s) => {
                NetworkError::HandshakeTimeout(s)
            }
            rubix_security::error::SecurityError::HandshakeCancelled => {
                NetworkError::HandshakeCancelled
            }
            rubix_security::error::SecurityError::FingerprintMismatch => {
                NetworkError::IdentityMismatch(
                    "peer fingerprint does not match expected".into()
                )
            }
            _ => NetworkError::HandshakeFailed(format!("{}", e)),
        })?;

        info!(
            "handshake complete with peer {} (verified: {})",
            remote_fingerprint,
            verified.fingerprint
        );

        // 5. Wrap in encrypted connection
        let conn = EncryptedConnection::new(
            stream,
            transport,
            remote_fingerprint.clone(),
        );

        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;
    use rubix_domain::identity::fingerprint::Fingerprint;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn client_connect_timeout() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let client = TcpClient::new(identity);

        // Create a peer that doesn't exist
        let fake_fp = Fingerprint::from_bytes(&[0u8; 20]).unwrap();
        let fake_peer = Peer::builder()
            .fingerprint(fake_fp)
            .ip_address("192.0.2.1".parse().unwrap()) // TEST-NET-1, non-routable
            .tcp_port(59999)
            .build()
            .unwrap();

        // Remote X25519 public key (not used because connect will timeout before handshake)
        let fake_x25519 = rubix_security::keys::x25519::X25519PublicKey::from_bytes(&[0u8; 32]).unwrap();

        let cancel = CancellationToken::new();
        let result = client
            .connect(
                fake_peer.ip_address(),
                fake_peer.tcp_port(),
                fake_peer.fingerprint(),
                &fake_x25519,
                cancel,
            )
            .await;
        assert!(matches!(result, Err(NetworkError::ConnectionTimeout(_))));
    }
}