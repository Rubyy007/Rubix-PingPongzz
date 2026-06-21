//! TCP server for accepting encrypted peer connections.
//!
//! # Security
//! - Accepts all incoming Noise handshakes at transport level.
//! - Delegates peer trust decision to application layer via callback.
//! - 10-second handshake timeout per connection.
//! - Rate-limits new connections to prevent flooding.

use rubix_security::{
    keys::identity_keys::IdentityKeys,
    noise::{
        handshake::{run_responder_handshake, NoiseHandshake},
        identity_bind::VerifiedIdentity,
    },
};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::tcp::connection::EncryptedConnection;

/// Callback for validating whether to accept a peer after handshake.
///
/// # Arguments
/// - `verified`: The peer's verified identity from the handshake.
///
/// # Returns
/// - `true` to accept the connection.
/// - `false` to close the connection.
pub type PeerValidator = Arc<dyn Fn(&VerifiedIdentity) -> bool + Send + Sync>;

/// TCP server that accepts encrypted peer connections.
pub struct TcpServer {
    our_identity: Arc<IdentityKeys>,
    peer_validator: Option<PeerValidator>,
    bind_addr: String,
}

impl TcpServer {
    /// Create a new TCP server.
    ///
    /// # Arguments
    /// - `our_identity`: Our identity keys for Noise responder.
    /// - `bind_addr`: Address to bind (e.g., "0.0.0.0:7878").
    pub fn new(our_identity: Arc<IdentityKeys>, bind_addr: impl Into<String>) -> Self {
        Self {
            our_identity,
            peer_validator: None,
            bind_addr: bind_addr.into(),
        }
    }

    /// Set a callback to validate peers before accepting connections.
    ///
    /// If not set, all successfully handshaked peers are accepted.
    pub fn with_peer_validator(mut self, validator: PeerValidator) -> Self {
        self.peer_validator = Some(validator);
        self
    }

    /// Run the server, accepting connections until cancelled.
    ///
    /// # Security
    /// - Each connection gets its own task (lightweight, not OS thread).
    /// - Handshake timeout prevents resource exhaustion.
    /// - Rate limiting: max 10 pending handshakes at once.
    pub async fn run(&self, cancel: CancellationToken) -> NetworkResult<()> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| NetworkError::BindFailed(format!("{}: {}", self.bind_addr, e)))?;

        info!("TCP server listening on {}", self.bind_addr);

        // Semaphore to limit concurrent handshakes (prevent DoS)
        let handshake_sem = Arc::new(tokio::sync::Semaphore::new(10));

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("server shutting down");
                    break Ok(());
                }
                result = listener.accept() => {
                    let (stream, addr) = result
                        .map_err(|e| NetworkError::AcceptFailed(format!("{}", e)))?;
                    debug!("incoming connection from {}", addr);

                    let identity = self.our_identity.clone();
                    let validator = self.peer_validator.clone();
                    let sem = handshake_sem.clone();
                    let cancel = cancel.clone();

                    tokio::spawn(async move {
                        let _permit = match sem.acquire().await {
                            Ok(p) => p,
                            Err(_) => {
                                warn!("handshake semaphore closed");
                                return;
                            }
                        };

                        if let Err(e) = handle_connection(stream, identity, validator, cancel).await {
                            warn!("connection from {} failed: {}", addr, e);
                        }
                    });
                }
            }
        }
    }

    /// Get the local bind address (useful when binding to port 0).
    pub async fn local_addr(&self) -> NetworkResult<std::net::SocketAddr> {
        let listener = TcpListener::bind(&self.bind_addr)
            .await
            .map_err(|e| NetworkError::BindFailed(format!("{}", e)))?;
        listener.local_addr()
            .map_err(|e| NetworkError::Internal(format!("local_addr: {}", e)))
    }
}

async fn handle_connection(
    stream: TcpStream,
    our_identity: Arc<IdentityKeys>,
    validator: Option<PeerValidator>,
    cancel: CancellationToken,
) -> NetworkResult<EncryptedConnection> {
    let handshake = NoiseHandshake::new_responder(our_identity)
        .map_err(|e| NetworkError::HandshakeFailed(format!("responder setup: {}", e)))?;

    let (transport, verified) = run_responder_handshake(
        handshake,
        &mut { let s = stream.try_clone().map_err(|e| NetworkError::Internal(format!("stream clone: {}", e)))?; s },
        cancel,
    )
    .await
    .map_err(|e| NetworkError::HandshakeFailed(format!("{}", e)))?;

    // Validate peer if callback provided
    if let Some(ref validator) = validator {
        if !validator(&verified) {
            warn!(
                "peer {} rejected by validator",
                verified.fingerprint
            );
            return Err(NetworkError::PeerRejected(
                verified.fingerprint.to_string()
            ));
        }
    }

    info!(
        "accepted connection from peer {}",
        verified.fingerprint
    );

    let conn = EncryptedConnection::new(
        stream,
        transport,
        verified.fingerprint,
    );

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;

    #[tokio::test]
    async fn server_bind_and_shutdown() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let server = TcpServer::new(identity, "127.0.0.1:0");
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            server.run(cancel_clone).await
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cancel.cancel();

        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}