//! UDP beacon broadcaster for peer discovery fallback.

use rubix_security::keys::identity_keys::IdentityKeys;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::udp::beacon::DiscoveryBeacon;

/// UDP port for discovery beacons.
const DISCOVERY_PORT: u16 = 9876;

/// Broadcast interval (seconds).
const BROADCAST_INTERVAL_SECS: u64 = 5;

/// Broadcasts discovery beacons over UDP.
pub struct UdpBroadcaster {
    socket: UdpSocket,
    identity: Arc<IdentityKeys>,
    tcp_port: u16,
    display_name: String,
}

impl UdpBroadcaster {
    /// Create a new broadcaster.
    ///
    /// # Arguments
    /// - `identity`: Our identity keys (public parts broadcasted).
    /// - `tcp_port`: The port our TCP server listens on.
    /// - `display_name`: Human-readable name.
    pub async fn new(
        identity: Arc<IdentityKeys>,
        tcp_port: u16,
        display_name: impl Into<String>,
    ) -> NetworkResult<Self> {
        // Bind to any available port
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetworkError::BindFailed(format!("UDP broadcast: {}", e)))?;

        // Enable broadcast
        socket
            .set_broadcast(true)
            .map_err(|e| NetworkError::UdpError(format!("set broadcast: {}", e)))?;

        info!("UDP broadcaster ready on {:?}", socket.local_addr());

        Ok(Self {
            socket,
            identity,
            tcp_port,
            display_name: display_name.into(),
        })
    }

    /// Run the broadcaster, sending beacons at regular intervals.
    pub async fn run(&self, cancel: CancellationToken) -> NetworkResult<()> {
        let broadcast_addr = SocketAddr::from(([255, 255, 255, 255], DISCOVERY_PORT));
        let mut ticker = interval(Duration::from_secs(BROADCAST_INTERVAL_SECS));

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("UDP broadcaster shutting down");
                    break Ok(());
                }
                _ = ticker.tick() => {
                    let beacon = DiscoveryBeacon::create(
                        &self.identity.ed25519,
                        &self.identity.x25519.public.0,
                        self.tcp_port,
                        &self.display_name,
                    );

                    let data = beacon.to_bytes();
                    match self.socket.send_to(&data, broadcast_addr).await {
                        Ok(n) => debug!("broadcasted {} bytes to {}", n, broadcast_addr),
                        Err(e) => warn!("broadcast failed: {}", e),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;

    #[tokio::test]
    async fn broadcaster_create() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let broadcaster = UdpBroadcaster::new(identity, 7878, "Test").await;
        assert!(broadcaster.is_ok());
    }
}