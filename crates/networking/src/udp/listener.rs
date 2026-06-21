//! UDP beacon listener for peer discovery fallback.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::tcp::connection_manager::PeerInfo;
use crate::udp::beacon::DiscoveryBeacon;

/// UDP port for discovery beacons.
const DISCOVERY_PORT: u16 = 9876;

/// Maximum beacon size.
const MAX_BEACON_SIZE: usize = 4096;

/// Discovered peer event from UDP.
#[derive(Clone, Debug)]
pub enum UdpDiscoveryEvent {
    /// New peer discovered via UDP beacon.
    Discovered(PeerInfo),
}

/// Listens for UDP discovery beacons.
pub struct UdpListener {
    socket: UdpSocket,
    tx: mpsc::Sender<UdpDiscoveryEvent>,
}

impl UdpListener {
    /// Create and start listening for beacons.
    pub async fn new() -> NetworkResult<(Self, mpsc::Receiver<UdpDiscoveryEvent>)> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], DISCOVERY_PORT));
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| NetworkError::BindFailed(format!("UDP listener: {}", e)))?;

        info!("UDP listener bound to {}", bind_addr);

        let (tx, rx) = mpsc::channel(100);

        Ok((Self { socket, tx }, rx))
    }

    /// Run the listener, processing incoming beacons.
    pub async fn run(&self, cancel: CancellationToken) -> NetworkResult<()> {
        let mut buf = vec![0u8; MAX_BEACON_SIZE];

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("UDP listener shutting down");
                    break Ok(());
                }
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            debug!("received {} bytes from {}", len, addr);
                            if let Some(peer) = self.process_beacon(&buf[..len]).await {
                                let _ = self.tx.send(UdpDiscoveryEvent::Discovered(peer)).await;
                            }
                        }
                        Err(e) => {
                            warn!("UDP recv error: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Process a received beacon.
    async fn process_beacon(&self, data: &[u8]) -> Option<PeerInfo> {
        let beacon = DiscoveryBeacon::from_bytes(data)?;

        if let Err(e) = beacon.verify() {
            warn!("invalid beacon from {}: {}", beacon.fingerprint, e);
            return None;
        }

        debug!("valid beacon from {}", beacon.fingerprint);

        let fingerprint = match rubix_domain::identity::fingerprint::Fingerprint::from_hex(&beacon.fingerprint) {
            Ok(fp) => fp,
            Err(_) => return None,
        };

        // Parse x25519 hex into bytes, if possible
        let x25519_public = hex::decode(&beacon.x25519_public).ok().and_then(|v| {
            if v.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                Some(arr)
            } else {
                None
            }
        });

        Some(PeerInfo {
            fingerprint,
            display_name: beacon.display_name,
            ip_address: beacon.source_ip.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
            tcp_port: beacon.tcp_port,
            x25519_public,
            last_seen: chrono::Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listener_create() {
        let (listener, _rx) = UdpListener::new().await;
        assert!(listener.is_ok());
    }
}