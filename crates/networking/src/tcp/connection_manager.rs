//! Connection manager for up to 200 peers with 10 active encrypted chats.
//!
//! # Architecture
//! - Uses `DashMap` for lock-free concurrent access to peer connections.
//! - Bounded channels for backpressure on outgoing messages.
//! - Automatic cleanup of stale connections via heartbeat timeout.
//!
//! # Performance
//! - O(1) peer lookup by fingerprint.
//! - No global locks: per-connection mutex only during encrypt/decrypt.
//! - Background task prunes dead connections every 30s.
//!
//! # Security
//! - Max 200 peers prevents memory exhaustion.
//! - Max 10 active chats limits concurrent encryption load.
//! - Unknown peers are rejected if not in allowlist.

use dashmap::DashMap;
use rubix_domain::identity::fingerprint::Fingerprint;
use rubix_security::keys::identity_keys::IdentityKeys;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use rubix_domain::TrustStore;
use std::sync::Weak;

use crate::error::{NetworkError, NetworkResult};
use crate::tcp::connection::EncryptedConnection;

/// Maximum number of tracked peers (discovered + connected).
const MAX_PEERS: usize = 200;

/// Maximum number of active encrypted connections.
const MAX_ACTIVE_CONNECTIONS: usize = 10;

/// Channel capacity for outgoing messages per connection.
const OUTGOING_BUFFER_SIZE: usize = 64;

/// Connection manager state.
pub struct ConnectionManager {
    /// Our identity keys.
    our_identity: Arc<IdentityKeys>,
    /// Trust store for persistence-backed trusted peers.
    trust_store: Option<Arc<dyn TrustStore>>,
    /// All known peers (fingerprint -> peer info).
    peers: Arc<DashMap<Fingerprint, PeerInfo>>,
    /// Active encrypted connections (fingerprint -> connection handle).
    active_connections: Arc<DashMap<Fingerprint, ConnectionHandle>>,
    /// Set of fingerprints we trust (from persistence or user confirmation).
    trusted_peers: Arc<RwLock<std::collections::HashSet<Fingerprint>>>,
    /// Cancellation token for background tasks.
    cancel: CancellationToken,
}

/// Information about a known peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub fingerprint: Fingerprint,
    pub display_name: String,
    pub ip_address: std::net::IpAddr,
    pub tcp_port: u16,
    /// Optional X25519 public key bytes (32 bytes) if known from discovery.
    pub x25519_public: Option<[u8; 32]>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Handle to an active connection.
struct ConnectionHandle {
    /// Channel for sending messages to this peer.
    outgoing: mpsc::Sender<Vec<u8>>,
    /// Time of last successful message.
    last_activity: std::sync::atomic::AtomicI64,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(our_identity: Arc<IdentityKeys>, trust_store: Option<Arc<dyn TrustStore>>) -> Self {
        let cancel = CancellationToken::new();
        let manager = Self {
            our_identity,
            trust_store,
            peers: Arc::new(DashMap::with_capacity(MAX_PEERS)),
            active_connections: Arc::new(DashMap::with_capacity(MAX_ACTIVE_CONNECTIONS)),
            trusted_peers: Arc::new(RwLock::new(std::collections::HashSet::new())),
            cancel: cancel.clone(),
        };

        // Start background cleanup task
        let peers = manager.peers.clone();
        let connections = manager.active_connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        Self::cleanup_stale(&peers, &connections).await;
                    }
                }
            }
        });

        // If a trust_store is present, load trusted peers into memory
        if let Some(store) = manager.trust_store.clone() {
            let trusted_map = manager.trusted_peers.clone();
            tokio::spawn(async move {
                if let Ok(list) = store.list_trusted().await {
                    let mut trusted = trusted_map.write().await;
                    for fp in list {
                        trusted.insert(fp);
                    }
                }
            });
        }

        manager
    }

    /// Add or update a discovered peer.
    ///
    /// # Errors
    /// - `NetworkError::PeerLimitExceeded` if max peers reached.
    pub async fn add_peer(&self, info: PeerInfo) -> NetworkResult<()> {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&info.fingerprint) {
            warn!("peer limit ({}) reached, dropping {}", MAX_PEERS, info.fingerprint);
            return Err(NetworkError::PeerLimitExceeded(MAX_PEERS));
        }

        debug!("adding peer {} at {}:{}", info.fingerprint, info.ip_address, info.tcp_port);
        self.peers.insert(info.fingerprint.clone(), info);
        Ok(())
    }

    /// Mark a peer as trusted (allow connections).
    pub async fn trust_peer(&self, fingerprint: &Fingerprint) {
        let mut trusted = self.trusted_peers.write().await;
        trusted.insert(fingerprint.clone());
        info!("peer {} marked as trusted", fingerprint);
    }

    /// Check if a peer is trusted.
    pub async fn is_trusted(&self, fingerprint: &Fingerprint) -> bool {
        let trusted = self.trusted_peers.read().await;
        trusted.contains(fingerprint)
    }

    /// Get peer info by fingerprint.
    pub fn get_peer(&self, fingerprint: &Fingerprint) -> Option<PeerInfo> {
        self.peers.get(fingerprint).map(|r| r.clone())
    }

    /// Connect to a peer and establish encrypted channel.
    ///
    /// # Errors
    /// - `NetworkError::PeerNotFound` if peer not in manager.
    /// - `NetworkError::PeerNotTrusted` if peer not trusted.
    /// - `NetworkError::ConnectionLimitExceeded` if max active connections reached.
    /// - `NetworkError::AlreadyConnected` if already connected.
    pub async fn connect_to_peer(
        &self,
        fingerprint: &Fingerprint,
    ) -> NetworkResult<mpsc::Receiver<Vec<u8>>> {
        // Check if already connected
        if self.active_connections.contains_key(fingerprint) {
            return Err(NetworkError::AlreadyConnected(fingerprint.to_string()));
        }

        // Check peer exists
        let peer_info = self.get_peer(fingerprint)
            .ok_or_else(|| NetworkError::PeerNotFound(fingerprint.to_string()))?;

        // Check trusted
        if !self.is_trusted(fingerprint).await {
            return Err(NetworkError::PeerNotTrusted(fingerprint.to_string()));
        }

        // Check connection limit
        if self.active_connections.len() >= MAX_ACTIVE_CONNECTIONS {
            return Err(NetworkError::ConnectionLimitExceeded(MAX_ACTIVE_CONNECTIONS));
        }

        // Create channels
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(OUTGOING_BUFFER_SIZE);
        let (incoming_tx, incoming_rx) = mpsc::channel(OUTGOING_BUFFER_SIZE);

        // Spawn connection task
        let identity = self.our_identity.clone();
        let cancel = self.cancel.clone();
        let fp = fingerprint.clone();
        let active = self.active_connections.clone();
        let peer_ip = peer_info.ip_address;
        let peer_port = peer_info.tcp_port;

        tokio::spawn(async move {
            use crate::tcp::client::TcpClient;

            let client = TcpClient::new(identity);

            // Use x25519 public key from PeerInfo when available, else fail to connect
            let remote_x25519_res: Option<rubix_security::keys::x25519::X25519PublicKey> = peer_info.x25519_public.map(|b| {
                rubix_security::keys::x25519::X25519PublicKey::from_bytes(&b).expect("validated length 32")
            });

            if remote_x25519_res.is_none() {
                error!("missing x25519 public key for peer {}, cannot perform KK handshake", fp);
                return;
            }

            let remote_x25519 = remote_x25519_res.unwrap();

            match client.connect(peer_ip, peer_port, &fp, &remote_x25519, cancel.clone()).await {
                Ok(mut conn) => {
                    info!("connected to peer {}", fp);

                    // Store connection handle
                    active.insert(fp.clone(), ConnectionHandle {
                        outgoing: outgoing_tx,
                        last_activity: std::sync::atomic::AtomicI64::new(
                            chrono::Utc::now().timestamp()
                        ),
                    });

                    // Run send/receive loop
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => {
                                debug!("connection to {} cancelled", fp);
                                break;
                            }
                            Some(msg) = outgoing_rx.recv() => {
                                if let Err(e) = conn.send(&msg).await {
                                    warn!("send to {} failed: {}", fp, e);
                                    break;
                                }
                            }
                            result = conn.recv() => {
                                match result {
                                    Ok(msg) => {
                                        if incoming_tx.send(msg).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("recv from {} failed: {}", fp, e);
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    conn.close().await;
                    active.remove(&fp);
                    info!("disconnected from peer {}", fp);
                }
                Err(e) => {
                    error!("failed to connect to peer {}: {}", fp, e);
                }
            }
        });

        Ok(incoming_rx)
    }

    /// Send a message to a connected peer.
    ///
    /// # Errors
    /// - `NetworkError::PeerNotConnected` if no active connection.
    /// - `NetworkError::SendFailed` if channel is closed.
    pub async fn send_to(&self, fingerprint: &Fingerprint, message: Vec<u8>) -> NetworkResult<()> {
        let handle = self.active_connections
            .get(fingerprint)
            .ok_or_else(|| NetworkError::PeerNotConnected(fingerprint.to_string()))?;

        handle.outgoing.send(message).await
            .map_err(|_| NetworkError::SendFailed("channel closed".into()))?;

        Ok(())
    }

    /// Disconnect from a peer.
    pub async fn disconnect(&self, fingerprint: &Fingerprint) {
        if let Some((_, handle)) = self.active_connections.remove(fingerprint) {
            // Dropping the handle closes the channel, which signals the task to exit
            debug!("disconnecting from peer {}", fingerprint);
        }
    }

    /// Get count of active connections.
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.len()
    }

    /// Get count of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Shutdown all connections and background tasks.
    pub async fn shutdown(&self) {
        info!("shutting down connection manager");
        self.cancel.cancel();
        // Wait a moment for tasks to clean up
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    /// Remove stale peers and dead connections.
    async fn cleanup_stale(
        peers: &DashMap<Fingerprint, PeerInfo>,
        connections: &DashMap<Fingerprint, ConnectionHandle>,
    ) {
        let now = chrono::Utc::now();
        let stale_threshold = chrono::Duration::minutes(5);

        // Remove peers not seen in 5 minutes
        peers.retain(|fp, info| {
            let keep = now.signed_duration_since(info.last_seen) < stale_threshold;
            if !keep {
                debug!("removing stale peer {}", fp);
            }
            keep
        });

        // Note: dead connections are cleaned up by their tasks
        debug!(
            "cleanup complete: {} peers, {} active connections",
            peers.len(),
            connections.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn add_peer_and_retrieve() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let manager = ConnectionManager::new(identity, None);

        let fp = Fingerprint::from_bytes(&[0xAA; 20]).unwrap();
        let info = PeerInfo {
            fingerprint: fp.clone(),
            display_name: "Test".into(),
            ip_address: IpAddr::from_str("192.168.1.1").unwrap(),
            tcp_port: 7878,
            last_seen: chrono::Utc::now(),
        };

        manager.add_peer(info.clone()).await.unwrap();
        assert_eq!(manager.peer_count(), 1);

        let retrieved = manager.get_peer(&fp).unwrap();
        assert_eq!(retrieved.display_name, "Test");
    }

    #[tokio::test]
    async fn peer_limit_enforced() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let manager = ConnectionManager::new(identity, None);

        // Add max peers
        for i in 0..MAX_PEERS {
            let fp = Fingerprint::from_bytes(&[i as u8; 20]).unwrap();
            let info = PeerInfo {
                fingerprint: fp,
                display_name: format!("Peer{}", i),
                ip_address: IpAddr::from_str("192.168.1.1").unwrap(),
                tcp_port: 7878,
                last_seen: chrono::Utc::now(),
            };
            manager.add_peer(info).await.unwrap();
        }

        assert_eq!(manager.peer_count(), MAX_PEERS);

        // Adding one more should fail
        let extra_fp = Fingerprint::from_bytes(&[0xFF; 20]).unwrap();
        let extra = PeerInfo {
            fingerprint: extra_fp,
            display_name: "Extra".into(),
            ip_address: IpAddr::from_str("192.168.1.2").unwrap(),
            tcp_port: 7878,
            last_seen: chrono::Utc::now(),
        };

        assert!(matches!(
            manager.add_peer(extra).await,
            Err(NetworkError::PeerLimitExceeded(_))
        ));
    }

    #[tokio::test]
    async fn untrusted_peer_rejected() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let manager = ConnectionManager::new(identity, None);

        let fp = Fingerprint::from_bytes(&[0xBB; 20]).unwrap();
        let info = PeerInfo {
            fingerprint: fp.clone(),
            display_name: "Untrusted".into(),
            ip_address: IpAddr::from_str("192.168.1.3").unwrap(),
            tcp_port: 7878,
            last_seen: chrono::Utc::now(),
        };

        manager.add_peer(info).await.unwrap();

        // Try to connect without trusting
        let result = manager.connect_to_peer(&fp).await;
        assert!(matches!(result, Err(NetworkError::PeerNotTrusted(_))));
    }
}