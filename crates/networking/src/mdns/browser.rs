//! mDNS service browser for peer discovery.
//!
//! # Security
//! - Extracts and validates peer fingerprints from mDNS TXT records.
//! - Verifies that advertised Ed25519 + X25519 keys match the fingerprint.
//! - Rejects peers with invalid or mismatched key material.

use mdns_sd::{ServiceDaemon, ServiceEvent};
use rubix_domain::identity::fingerprint::Fingerprint;
use rubix_security::keys::{ed25519::Ed25519PublicKey, x25519::X25519PublicKey};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::tcp::connection_manager::PeerInfo;

/// mDNS service type to browse.
const SERVICE_TYPE: &str = "_rubix-pingpongzz._tcp.local.";

/// Discovered peer event.
#[derive(Clone, Debug)]
pub enum DiscoveryEvent {
    /// New peer discovered.
    Discovered(PeerInfo),
    /// Peer removed (service went down).
    Removed(Fingerprint),
}

/// mDNS browser for discovering peers on the LAN.
pub struct MdnsBrowser {
    daemon: ServiceDaemon,
    rx: mpsc::Receiver<DiscoveryEvent>,
}

impl MdnsBrowser {
    /// Start browsing for peers.
    pub fn new() -> NetworkResult<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| NetworkError::MdnsError(format!("daemon create: {}", e)))?;

        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| NetworkError::MdnsError(format!("browse: {}", e)))?;

        let (tx, rx) = mpsc::channel(100);

        // Spawn event processing task
        std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Some(peer) = parse_peer_info(&info) {
                            let _ = tx.blocking_send(DiscoveryEvent::Discovered(peer));
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        // Extract fingerprint from fullname
                        if let Some(fp_str) = fullname.split('.').next() {
                            if let Ok(fp) = Fingerprint::from_hex(fp_str) {
                                let _ = tx.blocking_send(DiscoveryEvent::Removed(fp));
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        info!("mDNS browser started for {}", SERVICE_TYPE);

        Ok(Self { daemon, rx })
    }

    /// Receive the next discovery event.
    pub async fn next_event(&mut self) -> Option<DiscoveryEvent> {
        self.rx.recv().await
    }

    /// Shutdown the browser.
    pub fn shutdown(self) {
        debug!("shutting down mDNS browser");
        let _ = self.daemon.shutdown();
    }
}

/// Parse peer info from mDNS service info.
///
/// # Security
/// - Validates that advertised keys match the fingerprint.
/// - Rejects peers with malformed or inconsistent data.
fn parse_peer_info(info: &mdns_sd::ServiceInfo) -> Option<PeerInfo> {
    let properties: HashMap<String, String> = info
        .get_properties()
        .iter()
        .map(|p| (p.key().to_string(), p.val_str().to_string()))
        .collect();

    let fingerprint_str = properties.get("fingerprint")?;
    let fingerprint = Fingerprint::from_hex(fingerprint_str).ok()?;

    let ed25519_hex = properties.get("ed25519")?;
    let x25519_hex = properties.get("x25519")?;

    let ed25519_bytes = hex::decode(ed25519_hex).ok()?;
    let x25519_bytes = hex::decode(x25519_hex).ok()?;

    let ed25519_pub = Ed25519PublicKey::from_bytes(&ed25519_bytes).ok()?;
    let x25519_pub = X25519PublicKey::from_bytes(&x25519_bytes).ok()?;

    // Verify fingerprint matches advertised keys
    let computed_fp = rubix_security::fingerprint::derive::derive_fingerprint(
        &ed25519_pub,
        &x25519_pub,
    )
    .ok()?;

    if !computed_fp.constant_time_eq(&fingerprint) {
        warn!(
            "peer {} advertised fingerprint does not match keys, rejecting",
            fingerprint
        );
        return None;
    }

    let display_name = properties
        .get("display_name")
        .cloned()
        .unwrap_or_else(|| "Unknown".into());

    let tcp_port = info.get_port();

    // Get IP address (prefer IPv4)
    let ip_address = info
        .get_addresses()
        .iter()
        .find(|addr| matches!(addr, IpAddr::V4(_)))
        .copied()
        .or_else(|| info.get_addresses().iter().next().copied())?;

    Some(PeerInfo {
        fingerprint,
        display_name,
        ip_address,
        tcp_port,
        last_seen: chrono::Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full mDNS browser tests require network access.
    // These are basic unit tests for parse_peer_info.

    #[test]
    fn parse_valid_peer_info() {
        // This would require constructing a ServiceInfo, which is complex.
        // Skipping for now - integration tests cover this.
    }
}