//! mDNS service advertiser for peer discovery.
//!
//! # Security
//! - Advertises only public keys (Ed25519, X25519) and fingerprint.
//! - Never advertises secret keys or passphrases.
//! - Service type is `_rubix-pingpongzz._tcp.local`.

use mdns_sd::{ServiceDaemon, ServiceInfo};
use rubix_security::keys::identity_keys::IdentityKeys;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};

/// mDNS service type for Rubix-PingPongzz.
const SERVICE_TYPE: &str = "_rubix-pingpongzz._tcp.local.";

/// Advertises this peer's identity over mDNS for LAN discovery.
pub struct MdnsAdvertiser {
    daemon: ServiceDaemon,
    service_name: String,
}

impl MdnsAdvertiser {
    /// Create and start advertising.
    ///
    /// # Arguments
    /// - `identity`: Our identity keys (public parts advertised).
    /// - `tcp_port`: The port our TCP server listens on.
    /// - `display_name`: Human-readable name.
    pub fn new(
        identity: &IdentityKeys,
        tcp_port: u16,
        display_name: impl Into<String>,
    ) -> NetworkResult<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| NetworkError::MdnsError(format!("daemon create: {}", e)))?;

        let fingerprint = identity.fingerprint()
            .map_err(|e| NetworkError::Internal(format!("fingerprint: {}", e)))?;

        let service_name = format!("{}.{}", fingerprint, SERVICE_TYPE);

        let properties = [
            ("display_name".into(), display_name.into()),
            ("fingerprint".into(), fingerprint.to_string()),
            ("ed25519".into(), hex::encode(identity.ed25519_public().as_bytes())),
            ("x25519".into(), hex::encode(identity.x25519_public().as_bytes())),
            ("version".into(), "1".into()),
        ];

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &service_name,
            &format!("{}.{}", fingerprint, SERVICE_TYPE),
            "", // Let mDNS determine IP
            tcp_port,
            &properties[..],
        )
        .map_err(|e| NetworkError::MdnsError(format!("service info: {}", e)))?;

        daemon
            .register(service_info)
            .map_err(|e| NetworkError::MdnsError(format!("register: {}", e)))?;

        info!("mDNS advertising on port {} as {}", tcp_port, fingerprint);

        Ok(Self {
            daemon,
            service_name,
        })
    }

    /// Stop advertising.
    pub fn shutdown(self) {
        debug!("shutting down mDNS advertiser");
        let _ = self.daemon.unregister(&self.service_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;

    #[test]
    fn advertiser_create() {
        let identity = IdentityKeys::generate().unwrap();
        let advertiser = MdnsAdvertiser::new(&identity, 7878, "TestUser");
        assert!(advertiser.is_ok());
        // Clean up
        if let Ok(adv) = advertiser {
            adv.shutdown();
        }
    }
}