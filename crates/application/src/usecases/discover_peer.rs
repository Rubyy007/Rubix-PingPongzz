//! Discover Peer use case.
//!
//! # Security
//! - Discovered peers are **never** auto-trusted.
//! - All discovered peers are saved as unverified.
//! - Fingerprint collisions are handled (last-seen wins).
//!
//! # Performance
//! - Targets < 10 seconds for 200 peers.
//! - Deduplication by fingerprint prevents storage bloat.

use crate::dto::peer_dto::{DiscoverPeerRequest, PeerResponse};
use crate::error::{ApplicationError, ApplicationResult};
use crate::ports::network_port::NetworkPort;
use crate::ports::persistence_port::PersistencePort;
use domain::peer::{Peer, PeerStatus};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, instrument};

/// Discover Peer use case.
#[derive(Clone)]
pub struct DiscoverPeerUseCase {
    network: Arc<dyn NetworkPort>,
    persistence: Arc<dyn PersistencePort>,
}

impl DiscoverPeerUseCase {
    pub fn new(network: Arc<dyn NetworkPort>, persistence: Arc<dyn PersistencePort>) -> Self {
        Self {
            network,
            persistence,
        }
    }

    /// Execute peer discovery.
    ///
    /// # Performance
    /// Listens for LAN advertisements for `request.timeout_secs` (default 10).
    /// Returns up to `request.max_results` unique peers.
    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        request: DiscoverPeerRequest,
    ) -> ApplicationResult<Vec<PeerResponse>> {
        let timeout = Duration::from_secs(request.timeout_secs);
        let max_results = request.max_results.min(200); // Hard cap per acceptance criteria

        // Broadcast presence and listen for responses
        let discovered = self
            .network
            .discover_peers(timeout)
            .await
            .map_err(|_| ApplicationError::Network)?;

        info!(
            count = discovered.len(),
            timeout = request.timeout_secs,
            "discovery complete"
        );

        let mut responses = Vec::with_capacity(discovered.len().min(max_results));

        for dp in discovered.into_iter().take(max_results) {
            let peer = Peer::builder()
                .display_name(&dp.display_name)
                .fingerprint(dp.fingerprint.clone())
                .ed25519_public(dp.ed25519_public)
                .x25519_public(dp.x25519_public)
                .addresses(dp.addresses)
                .build()
                .map_err(|_| ApplicationError::Domain)?;

            // Save or update in persistence
            if let Some(mut existing) = self
                .persistence
                .load_peer(peer.fingerprint())
                .await
                .map_err(|_| ApplicationError::Persistence)?
            {
                existing.set_addresses(peer.addresses().to_vec()).map_err(|_| {
                    ApplicationError::Validation {
                        field: "addresses".into(),
                        reason: "limit exceeded".into(),
                    }
                })?;
                existing.set_status(PeerStatus::offline());
                self.persistence
                    .save_peer(&existing)
                    .await
                    .map_err(|_| ApplicationError::Persistence)?;
            } else {
                self.persistence
                    .save_peer(&peer)
                    .await
                    .map_err(|_| ApplicationError::Persistence)?;
            }

            responses.push(PeerResponse::from_peer(&peer));
        }

        Ok(responses)
    }
}