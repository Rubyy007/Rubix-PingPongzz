//! Connect Peer use case.
//!
//! # Security
//! - Validates address format before network operation.
//! - Rate limits connection attempts per peer fingerprint.
//! - Verifies peer fingerprint matches expected value.
//! - Saves peer only after successful cryptographic handshake.
//!
//! # Performance
//! - Handshake timeout: 5 seconds.
//! - Parallel connection attempts to multiple addresses are possible
//!   but not implemented here (future optimization).

use crate::dto::peer_dto::{ConnectPeerRequest, PeerResponse};
use crate::error::{ApplicationError, ApplicationResult};
use crate::ports::network_port::{NetworkError, NetworkPort};
use crate::ports::persistence_port::PersistencePort;
use crate::ports::trust_port::TrustPort;
use crate::rate_limit::RateLimiter;
use domain::identity::Fingerprint;
use domain::peer::{Peer, PeerStatus};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tracing::{info, instrument, warn};

/// Connection attempt timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Max connection attempts per minute per peer.
const CONNECT_RATE_LIMIT: usize = 3;

/// Connect Peer use case.
#[derive(Clone)]
pub struct ConnectPeerUseCase {
    network: Arc<dyn NetworkPort>,
    persistence: Arc<dyn PersistencePort>,
    trust: Arc<dyn TrustPort>,
    rate_limiter: Arc<RateLimiter>,
}

impl ConnectPeerUseCase {
    pub fn new(
        network: Arc<dyn NetworkPort>,
        persistence: Arc<dyn PersistencePort>,
        trust: Arc<dyn TrustPort>,
    ) -> Self {
        Self {
            network,
            persistence,
            trust,
            rate_limiter: Arc::new(RateLimiter::with_config(
                Duration::from_secs(60),
                CONNECT_RATE_LIMIT,
            )),
        }
    }

    /// Execute connection to a peer.
    #[instrument(skip(self, request), fields(addr = %request.address))]
    pub async fn execute(&self, request: ConnectPeerRequest) -> ApplicationResult<PeerResponse> {
        // 1. Validate address
        let addr: SocketAddr = request.address.parse().map_err(|_| ApplicationError::Validation {
            field: "address".into(),
            reason: "invalid socket address format".into(),
        })?;

        // 2. Parse expected fingerprint
        let expected_fp = Fingerprint::from_hex(&request.fingerprint).map_err(|_| {
            ApplicationError::Validation {
                field: "fingerprint".into(),
                reason: "invalid hex format".into(),
            }
        })?;

        // 3. Rate limit
        let rate_key = format!("connect:{}", expected_fp.to_formatted_string());
        if !self.rate_limiter.check(&rate_key) {
            return Err(ApplicationError::RateLimited);
        }

        // 4. Connect with timeout
        let (conn_id, mut peer) = timeout(
            CONNECT_TIMEOUT,
            self.network.connect(addr, Some(&expected_fp)),
        )
        .await
        .map_err(|_| {
            self.rate_limiter.reset(&rate_key);
            ApplicationError::Timeout
        })?
        .map_err(|e| match e {
            NetworkError::HandshakeFailed => ApplicationError::Security,
            NetworkError::ConnectionRefused => ApplicationError::Network,
            _ => ApplicationError::Network,
        })?;

        info!(peer = %peer.fingerprint(), "peer connected and handshake complete");

        // 5. Check trust and set verification
        let is_trusted = self
            .trust
            .is_trusted(peer.fingerprint())
            .await
            .unwrap_or(false);

        if is_trusted {
            peer.verify();
            info!(peer = %peer.fingerprint(), "peer marked verified (trusted)");
        } else {
            warn!(peer = %peer.fingerprint(), "peer connected but NOT trusted");
        }

        // 6. Update or insert peer in persistence
        if let Some(mut existing) = self
            .persistence
            .load_peer(peer.fingerprint())
            .await
            .map_err(|_| ApplicationError::Persistence)?
        {
            existing.set_addresses(peer.addresses().to_vec()).map_err(|_| {
                ApplicationError::Validation {
                    field: "addresses".into(),
                    reason: "too many addresses".into(),
                }
            })?;
            existing.set_status(PeerStatus::online_now());
            if peer.is_verified() {
                existing.verify();
            }
            self.persistence
                .save_peer(&existing)
                .await
                .map_err(|_| ApplicationError::Persistence)?;
        } else {
            peer.set_status(PeerStatus::online_now());
            self.persistence
                .save_peer(&peer)
                .await
                .map_err(|_| ApplicationError::Persistence)?;
        }

        Ok(PeerResponse::from_peer(&peer))
    }
}