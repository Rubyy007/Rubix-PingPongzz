//! Trust management for peer relationships.
//!
//! Defines the repository trait for trusted peer storage. This is a domain
//! trait implemented by the persistence layer.
//!
//! # Security
//! - Trust decisions are persistent and survive application restarts
//! - TrustStore operations are async to allow for encrypted storage backends
//! - Fingerprint-based trust prevents display name spoofing

use async_trait::async_trait;
use crate::errors::DomainResult;
use crate::identity::fingerprint::Fingerprint;
use crate::peer::Peer;

/// Storage and retrieval of trusted peers and peer metadata.
///
/// # Thread Safety
/// All methods require `Send + Sync` as implementations may be shared
/// across async tasks.
///
/// # Performance
/// Implementations should cache trust status in memory with periodic
/// persistence to avoid SQLite contention on hot paths.
#[async_trait]
pub trait TrustStore: Send + Sync {
    /// Check if a fingerprint is in the trusted set.
    ///
    /// # Security
    /// Returns `false` for any error condition — fail-closed principle.
    async fn is_trusted(&self, fp: &Fingerprint) -> DomainResult<bool>;

    /// Add a fingerprint to the trusted set.
    ///
    /// # Idempotency
    /// Adding an already-trusted fingerprint must succeed (no-op).
    async fn add_trusted(&self, fp: &Fingerprint) -> DomainResult<()>;

    /// Remove a fingerprint from the trusted set.
    ///
    /// # Security
    /// Untrusting a peer immediately invalidates any active encrypted sessions.
    async fn remove_trusted(&self, fp: &Fingerprint) -> DomainResult<()>;

    /// List all trusted fingerprints.
    ///
    /// # Performance
    /// For large trust stores (>1000 entries), consider pagination.
    async fn list_trusted(&self) -> DomainResult<Vec<Fingerprint>>;

    /// Add or update a peer record.
    ///
    /// # Security
    /// Overwrites existing peer data — caller must verify fingerprint
    /// binding before calling.
    async fn add_peer(&self, peer: Peer) -> DomainResult<()>;

    /// Get a peer by fingerprint if present in local store.
    ///
    /// Returns `None` if peer is unknown, even if fingerprint is trusted.
    /// Trust and peer metadata are separate concerns.
    async fn get_peer(&self, fp: &Fingerprint) -> DomainResult<Option<Peer>>;
}