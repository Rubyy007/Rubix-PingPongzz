//! Trust port — abstraction over trust decision storage.

use async_trait::async_trait;
use domain::identity::Fingerprint;
use thiserror::Error;

/// Trust operation errors.
#[derive(Error, Debug, Clone)]
pub enum TrustError {
    #[error("storage error")]
    Storage,
    #[error("internal error")]
    Internal,
}

/// Trust infrastructure port.
///
/// # Security
/// Trust decisions are persistent and survive restarts.
/// Default state for any peer is **untrusted** (fail-closed).
#[async_trait]
pub trait TrustPort: Send + Sync {
    /// Check if a fingerprint is in the trusted set.
    ///
    /// Returns `false` for any error — fail-closed.
    async fn is_trusted(&self, fingerprint: &Fingerprint) -> Result<bool, TrustError>;

    /// Add fingerprint to trusted set.
    async fn add_trusted(&self, fingerprint: &Fingerprint) -> Result<(), TrustError>;

    /// Remove fingerprint from trusted set.
    async fn remove_trusted(&self, fingerprint: &Fingerprint) -> Result<(), TrustError>;

    /// List all trusted fingerprints.
    async fn list_trusted(&self) -> Result<Vec<Fingerprint>, TrustError>;
}