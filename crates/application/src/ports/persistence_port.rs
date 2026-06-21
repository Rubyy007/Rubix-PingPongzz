//! Persistence port — abstraction over SQLite storage.

use async_trait::async_trait;
use domain::identity::Fingerprint;
use domain::message::Message;
use domain::peer::{Peer, PeerStatus};
use thiserror::Error;

/// Persistence operation errors.
#[derive(Error, Debug, Clone)]
pub enum PersistenceError {
    /// Database connection lost.
    #[error("database unavailable")]
    Unavailable,

    /// Query execution failed.
    #[error("query failed: {0}")]
    QueryFailed(String),

    /// Constraint violation (unique index, foreign key).
    #[error("constraint violation")]
    ConstraintViolation,

    /// Internal storage error.
    #[error("internal storage error")]
    Internal,
}

/// Persistence infrastructure port.
#[async_trait]
pub trait PersistencePort: Send + Sync {
    /// Save a message (insert or update).
    async fn save_message(&self, msg: &Message) -> Result<(), PersistenceError>;

    /// Load messages for a specific peer conversation.
    ///
    /// # Performance
    /// `limit` should be ≤ 1000 to prevent memory spikes.
    async fn load_messages(
        &self,
        peer_fp: &Fingerprint,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Message>, PersistenceError>;

    /// Save or update a peer record.
    async fn save_peer(&self, peer: &Peer) -> Result<(), PersistenceError>;

    /// Load a single peer by fingerprint.
    async fn load_peer(
        &self,
        fp: &Fingerprint,
    ) -> Result<Option<Peer>, PersistenceError>;

    /// Load all known peers.
    async fn load_peers(&self) -> Result<Vec<Peer>, PersistenceError>;

    /// Update peer status (online/away/offline).
    async fn update_peer_status(
        &self,
        fp: &Fingerprint,
        status: PeerStatus,
    ) -> Result<(), PersistenceError>;

    /// Remove a peer and all associated messages.
    ///
    /// # Security
    /// Destructive operation — caller must confirm with user.
    async fn delete_peer(&self, fp: &Fingerprint) -> Result<(), PersistenceError>;
}