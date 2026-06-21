//! Application layer for Rubix-PingPongzz.
//!
//! Orchestrates use cases, defines **Ports** (trait boundaries) for infrastructure,
//! and shapes Data Transfer Objects (DTOs) for the UI boundary.
//!
//! # Clean Architecture
//! ```text
//! UI → Application → Domain
//!           ↓
//!     Ports (traits)
//!           ↓
//! Infrastructure implements Ports
//! ```
//!
//! # Security
//! - All input validated before crossing into Domain.
//! - Peer trust is **fail-closed**: unverified until user explicitly trusts.
//! - Message content is encrypted before Domain entity construction.
//! - Rate limiting on peer connection attempts prevents DoS.
//! - Sensitive errors are sanitized before returning to UI.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

pub mod dto;
pub mod error;
pub mod ports;
pub mod rate_limit;
pub mod usecases;

// Re-exports for UI consumers
pub use dto::message_dto::{MessageResponse, SendMessageRequest};
pub use dto::peer_dto::{ConnectPeerRequest, DiscoverPeerRequest, PeerResponse};
pub use error::ApplicationError;
pub use ports::{
    network_port::{ConnectionId, DiscoveredPeer, IncomingMessage, NetworkError, NetworkPort},
    notification_port::{NotificationError, NotificationPort},
    persistence_port::{PersistenceError, PersistencePort},
    security_port::{SecurityError, SecurityPort},
    trust_port::{TrustError, TrustPort},
};
pub use usecases::{
    connect_peer::ConnectPeerUseCase,
    discover_peer::DiscoverPeerUseCase,
    receive_message::ReceiveMessageUseCase,
    reset_identity::ResetIdentityUseCase,
    send_message::SendMessageUseCase,
};