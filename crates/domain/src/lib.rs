//! Domain core for Rubix-PingPongzz.
//!
//! This crate defines the central entities, value objects, error types, and
//! repository traits that form the heart of the application. It has **zero
//! dependencies** on infrastructure (networking, persistence, UI) — preserving
//! the Clean Architecture rule that `Domain → Nothing`.
//!
//! # Module Hierarchy
//! ```text
//! domain/
//! ├── errors/        — Domain-level error types with security-conscious messaging
//! ├── identity/      — Local user identity (fingerprint + public keys)
//! ├── message/       — Chat messages and delivery state machine
//! ├── peer/          — Remote peer entities and connection status
//! └── trust/         — Trust repository trait (implemented by persistence)
//! ```
//!
//! # Security
//! - All cryptographic identities are bound via constant-time fingerprint comparisons.
//! - Message state transitions are monotonic and cannot be rolled back.
//! - Sensitive data is zeroized on drop.
//! - Error variants are designed to leak minimal information.
//! - Trust decisions are fail-closed (untrusted by default).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

// ── Top-level modules ──────────────────────────────────────────────────────
// ONLY these are top-level. Submodules (fingerprint, message_state, peer_status)
// live inside their parent directories (identity/, message/, peer/).

pub mod errors;
pub mod identity;
pub mod message;
pub mod peer;
pub mod trust;

// ── Crate-level re-exports ─────────────────────────────────────────────────
// Flat API for consumers. Internal module structure is preserved but hidden
// behind these stable re-exports.

// Error types and validation helpers
pub use errors::{
    DomainError, DomainResult, IdentityError, MessageError, PeerError,
    validate_display_name, validate_message_content,
    MAX_DISPLAY_NAME_LEN, MAX_MESSAGE_CONTENT_LEN, MAX_RECIPIENTS,
};

// Identity (nested: identity::fingerprint, identity::identity)
pub use identity::{
    Fingerprint, FINGERPRINT_BYTES, FINGERPRINT_STRING_LEN,
    Identity, IdentityBuilder,
    ED25519_PUBLIC_KEY_LEN, X25519_PUBLIC_KEY_LEN,
};

// Message (nested: message::message, message::message_state)
pub use message::{
    ContentType, Message, MessageBuilder, MAX_RECIPIENTS,
    MessageState, MessageStateError,
};

// Peer (nested: peer::peer, peer::peer_status)
pub use peer::{
    Peer, PeerBuilder, MAX_PEER_ADDRESSES,
    PeerStatus, ONLINE_TIMEOUT_SECONDS,
};

// Trust repository trait (implemented by persistence layer)
pub use trust::TrustStore;