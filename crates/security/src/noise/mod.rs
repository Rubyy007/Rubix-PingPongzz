//! Noise protocol implementation (KK pattern) with identity binding.

pub mod handshake;
pub mod identity_bind;
pub mod transport;

pub use handshake::{
    NoiseHandshake, run_initiator_handshake, run_responder_handshake, HANDSHAKE_TIMEOUT_SECS,
};
pub use identity_bind::{IdentityBindPayload, VerifiedIdentity};
pub use transport::{Transport, TransportState, encrypt_batch};