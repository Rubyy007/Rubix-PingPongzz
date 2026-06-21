//! Security crate for Rubix-PingPongzz.
//! Provides cryptographic key management, Noise handshakes,
//! secure transport, and encrypted storage.
//!
//! # Architecture
//! This crate is part of the Infrastructure layer in Clean Architecture.
//! It depends only on the Domain crate (for `Fingerprint`, `Identity`, `DomainError`).
//!
//! # Security Guarantees
//! - All key material is zeroized on drop.
//! - Passphrase-derived keys use Argon2id (memory-hard).
//! - Noise KK pattern provides mutual authentication.
//! - Ed25519 identity binding prevents key substitution attacks.
//! - Transport enforces max message size and prevents replay.
//!
//! # Performance
//! - Handshake: < 10ms for two round trips.
//! - Encryption: ~1ms for 64KB messages.
//! - Key derivation: ~100ms with Argon2id (64MB, 3 iterations).

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod error;
pub mod keys;
pub mod noise;
pub mod fingerprint;
pub mod storage;

pub use error::SecurityError;
pub use keys::identity_keys::IdentityKeys;
pub use keys::x25519::X25519PublicKey;
pub use keys::ed25519::Ed25519PublicKey;
pub use noise::handshake::NoiseHandshake;
pub use noise::transport::{Transport, TransportState};
pub use noise::identity_bind::{IdentityBindPayload, VerifiedIdentity};
pub use fingerprint::derive::derive_fingerprint;
pub use storage::secure_store::SecureStore;