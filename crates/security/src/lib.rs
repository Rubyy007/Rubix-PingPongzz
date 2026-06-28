//! Security infrastructure for Rubix-PingPongzz.
//!
//! This crate provides cryptographic primitives, Noise KK handshakes,
//! secure transport, and encrypted key storage. It depends only on the
//! domain crate for `Fingerprint`, `Identity`, and error conversion.
//!
//! # Architecture
//! This crate is part of the **Infrastructure** layer in Clean Architecture.
//! It must **never** import application or UI crates.
//!
//! # Security Guarantees
//! - All key material is zeroized on drop (via `zeroize`).
//! - Passphrase‑derived keys use Argon2id (memory‑hard, GPU‑resistant).
//! - Noise_KK_25519_ChaChaPoly_BLAKE2s provides mutual authentication.
//! - Ed25519 identity binding prevents key substitution attacks.
//! - Transport enforces max message size and prevents replay (via Noise nonces).
//! - Handshakes are timeout‑aware and cancellable.
//!
//! # Performance
//! - Handshake: < 10 ms for two round‑trips.
//! - Encryption: ~1 ms for 64 KB messages.
//! - Key derivation: ~100 ms with Argon2id (64 MB, 3 iterations).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]

/// Error types and result aliases for the security layer.
pub mod error;
/// Fingerprint derivation from public key material.
pub mod fingerprint;
/// Cryptographic key primitives (Ed25519, X25519, identity bundles).
pub mod keys;
/// Noise protocol handshake, identity binding, and secure transport.
pub mod noise;
/// Encrypted key storage with passphrase-derived keys.
pub mod storage;

// Re‑export core error type and result alias
pub use error::{SecurityError, SecurityResult};

// Re‑export all key types (both public and keypairs)
pub use keys::ed25519::{Ed25519Keypair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
pub use keys::x25519::{X25519Keypair, X25519PublicKey, X25519SecretKey};
pub use keys::identity_keys::IdentityKeys;

// Re‑export fingerprint derivation
pub use fingerprint::derive::derive_fingerprint;

// Re‑export Noise handshake, identity binding, and transport
pub use noise::handshake::{
    NoiseHandshake,
    NonceCache,
    run_initiator_handshake,
    run_responder_handshake,
    HANDSHAKE_TIMEOUT_SECS,
};
pub use noise::identity_bind::{IdentityBindPayload, VerifiedIdentity};
pub use noise::transport::{Transport, MAX_TRANSPORT_FRAME_SIZE, MAX_TRANSPORT_MSG_SIZE};

// Re‑export secure storage
pub use storage::secure_store::SecureStore;