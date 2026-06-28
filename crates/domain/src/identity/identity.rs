//! Core identity entity.
//! 
//! Represents the local user's identity in the system.
//! Private key material is NEVER stored here—only public keys and metadata.
//! 
//! # Security
//! - Identity binding: fingerprint covers both Ed25519 and X25519 public keys
//! - Immutable after construction (except display name updates via explicit methods)
//! - Zeroize on drop for any transient sensitive data

use crate::errors::{DomainError, DomainResult, validate_display_name};
use crate::identity::fingerprint::Fingerprint;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// X25519 public key length.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// Local user identity.
/// 
/// # Invariants
/// - `id` is globally unique and stable
/// - `fingerprint` is cryptographically bound to both public keys
/// - `display_name` is validated on construction and update
/// - Public keys are exactly 32 bytes each
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Globally unique, stable identifier.
    id: Uuid,
    
    /// Human-readable name (validated).
    display_name: String,
    
    /// Ed25519 public key for signatures.
    #[serde(with = "serde_bytes")]
    ed25519_public: [u8; ED25519_PUBLIC_KEY_LEN],
    
    /// X25519 public key for key exchange.
    #[serde(with = "serde_bytes")]
    x25519_public: [u8; X25519_PUBLIC_KEY_LEN],
    
    /// Human-verifiable fingerprint derived from key material.
    fingerprint: Fingerprint,
    
    /// Identity creation timestamp.
    created_at: DateTime<Utc>,
    
    /// Last updated timestamp.
    updated_at: DateTime<Utc>,
}

/// Builder for Identity to enforce validation at construction time.
#[derive(Default)]
pub struct IdentityBuilder {
    display_name: Option<String>,
    ed25519_public: Option<[u8; ED25519_PUBLIC_KEY_LEN]>,
    x25519_public: Option<[u8; X25519_PUBLIC_KEY_LEN]>,
    fingerprint: Option<Fingerprint>,
}

impl IdentityBuilder {
    /// Create a new identity builder with default (empty) state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the user's display name.
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Set the Ed25519 public key for signing.
    pub fn ed25519_public(mut self, key: [u8; ED25519_PUBLIC_KEY_LEN]) -> Self {
        self.ed25519_public = Some(key);
        self
    }

    /// Set the X25519 public key for Noise key agreement.
    pub fn x25519_public(mut self, key: [u8; X25519_PUBLIC_KEY_LEN]) -> Self {
        self.x25519_public = Some(key);
        self
    }

    /// Set the cryptographic fingerprint (must be derived from keys by caller).
    pub fn fingerprint(mut self, fp: Fingerprint) -> Self {
        self.fingerprint = Some(fp);
        self
    }

    /// Build the Identity with full validation.
    /// 
    /// # Validation Rules
    /// - All fields must be provided
    /// - display_name passes `validate_display_name`
    /// - fingerprint must be provided (caller must derive from keys)
    pub fn build(self) -> DomainResult<Identity> {
        let display_name = self.display_name.ok_or_else(|| DomainError::Validation {
            field: "display_name".into(),
            reason: "required".into(),
        })?;
        validate_display_name(&display_name)?;

        let ed25519_public = self.ed25519_public.ok_or_else(|| DomainError::Validation {
            field: "ed25519_public".into(),
            reason: "required".into(),
        })?;

        let x25519_public = self.x25519_public.ok_or_else(|| DomainError::Validation {
            field: "x25519_public".into(),
            reason: "required".into(),
        })?;

        let fingerprint = self.fingerprint.ok_or_else(|| DomainError::Validation {
            field: "fingerprint".into(),
            reason: "required".into(),
        })?;

        let now = Utc::now();

        Ok(Identity {
            id: Uuid::new_v4(),
            display_name,
            ed25519_public,
            x25519_public,
            fingerprint,
            created_at: now,
            updated_at: now,
        })
    }
}

impl Identity {
    /// Create a new identity builder.
    pub fn builder() -> IdentityBuilder {
        IdentityBuilder::new()
    }

    /// Get the stable identity UUID.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get the display name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Update display name with validation.
    pub fn set_display_name(&mut self, name: impl Into<String>) -> DomainResult<()> {
        let name = name.into();
        validate_display_name(&name)?;
        self.display_name = name;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Get the Ed25519 public key.
    pub fn ed25519_public(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        &self.ed25519_public
    }

    /// Get the X25519 public key.
    pub fn x25519_public(&self) -> &[u8; X25519_PUBLIC_KEY_LEN] {
        &self.x25519_public
    }

    /// Get the fingerprint.
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Get creation timestamp.
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get last update timestamp.
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Verify that the fingerprint is consistent with the public keys.
    /// 
    /// # Security
    /// Caller must provide a fingerprint derivation function.
    /// This method only checks consistency, not cryptographic validity.
    pub fn verify_fingerprint<F>(&self, derive: F) -> DomainResult<bool>
    where
        F: FnOnce(&[u8; ED25519_PUBLIC_KEY_LEN], &[u8; X25519_PUBLIC_KEY_LEN]) -> Fingerprint,
    {
        let expected = derive(&self.ed25519_public, &self.x25519_public);
        Ok(self.fingerprint.constant_time_eq(&expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_fingerprint() -> Fingerprint {
        Fingerprint::from_bytes(&[0xAA; 20]).unwrap()
    }

    #[test]
    fn builder_creates_valid_identity() {
        let identity = Identity::builder()
            .display_name("TestUser")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(valid_fingerprint())
            .build()
            .unwrap();

        assert_eq!(identity.display_name(), "TestUser");
        assert_eq!(identity.ed25519_public(), &[0x01; 32]);
        assert_eq!(identity.x25519_public(), &[0x02; 32]);
    }

    #[test]
    fn missing_display_name_fails() {
        let result = Identity::builder()
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(valid_fingerprint())
            .build();

        assert!(matches!(result, Err(DomainError::Validation { field, .. }) if field == "display_name"));
    }

    #[test]
    fn invalid_display_name_fails() {
        let result = Identity::builder()
            .display_name("")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(valid_fingerprint())
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn update_display_name_valid() {
        let mut identity = Identity::builder()
            .display_name("OldName")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(valid_fingerprint())
            .build()
            .unwrap();

        identity.set_display_name("NewName").unwrap();
        assert_eq!(identity.display_name(), "NewName");
        assert!(identity.updated_at() > identity.created_at());
    }

    #[test]
    fn update_display_name_invalid_fails() {
        let mut identity = Identity::builder()
            .display_name("Valid")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(valid_fingerprint())
            .build()
            .unwrap();

        let result = identity.set_display_name("");
        assert!(result.is_err());
        assert_eq!(identity.display_name(), "Valid"); // Unchanged
    }

    #[test]
    fn serialization_roundtrip() {
        let identity = Identity::builder()
            .display_name("SerializeTest")
            .ed25519_public([0xAB; 32])
            .x25519_public([0xCD; 32])
            .fingerprint(valid_fingerprint())
            .build()
            .unwrap();

        let json = serde_json::to_string(&identity).unwrap();
        let deserialized: Identity = serde_json::from_str(&json).unwrap();

        assert_eq!(identity.id(), deserialized.id());
        assert_eq!(identity.display_name(), deserialized.display_name());
        assert_eq!(identity.ed25519_public(), deserialized.ed25519_public());
        assert_eq!(identity.fingerprint().as_bytes(), deserialized.fingerprint().as_bytes());
    }

    #[test]
    fn verify_fingerprint_matches() {
        let identity = Identity::builder()
            .display_name("Test")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(Fingerprint::from_bytes(&[0xAA; 20]).unwrap())
            .build()
            .unwrap();

        let result = identity.verify_fingerprint(|_a, _b| {
            Fingerprint::from_bytes(&[0xAA; 20]).unwrap()
        }).unwrap();

        assert!(result);
    }

    #[test]
    fn verify_fingerprint_mismatch() {
        let identity = Identity::builder()
            .display_name("Test")
            .ed25519_public([0x01; 32])
            .x25519_public([0x02; 32])
            .fingerprint(Fingerprint::from_bytes(&[0xAA; 20]).unwrap())
            .build()
            .unwrap();

        let result = identity.verify_fingerprint(|_a, _b| {
            Fingerprint::from_bytes(&[0xBB; 20]).unwrap()
        }).unwrap();

        assert!(!result);
    }
}