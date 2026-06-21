//! Human-verifiable identity fingerprints.
//! 
//! Fingerprints provide a short, human-comparable string derived from
//! public key material. They are used for out-of-band verification.
//! 
//! # Security
//! - Uses BLAKE3-256 truncated to 160 bits (20 bytes) for collision resistance
//! - Constant-time comparison to prevent timing attacks
//! - Canonical text representation prevents visual spoofing

use crate::errors::{DomainError, DomainResult};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of raw fingerprint bytes.
pub const FINGERPRINT_BYTES: usize = 20;

/// Length of formatted fingerprint string (40 hex chars + 4 separators).
pub const FINGERPRINT_STRING_LEN: usize = 44;

/// A fingerprint derived from public key material for human verification.
/// 
/// # Invariants
/// - Inner bytes are exactly `FINGERPRINT_BYTES` (20) in length
/// - Immutable after construction
/// - Securely zeroized on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    bytes: [u8; FINGERPRINT_BYTES],
}

impl Fingerprint {
    /// Create a fingerprint from raw bytes.
    /// 
    /// # Errors
    /// Returns `DomainError::Validation` if bytes length is incorrect.
    /// 
    /// # Security
    /// Does not validate cryptographic properties—caller must ensure
    /// bytes are derived from a secure hash of public key material.
    pub fn from_bytes(bytes: &[u8]) -> DomainResult<Self> {
        if bytes.len() != FINGERPRINT_BYTES {
            return Err(DomainError::Validation {
                field: "fingerprint".into(),
                reason: format!("expected {} bytes, got {}", FINGERPRINT_BYTES, bytes.len()),
            });
        }
        let mut arr = [0u8; FINGERPRINT_BYTES];
        arr.copy_from_slice(bytes);
        Ok(Self { bytes: arr })
    }

    /// Create a fingerprint from a hex string (with or without separators).
    /// 
    /// Accepts formats: `A1B2C3...` or `A1B2-C3D4-...`
    pub fn from_hex(hex: &str) -> DomainResult<Self> {
        let cleaned: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if cleaned.len() != FINGERPRINT_BYTES * 2 {
            return Err(DomainError::Validation {
                field: "fingerprint".into(),
                reason: format!("expected {} hex chars, got {}", FINGERPRINT_BYTES * 2, cleaned.len()),
            });
        }
        let mut bytes = [0u8; FINGERPRINT_BYTES];
        for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| DomainError::Validation {
                field: "fingerprint".into(),
                reason: "invalid hex encoding".into(),
            })?;
            bytes[i] = u8::from_str_radix(hex_str, 16).map_err(|_| DomainError::Validation {
                field: "fingerprint".into(),
                reason: "invalid hex digit".into(),
            })?;
        }
        Ok(Self { bytes })
    }

    /// Get the raw fingerprint bytes.
    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.bytes
    }

    /// Constant-time comparison with another fingerprint.
    /// 
    /// # Security
    /// Uses `subtle::ConstantTimeEq` to prevent timing attacks.
    /// Do NOT use `==` for security-critical comparisons.
    pub fn constant_time_eq(&self, other: &Fingerprint) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }

    /// Format as human-readable grouped hex: `A1B2-C3D4-E5F6-7890-1234`
    pub fn to_formatted_string(&self) -> String {
        let hex = hex::encode(self.bytes).to_ascii_uppercase();
        let mut result = String::with_capacity(FINGERPRINT_STRING_LEN);
        for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                result.push('-');
            }
            result.push_str(std::str::from_utf8(chunk).unwrap());
        }
        result
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_formatted_string())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_formatted_string())
    }
}

impl serde::Serialize for Fingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.bytes))
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_bytes_construction() {
        let bytes = [0xA1u8, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x78, 0x90,
                     0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                     0x11, 0x22, 0x33, 0x44];
        let fp = Fingerprint::from_bytes(&bytes).unwrap();
        assert_eq!(fp.as_bytes(), &bytes);
    }

    #[test]
    fn wrong_byte_length_fails() {
        let result = Fingerprint::from_bytes(&[0u8; 19]);
        assert!(matches!(result, Err(DomainError::Validation { .. })));
    }

    #[test]
    fn hex_parsing_with_separators() {
        let fp = Fingerprint::from_hex("A1B2-C3D4-E5F6-7890-1234-5678-9ABC-DEF0-1122-3344").unwrap();
        assert_eq!(fp.as_bytes()[0], 0xA1);
        assert_eq!(fp.as_bytes()[19], 0x44);
    }

    #[test]
    fn hex_parsing_without_separators() {
        let fp = Fingerprint::from_hex("A1B2C3D4E5F67890123456789ABCDEF011223344").unwrap();
        assert_eq!(fp.as_bytes()[0], 0xA1);
    }

    #[test]
    fn formatted_string_length() {
        let bytes = [0xFFu8; 20];
        let fp = Fingerprint::from_bytes(&bytes).unwrap();
        let s = fp.to_formatted_string();
        assert_eq!(s.len(), FINGERPRINT_STRING_LEN);
        assert_eq!(s, "FFFF-FFFF-FFFF-FFFF-FFFF-FFFF-FFFF-FFFF-FFFF-FFFF");
    }

    #[test]
    fn constant_time_equality() {
        let a = Fingerprint::from_bytes(&[0xAA; 20]).unwrap();
        let b = Fingerprint::from_bytes(&[0xAA; 20]).unwrap();
        let c = Fingerprint::from_bytes(&[0xBB; 20]).unwrap();
        
        assert!(a.constant_time_eq(&b));
        assert!(!a.constant_time_eq(&c));
    }

    #[test]
    fn display_does_not_expose_raw_bytes() {
        let fp = Fingerprint::from_bytes(&[0xFF; 20]).unwrap();
        let display = format!("{}", fp);
        assert!(!display.contains('\0'));
        assert_eq!(display.len(), FINGERPRINT_STRING_LEN);
    }

    #[test]
    fn serialization_roundtrip() {
        let bytes = [0x12u8, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                     0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                     0x99, 0xAA, 0xBB, 0xCC];
        let fp = Fingerprint::from_bytes(&bytes).unwrap();
        
        let serialized = serde_json::to_string(&fp).unwrap();
        let deserialized: Fingerprint = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(fp.as_bytes(), deserialized.as_bytes());
    }
}