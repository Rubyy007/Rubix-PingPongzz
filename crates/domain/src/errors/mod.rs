//! Error types and validation for the domain layer.
//!
//! Security note: Errors are designed to minimize information leakage.

pub mod domain_error;

pub use domain_error::{
	DomainError, DomainResult, IdentityError, PeerError, MessageError,
	validate_display_name, validate_message_content,
	MAX_DISPLAY_NAME_LEN, MAX_MESSAGE_CONTENT_LEN, MAX_RECIPIENTS,
};
