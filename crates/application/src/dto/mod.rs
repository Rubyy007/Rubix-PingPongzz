//! Data Transfer Objects for the UI ↔ Application boundary.
//!
//! DTOs are plain serializable structs with **no business logic**.
//! All validation and domain conversion happens in use cases.

pub mod message_dto;
pub mod peer_dto;