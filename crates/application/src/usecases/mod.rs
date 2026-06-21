//! Application use cases (interactors).
//!
//! Each use case is a stateless struct with injected ports.
//! They orchestrate domain entities and infrastructure without
//! containing business logic themselves.

pub mod connect_peer;
pub mod discover_peer;
pub mod receive_message;
pub mod reset_identity;
pub mod send_message;