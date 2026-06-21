//! Port traits (dependency inversion boundaries).
//!
//! Infrastructure crates (networking, persistence, security, notifications)
//! implement these traits. Application depends only on Domain + these traits.

pub mod network_port;
pub mod notification_port;
pub mod persistence_port;
pub mod security_port;
pub mod trust_port;