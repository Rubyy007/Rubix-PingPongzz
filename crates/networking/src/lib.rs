//! Networking crate for Rubix-PingPongzz.
//!
//! Provides peer discovery (mDNS + UDP), encrypted TCP connections,
//! and connection management for up to 200 peers with 10 active chats.
//!
//! # Architecture
//! This crate is part of the Infrastructure layer in Clean Architecture.
//! It depends on:
//! - `rubix-domain` for peer identity types
//! - `rubix-security` for Noise handshake and encrypted transport
//! - `rubix-persistence` for peer storage (optional, via trait)
//!
//! # Security
//! - All TCP connections use Noise KK pattern with Ed25519 identity binding.
//! - Peer discovery broadcasts only public keys (no secret material).
//! - Unknown peers are accepted at transport level but flagged for application review.
//!
//! # Performance
//! - mDNS discovery: < 10s on typical LAN.
//! - Message latency: < 150ms (LAN RTT + Noise overhead ~1ms).
//! - Connection pool: bounded at 200 peers, 10 active encrypted connections.

#![deny(missing_docs)]

pub mod tcp;
pub mod protocol;
pub mod mdns;
pub mod udp;
pub mod heartbeat;

pub use tcp::{
    client::TcpClient,
    server::TcpServer,
    connection::EncryptedConnection,
    connection_manager::ConnectionManager,
};
pub use protocol::{
    codec::EncryptedFrameCodec,
    frame::{MessageFrame, FrameType},
};
pub use mdns::{advertiser::MdnsAdvertiser, browser::MdnsBrowser};
pub use udp::{beacon::DiscoveryBeacon, broadcaster::UdpBroadcaster, listener::UdpListener};