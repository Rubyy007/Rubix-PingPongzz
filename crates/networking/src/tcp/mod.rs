//! TCP networking with Noise encryption.

pub mod client;
pub mod server;
pub mod connection;
pub mod connection_manager;

pub use client::TcpClient;
pub use server::TcpServer;
pub use connection::EncryptedConnection;
pub use connection_manager::{ConnectionManager, PeerInfo};