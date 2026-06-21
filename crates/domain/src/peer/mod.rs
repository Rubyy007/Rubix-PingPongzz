pub mod peer;
pub mod peer_status;

pub use peer::{Peer, PeerBuilder, MAX_PEER_ADDRESSES};
pub use peer_status::{PeerStatus, ONLINE_TIMEOUT_SECONDS};