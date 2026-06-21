//! UI widgets for Rubix-PingPongzz.
//!
//! Pure rendering functions — no business logic.

pub mod message_bubble;
pub mod peer_list;
pub mod status_indicator;

pub use message_bubble::render as message_bubble;
pub use peer_list::render as peer_list;
pub use status_indicator::render as status_indicator;