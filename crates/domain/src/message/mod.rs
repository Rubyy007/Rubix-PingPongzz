//! Message module exports.
//!
//! Contains chat message entities, delivery state machine, and content types.

pub mod message;
pub mod message_state;

pub use message::{ContentType, Message, MessageBuilder, MAX_RECIPIENTS};
pub use message_state::{MessageState, MessageStateError};