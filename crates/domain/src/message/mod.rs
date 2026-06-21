pub mod message;
pub mod message_state;

pub use message::{ContentType, Message, MessageBuilder, MAX_RECIPIENTS};
pub use message_state::{MessageState, MessageStateError};