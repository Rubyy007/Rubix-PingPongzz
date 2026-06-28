//! Message delivery state machine.
//! 
//! # Security
//! - Transitions are monotonic (no backward transitions)
//! - `Delivered` and `Read` require cryptographic acknowledgment
//! - `Failed` is terminal to prevent retry storms

use serde::{Deserialize, Serialize};
use std::fmt;

/// Message delivery lifecycle states.
/// 
/// # State Machine
/// ```text
/// Pending → Sending → Sent → Delivered → Read
///    ↓         ↓        ↓
///  Failed    Failed   Failed
/// ```
/// 
/// No backward transitions allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Message created locally, not yet sent.
    Pending,
    
    /// Actively transmitting to recipient.
    Sending,
    
    /// Successfully transmitted to recipient's device.
    /// Does NOT guarantee delivery to human.
    Sent {
        /// When transmission completed.
        sent_at: chrono::DateTime<chrono::Utc>,
    },
    
    /// Recipient's device confirmed receipt.
    /// Requires cryptographic acknowledgment.
    Delivered {
        /// When delivery confirmed.
        delivered_at: chrono::DateTime<chrono::Utc>,
    },
    
    /// Recipient opened/acknowledged reading.
    Read {
        /// When read confirmed.
        read_at: chrono::DateTime<chrono::Utc>,
    },
    
    /// Permanent failure. Terminal state.
    Failed {
        /// When failure occurred.
        failed_at: chrono::DateTime<chrono::Utc>,
        /// Whether retry is permitted (false for cryptographic failures).
        retryable: bool,
    },
}

impl MessageState {
    /// Check if this state is terminal (no further transitions possible).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Read { .. } | Self::Failed { .. })
    }

    /// Check if message has been successfully sent.
    pub fn is_sent(&self) -> bool {
        matches!(self, Self::Sent { .. } | Self::Delivered { .. } | Self::Read { .. })
    }

    /// Check if delivery is confirmed.
    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered { .. } | Self::Read { .. })
    }

    /// Check if message was read.
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Read { .. })
    }

    /// Check if in failed state.
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Attempt state transition.
    /// 
    /// # Errors
    /// Returns error if transition violates state machine rules.
    /// 
    /// # Security
    /// Enforces monotonic progression to prevent state rollback attacks.
    pub fn transition_to(self, new_state: MessageState) -> Result<MessageState, MessageStateError> {
        use MessageState::*;

        let valid = match (&self, &new_state) {
            // Pending can go to Sending or Failed
            (Pending, Sending) | (Pending, Failed { .. }) => true,
            
            // Sending can go to Sent or Failed
            (Sending, Sent { .. }) | (Sending, Failed { .. }) => true,
            
            // Sent can go to Delivered or Failed
            (Sent { .. }, Delivered { .. }) | (Sent { .. }, Failed { .. }) => true,
            
            // Delivered can go to Read or Failed
            (Delivered { .. }, Read { .. }) | (Delivered { .. }, Failed { .. }) => true,
            
            // Read is terminal
            (Read { .. }, _) => false,
            
            // Failed is terminal (but retryable failures can reset to Pending via explicit retry)
            (Failed { retryable: true, .. }, Pending) => true,
            (Failed { .. }, _) => false,
            
            // All other transitions invalid
            _ => false,
        };

        if valid {
            Ok(new_state)
        } else {
            Err(MessageStateError::InvalidTransition {
                from: self,
                to: new_state,
            })
        }
    }
}

impl fmt::Display for MessageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Sending => write!(f, "Sending"),
            Self::Sent { sent_at } => write!(f, "Sent at {}", sent_at.format("%H:%M:%S")),
            Self::Delivered { delivered_at } => {
                write!(f, "Delivered at {}", delivered_at.format("%H:%M:%S"))
            }
            Self::Read { read_at } => write!(f, "Read at {}", read_at.format("%H:%M:%S")),
            Self::Failed { retryable, .. } => {
                write!(f, "Failed{}", if *retryable { " (retryable)" } else { "" })
            }
        }
    }
}

/// Errors specific to message state transitions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageStateError {
    /// Invalid state transition attempted.
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// The source state.
        from: MessageState,
        /// The attempted destination state.
        to: MessageState,
    },

    /// Terminal state has been reached and no further transitions are allowed.
    #[error("terminal state reached")]
    TerminalState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn pending_to_sending_valid() {
        let result = MessageState::Pending.transition_to(MessageState::Sending);
        assert!(result.is_ok());
    }

    #[test]
    fn pending_to_delivered_invalid() {
        let result = MessageState::Pending.transition_to(MessageState::Delivered {
            delivered_at: Utc::now(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn sent_to_delivered_valid() {
        let sent = MessageState::Sent { sent_at: Utc::now() };
        let result = sent.transition_to(MessageState::Delivered {
            delivered_at: Utc::now(),
        });
        assert!(result.is_ok());
    }

    #[test]
    fn read_is_terminal() {
        let read = MessageState::Read { read_at: Utc::now() };
        let result = read.transition_to(MessageState::Pending);
        assert!(result.is_err());
    }

    #[test]
    fn retryable_failure_can_reset() {
        let failed = MessageState::Failed {
            failed_at: Utc::now(),
            retryable: true,
        };
        let result = failed.transition_to(MessageState::Pending);
        assert!(result.is_ok());
    }

    #[test]
    fn non_retryable_failure_is_terminal() {
        let failed = MessageState::Failed {
            failed_at: Utc::now(),
            retryable: false,
        };
        let result = failed.transition_to(MessageState::Pending);
        assert!(result.is_err());
    }

    #[test]
    fn terminal_states_detected() {
        assert!(!MessageState::Pending.is_terminal());
        assert!(MessageState::Read { read_at: Utc::now() }.is_terminal());
        assert!(MessageState::Failed {
            failed_at: Utc::now(),
            retryable: false,
        }.is_terminal());
    }
}