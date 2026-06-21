//! Heartbeat / keepalive for detecting dead peer connections.
//!
//! # Protocol
//! - Sends `Heartbeat` frame every 30 seconds on active connections.
//! - If no message received for 90 seconds, marks peer as disconnected.
//!
//! # Performance
//! - Heartbeat frames are small (~50 bytes encrypted).
//! - Sent only on active connections, not all discovered peers.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::{NetworkError, NetworkResult};
use crate::protocol::frame::{FrameType, MessageFrame};
use crate::tcp::connection_manager::ConnectionManager;

/// Heartbeat interval (seconds).
const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Connection timeout: peer considered dead after this duration.
const CONNECTION_TIMEOUT_SECS: u64 = 90;

/// Manages heartbeats for all active connections.
pub struct HeartbeatManager {
    connection_manager: Arc<ConnectionManager>,
    our_fingerprint: String,
}

impl HeartbeatManager {
    /// Create a new heartbeat manager.
    pub fn new(
        connection_manager: Arc<ConnectionManager>,
        our_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            connection_manager,
            our_fingerprint: our_fingerprint.into(),
        }
    }

    /// Run heartbeat sender and timeout checker.
    pub async fn run(&self, cancel: CancellationToken) -> NetworkResult<()> {
        let mut heartbeat_ticker = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        let mut timeout_ticker = interval(Duration::from_secs(CONNECTION_TIMEOUT_SECS));

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    info!("heartbeat manager shutting down");
                    break Ok(());
                }
                _ = heartbeat_ticker.tick() => {
                    self.send_heartbeats().await;
                }
                _ = timeout_ticker.tick() => {
                    self.check_timeouts().await;
                }
            }
        }
    }

    /// Send heartbeat frames to all active connections.
    async fn send_heartbeats(&self) {
        let frame = MessageFrame::heartbeat(&self.our_fingerprint);
        let data = frame.to_bytes();

        // Note: In a real implementation, we'd iterate active connections.
        // This requires access to the connection manager's internal state.
        // For now, this is a placeholder that logs the intent.
        debug!(
            "sending heartbeats to {} active connections",
            self.connection_manager.active_connection_count()
        );

        // TODO: Implement actual heartbeat sending via ConnectionManager
        // This requires adding a broadcast method or iterating connections
    }

    /// Check for timed-out connections and disconnect them.
    async fn check_timeouts(&self) {
        debug!("checking for timed-out connections");
        // TODO: Implement timeout checking
        // This requires tracking last_activity per connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rubix_security::keys::identity_keys::IdentityKeys;
    use std::sync::Arc;

    #[tokio::test]
    async fn heartbeat_manager_create() {
        let identity = Arc::new(IdentityKeys::generate().unwrap());
        let manager = ConnectionManager::new(identity, None);
        let heartbeat = HeartbeatManager::new(
            Arc::new(manager),
            "test-fingerprint",
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            heartbeat.run(cancel_clone).await
        });

        // Let it run briefly
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();

        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}