//! System notifier implementation using `notify-rust`.
//!
//! # Security
//! - All preview text is truncated to `MAX_PREVIEW_LEN` (100 chars).
//! - Deduplication prevents rapid-fire notifications from the same sender.
//! - Rate limiting: max 1 notification per sender per `NOTIFICATION_COOLDOWN`.

use application::ports::notification_port::{NotificationError, NotificationPort};
use async_trait::async_trait;
use domain::identity::Fingerprint;
use domain::peer::Peer;
use notify_rust::Notification;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Maximum characters shown in notification preview.
const MAX_PREVIEW_LEN: usize = 100;

/// Cooldown between notifications from the same sender.
const NOTIFICATION_COOLDOWN: Duration = Duration::from_secs(5);

/// Cross-platform system notifier with deduplication and rate limiting.
#[derive(Debug)]
pub struct SystemNotifier {
    /// Last notification time per sender fingerprint (hex).
    last_notify: Mutex<HashMap<String, Instant>>,
}

impl SystemNotifier {
    /// Create a new system notifier.
    pub fn new() -> Self {
        Self {
            last_notify: Mutex::new(HashMap::new()),
        }
    }

    /// Check if notification is allowed for this sender (rate limit + dedup).
    fn is_allowed(&self, sender_fp: &Fingerprint) -> bool {
        let key = sender_fp.to_formatted_string();
        let now = Instant::now();
        let mut map = self.last_notify.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(&last) = map.get(&key) {
            if now - last < NOTIFICATION_COOLDOWN {
                debug!(sender = %key, "notification rate limited");
                return false;
            }
        }
        map.insert(key, now);
        true
    }

    /// Truncate preview to safe length.
    fn truncate_preview(preview: &str) -> String {
        if preview.chars().count() > MAX_PREVIEW_LEN {
            let mut result = String::with_capacity(MAX_PREVIEW_LEN + 3);
            for (i, ch) in preview.chars().enumerate() {
                if i >= MAX_PREVIEW_LEN {
                    result.push('…');
                    break;
                }
                result.push(ch);
            }
            result
        } else {
            preview.to_string()
        }
    }
}

impl Default for SystemNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NotificationPort for SystemNotifier {
    async fn notify_message_received(
        &self,
        sender_fp: &Fingerprint,
        preview: &str,
    ) -> Result<(), NotificationError> {
        if !self.is_allowed(sender_fp) {
            return Ok(()); // Silently drop — not an error
        }

        let truncated = Self::truncate_preview(preview);
        let sender_str = sender_fp.to_formatted_string();

        let result = tokio::task::spawn_blocking(move || {
            Notification::new()
                .summary("Rubix-PingPongzz")
                .subtitle(&format!("Message from {}", sender_str))
                .body(&truncated)
                .icon("dialog-information")
                .timeout(5000)
                .show()
        })
        .await;

        match result {
            Ok(Ok(_)) => {
                info!(sender = %sender_fp, "notification displayed");
                Ok(())
            }
            Ok(Err(e)) => {
                warn!(error = %e, "notification display failed");
                Err(NotificationError::Unavailable)
            }
            Err(e) => {
                error!(error = %e, "notification task panicked");
                Err(NotificationError::Internal)
            }
        }
    }

    async fn notify_peer_connected(&self, peer: &Peer) -> Result<(), NotificationError> {
        if !self.is_allowed(peer.fingerprint()) {
            return Ok(());
        }

        let name = peer.display_name().to_string();
        let fp = peer.fingerprint().to_formatted_string();

        let result = tokio::task::spawn_blocking(move || {
            Notification::new()
                .summary("Rubix-PingPongzz")
                .subtitle(&format!("{} is online", name))
                .body(&format!("Fingerprint: {}", fp))
                .icon("dialog-information")
                .timeout(3000)
                .show()
        })
        .await;

        match result {
            Ok(Ok(_)) => Ok(()),
            _ => Err(NotificationError::Unavailable),
        }
    }

    async fn notify_peer_disconnected(
        &self,
        fingerprint: &Fingerprint,
    ) -> Result<(), NotificationError> {
        // Disconnection notifications are suppressed to avoid noise
        debug!(fp = %fingerprint, "peer disconnected — notification suppressed");
        Ok(())
    }

    async fn notify_identity_reset(
        &self,
        new_fp: &Fingerprint,
    ) -> Result<(), NotificationError> {
        let fp_str = new_fp.to_formatted_string();

        let result = tokio::task::spawn_blocking(move || {
            Notification::new()
                .summary("Rubix-PingPongzz")
                .subtitle("Identity Reset Complete")
                .body(&format!("New fingerprint: {}", fp_str))
                .icon("dialog-warning")
                .timeout(10000)
                .show()
        })
        .await;

        match result {
            Ok(Ok(_)) => Ok(()),
            _ => Err(NotificationError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::identity::Fingerprint;

    fn test_fp() -> Fingerprint {
        Fingerprint::from_bytes(&[0xAA; 20]).unwrap()
    }

    #[test]
    fn truncate_preview_long() {
        let long = "a".repeat(200);
        let truncated = SystemNotifier::truncate_preview(&long);
        assert!(truncated.len() <= 103); // 100 chars + "…"
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn truncate_preview_short() {
        let short = "Hello";
        let truncated = SystemNotifier::truncate_preview(short);
        assert_eq!(truncated, "Hello");
    }

    #[test]
    fn rate_limit_blocks_duplicate() {
        let notifier = SystemNotifier::new();
        let fp = test_fp();
        assert!(notifier.is_allowed(&fp));
        assert!(!notifier.is_allowed(&fp)); // Within cooldown
    }

    #[test]
    fn rate_limit_allows_different_senders() {
        let notifier = SystemNotifier::new();
        let fp1 = Fingerprint::from_bytes(&[0xAA; 20]).unwrap();
        let fp2 = Fingerprint::from_bytes(&[0xBB; 20]).unwrap();
        assert!(notifier.is_allowed(&fp1));
        assert!(notifier.is_allowed(&fp2));
    }
}