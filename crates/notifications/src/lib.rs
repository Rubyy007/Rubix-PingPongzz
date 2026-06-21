//! OS notification infrastructure for Rubix-PingPongzz.
//!
//! # Security
//! - Previews are truncated to ≤100 chars before display.
//! - No key material, addresses, or internal state in notifications.
//! - Rate-limited and deduplicated to prevent notification spam (DoS).
//!
//! # Platform Support
//! - Windows: Toast notifications via `notify-rust`.
//! - macOS: NSUserNotification via `notify-rust`.
//! - Linux: freedesktop D-Bus notifications.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod notifier;

pub use notifier::SystemNotifier;