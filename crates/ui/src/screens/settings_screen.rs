//! Settings screen — theme, notifications, and discovery preferences.
//!
//! # Performance
//! - Settings are applied immediately (no restart required).
//! - Discovery timeout is bounded to 1-60 seconds.

use crate::{AppController, UiCommand, UiState};
use egui::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Minimum discovery timeout (seconds).
const MIN_DISCOVERY_TIMEOUT: u64 = 1;

/// Maximum discovery timeout (seconds).
const MAX_DISCOVERY_TIMEOUT: u64 = 60;

/// Render the settings screen.
pub fn render(ui: &mut Ui, _ctx: &Context, state: &Arc<RwLock<UiState>>, controller: &AppController) {
    let state_read = state.blocking_read();
    let dark_mode = state_read.dark_mode;
    let notifications_enabled = state_read.notifications_enabled;
    let discovery_timeout = state_read.discovery_timeout_secs;
    drop(state_read);

    ui.heading("⚙️ Settings");
    ui.separator();

    // ── Appearance ───────────────────────────────────────────────────────
    egui::Frame::default()
        .fill(Color32::from_rgb(28, 28, 36))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.heading("Appearance");
            
            let mut dark = dark_mode;
            ui.checkbox(&mut dark, "Dark Mode");
            if dark != dark_mode {
                controller.send_command(UiCommand::UpdateSettings {
                    dark_mode: dark,
                    notifications_enabled,
                    discovery_timeout,
                });
            }
        });

    ui.separator();

    // ── Notifications ────────────────────────────────────────────────────
    egui::Frame::default()
        .fill(Color32::from_rgb(28, 28, 36))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.heading("Notifications");
            
            let mut notif = notifications_enabled;
            ui.checkbox(&mut notif, "Enable OS Notifications");
            ui.label(RichText::new("Show toast notifications for incoming messages and peer connections.").size(11.0).color(Color32::GRAY));
            
            if notif != notifications_enabled {
                controller.send_command(UiCommand::UpdateSettings {
                    dark_mode,
                    notifications_enabled: notif,
                    discovery_timeout,
                });
            }
        });

    ui.separator();

    // ── Discovery ───────────────────────────────────────────────────────
    egui::Frame::default()
        .fill(Color32::from_rgb(28, 28, 36))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.heading("Peer Discovery");
            
            ui.label("Discovery Timeout (seconds):");
            let mut timeout = discovery_timeout as f64;
            ui.add(Slider::new(&mut timeout, MIN_DISCOVERY_TIMEOUT as f64..=MAX_DISCOVERY_TIMEOUT as f64).step_by(1.0));
            
            let timeout_u64 = timeout as u64;
            if timeout_u64 != discovery_timeout {
                controller.send_command(UiCommand::UpdateSettings {
                    dark_mode,
                    notifications_enabled,
                    discovery_timeout: timeout_u64.clamp(MIN_DISCOVERY_TIMEOUT, MAX_DISCOVERY_TIMEOUT),
                });
            }
            
            ui.label(RichText::new(format!("Peers will be discovered for up to {} seconds.", timeout_u64)).size(11.0).color(Color32::GRAY));
        });

    ui.separator();

    // ── Security ─────────────────────────────────────────────────────────
    egui::Frame::default()
        .fill(Color32::from_rgb(28, 28, 36))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.heading("Security");
            ui.label(RichText::new("All communications are encrypted with Noise Protocol (X25519 + Ed25519).").size(11.0));
            ui.label(RichText::new("No messages are stored unencrypted.").size(11.0));
            ui.label(RichText::new("No internet connection is required.").size(11.0));
            
            ui.separator();
            ui.label(RichText::new("Protocol: Noise_XX_25519_ChaChaPoly_BLAKE3").monospace().size(10.0).color(Color32::GRAY));
        });

    ui.separator();

    // ── About ────────────────────────────────────────────────────────────
    egui::Frame::default()
        .fill(Color32::from_rgb(28, 28, 36))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.heading("About");
            ui.label("Rubix-PingPongzz v1.0.0");
            ui.label("Secure Offline LAN Messaging");
            ui.label(RichText::new("Built with Rust • Tokio • egui • Noise Protocol").size(10.0).color(Color32::GRAY));
        });
}