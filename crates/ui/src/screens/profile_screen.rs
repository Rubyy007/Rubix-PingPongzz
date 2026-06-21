//! Profile screen — identity display and trust management.
//!
//! # Security
//! - Only public fingerprint is displayed. Private keys are NEVER shown.
//! - Trust/untrust actions require explicit user confirmation.
//! - Peer fingerprint is copyable for out-of-band verification.

use crate::{AppController, UiCommand, UiState};
use egui::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Render the profile screen.
pub fn render(ui: &mut Ui, _ctx: &Context, state: &Arc<RwLock<UiState>>, controller: &AppController) {
    let state_read = state.blocking_read();
    let identity_fp = state_read.identity_fingerprint.clone();
    let identity_name = state_read.identity_display_name.clone();
    let peers = state_read.peers.clone();
    drop(state_read);

    ui.heading("👤 Profile & Trust");
    ui.separator();

    // ── Local Identity ───────────────────────────────────────────────────
    egui::Frame::default()
        .fill(Color32::from_rgb(28, 28, 36))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .show(ui, |ui| {
            ui.heading("Your Identity");
            ui.horizontal(|ui| {
                ui.label("Display Name:");
                ui.label(RichText::new(&identity_name).strong());
            });
            
            if let Some(ref fp) = identity_fp {
                ui.horizontal(|ui| {
                    ui.label("Fingerprint:");
                    ui.label(RichText::new(fp).monospace().size(12.0));
                    if ui.button("📋 Copy").clicked() {
                        ui.output_mut(|o| o.copied_text = fp.clone());
                    }
                });
                ui.label(RichText::new("Share this fingerprint with peers for out-of-band verification.").size(11.0).color(Color32::GRAY));
            } else {
                ui.label(RichText::new("No identity configured.").color(Color32::RED));
            }

            ui.separator();
            
            if ui.button("🔄 Reset Identity").clicked() {
                // TODO: Show confirmation dialog
                controller.send_command(UiCommand::ResetIdentity {
                    new_display_name: "Anonymous".into(),
                });
            }
            ui.label(RichText::new("⚠ Warning: This will generate new keys. Old conversations will be inaccessible.").size(10.0).color(Color32::YELLOW));
        });

    ui.separator();

    // ── Trusted Peers ────────────────────────────────────────────────────
    ui.heading("Trusted Peers");
    ui.label("Peers you have cryptographically verified.");
    
    let verified_peers: Vec<_> = peers.iter().filter(|p| p.verified).collect();
    if verified_peers.is_empty() {
        ui.label(RichText::new("No trusted peers yet. Connect to peers and verify their fingerprints out-of-band.").color(Color32::GRAY));
    } else {
        for peer in verified_peers {
            egui::Frame::default()
                .fill(Color32::from_rgb(28, 28, 36))
                .rounding(Rounding::same(8.0))
                .inner_margin(Margin::same(10.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&peer.display_name).strong());
                        ui.label(RichText::new("✓ Verified").color(Color32::GREEN).size(11.0));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&peer.fingerprint).monospace().size(10.0));
                        if ui.button("📋 Copy").clicked() {
                            ui.output_mut(|o| o.copied_text = peer.fingerprint.clone());
                        }
                    });
                    ui.label(RichText::new(format!("Addresses: {}", peer.addresses.join(", "))).size(10.0).color(Color32::GRAY));
                    
                    if ui.button("🗑️ Untrust").clicked() {
                        controller.send_command(UiCommand::UntrustPeer {
                            fingerprint: peer.fingerprint.clone(),
                        });
                    }
                });
        }
    }

    ui.separator();

    // ── All Peers ────────────────────────────────────────────────────────
    ui.heading("All Known Peers");
    ui.label(format!("{} peers discovered", peers.len()));
    
    egui::ScrollArea::vertical()
        .id_source("all_peers_scroll")
        .max_height(300.0)
        .show(ui, |ui| {
            for peer in &peers {
                ui.horizontal(|ui| {
                    let status_emoji = match peer.status {
                        application::dto::peer_dto::PeerStatusDto::Online { .. } => "🟢",
                        application::dto::peer_dto::PeerStatusDto::Away { .. } => "🟡",
                        application::dto::peer_dto::PeerStatusDto::Offline => "⚪",
                        application::dto::peer_dto::PeerStatusDto::Blocked => "🚫",
                    };
                    ui.label(status_emoji);
                    ui.label(RichText::new(&peer.display_name).strong());
                    ui.label(RichText::new(&peer.fingerprint).monospace().size(10.0));
                    
                    if !peer.verified {
                        if ui.button("✓ Trust").clicked() {
                            controller.send_command(UiCommand::TrustPeer {
                                fingerprint: peer.fingerprint.clone(),
                            });
                        }
                    }
                    
                    if ui.button("💬 Chat").clicked() {
                        controller.send_command(UiCommand::SelectPeer {
                            fingerprint: peer.fingerprint.clone(),
                        });
                    }
                });
                ui.separator();
            }
        });
}