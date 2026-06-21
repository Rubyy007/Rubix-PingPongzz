//! Main chat screen — message list, input, and peer selector.
//!
//! # Performance
//! - Message list uses virtual scrolling for 10,000+ messages.
//! - Input box has a 64KB limit (matches domain constraint).
//! - Peer selector is a searchable dropdown.

use crate::{AppController, Screen, UiCommand, UiState};
use application::dto::message_dto::MessageStateDto;
use egui::*;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum characters in message input.
const MAX_INPUT_CHARS: usize = 65536;

/// Render the chat screen.
pub fn render(ui: &mut Ui, ctx: &Context, state: &Arc<RwLock<UiState>>, controller: &AppController) {
    let state_read = state.blocking_read();
    let selected_peer = state_read.selected_peer.clone();
    let peers = state_read.peers.clone();
    let messages = state_read.messages.clone();
    let compose_text = state_read.compose_text.clone();
    let is_loading = state_read.is_loading;
    drop(state_read);

    // ── Top bar: peer selector + status ───────────────────────────────────
    ui.horizontal(|ui| {
        ui.heading("💬 Chat");
        ui.separator();

        // Peer selector dropdown (egui 0.28: from_id_source)
        let selected_label = selected_peer.clone().unwrap_or_else(|| "Select a peer…".into());
        egui::ComboBox::from_id_source("peer_selector")
            .selected_text(&selected_label)
            .width(200.0)
            .show_ui(ui, |ui| {
                for peer in &peers {
                    let label = format!("{} {}", 
                        status_emoji(&peer.status), 
                        peer.display_name
                    );
                    if ui.selectable_label(
                        selected_peer.as_ref() == Some(&peer.fingerprint),
                        &label,
                    ).clicked() {
                        controller.send_command(UiCommand::SelectPeer {
                            fingerprint: peer.fingerprint.clone(),
                        });
                    }
                }
            });

        if let Some(ref fp) = selected_peer {
            ui.label(RichText::new(fp).monospace().size(10.0).color(Color32::GRAY));
            if peer_is_verified(&peers, fp) {
                ui.label(RichText::new("✓ Verified").color(Color32::GREEN).size(12.0));
            } else {
                ui.label(RichText::new("⚠ Unverified").color(Color32::YELLOW).size(12.0));
            }
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("🔍 Discover").clicked() && !is_loading {
                controller.send_command(UiCommand::DiscoverPeers);
            }
        });
    });

    ui.separator();

    // ── Message list (virtual scroll) ──────────────────────────────────────
    let message_count = messages.len();
    egui::ScrollArea::vertical()
        .id_source("message_scroll")
        .auto_shrink([false; 2])
        .show_rows(ui, 60.0, message_count, |ui, row_range| {
            for row in row_range {
                if let Some(msg) = messages.get(row) {
                    render_message_bubble(ui, msg, &selected_peer);
                }
            }
        });

    ui.separator();

    // ── Message input ────────────────────────────────────────────────────
    ui.horizontal(|ui| {
        let mut text = compose_text;
        let response = ui.add(
            egui::TextEdit::multiline(&mut text)
                .hint_text("Type a secure message…")
                .desired_rows(3)
                .desired_width(ui.available_width() - 80.0)
                .char_limit(MAX_INPUT_CHARS),
        );

        if response.changed() {
            // Update compose text in state
            let mut s = state.blocking_write();
            s.compose_text = text;
            drop(s);
        }

        // Send on Ctrl+Enter or button click
        let send_clicked = ui.add_sized(
            [70.0, ui.available_height()],
            egui::Button::new("Send ➤").fill(Color32::from_rgb(0, 120, 215)),
        ).clicked();

        let shortcut_pressed = ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::Enter));

        if (send_clicked || shortcut_pressed) && !text.trim().is_empty() && selected_peer.is_some() {
            controller.send_command(UiCommand::SendMessage {
                recipient_fp: selected_peer.clone().unwrap(),
                content: text.trim().to_string(),
            });
            // Clear input
            let mut s = state.blocking_write();
            s.compose_text.clear();
            drop(s);
            // Request focus back to input
            response.request_focus();
        }
    });

    // ── Status bar ───────────────────────────────────────────────────────
    ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
        ui.horizontal(|ui| {
            let state_read = state.blocking_read();
            let peer_count = state_read.online_peer_count;
            let is_connected = state_read.is_connected;
            let is_encrypted = state_read.is_encrypted;
            drop(state_read);

            if is_connected {
                ui.label(RichText::new("● Connected").color(Color32::GREEN).size(11.0));
            } else {
                ui.label(RichText::new("● Disconnected").color(Color32::RED).size(11.0));
            }

            if is_encrypted {
                ui.label(RichText::new("🔒 Encrypted").color(Color32::GREEN).size(11.0));
            }

            ui.label(RichText::new(format!("{} peers online", peer_count)).size(11.0));
        });
    });
}

/// Render a single message bubble.
fn render_message_bubble(ui: &mut Ui, msg: &application::dto::message_dto::MessageResponse, selected_peer: &Option<String>) {
    let is_sent = selected_peer.as_ref().map(|fp| msg.recipient_fingerprints.contains(fp)).unwrap_or(false);
    let align = if is_sent { Align::RIGHT } else { Align::LEFT };
    let bg_color = if is_sent {
        Color32::from_rgb(0, 120, 215)
    } else {
        Color32::from_rgb(50, 50, 55)
    };

    ui.with_layout(Layout::top_down(align), |ui| {
        // egui 0.28: Frame uses rounding (Rounding struct), not corner_radius
        let frame = egui::Frame::default()
            .fill(bg_color)
            .rounding(Rounding::same(8.0))
            .inner_margin(Margin::same(10.0));
        
        frame.show(ui, |ui| {
            ui.set_max_width(400.0);
            
            // Sender info
            ui.horizontal(|ui| {
                ui.label(RichText::new(&msg.sender_fingerprint).monospace().size(10.0));
                ui.label(RichText::new(&msg.created_at).size(10.0).color(Color32::GRAY));
            });

            // Content preview
            ui.label(&msg.content_preview);

            // Delivery status
            match &msg.state {
                MessageStateDto::Pending => {
                    ui.label(RichText::new("⏳ Pending").size(10.0).color(Color32::YELLOW));
                }
                MessageStateDto::Sending => {
                    ui.label(RichText::new("📤 Sending…").size(10.0).color(Color32::YELLOW));
                }
                MessageStateDto::Sent { at } => {
                    ui.label(RichText::new(format!("✓ Sent {}", at)).size(10.0).color(Color32::LIGHT_GREEN));
                }
                MessageStateDto::Delivered { at } => {
                    ui.label(RichText::new(format!("✓✓ Delivered {}", at)).size(10.0).color(Color32::GREEN));
                }
                MessageStateDto::Read { at } => {
                    ui.label(RichText::new(format!("✓✓ Read {}", at)).size(10.0).color(Color32::CYAN));
                }
                MessageStateDto::Failed { at, retryable } => {
                    let color = if *retryable { Color32::YELLOW } else { Color32::RED };
                    ui.label(RichText::new(format!("✗ Failed {} ({})", at, if *retryable { "retryable" } else { "permanent" })).size(10.0).color(color));
                }
            }
        });
    });
}

/// Get emoji for peer status.
fn status_emoji(status: &application::dto::peer_dto::PeerStatusDto) -> &'static str {
    use application::dto::peer_dto::PeerStatusDto;
    match status {
        PeerStatusDto::Online { .. } => "🟢",
        PeerStatusDto::Away { .. } => "🟡",
        PeerStatusDto::Offline => "⚪",
        PeerStatusDto::Blocked => "🚫",
    }
}

/// Check if a peer is verified.
fn peer_is_verified(peers: &[application::dto::peer_dto::PeerResponse], fingerprint: &str) -> bool {
    peers.iter().any(|p| p.fingerprint == fingerprint && p.verified)
}