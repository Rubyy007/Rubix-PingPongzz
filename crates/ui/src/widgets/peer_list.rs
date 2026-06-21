//! Peer list widget with virtual scrolling.
//!
//! # Performance
//! - Virtual scrolling via `show_rows` for 200+ peers.
//! - Each row is ~40px tall, so 200 peers = ~8000px virtual height.
//! - Selection state is managed externally (UiState).

use application::dto::peer_dto::{PeerResponse, PeerStatusDto};
use egui::*;

/// Height of each peer row in pixels.
const ROW_HEIGHT: f32 = 40.0;

/// Render a scrollable peer list.
///
/// # Returns
/// The fingerprint of the clicked peer, if any.
pub fn render(ui: &mut Ui, peers: &[PeerResponse], selected: &Option<String>) -> Option<String> {
    let mut clicked = None;
    let peer_count = peers.len();

    ScrollArea::vertical()
        .id_source("peer_list")
        .auto_shrink([false; 2])
        .show_rows(ui, ROW_HEIGHT, peer_count, |ui, row_range| {
            for row in row_range {
                if let Some(peer) = peers.get(row) {
                    if render_peer_row(ui, peer, selected.as_ref() == Some(&peer.fingerprint)) {
                        clicked = Some(peer.fingerprint.clone());
                    }
                }
            }
        });

    clicked
}

/// Render a single peer row.
///
/// # Returns
/// `true` if this row was clicked.
fn render_peer_row(ui: &mut Ui, peer: &PeerResponse, is_selected: bool) -> bool {
    let bg_color = if is_selected {
        Color32::from_rgb(0, 100, 180)
    } else {
        Color32::TRANSPARENT
    };

    let response = ui.allocate_ui_with_layout(
        vec2(ui.available_width(), ROW_HEIGHT),
        Layout::left_to_right(Align::Center),
        |ui| {
            let frame = Frame::default()
                .fill(bg_color)
                .rounding(Rounding::same(4.0))
                .inner_margin(Margin::same(6.0));
            
            frame.show(ui, |ui| {
                ui.set_width(ui.available_width());
                
                // Status dot color
                let status_color = match peer.status {
                    PeerStatusDto::Online { .. } => Color32::from_rgb(0, 200, 100),
                    PeerStatusDto::Away { .. } => Color32::from_rgb(255, 180, 0),
                    PeerStatusDto::Offline => Color32::from_rgb(120, 120, 120),
                    PeerStatusDto::Blocked => Color32::from_rgb(255, 80, 100),
                };
                
                // Draw status circle using painter (egui 0.28 compatible)
                let circle_pos = ui.cursor().min + vec2(10.0, ROW_HEIGHT / 2.0);
                ui.painter().circle_filled(circle_pos, 5.0, status_color);
                ui.add_space(20.0);

                // Display name
                ui.label(RichText::new(&peer.display_name).strong().size(13.0));
                
                // Verification badge
                if peer.verified {
                    ui.label(RichText::new("✓").color(Color32::from_rgb(0, 200, 180)).size(12.0));
                }
                
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(&peer.fingerprint[..8])
                            .monospace()
                            .size(10.0)
                            .color(Color32::from_rgb(120, 120, 140)),
                    );
                });
            });
        },
    );

    response.response.clicked()
}