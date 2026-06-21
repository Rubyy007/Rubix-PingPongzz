//! Status indicator widget for the bottom bar.
//!
//! Shows: connection state, encryption status, peer count, network activity.

use egui::*;

/// Render the status indicator bar.
///
/// # Layout
/// Horizontal bar at bottom of window. Fixed height 24px.
pub fn render(ui: &mut Ui, is_connected: bool, is_encrypted: bool, peer_count: usize, is_loading: bool) {
    ui.horizontal(|ui| {
        ui.set_height(24.0);
        
        // Connection status
        let (conn_text, conn_color) = if is_connected {
            ("● Connected", Color32::from_rgb(0, 200, 100))
        } else {
            ("● Disconnected", Color32::from_rgb(255, 80, 100))
        };
        ui.label(RichText::new(conn_text).color(conn_color).size(11.0));
        
        ui.add_space(12.0);
        
        // Encryption status
        let (enc_text, enc_color) = if is_encrypted {
            ("🔒 Encrypted", Color32::from_rgb(0, 200, 180))
        } else {
            ("🔓 Unencrypted", Color32::from_rgb(255, 180, 0))
        };
        ui.label(RichText::new(enc_text).color(enc_color).size(11.0));
        
        ui.add_space(12.0);
        
        // Peer count
        let peer_text = if peer_count == 1 {
            "1 peer online".to_string()
        } else {
            format!("{} peers online", peer_count)
        };
        ui.label(RichText::new(peer_text).size(11.0).color(Color32::from_rgb(150, 150, 170)));
        
        // Loading spinner (egui 0.28: ui.spinner() exists)
        if is_loading {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spinner();
                ui.label(RichText::new("Working…").size(11.0).color(Color32::from_rgb(150, 150, 170)));
            });
        }
    });
}