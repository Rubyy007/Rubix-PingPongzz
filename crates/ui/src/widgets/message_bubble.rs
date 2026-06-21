//! Message bubble widget for chat display.
//!
//! # Security
//! - Only renders `MessageResponse` DTO fields (no raw content).
//! - Preview is already truncated by the use case (≤256 chars).

use application::dto::message_dto::{MessageResponse, MessageStateDto};
use egui::*;

/// Render a message bubble.
///
/// # Layout
/// - Sent messages: aligned right, blue background.
/// - Received messages: aligned left, dark background.
/// - Status indicator below content.
pub fn render(ui: &mut Ui, msg: &MessageResponse, is_sent: bool) {
    let align = if is_sent { Align::RIGHT } else { Align::LEFT };
    let bg_color = if is_sent {
        Color32::from_rgb(0, 120, 215)
    } else {
        Color32::from_rgb(50, 50, 55)
    };
    let text_color = Color32::WHITE;

    ui.with_layout(Layout::top_down(align), |ui| {
        // egui 0.28: Frame uses rounding (Rounding struct)
        let frame = Frame::default()
            .fill(bg_color)
            .rounding(Rounding::same(8.0))
            .inner_margin(Margin::same(10.0));
        
        frame.show(ui, |ui| {
            ui.set_max_width(400.0);
            
            // Header: sender + timestamp
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&msg.sender_fingerprint)
                        .monospace()
                        .size(10.0)
                        .color(Color32::from_rgb(200, 200, 220)),
                );
                ui.label(
                    RichText::new(&msg.created_at)
                        .size(10.0)
                        .color(Color32::from_rgb(150, 150, 170)),
                );
            });

            // Content
            ui.label(RichText::new(&msg.content_preview).color(text_color).size(13.0));

            // Status indicator
            render_status(ui, &msg.state);
        });
    });
}

/// Render delivery status indicator.
fn render_status(ui: &mut Ui, state: &MessageStateDto) {
    let (text, color) = match state {
        MessageStateDto::Pending => ("⏳ Pending", Color32::YELLOW),
        MessageStateDto::Sending => ("📤 Sending…", Color32::YELLOW),
        MessageStateDto::Sent { at } => (format!("✓ Sent {}", at).as_str(), Color32::from_rgb(0, 200, 180)),
        MessageStateDto::Delivered { at } => (format!("✓✓ Delivered {}", at).as_str(), Color32::GREEN),
        MessageStateDto::Read { at } => (format!("✓✓ Read {}", at).as_str(), Color32::CYAN),
        MessageStateDto::Failed { at, retryable } => {
            let label = if *retryable {
                format!("✗ Failed {} (retryable)", at)
            } else {
                format!("✗ Failed {} (permanent)", at)
            };
            (label.as_str(), Color32::from_rgb(255, 80, 100))
        }
    };

    ui.label(RichText::new(text).size(10.0).color(color));
}