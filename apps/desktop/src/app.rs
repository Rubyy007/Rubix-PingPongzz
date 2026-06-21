//! eframe App implementation for Rubix-PingPongzz.
//!
//! # Architecture
//! `update()` is called every frame by egui (~60 FPS). It must be fast.
//! All async work is delegated to the background task via `AppController`.
//!
//! # Performance
//! - Frame time target: <16ms (60 FPS).
//! - State reads are `blocking_read()` — fast, no await.
//! - Async messages are processed once per frame via `try_recv()`.
//! - Repaint is requested at 60 FPS intervals.

use eframe::egui;
use egui::*;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, trace};
use ui::{AppController, Screen, UiCommand, UiMessage, UiState};

/// Main application struct for eframe.
pub struct RubixApp {
    /// egui context for requesting repaints.
    ctx: egui::Context,
    /// Tokio runtime handle for spawning async tasks.
    _rt: Arc<Runtime>,
    /// UI controller — bridges to Application use cases.
    controller: AppController,
    /// Shutdown flag.
    shutdown: bool,
}

impl RubixApp {
    /// Create a new app instance.
    pub fn new(ctx: egui::Context, rt: Arc<Runtime>, controller: AppController) -> Self {
        Self {
            ctx,
            _rt: rt,
            controller,
            shutdown: false,
        }
    }

    /// Process async messages from the background worker.
    fn process_messages(&mut self) {
        // Use a short-lived tokio task to process messages
        let controller = self.controller.clone();
        let ctx = self.ctx.clone();

        self._rt.spawn(async move {
            controller.process_messages().await;
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        });
    }

    /// Render the navigation sidebar.
    fn render_sidebar(&mut self, ui: &mut Ui) {
        let state_read = self.controller.state.blocking_read();
        let current_screen = state_read.current_screen;
        let identity_name = state_read.identity_display_name.clone();
        drop(state_read);

        ui.vertical(|ui| {
            // App title
            ui.heading(RichText::new("Rubix").size(20.0).strong());
            ui.label(RichText::new("PingPongzz").size(12.0).color(Color32::from_rgb(150, 150, 170)));
            ui.add_space(16.0);

            // Identity info
            ui.group(|ui| {
                ui.label(RichText::new(&identity_name).strong().size(12.0));
                ui.label(RichText::new("Secure LAN Messaging").size(10.0).color(Color32::GRAY));
            });
            ui.add_space(16.0);

            // Navigation buttons
            let nav_button = |ui: &mut Ui, label: &str, screen: Screen, icon: &str| {
                let is_active = current_screen == screen;
                let bg = if is_active {
                    Color32::from_rgb(0, 100, 180)
                } else {
                    Color32::TRANSPARENT
                };

                let response = ui.add_sized(
                    [ui.available_width(), 36.0],
                    Button::new(RichText::new(format!("{} {}", icon, label)).size(13.0))
                        .fill(bg),
                );

                if response.clicked() && !is_active {
                    let mut s = self.controller.state.blocking_write();
                    s.current_screen = screen;
                    drop(s);
                }
                response
            };

            nav_button(ui, "Chat", Screen::Chat, "💬");
            ui.add_space(4.0);
            nav_button(ui, "Profile", Screen::Profile, "👤");
            ui.add_space(4.0);
            nav_button(ui, "Settings", Screen::Settings, "⚙️");

            ui.add_space(ui.available_height() - 60.0);

            // Status bar at bottom of sidebar
            let state_read = self.controller.state.blocking_read();
            let is_connected = state_read.is_connected;
            let peer_count = state_read.online_peer_count;
            let is_encrypted = state_read.is_encrypted;
            drop(state_read);

            ui.horizontal(|ui| {
                let conn_dot = if is_connected { "🟢" } else { "🔴" };
                ui.label(RichText::new(format!("{} {} peers", conn_dot, peer_count)).size(10.0));
            });
            if is_encrypted {
                ui.label(RichText::new("🔒 Encrypted").size(10.0).color(Color32::from_rgb(0, 200, 180)));
            }
        });
    }

    /// Render the main content area based on current screen.
    fn render_content(&mut self, ui: &mut Ui, ctx: &Context) {
        let state_read = self.controller.state.blocking_read();
        let screen = state_read.current_screen;
        drop(state_read);

        match screen {
            Screen::Chat => {
                ui::screens::chat_screen::render(ui, ctx, &self.controller.state, &self.controller);
            }
            Screen::Profile => {
                ui::screens::profile_screen::render(ui, ctx, &self.controller.state, &self.controller);
            }
            Screen::Settings => {
                ui::screens::settings_screen::render(ui, ctx, &self.controller.state, &self.controller);
            }
        }
    }

    /// Render global error banner if present.
    fn render_error_banner(&mut self, ui: &mut Ui) {
        let state_read = self.controller.state.blocking_read();
        let error = state_read.error_banner.clone();
        drop(state_read);

        if let Some(msg) = error {
            let frame = Frame::default()
                .fill(Color32::from_rgb(80, 30, 30))
                .corner_radius(4.0)
                .inner_margin(Margin::same(8.0));

            frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚠️ Error").strong().color(Color32::from_rgb(255, 150, 150)));
                    ui.label(RichText::new(&msg).color(Color32::from_rgb(255, 200, 200)));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("✕ Dismiss").clicked() {
                            self.controller.send_command(UiCommand::ClearError);
                        }
                    });
                });
            });
            ui.add_space(4.0);
        }
    }
}

impl eframe::App for RubixApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.shutdown {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Process async messages from background worker
        self.process_messages();

        // Request repaint at 60 FPS for smooth UI
        ctx.request_repaint_after(std::time::Duration::from_millis(16));

        // Main layout: sidebar + content
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(200.0)
            .show(ctx, |ui| {
                self.render_sidebar(ui);
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_error_banner(ui);
            self.render_content(ui, ctx);
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        info!("application shutting down…");
        self.controller.send_command(UiCommand::Shutdown);
        self.shutdown = true;
    }
}