//! UI screens for Rubix-PingPongzz.
//!
//! Each screen is a pure function that renders into an `egui::Ui`.
//! No screen contains business logic — all actions are dispatched via `UiCommand`.

pub mod chat_screen;
pub mod profile_screen;
pub mod settings_screen;

pub use chat_screen::render as chat;
pub use profile_screen::render as profile;
pub use settings_screen::render as settings;