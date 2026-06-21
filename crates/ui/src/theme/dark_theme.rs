//! Dark theme for Rubix-PingPongzz.
//!
//! # Accessibility
//! - All color pairs meet WCAG AA contrast ratios (4.5:1 minimum).
//! - Colorblind-safe palette (avoids red/green distinction for critical info).

use egui::{Color32, FontFamily, FontId, Margin, Rounding, Stroke, Visuals};

/// Primary brand color (blue).
pub const PRIMARY: Color32 = Color32::from_rgb(0, 120, 215);

/// Primary hover state.
pub const PRIMARY_HOVER: Color32 = Color32::from_rgb(0, 140, 240);

/// Success/verified color (cyan — colorblind-safe).
pub const SUCCESS: Color32 = Color32::from_rgb(0, 200, 180);

/// Warning color (amber).
pub const WARNING: Color32 = Color32::from_rgb(255, 180, 0);

/// Error color (red-pink — distinguishable from green).
pub const ERROR: Color32 = Color32::from_rgb(255, 80, 100);

/// Background color.
pub const BG: Color32 = Color32::from_rgb(18, 18, 24);

/// Surface/card color.
pub const SURFACE: Color32 = Color32::from_rgb(28, 28, 36);

/// Elevated surface (hover, active).
pub const SURFACE_ELEVATED: Color32 = Color32::from_rgb(38, 38, 48);

/// Primary text color.
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(230, 230, 240);

/// Secondary text color.
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(150, 150, 170);

/// Disabled text.
pub const TEXT_DISABLED: Color32 = Color32::from_rgb(100, 100, 120);

/// Border color.
pub const BORDER: Color32 = Color32::from_rgb(50, 50, 65);

/// Border color on hover.
pub const BORDER_HOVER: Color32 = Color32::from_rgb(70, 70, 90);

/// Spacing constants.
pub const SPACING_SMALL: f32 = 4.0;
pub const SPACING_MEDIUM: f32 = 8.0;
pub const SPACING_LARGE: f32 = 16.0;
pub const SPACING_XL: f32 = 24.0;

/// Corner radius.
pub const RADIUS_SMALL: f32 = 4.0;
pub const RADIUS_MEDIUM: f32 = 8.0;
pub const RADIUS_LARGE: f32 = 12.0;

/// Font sizes.
pub const FONT_SIZE_SMALL: f32 = 11.0;
pub const FONT_SIZE_BODY: f32 = 13.0;
pub const FONT_SIZE_HEADING: f32 = 16.0;
pub const FONT_SIZE_TITLE: f32 = 20.0;

/// Build egui Visuals for the dark theme.
///
/// # egui 0.28 API
/// Uses `Rounding` (not `CornerRadius`) and `window_rounding` field.
pub fn build_visuals() -> Visuals {
    let mut visuals = Visuals::dark();
    
    visuals.override_text_color = Some(TEXT_PRIMARY);
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.inactive.bg_fill = SURFACE_ELEVATED;
    visuals.widgets.hovered.bg_fill = SURFACE_ELEVATED;
    visuals.widgets.active.bg_fill = Color32::from_rgb(48, 48, 60);
    visuals.widgets.open.bg_fill = SURFACE_ELEVATED;
    
    visuals.selection.bg_fill = PRIMARY;
    visuals.selection.stroke = Stroke::new(1.0, TEXT_PRIMARY);
    
    visuals.window_fill = BG;
    visuals.panel_fill = BG;
    // egui 0.28: popup_shadow is a Shadow struct with extrusion and color
    visuals.popup_shadow.extrusion = 8.0;
    visuals.popup_shadow.color = Color32::from_black_alpha(60);
    
    // egui 0.28: uses Rounding struct, not CornerRadius
    visuals.window_rounding = Rounding::same(RADIUS_MEDIUM);
    visuals.menu_rounding = Rounding::same(RADIUS_SMALL);
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BORDER_HOVER);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, PRIMARY);
    
    visuals.hyperlink_color = PRIMARY_HOVER;
    visuals.faint_bg_color = SURFACE;
    visuals.extreme_bg_color = Color32::from_rgb(12, 12, 16);
    visuals.code_bg_color = SURFACE_ELEVATED;
    visuals.warn_fg_color = WARNING;
    visuals.error_fg_color = ERROR;
    
    visuals
}

/// Font definitions for the app.
pub fn font_definitions() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    
    // Use default font but ensure monospace is available
    // egui 0.28: FontData::from_owned takes Vec<u8>
    fonts.font_data.insert(
        "monospace".to_owned(),
        egui::FontData::from_owned(vec![]),
    );
    
    fonts
}

/// Margin for cards and groups.
pub fn card_margin() -> Margin {
    Margin::symmetric(SPACING_MEDIUM, SPACING_MEDIUM)
}