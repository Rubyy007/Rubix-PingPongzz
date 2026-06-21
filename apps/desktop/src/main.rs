//! Desktop entry point for Rubix-PingPongzz.
//!
//! # Architecture
//! This is the composition root — the only place where infrastructure
//! implementations are instantiated and wired into Application use cases.
//!
//! # Startup Sequence
//! 1. Initialize tokio runtime.
//! 2. Initialize tracing subscriber.
//! 3. Bootstrap: create all port implementations and wire use cases.
//! 4. Launch eframe native window.
//! 5. Run event loop until shutdown.

use rubix_desktop::app::RubixApp;
use rubix_desktop::bootstrap::bootstrap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{error, info};

fn main() -> eframe::Result<()> {
    // Initialize tracing before anything else
    tracing_subscriber::fmt()
        .with_env_filter("rubix=info,rubix_desktop=debug")
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("Rubix-PingPongzz v1.0.0 starting…");

    // Create tokio runtime for async operations
    let rt = match Runtime::new() {
        Ok(rt) => Arc::new(rt),
        Err(e) => {
            error!(error = %e, "failed to create tokio runtime");
            std::process::exit(1);
        }
    };

    // Bootstrap: wire all infrastructure into application use cases
    let controller = rt.block_on(async {
        match bootstrap().await {
            Ok(controller) => {
                info!("bootstrap complete — all ports wired");
                controller
            }
            Err(e) => {
                error!(error = %e, "bootstrap failed");
                std::process::exit(1);
            }
        }
    });

    // Native options for eframe 0.28
    // ViewportBuilder API for window configuration
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("Rubix-PingPongzz — Secure LAN Messaging"),
        ..Default::default()
    };

    // Run the app
    // eframe 0.28: AppCreator signature is Box::new(|cc| Ok(Box::new(app)))
    // where cc is &eframe::CreationContext
    let rt_clone = rt.clone();
    eframe::run_native(
        "Rubix-PingPongzz",
        native_options,
        Box::new(move |cc| {
            // Install dark theme visuals
            cc.egui_ctx.set_visuals(ui::theme::dark_theme::build_visuals());
            
            Ok(Box::new(RubixApp::new(
                cc.egui_ctx.clone(),
                rt_clone,
                controller,
            )))
        }),
    )
}