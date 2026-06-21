//! Desktop application crate for Rubix-PingPongzz.
//!
//! This crate is the composition root — it wires all infrastructure
//! implementations into the Application layer's port traits.
//!
//! # Clean Architecture Compliance
//! - `main.rs` — entry point, runtime creation.
//! - `bootstrap.rs` — dependency injection (infrastructure → ports).
//! - `app.rs` — eframe App implementation, event loop.
//!
//! No business logic lives here. All logic is in Application and Domain.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod app;
pub mod bootstrap;

pub use app::RubixApp;