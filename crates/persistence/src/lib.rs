// Persistence crate public API.

pub mod error;
pub mod db;
pub mod models;
pub mod repositories;
pub mod migrations;

pub use error::{PersistenceError, PersistenceResult};
