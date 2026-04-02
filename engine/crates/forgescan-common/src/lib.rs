//! ForgeScan Common - Shared utilities: logging, configuration, crypto helpers
//!
//! This crate provides common functionality used across all ForgeScan crates.

pub mod config;
pub mod crypto;
pub mod logging;
pub mod scope;

pub use config::{Config, ConfigBuilder};
pub use logging::init_logging;
pub use scope::{ScopeConfig, ScopeValidator};
