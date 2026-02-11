//! ForgeScan Checks - Check registry, YAML parser, and check loader
//!
//! This crate provides:
//! - `CheckRegistry`: Index of all available vulnerability checks
//! - YAML parser for declarative check definitions
//! - Check loader that converts definitions into executable checks

pub mod loader;
pub mod registry;
pub mod yaml_check;

pub use registry::CheckRegistry;
pub use yaml_check::YamlCheck;
