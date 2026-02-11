//! ForgeScan Transport - gRPC server/client for scanner-platform communication
//!
//! This crate provides:
//! - gRPC client for scanners to connect to the platform
//! - gRPC server for the platform to receive scan results
//! - Message types for scan tasks, events, and findings
//!
//! Note: Full gRPC implementation requires proto compilation with tonic-build.
//! This module provides the Rust types and traits that will integrate with
//! the generated protobuf code.

pub mod client;
pub mod server;
pub mod types;

pub use client::ScannerClient;
pub use server::ScanServiceServer;
pub use types::*;
