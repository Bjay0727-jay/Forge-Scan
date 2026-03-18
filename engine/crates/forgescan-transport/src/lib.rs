//! ForgeScan Transport - gRPC server/client for scanner-platform communication
//!
//! This crate provides:
//! - gRPC client/server for real-time scan streaming (tonic/protobuf)
//! - REST API client for Cloudflare Workers-based platform communication
//! - Message types for scan tasks, events, and findings

pub mod client;
pub mod grpc_client;
pub mod grpc_server;
pub mod rest_client;
pub mod server;
pub mod types;

/// Generated protobuf types for inter-service communication
pub mod proto {
    /// Common types (Severity, CheckCategory, ComplianceRef, etc.)
    pub mod common {
        tonic::include_proto!("forgescan.common");
    }
    /// Scan result types (Finding, ScanResult, ScanStats, etc.)
    pub mod results {
        tonic::include_proto!("forgescan.results");
    }
    /// Scan service (ScanService, ScanTask, ScanEvent, etc.)
    pub mod scan {
        tonic::include_proto!("forgescan.scan");
    }
    /// Agent service (AgentService, AgentRegistration, etc.)
    pub mod agent {
        tonic::include_proto!("forgescan.agent");
    }
}

pub use client::ScannerClient;
pub use grpc_server::ForgeScanGrpcServer;
pub use rest_client::{
    ApiTask, AssetPayload, CaptureStatsPayload, FindingPayload, PortPayload, RestApiClient,
    RestClientConfig, RestClientError, TaskResultsPayload,
};
pub use server::ScanServiceServer;
pub use types::*;
