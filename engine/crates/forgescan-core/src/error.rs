//! Error types for ForgeScan Engine

use thiserror::Error;

/// Result type alias using ForgeScan Error
pub type Result<T> = std::result::Result<T, Error>;

/// ForgeScan error types
#[derive(Error, Debug)]
pub enum Error {
    // === Scanning Errors ===
    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("Target unreachable: {target}")]
    TargetUnreachable { target: String },

    #[error("Connection timeout to {target}:{port}")]
    ConnectionTimeout { target: String, port: u16 },

    #[error("Connection refused by {target}:{port}")]
    ConnectionRefused { target: String, port: u16 },

    #[error("Scan cancelled: {reason}")]
    ScanCancelled { reason: String },

    // === Check Errors ===
    #[error("Check failed: {check_id} - {message}")]
    CheckFailed { check_id: String, message: String },

    #[error("Check not found: {check_id}")]
    CheckNotFound { check_id: String },

    #[error("Invalid check definition: {path} - {message}")]
    InvalidCheckDefinition { path: String, message: String },

    // === Target Errors ===
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    #[error("DNS resolution failed for: {hostname}")]
    DnsResolutionFailed { hostname: String },

    // === Authentication Errors ===
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Credential not found: {credential_id}")]
    CredentialNotFound { credential_id: String },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    // === Database Errors ===
    #[error("Database error: {0}")]
    Database(String),

    #[error("NVD database not found at: {path}")]
    NvdDatabaseNotFound { path: String },

    #[error("NVD sync failed: {0}")]
    NvdSyncFailed(String),

    // === Configuration Errors ===
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Missing required configuration: {key}")]
    MissingConfig { key: String },

    #[error("Invalid configuration value for {key}: {message}")]
    InvalidConfig { key: String, message: String },

    // === Transport Errors ===
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("gRPC error: {0}")]
    Grpc(String),

    #[error("Connection lost to platform")]
    ConnectionLost,

    // === Cloud Provider Errors ===
    #[error("AWS error: {0}")]
    Aws(String),

    #[error("Azure error: {0}")]
    Azure(String),

    #[error("GCP error: {0}")]
    Gcp(String),

    // === IO Errors ===
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File not found: {path}")]
    FileNotFound { path: String },

    // === Serialization Errors ===
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    // === Agent Errors ===
    #[error("Agent registration failed: {0}")]
    AgentRegistrationFailed(String),

    #[error("Agent not registered")]
    AgentNotRegistered,

    #[error("Certificate expired")]
    CertificateExpired,

    // === Resource Errors ===
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    #[error("Rate limited: retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u32 },

    // === Generic ===
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::ConnectionTimeout { .. }
                | Error::ConnectionLost
                | Error::RateLimited { .. }
                | Error::Transport(_)
        )
    }

    /// Check if this error is fatal (should stop the scan)
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::ScanCancelled { .. }
                | Error::Configuration(_)
                | Error::MissingConfig { .. }
                | Error::AgentNotRegistered
                | Error::CertificateExpired
        )
    }

    /// Get an error code for logging/metrics
    pub fn code(&self) -> &'static str {
        match self {
            Error::ScanFailed(_) => "SCAN_FAILED",
            Error::TargetUnreachable { .. } => "TARGET_UNREACHABLE",
            Error::ConnectionTimeout { .. } => "CONNECTION_TIMEOUT",
            Error::ConnectionRefused { .. } => "CONNECTION_REFUSED",
            Error::ScanCancelled { .. } => "SCAN_CANCELLED",
            Error::CheckFailed { .. } => "CHECK_FAILED",
            Error::CheckNotFound { .. } => "CHECK_NOT_FOUND",
            Error::InvalidCheckDefinition { .. } => "INVALID_CHECK_DEF",
            Error::InvalidTarget(_) => "INVALID_TARGET",
            Error::DnsResolutionFailed { .. } => "DNS_FAILED",
            Error::AuthenticationFailed(_) => "AUTH_FAILED",
            Error::CredentialNotFound { .. } => "CRED_NOT_FOUND",
            Error::PermissionDenied(_) => "PERMISSION_DENIED",
            Error::Database(_) => "DATABASE_ERROR",
            Error::NvdDatabaseNotFound { .. } => "NVD_NOT_FOUND",
            Error::NvdSyncFailed(_) => "NVD_SYNC_FAILED",
            Error::Configuration(_) => "CONFIG_ERROR",
            Error::MissingConfig { .. } => "MISSING_CONFIG",
            Error::InvalidConfig { .. } => "INVALID_CONFIG",
            Error::Transport(_) => "TRANSPORT_ERROR",
            Error::Grpc(_) => "GRPC_ERROR",
            Error::ConnectionLost => "CONNECTION_LOST",
            Error::Aws(_) => "AWS_ERROR",
            Error::Azure(_) => "AZURE_ERROR",
            Error::Gcp(_) => "GCP_ERROR",
            Error::Io(_) => "IO_ERROR",
            Error::FileNotFound { .. } => "FILE_NOT_FOUND",
            Error::Json(_) => "JSON_ERROR",
            Error::Parse(_) => "PARSE_ERROR",
            Error::AgentRegistrationFailed(_) => "AGENT_REG_FAILED",
            Error::AgentNotRegistered => "AGENT_NOT_REG",
            Error::CertificateExpired => "CERT_EXPIRED",
            Error::ResourceLimitExceeded(_) => "RESOURCE_LIMIT",
            Error::RateLimited { .. } => "RATE_LIMITED",
            Error::Internal(_) => "INTERNAL_ERROR",
            Error::Other(_) => "OTHER",
        }
    }
}
