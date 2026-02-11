//! Transport message types
//!
//! These types mirror the protobuf definitions and will be used with
//! the generated gRPC code once tonic-build is configured.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use forgescan_core::{Finding, Severity};

/// Scan task received from platform
#[derive(Debug, Clone)]
pub struct ScanTask {
    /// Unique job ID from platform
    pub job_id: String,
    /// Task ID within the job
    pub task_id: String,
    /// Targets to scan
    pub targets: Vec<ScanTarget>,
    /// Specific check IDs to run (empty = all applicable)
    pub check_ids: Vec<String>,
    /// Categories to scan
    pub categories: Vec<CheckCategory>,
    /// Minimum severity to report
    pub min_severity: Option<Severity>,
    /// Scan intensity
    pub intensity: ScanIntensity,
    /// Timeout in seconds
    pub timeout_seconds: u32,
    /// Max concurrent targets
    pub max_concurrent_targets: u32,
    /// Port scan configuration
    pub port_config: Option<PortScanConfig>,
    /// Cloud configurations
    pub cloud_configs: Vec<CloudConfig>,
}

impl Default for ScanTask {
    fn default() -> Self {
        Self {
            job_id: String::new(),
            task_id: String::new(),
            targets: Vec::new(),
            check_ids: Vec::new(),
            categories: Vec::new(),
            min_severity: None,
            intensity: ScanIntensity::Normal,
            timeout_seconds: 3600,
            max_concurrent_targets: 100,
            port_config: None,
            cloud_configs: Vec::new(),
        }
    }
}

/// A target to scan
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// Single IP address
    Ip(IpAddr),
    /// CIDR range (e.g., "192.168.1.0/24")
    Cidr(String),
    /// Hostname
    Hostname(String),
    /// Web application URL
    Url(String),
    /// IP range (start-end)
    IpRange { start: IpAddr, end: IpAddr },
}

impl ScanTarget {
    /// Get a string representation of the target
    pub fn to_string(&self) -> String {
        match self {
            ScanTarget::Ip(ip) => ip.to_string(),
            ScanTarget::Cidr(cidr) => cidr.clone(),
            ScanTarget::Hostname(host) => host.clone(),
            ScanTarget::Url(url) => url.clone(),
            ScanTarget::IpRange { start, end } => format!("{}-{}", start, end),
        }
    }
}

/// Check categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckCategory {
    Vulnerability,
    Configuration,
    Compliance,
    WebApp,
    Cloud,
    Custom,
}

/// Scan intensity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanIntensity {
    /// Stealthy - minimal probes, longer delays
    Light,
    /// Normal - balanced approach
    Normal,
    /// Aggressive - faster, more probes
    Aggressive,
    /// Full - all checks, maximum coverage
    Full,
}

/// Port scan configuration
#[derive(Debug, Clone)]
pub struct PortScanConfig {
    /// Explicit list of ports
    pub ports: Vec<u16>,
    /// Port range string (e.g., "1-1024")
    pub port_range: Option<String>,
    /// Use top N common ports
    pub top_ports: Option<u32>,
    /// Include UDP scanning
    pub scan_udp: bool,
    /// Per-port connect timeout in ms
    pub connect_timeout_ms: u32,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            ports: Vec::new(),
            port_range: None,
            top_ports: Some(1000),
            scan_udp: false,
            connect_timeout_ms: 3000,
        }
    }
}

/// Cloud provider configuration
#[derive(Debug, Clone)]
pub struct CloudConfig {
    /// Provider name (aws, azure, gcp)
    pub provider: String,
    /// Region
    pub region: String,
    /// Account/subscription ID
    pub account_id: String,
    /// Role ARN for assume role (AWS)
    pub role_arn: Option<String>,
    /// Additional options
    pub options: HashMap<String, String>,
}

/// Event emitted during scan execution
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Progress update
    Progress(ScanProgress),
    /// Finding discovered
    Finding(Finding),
    /// Target discovered during host discovery
    TargetDiscovered(TargetDiscoveredEvent),
    /// Port discovered during port scan
    PortDiscovered(PortDiscoveredEvent),
    /// Error during scanning
    Error(ScanError),
    /// Scan completed
    Complete(ScanComplete),
}

/// Scan progress update
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub task_id: String,
    pub targets_total: u32,
    pub targets_completed: u32,
    pub checks_total: u32,
    pub checks_completed: u32,
    pub percent_complete: f32,
    pub current_target: Option<String>,
    pub current_check: Option<String>,
    pub findings_so_far: u32,
}

/// Target discovered event
#[derive(Debug, Clone)]
pub struct TargetDiscoveredEvent {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
    pub os_fingerprint: Option<String>,
    pub is_up: bool,
}

/// Port discovered event
#[derive(Debug, Clone)]
pub struct PortDiscoveredEvent {
    pub target: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

/// Scan error event
#[derive(Debug, Clone)]
pub struct ScanError {
    pub task_id: String,
    pub target: Option<String>,
    pub check_id: Option<String>,
    pub error_code: String,
    pub error_message: String,
    pub is_fatal: bool,
}

/// Scan completion event
#[derive(Debug, Clone)]
pub struct ScanComplete {
    pub task_id: String,
    pub success: bool,
    pub stats: ScanStats,
    pub error_message: Option<String>,
}

/// Scan statistics
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub targets_scanned: u32,
    pub targets_up: u32,
    pub ports_scanned: u32,
    pub ports_open: u32,
    pub checks_executed: u32,
    pub findings_total: u32,
    pub findings_critical: u32,
    pub findings_high: u32,
    pub findings_medium: u32,
    pub findings_low: u32,
    pub findings_info: u32,
    pub duration_seconds: u32,
}

/// Scanner heartbeat request
#[derive(Debug, Clone)]
pub struct HeartbeatRequest {
    pub scanner_id: String,
    pub hostname: String,
    pub version: String,
    pub status: ScannerStatus,
    pub active_task_ids: Vec<String>,
    pub resources: ResourceUsage,
}

/// Scanner status
#[derive(Debug, Clone)]
pub struct ScannerStatus {
    pub state: ScannerState,
    pub queue_depth: u32,
    pub active_scans: u32,
}

/// Scanner state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerState {
    Idle,
    Scanning,
    Updating,
    Error,
}

/// Resource usage
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub open_connections: u32,
}

/// Heartbeat response from platform
#[derive(Debug, Clone)]
pub struct HeartbeatResponse {
    pub acknowledged: bool,
    pub server_time: SystemTime,
    pub cancel_task_ids: Vec<String>,
    pub update_available: bool,
    pub update_version: Option<String>,
}

/// Scanner configuration from platform
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub version: String,
    pub max_concurrent_scans: u32,
    pub max_concurrent_targets: u32,
    pub default_timeout_seconds: u32,
    pub enabled_check_categories: Vec<String>,
    pub custom_settings: HashMap<String, String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            max_concurrent_scans: 5,
            max_concurrent_targets: 100,
            default_timeout_seconds: 3600,
            enabled_check_categories: Vec::new(),
            custom_settings: HashMap::new(),
        }
    }
}
