//! Configuration management for ForgeScan components

use forgescan_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Platform connection settings
    #[serde(default)]
    pub platform: PlatformConfig,

    /// Scanner settings
    #[serde(default)]
    pub scanner: ScannerConfig,

    /// Agent settings (only used by forgescan-agent)
    #[serde(default)]
    pub agent: AgentConfig,

    /// NVD database settings
    #[serde(default)]
    pub nvd: NvdConfig,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingConfig,

    /// TLS/mTLS settings
    #[serde(default)]
    pub tls: TlsConfig,

    /// Packet capture settings
    #[serde(default)]
    pub capture: CaptureSettings,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Configuration(format!("Failed to read config file {:?}: {}", path, e))
        })?;
        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| Error::Configuration(format!("Failed to parse config: {}", e)))
    }

    /// Create a configuration builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }

    /// Merge with environment variables (FORGESCAN_ prefix)
    pub fn merge_env(mut self) -> Self {
        // Platform settings
        if let Ok(val) = std::env::var("FORGESCAN_PLATFORM_ENDPOINT") {
            self.platform.endpoint = val;
        }
        if let Ok(val) = std::env::var("FORGESCAN_PLATFORM_API_KEY") {
            self.platform.api_key = Some(val);
        }

        // Scanner settings
        if let Ok(val) = std::env::var("FORGESCAN_SCANNER_ID") {
            self.scanner.scanner_id = Some(val);
        }
        if let Ok(val) = std::env::var("FORGESCAN_MAX_CONCURRENT_SCANS") {
            if let Ok(n) = val.parse() {
                self.scanner.max_concurrent_scans = n;
            }
        }
        if let Ok(val) = std::env::var("FORGESCAN_SCANNER_KILL_SWITCH") {
            self.scanner.kill_switch = val == "true" || val == "1";
        }
        if let Ok(val) = std::env::var("FORGESCAN_MAX_TARGETS_PER_TASK") {
            if let Ok(n) = val.parse() {
                self.scanner.max_targets_per_task = n;
            }
        }

        // Agent settings
        if let Ok(val) = std::env::var("FORGESCAN_AGENT_ID") {
            self.agent.agent_id = Some(val);
        }

        // Capture settings
        if let Ok(val) = std::env::var("FORGESCAN_CAPTURE_ENABLED") {
            self.capture.enabled = val == "true" || val == "1";
        }
        if let Ok(val) = std::env::var("FORGESCAN_CAPTURE_INTERFACE") {
            self.capture.default_interface = Some(val);
        }
        if let Ok(val) = std::env::var("FORGESCAN_CAPTURE_DIR") {
            self.capture.capture_dir = val;
        }

        // Logging
        if let Ok(val) = std::env::var("FORGESCAN_LOG_LEVEL") {
            self.logging.level = val;
        }
        if let Ok(val) = std::env::var("FORGESCAN_LOG_FORMAT") {
            self.logging.format = val;
        }

        self
    }
}

/// Platform connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Platform gRPC endpoint
    pub endpoint: String,

    /// API key for authentication
    pub api_key: Option<String>,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,

    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u32,

    /// Enable TLS
    #[serde(default = "default_true")]
    pub use_tls: bool,
}

fn default_connect_timeout() -> u32 {
    10
}

fn default_request_timeout() -> u32 {
    30
}

fn default_true() -> bool {
    true
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            endpoint: String::from("https://localhost:8443"),
            api_key: None,
            connect_timeout_seconds: 10,
            request_timeout_seconds: 30,
            use_tls: true,
        }
    }
}

/// Scanner-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Unique scanner identifier
    pub scanner_id: Option<String>,

    /// Maximum concurrent scans
    #[serde(default = "default_max_scans")]
    pub max_concurrent_scans: u32,

    /// Maximum concurrent targets per scan
    #[serde(default = "default_max_targets")]
    pub max_concurrent_targets: u32,

    /// Default scan timeout in seconds
    #[serde(default = "default_scan_timeout")]
    pub default_timeout_seconds: u32,

    /// Directory for check definitions
    pub checks_dir: Option<String>,

    /// Enabled check categories
    #[serde(default)]
    pub enabled_categories: Vec<String>,

    /// Emergency stop for all scanner task execution
    #[serde(default)]
    pub kill_switch: bool,

    /// Optional allow-list CIDRs for IP targets (empty = allow all)
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,

    /// Explicit deny-list for targets (exact host/IP/CIDR match)
    #[serde(default)]
    pub denied_targets: Vec<String>,

    /// Hard upper bound on number of targets accepted per task
    #[serde(default = "default_max_targets_per_task")]
    pub max_targets_per_task: u32,
}

fn default_max_scans() -> u32 {
    5
}

fn default_max_targets() -> u32 {
    100
}

fn default_scan_timeout() -> u32 {
    3600
}

fn default_max_targets_per_task() -> u32 {
    256
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scanner_id: None,
            max_concurrent_scans: 5,
            max_concurrent_targets: 100,
            default_timeout_seconds: 3600,
            checks_dir: Some(String::from("/etc/forgescan/checks")),
            enabled_categories: vec![],
            kill_switch: false,
            allowed_cidrs: vec![],
            denied_targets: vec![],
            max_targets_per_task: default_max_targets_per_task(),
        }
    }
}

/// Agent-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Unique agent identifier (assigned during registration)
    pub agent_id: Option<String>,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_seconds: u32,

    /// Maximum CPU usage during scanning (percent)
    #[serde(default = "default_cpu_limit")]
    pub scan_cpu_limit_percent: u32,

    /// Maximum memory usage during scanning (MB)
    #[serde(default = "default_memory_limit")]
    pub scan_memory_limit_mb: u32,

    /// Enable auto-updates
    #[serde(default = "default_true")]
    pub auto_update: bool,
}

fn default_heartbeat() -> u32 {
    300
}

fn default_cpu_limit() -> u32 {
    20
}

fn default_memory_limit() -> u32 {
    256
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: None,
            heartbeat_interval_seconds: 300,
            scan_cpu_limit_percent: 20,
            scan_memory_limit_mb: 256,
            auto_update: true,
        }
    }
}

/// NVD database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdConfig {
    /// Path to NVD SQLite database
    pub database_path: String,

    /// NVD API URL for updates
    pub api_url: String,

    /// Update interval in hours (0 = no auto-update)
    #[serde(default = "default_nvd_update")]
    pub update_interval_hours: u32,

    /// NVD API key (optional, for higher rate limits)
    pub api_key: Option<String>,
}

fn default_nvd_update() -> u32 {
    24
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            database_path: String::from("/var/lib/forgescan/nvd.db"),
            api_url: String::from("https://services.nvd.nist.gov/rest/json/cves/2.0"),
            update_interval_hours: 24,
            api_key: None,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (pretty, json, compact)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Log file path (optional)
    pub file: Option<String>,
}

fn default_log_level() -> String {
    String::from("info")
}

fn default_log_format() -> String {
    String::from("pretty")
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: String::from("info"),
            format: String::from("pretty"),
            file: None,
        }
    }
}

/// Packet capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSettings {
    /// Enable capture features
    #[serde(default)]
    pub enabled: bool,

    /// Default network interface for capture (None = auto-detect)
    pub default_interface: Option<String>,

    /// Directory for PCAP file storage
    #[serde(default = "default_capture_dir")]
    pub capture_dir: String,

    /// Maximum capture file size in megabytes
    #[serde(default = "default_max_capture_size_mb")]
    pub max_capture_size_mb: u32,

    /// Maximum capture duration in seconds
    #[serde(default = "default_max_capture_duration_sec")]
    pub max_capture_duration_sec: u32,

    /// PCAP file retention in days
    #[serde(default = "default_capture_retention_days")]
    pub retention_days: u32,

    /// Enable passive monitoring mode (requires explicit opt-in)
    #[serde(default)]
    pub passive_mode_enabled: bool,

    /// Automatically capture packets during active scans
    #[serde(default)]
    pub correlate_with_scans: bool,
}

fn default_capture_dir() -> String {
    String::from("/var/lib/forgescan/captures")
}

fn default_max_capture_size_mb() -> u32 {
    50
}

fn default_max_capture_duration_sec() -> u32 {
    300
}

fn default_capture_retention_days() -> u32 {
    7
}

impl Default for CaptureSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            default_interface: None,
            capture_dir: default_capture_dir(),
            max_capture_size_mb: 50,
            max_capture_duration_sec: 300,
            retention_days: 7,
            passive_mode_enabled: false,
            correlate_with_scans: false,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to CA certificate
    pub ca_cert_path: Option<String>,

    /// Path to client certificate (for mTLS)
    pub cert_path: Option<String>,

    /// Path to client private key
    pub key_path: Option<String>,

    /// Skip server certificate verification (NOT recommended for production)
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// Builder for constructing Config
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    pub fn platform_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.platform.endpoint = endpoint.into();
        self
    }

    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.config.platform.api_key = Some(key.into());
        self
    }

    pub fn scanner_id(mut self, id: impl Into<String>) -> Self {
        self.config.scanner.scanner_id = Some(id.into());
        self
    }

    pub fn agent_id(mut self, id: impl Into<String>) -> Self {
        self.config.agent.agent_id = Some(id.into());
        self
    }

    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.config.logging.level = level.into();
        self
    }

    pub fn nvd_path(mut self, path: impl Into<String>) -> Self {
        self.config.nvd.database_path = path.into();
        self
    }

    pub fn build(self) -> Config {
        self.config
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
            [platform]
            endpoint = "https://forge.example.com:8443"
            api_key = "secret-key"

            [scanner]
            max_concurrent_scans = 10

            [logging]
            level = "debug"
            format = "json"
        "#;

        let config = Config::from_toml(toml).unwrap();
        assert_eq!(config.platform.endpoint, "https://forge.example.com:8443");
        assert_eq!(config.platform.api_key, Some(String::from("secret-key")));
        assert_eq!(config.scanner.max_concurrent_scans, 10);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_config_builder() {
        let config = Config::builder()
            .platform_endpoint("https://test.com")
            .api_key("key123")
            .log_level("warn")
            .build();

        assert_eq!(config.platform.endpoint, "https://test.com");
        assert_eq!(config.platform.api_key, Some(String::from("key123")));
        assert_eq!(config.logging.level, "warn");
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.platform.endpoint.contains("localhost"));
        assert_eq!(config.scanner.max_concurrent_scans, 5);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "pretty");
        assert!(config.platform.use_tls);
        assert_eq!(config.agent.heartbeat_interval_seconds, 300);
        assert!(!config.capture.enabled);
    }

    #[test]
    fn test_config_from_toml_minimal() {
        let config = Config::from_toml("").unwrap();
        assert_eq!(config.platform.endpoint, "https://localhost:8443");
        assert_eq!(config.scanner.max_concurrent_scans, 5);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_config_from_toml_invalid() {
        let result = Config::from_toml("this is not valid [[[toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_from_file_missing() {
        let result = Config::from_file("nonexistent.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_merge_env() {
        let config = Config::default();

        std::env::set_var(
            "FORGESCAN_PLATFORM_ENDPOINT",
            "https://env.example.com:9999",
        );
        std::env::set_var("FORGESCAN_LOG_LEVEL", "trace");
        std::env::set_var("FORGESCAN_MAX_CONCURRENT_SCANS", "42");
        std::env::set_var("FORGESCAN_SCANNER_KILL_SWITCH", "1");
        std::env::set_var("FORGESCAN_MAX_TARGETS_PER_TASK", "20");

        let config = config.merge_env();

        assert_eq!(config.platform.endpoint, "https://env.example.com:9999");
        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.scanner.max_concurrent_scans, 42);
        assert!(config.scanner.kill_switch);
        assert_eq!(config.scanner.max_targets_per_task, 20);

        std::env::remove_var("FORGESCAN_PLATFORM_ENDPOINT");
        std::env::remove_var("FORGESCAN_LOG_LEVEL");
        std::env::remove_var("FORGESCAN_MAX_CONCURRENT_SCANS");
        std::env::remove_var("FORGESCAN_SCANNER_KILL_SWITCH");
        std::env::remove_var("FORGESCAN_MAX_TARGETS_PER_TASK");
    }

    #[test]
    fn test_platform_config_default() {
        let pc = PlatformConfig::default();
        assert!(pc.endpoint.contains("localhost"));
        assert!(pc.use_tls);
        assert_eq!(pc.connect_timeout_seconds, 10);
        assert_eq!(pc.request_timeout_seconds, 30);
        assert!(pc.api_key.is_none());
    }

    #[test]
    fn test_scanner_config_default() {
        let sc = ScannerConfig::default();
        assert_eq!(sc.max_concurrent_scans, 5);
        assert_eq!(sc.max_concurrent_targets, 100);
        assert_eq!(sc.default_timeout_seconds, 3600);
        assert!(sc.checks_dir.is_some());
        assert!(!sc.kill_switch);
        assert!(sc.allowed_cidrs.is_empty());
        assert!(sc.denied_targets.is_empty());
        assert_eq!(sc.max_targets_per_task, 256);
    }

    #[test]
    fn test_agent_config_default() {
        let ac = AgentConfig::default();
        assert_eq!(ac.heartbeat_interval_seconds, 300);
        assert_eq!(ac.scan_cpu_limit_percent, 20);
        assert_eq!(ac.scan_memory_limit_mb, 256);
        assert!(ac.auto_update);
        assert!(ac.agent_id.is_none());
    }

    #[test]
    fn test_nvd_config_default() {
        let nc = NvdConfig::default();
        assert_eq!(nc.update_interval_hours, 24);
        assert!(nc.api_url.contains("nvd.nist.gov"));
        assert!(nc.api_key.is_none());
    }

    #[test]
    fn test_logging_config_default() {
        let lc = LoggingConfig::default();
        assert_eq!(lc.level, "info");
        assert_eq!(lc.format, "pretty");
        assert!(lc.file.is_none());
    }

    #[test]
    fn test_capture_settings_default() {
        let cs = CaptureSettings::default();
        assert!(!cs.enabled);
        assert_eq!(cs.max_capture_size_mb, 50);
        assert_eq!(cs.retention_days, 7);
        assert!(cs.default_interface.is_none());
        assert!(!cs.passive_mode_enabled);
        assert!(!cs.correlate_with_scans);
    }

    #[test]
    fn test_tls_config_default() {
        let tc = TlsConfig::default();
        assert!(tc.ca_cert_path.is_none());
        assert!(tc.cert_path.is_none());
        assert!(tc.key_path.is_none());
        assert!(!tc.insecure_skip_verify);
    }

    #[test]
    fn test_config_builder_all_methods() {
        let config = Config::builder()
            .platform_endpoint("https://builder.test:443")
            .api_key("builder-key")
            .scanner_id("scanner-001")
            .agent_id("agent-001")
            .log_level("debug")
            .nvd_path("/tmp/nvd.db")
            .build();

        assert_eq!(config.platform.endpoint, "https://builder.test:443");
        assert_eq!(config.platform.api_key, Some(String::from("builder-key")));
        assert_eq!(config.scanner.scanner_id, Some(String::from("scanner-001")));
        assert_eq!(config.agent.agent_id, Some(String::from("agent-001")));
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.nvd.database_path, "/tmp/nvd.db");
    }

    #[test]
    fn test_config_full_toml() {
        let toml = r#"
            [platform]
            endpoint = "https://forge.prod.com:8443"
            api_key = "prod-key"
            connect_timeout_seconds = 20
            request_timeout_seconds = 60
            use_tls = true

            [scanner]
            scanner_id = "sc-1"
            max_concurrent_scans = 8
            max_concurrent_targets = 50
            default_timeout_seconds = 1800
            checks_dir = "/opt/checks"
            enabled_categories = ["network", "web"]
            kill_switch = false
            allowed_cidrs = ["10.0.0.0/24", "192.168.1.0/24"]
            denied_targets = ["10.0.0.10", "192.168.1.8/32"]
            max_targets_per_task = 120

            [agent]
            agent_id = "ag-1"
            heartbeat_interval_seconds = 120
            scan_cpu_limit_percent = 50
            scan_memory_limit_mb = 512
            auto_update = false

            [nvd]
            database_path = "/data/nvd.db"
            api_url = "https://custom-nvd.example.com/api"
            update_interval_hours = 12
            api_key = "nvd-key"

            [logging]
            level = "trace"
            format = "json"
            file = "/var/log/forgescan.log"

            [tls]
            ca_cert_path = "/etc/ssl/ca.pem"
            cert_path = "/etc/ssl/cert.pem"
            key_path = "/etc/ssl/key.pem"
            insecure_skip_verify = false

            [capture]
            enabled = true
            default_interface = "eth0"
            capture_dir = "/data/captures"
            max_capture_size_mb = 100
            max_capture_duration_sec = 600
            retention_days = 14
            passive_mode_enabled = true
            correlate_with_scans = true
        "#;

        let config = Config::from_toml(toml).unwrap();

        assert_eq!(config.platform.endpoint, "https://forge.prod.com:8443");
        assert_eq!(config.platform.api_key, Some(String::from("prod-key")));
        assert_eq!(config.platform.connect_timeout_seconds, 20);
        assert_eq!(config.platform.request_timeout_seconds, 60);
        assert!(config.platform.use_tls);

        assert_eq!(config.scanner.scanner_id, Some(String::from("sc-1")));
        assert_eq!(config.scanner.max_concurrent_scans, 8);
        assert_eq!(config.scanner.max_concurrent_targets, 50);
        assert_eq!(config.scanner.default_timeout_seconds, 1800);
        assert_eq!(config.scanner.checks_dir, Some(String::from("/opt/checks")));
        assert_eq!(config.scanner.enabled_categories, vec!["network", "web"]);
        assert!(!config.scanner.kill_switch);
        assert_eq!(config.scanner.allowed_cidrs.len(), 2);
        assert_eq!(config.scanner.denied_targets.len(), 2);
        assert_eq!(config.scanner.max_targets_per_task, 120);

        assert_eq!(config.agent.agent_id, Some(String::from("ag-1")));
        assert_eq!(config.agent.heartbeat_interval_seconds, 120);
        assert_eq!(config.agent.scan_cpu_limit_percent, 50);
        assert_eq!(config.agent.scan_memory_limit_mb, 512);
        assert!(!config.agent.auto_update);

        assert_eq!(config.nvd.database_path, "/data/nvd.db");
        assert_eq!(config.nvd.api_url, "https://custom-nvd.example.com/api");
        assert_eq!(config.nvd.update_interval_hours, 12);
        assert_eq!(config.nvd.api_key, Some(String::from("nvd-key")));

        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.logging.format, "json");
        assert_eq!(
            config.logging.file,
            Some(String::from("/var/log/forgescan.log"))
        );

        assert_eq!(
            config.tls.ca_cert_path,
            Some(String::from("/etc/ssl/ca.pem"))
        );
        assert_eq!(
            config.tls.cert_path,
            Some(String::from("/etc/ssl/cert.pem"))
        );
        assert_eq!(config.tls.key_path, Some(String::from("/etc/ssl/key.pem")));
        assert!(!config.tls.insecure_skip_verify);

        assert!(config.capture.enabled);
        assert_eq!(config.capture.default_interface, Some(String::from("eth0")));
        assert_eq!(config.capture.capture_dir, "/data/captures");
        assert_eq!(config.capture.max_capture_size_mb, 100);
        assert_eq!(config.capture.max_capture_duration_sec, 600);
        assert_eq!(config.capture.retention_days, 14);
        assert!(config.capture.passive_mode_enabled);
        assert!(config.capture.correlate_with_scans);
    }
}
