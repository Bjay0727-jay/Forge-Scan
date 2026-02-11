//! Configuration management for ForgeScan components

use forgescan_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            platform: PlatformConfig::default(),
            scanner: ScannerConfig::default(),
            agent: AgentConfig::default(),
            nvd: NvdConfig::default(),
            logging: LoggingConfig::default(),
            tls: TlsConfig::default(),
        }
    }
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

        // Agent settings
        if let Ok(val) = std::env::var("FORGESCAN_AGENT_ID") {
            self.agent.agent_id = Some(val);
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

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scanner_id: None,
            max_concurrent_scans: 5,
            max_concurrent_targets: 100,
            default_timeout_seconds: 3600,
            checks_dir: Some(String::from("/etc/forgescan/checks")),
            enabled_categories: vec![],
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

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ca_cert_path: None,
            cert_path: None,
            key_path: None,
            insecure_skip_verify: false,
        }
    }
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
}
