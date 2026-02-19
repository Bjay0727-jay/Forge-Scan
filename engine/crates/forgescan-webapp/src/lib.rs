//! ForgeScan WebApp - Web application scanning (OWASP Top 10)
//!
//! This crate provides web application security testing capabilities:
//! - HTTP client with security-focused configuration
//! - Crawler for discovering web endpoints
//! - OWASP Top 10 vulnerability checks
//! - Security header analysis
//! - SSL/TLS configuration validation
//!
//! # Example
//!
//! ```no_run
//! use forgescan_webapp::{WebScanner, ScanConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = ScanConfig::default()
//!         .with_max_depth(3)
//!         .with_timeout_seconds(30);
//!
//!     let scanner = WebScanner::new(config);
//!     let results = scanner.scan("https://example.com").await.unwrap();
//!
//!     for finding in results.findings {
//!         println!("{}: {}", finding.severity, finding.title);
//!     }
//! }
//! ```

pub mod checks;
pub mod client;
pub mod crawler;
pub mod headers;
pub mod tls;

pub use checks::{WebCheck, WebCheckResult};
pub use client::{HttpClient, HttpResponse};
pub use crawler::{CrawlResult, Crawler, DiscoveredEndpoint};
pub use headers::{HeaderAnalysis, SecurityHeaders};
pub use tls::{TlsAnalyzer, TlsInfo};

use forgescan_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Web scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum crawl depth
    pub max_depth: u32,
    /// Maximum pages to crawl
    pub max_pages: u32,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// User agent string
    pub user_agent: String,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirects to follow
    pub max_redirects: u32,
    /// Concurrent requests limit
    pub concurrency: u32,
    /// Delay between requests (ms)
    pub request_delay_ms: u64,
    /// Check TLS configuration
    pub check_tls: bool,
    /// Check security headers
    pub check_headers: bool,
    /// Enable active checks (injection testing)
    pub active_checks: bool,
    /// Respect robots.txt
    pub respect_robots: bool,
    /// Custom headers to include
    pub custom_headers: Vec<(String, String)>,
    /// Authentication
    pub auth: Option<WebAuth>,
}

/// Web authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebAuth {
    /// HTTP Basic authentication
    Basic { username: String, password: String },
    /// Bearer token
    Bearer { token: String },
    /// Cookie-based session
    Cookie { name: String, value: String },
    /// Form-based login
    Form {
        login_url: String,
        username_field: String,
        password_field: String,
        username: String,
        password: String,
    },
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_pages: 100,
            timeout_seconds: 30,
            user_agent: format!("ForgeScan/{} (Security Scanner)", env!("CARGO_PKG_VERSION")),
            follow_redirects: true,
            max_redirects: 10,
            concurrency: 5,
            request_delay_ms: 100,
            check_tls: true,
            check_headers: true,
            active_checks: false, // Passive by default
            respect_robots: true,
            custom_headers: Vec::new(),
            auth: None,
        }
    }
}

impl ScanConfig {
    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_max_pages(mut self, pages: u32) -> Self {
        self.max_pages = pages;
        self
    }

    pub fn with_timeout_seconds(mut self, timeout: u64) -> Self {
        self.timeout_seconds = timeout;
        self
    }

    pub fn with_concurrency(mut self, concurrency: u32) -> Self {
        self.concurrency = concurrency;
        self
    }

    pub fn with_active_checks(mut self, enabled: bool) -> Self {
        self.active_checks = enabled;
        self
    }

    pub fn with_auth(mut self, auth: WebAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
}

/// Result of a web scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Target URL
    pub target: String,
    /// Discovered endpoints
    pub endpoints: Vec<DiscoveredEndpoint>,
    /// Security findings
    pub findings: Vec<Finding>,
    /// TLS information
    pub tls_info: Option<TlsInfo>,
    /// Header analysis
    pub header_analysis: Option<HeaderAnalysis>,
    /// Scan statistics
    pub stats: ScanStats,
}

/// Scan statistics
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    /// Total requests made
    pub requests_made: u32,
    /// Pages crawled
    pub pages_crawled: u32,
    /// Forms found
    pub forms_found: u32,
    /// Parameters found
    pub parameters_found: u32,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

/// Main web scanner
pub struct WebScanner {
    config: ScanConfig,
    client: HttpClient,
}

impl WebScanner {
    /// Create a new web scanner with the given configuration
    pub fn new(config: ScanConfig) -> Self {
        let client = HttpClient::new(&config);
        Self { config, client }
    }

    /// Scan a target URL
    pub async fn scan(&self, target: &str) -> anyhow::Result<ScanResult> {
        use std::time::Instant;
        use tracing::{debug, info};

        let start = Instant::now();
        info!("Starting web scan of {}", target);

        let mut findings = Vec::new();
        let mut stats = ScanStats::default();

        // Validate and normalize URL
        let base_url = url::Url::parse(target)?;

        // Check TLS if HTTPS
        let tls_info = if self.config.check_tls && base_url.scheme() == "https" {
            debug!("Analyzing TLS configuration");
            match TlsAnalyzer::analyze(&base_url).await {
                Ok(info) => {
                    findings.extend(info.to_findings(&base_url));
                    Some(info)
                }
                Err(e) => {
                    debug!("TLS analysis failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Initial request to check headers
        let header_analysis = if self.config.check_headers {
            debug!("Analyzing security headers");
            match self.client.get(target).await {
                Ok(response) => {
                    stats.requests_made += 1;
                    let analysis = SecurityHeaders::analyze(&response);
                    findings.extend(analysis.to_findings(target));
                    Some(analysis)
                }
                Err(e) => {
                    debug!("Header analysis failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Crawl the site
        let crawler = Crawler::new(&self.config, &self.client);
        let crawl_result = crawler.crawl(target).await?;

        stats.pages_crawled = crawl_result.pages.len() as u32;
        stats.forms_found = crawl_result.forms.len() as u32;
        stats.parameters_found = crawl_result.parameters.len() as u32;
        stats.requests_made += crawl_result.requests_made;

        // Run passive checks on discovered content
        let passive_findings = checks::run_passive_checks(&crawl_result, &self.config);
        findings.extend(passive_findings);

        // Run active checks if enabled
        if self.config.active_checks {
            debug!("Running active security checks");
            let active_findings =
                checks::run_active_checks(&crawl_result, &self.client, &self.config).await;
            findings.extend(active_findings);
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "Web scan complete: {} pages, {} findings in {}ms",
            stats.pages_crawled,
            findings.len(),
            stats.duration_ms
        );

        Ok(ScanResult {
            target: target.to_string(),
            endpoints: crawl_result.pages,
            findings,
            tls_info,
            header_analysis,
            stats,
        })
    }

    /// Quick scan - headers and TLS only, no crawling
    pub async fn quick_scan(&self, target: &str) -> anyhow::Result<ScanResult> {
        let mut config = self.config.clone();
        config.max_depth = 0;
        config.max_pages = 1;

        let scanner = WebScanner::new(config);
        scanner.scan(target).await
    }
}

/// OWASP Top 10 2021 categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OwaspCategory {
    /// A01:2021 - Broken Access Control
    A01BrokenAccessControl,
    /// A02:2021 - Cryptographic Failures
    A02CryptographicFailures,
    /// A03:2021 - Injection
    A03Injection,
    /// A04:2021 - Insecure Design
    A04InsecureDesign,
    /// A05:2021 - Security Misconfiguration
    A05SecurityMisconfiguration,
    /// A06:2021 - Vulnerable and Outdated Components
    A06VulnerableComponents,
    /// A07:2021 - Identification and Authentication Failures
    A07AuthenticationFailures,
    /// A08:2021 - Software and Data Integrity Failures
    A08IntegrityFailures,
    /// A09:2021 - Security Logging and Monitoring Failures
    A09LoggingFailures,
    /// A10:2021 - Server-Side Request Forgery
    A10SSRF,
}

impl OwaspCategory {
    pub fn code(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01:2021",
            Self::A02CryptographicFailures => "A02:2021",
            Self::A03Injection => "A03:2021",
            Self::A04InsecureDesign => "A04:2021",
            Self::A05SecurityMisconfiguration => "A05:2021",
            Self::A06VulnerableComponents => "A06:2021",
            Self::A07AuthenticationFailures => "A07:2021",
            Self::A08IntegrityFailures => "A08:2021",
            Self::A09LoggingFailures => "A09:2021",
            Self::A10SSRF => "A10:2021",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02CryptographicFailures => "Cryptographic Failures",
            Self::A03Injection => "Injection",
            Self::A04InsecureDesign => "Insecure Design",
            Self::A05SecurityMisconfiguration => "Security Misconfiguration",
            Self::A06VulnerableComponents => "Vulnerable and Outdated Components",
            Self::A07AuthenticationFailures => "Identification and Authentication Failures",
            Self::A08IntegrityFailures => "Software and Data Integrity Failures",
            Self::A09LoggingFailures => "Security Logging and Monitoring Failures",
            Self::A10SSRF => "Server-Side Request Forgery",
        }
    }
}
