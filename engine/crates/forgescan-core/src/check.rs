//! Check trait and metadata - the interface all vulnerability checks implement

use crate::error::Result;
use crate::finding::{ComplianceRef, Finding};
use crate::severity::{CheckCategory, Severity};
use crate::target::{ScanMode, ScanTarget};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Result of executing a check
pub type CheckResult = Result<Vec<Finding>>;

/// The trait that all vulnerability checks must implement
pub trait Check: Send + Sync {
    /// Unique identifier for this check (e.g., "FSC-VULN-0001")
    fn id(&self) -> &str;

    /// Get the check metadata
    fn metadata(&self) -> &CheckMetadata;

    /// Execute the check against the given context
    /// Returns zero or more findings
    fn execute(&self, ctx: &CheckContext) -> CheckResult;

    /// Which scanning modes this check supports
    fn supported_modes(&self) -> &[ScanMode] {
        &[ScanMode::Agentless, ScanMode::Agent]
    }

    /// Check if this check applies to the given target
    /// Override for checks that only apply to specific targets
    fn applies_to(&self, _target: &ScanTarget) -> bool {
        true
    }

    /// Estimated time to run this check in milliseconds
    fn estimated_duration_ms(&self) -> u32 {
        1000 // Default 1 second
    }
}

/// Metadata describing a check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckMetadata {
    /// Unique identifier
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Detailed description
    pub description: String,

    /// Check category
    pub category: CheckCategory,

    /// Default severity of findings from this check
    pub severity: Severity,

    /// CVE IDs this check detects
    #[serde(default)]
    pub cve_ids: Vec<String>,

    /// CWE IDs this check relates to
    #[serde(default)]
    pub cwe_ids: Vec<String>,

    /// Compliance framework mappings
    #[serde(default)]
    pub compliance: Vec<ComplianceRef>,

    /// Reference URLs
    #[serde(default)]
    pub references: Vec<String>,

    /// Check version
    pub version: String,

    /// Check author
    pub author: Option<String>,

    /// Whether this check is enabled by default
    #[serde(default = "default_enabled")]
    pub enabled_by_default: bool,

    /// Tags for filtering/grouping
    #[serde(default)]
    pub tags: Vec<String>,

    /// Supported scan modes
    #[serde(default = "default_modes")]
    pub supported_modes: Vec<ScanMode>,
}

fn default_enabled() -> bool {
    true
}

fn default_modes() -> Vec<ScanMode> {
    vec![ScanMode::Agentless, ScanMode::Agent]
}

impl CheckMetadata {
    /// Create new check metadata
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        category: CheckCategory,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            category,
            severity,
            cve_ids: Vec::new(),
            cwe_ids: Vec::new(),
            compliance: Vec::new(),
            references: Vec::new(),
            version: String::from("1.0.0"),
            author: None,
            enabled_by_default: true,
            tags: Vec::new(),
            supported_modes: vec![ScanMode::Agentless, ScanMode::Agent],
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn with_cve(mut self, cve_id: impl Into<String>) -> Self {
        self.cve_ids.push(cve_id.into());
        self
    }

    pub fn with_cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.cwe_ids.push(cwe_id.into());
        self
    }

    pub fn with_compliance(mut self, mapping: ComplianceRef) -> Self {
        self.compliance.push(mapping);
        self
    }

    pub fn with_reference(mut self, url: impl Into<String>) -> Self {
        self.references.push(url.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn agent_only(mut self) -> Self {
        self.supported_modes = vec![ScanMode::Agent];
        self
    }

    pub fn agentless_only(mut self) -> Self {
        self.supported_modes = vec![ScanMode::Agentless];
        self
    }
}

/// Context passed to checks during execution
#[derive(Clone)]
pub struct CheckContext {
    /// The target being scanned
    pub target: ScanTarget,

    /// Resolved IP address (if target was hostname)
    pub resolved_ip: Option<std::net::IpAddr>,

    /// Port being checked (if port-specific)
    pub port: Option<u16>,

    /// Protocol (tcp/udp)
    pub protocol: Option<String>,

    /// Detected service name
    pub service: Option<String>,

    /// Detected service version
    pub service_version: Option<String>,

    /// Service banner
    pub banner: Option<String>,

    /// Detected CPE
    pub cpe: Option<String>,

    /// Current scan mode
    pub scan_mode: ScanMode,

    /// Timeout for operations in milliseconds
    pub timeout_ms: u32,

    /// Additional context data
    pub extra: std::collections::HashMap<String, String>,

    /// Reference to NVD data (for CVE lookups)
    pub nvd_db: Option<Arc<dyn NvdDatabase>>,

    /// Credentials for authenticated checks
    pub credentials: Option<Arc<dyn CredentialProvider>>,
}

impl std::fmt::Debug for CheckContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckContext")
            .field("target", &self.target)
            .field("resolved_ip", &self.resolved_ip)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("service", &self.service)
            .field("service_version", &self.service_version)
            .field("banner", &self.banner)
            .field("cpe", &self.cpe)
            .field("scan_mode", &self.scan_mode)
            .field("timeout_ms", &self.timeout_ms)
            .field("extra", &self.extra)
            .field("nvd_db", &self.nvd_db.as_ref().map(|_| "..."))
            .field("credentials", &self.credentials.as_ref().map(|_| "..."))
            .finish()
    }
}

impl CheckContext {
    /// Create a new check context for a target
    pub fn new(target: ScanTarget) -> Self {
        Self {
            target,
            resolved_ip: None,
            port: None,
            protocol: None,
            service: None,
            service_version: None,
            banner: None,
            cpe: None,
            scan_mode: ScanMode::Agentless,
            timeout_ms: 5000,
            extra: std::collections::HashMap::new(),
            nvd_db: None,
            credentials: None,
        }
    }

    /// Set the resolved IP
    pub fn with_resolved_ip(mut self, ip: std::net::IpAddr) -> Self {
        self.resolved_ip = Some(ip);
        self
    }

    /// Set port information
    pub fn with_port(mut self, port: u16, protocol: impl Into<String>) -> Self {
        self.port = Some(port);
        self.protocol = Some(protocol.into());
        self
    }

    /// Set service information
    pub fn with_service(
        mut self,
        service: impl Into<String>,
        version: Option<String>,
        banner: Option<String>,
    ) -> Self {
        self.service = Some(service.into());
        self.service_version = version;
        self.banner = banner;
        self
    }

    /// Set the scan mode
    pub fn with_mode(mut self, mode: ScanMode) -> Self {
        self.scan_mode = mode;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout_ms: u32) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Add extra context data
    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }

    /// Get the target as a string
    pub fn target_str(&self) -> String {
        if let Some(ip) = self.resolved_ip {
            ip.to_string()
        } else {
            self.target.display()
        }
    }
}

/// Interface for NVD database access (implemented in forgescan-nvd)
pub trait NvdDatabase: Send + Sync {
    /// Look up CVEs affecting a CPE
    fn lookup_cpe(&self, cpe: &str) -> Vec<CveInfo>;

    /// Check if a CVE is in CISA KEV
    fn is_cisa_kev(&self, cve_id: &str) -> bool;

    /// Get CVE details
    fn get_cve(&self, cve_id: &str) -> Option<CveInfo>;
}

/// Basic CVE information (full implementation in forgescan-nvd)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve_id: String,
    pub description: String,
    pub cvss_v3_score: Option<f32>,
    pub cvss_v3_vector: Option<String>,
    pub cwe_ids: Vec<String>,
    pub references: Vec<String>,
    pub published_date: String,
}

/// Interface for credential access (implemented in forgescan-common)
pub trait CredentialProvider: Send + Sync {
    /// Get SSH credentials
    fn get_ssh(&self, id: &str) -> Option<SshCredential>;

    /// Get WinRM credentials
    fn get_winrm(&self, id: &str) -> Option<WinRmCredential>;

    /// Get HTTP Basic credentials
    fn get_http_basic(&self, id: &str) -> Option<HttpBasicCredential>;
}

#[derive(Debug, Clone)]
pub struct SshCredential {
    pub username: String,
    pub private_key: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WinRmCredential {
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpBasicCredential {
    pub username: String,
    pub password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCheck;

    impl Check for TestCheck {
        fn id(&self) -> &str {
            "TEST-001"
        }

        fn metadata(&self) -> &CheckMetadata {
            static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
            METADATA.get_or_init(|| {
                CheckMetadata::new(
                    "TEST-001",
                    "Test Check",
                    CheckCategory::Vulnerability,
                    Severity::High,
                )
            })
        }

        fn execute(&self, ctx: &CheckContext) -> CheckResult {
            // Simple test: generate a finding if port 22 is being checked
            if ctx.port == Some(22) {
                Ok(vec![Finding::builder("TEST-001", ctx.target_str())
                    .title("Test Finding")
                    .severity(Severity::High)
                    .build()])
            } else {
                Ok(vec![])
            }
        }
    }

    #[test]
    fn test_check_execution() {
        let check = TestCheck;
        let ctx = CheckContext::new(ScanTarget::parse("192.168.1.1").unwrap()).with_port(22, "tcp");

        let findings = check.execute(&ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id, "TEST-001");
    }
}
