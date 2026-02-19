//! Data normalization for cross-vendor compatibility

use chrono::{DateTime, Utc};
use forgescan_core::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Normalized vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedFinding {
    /// Unique finding ID (generated)
    pub id: String,
    /// Original vendor finding ID
    pub vendor_id: String,
    /// Vendor source
    pub vendor: String,
    /// Finding title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// CVSS v3 score (if available)
    pub cvss_score: Option<f32>,
    /// CVSS v3 vector (if available)
    pub cvss_vector: Option<String>,
    /// Associated CVE IDs
    pub cve_ids: Vec<String>,
    /// CWE IDs
    pub cwe_ids: Vec<String>,
    /// Affected asset
    pub asset: NormalizedAsset,
    /// Port/service if applicable
    pub port: Option<u16>,
    /// Protocol (tcp/udp)
    pub protocol: Option<String>,
    /// Service name
    pub service: Option<String>,
    /// First discovered
    pub first_seen: DateTime<Utc>,
    /// Last observed
    pub last_seen: DateTime<Utc>,
    /// Finding state
    pub state: FindingState,
    /// Plugin/check family
    pub family: Option<String>,
    /// Solution/remediation
    pub solution: Option<String>,
    /// References
    pub references: Vec<String>,
    /// Evidence/output
    pub evidence: Option<String>,
    /// Exploitability info
    pub exploit_available: bool,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Finding state
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingState {
    /// Active/open finding
    #[default]
    Open,
    /// Finding has been fixed
    Fixed,
    /// Finding accepted as risk
    Accepted,
    /// False positive
    FalsePositive,
    /// Reopened finding
    Reopened,
}

/// Normalized asset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedAsset {
    /// Unique asset ID (generated)
    pub id: String,
    /// Original vendor asset ID
    pub vendor_id: Option<String>,
    /// Hostname
    pub hostname: Option<String>,
    /// FQDN
    pub fqdn: Option<String>,
    /// IP addresses
    pub ip_addresses: Vec<String>,
    /// MAC addresses
    pub mac_addresses: Vec<String>,
    /// Operating system
    pub os: Option<String>,
    /// OS version
    pub os_version: Option<String>,
    /// Asset type
    pub asset_type: AssetType,
    /// Network zone
    pub network_zone: Option<String>,
    /// Tags
    pub tags: Vec<String>,
    /// First discovered
    pub first_seen: Option<DateTime<Utc>>,
    /// Last scanned
    pub last_seen: Option<DateTime<Utc>>,
    /// Is asset authenticated
    pub authenticated: bool,
    /// Agent installed
    pub has_agent: bool,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

/// Asset type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    Server,
    Workstation,
    NetworkDevice,
    Container,
    VirtualMachine,
    CloudInstance,
    Database,
    WebApplication,
    #[default]
    Unknown,
}

/// Normalizer for converting vendor-specific data
pub struct Normalizer;

impl Normalizer {
    /// Convert vendor severity to normalized severity
    pub fn normalize_severity(_vendor: &str, value: &str, score: Option<f32>) -> Severity {
        // First try CVSS score if available
        if let Some(cvss) = score {
            return Severity::from_cvss(cvss);
        }

        // Normalize vendor-specific severity strings
        let value_lower = value.to_lowercase();

        match value_lower.as_str() {
            "critical" | "4" | "urgent" => Severity::Critical,
            "high" | "3" | "serious" => Severity::High,
            "medium" | "2" | "moderate" => Severity::Medium,
            "low" | "1" | "minimal" => Severity::Low,
            "info" | "informational" | "0" | "none" => Severity::Info,
            _ => {
                // Try to parse as number
                if let Ok(num) = value.parse::<u8>() {
                    match num {
                        4.. => Severity::Critical,
                        3 => Severity::High,
                        2 => Severity::Medium,
                        1 => Severity::Low,
                        _ => Severity::Info,
                    }
                } else {
                    Severity::Medium // Default to medium
                }
            }
        }
    }

    /// Extract CVE IDs from text
    pub fn extract_cve_ids(text: &str) -> Vec<String> {
        let re = regex::Regex::new(r"CVE-\d{4}-\d{4,}").unwrap();
        re.find_iter(text).map(|m| m.as_str().to_string()).collect()
    }

    /// Alias for extract_cve_ids
    pub fn extract_cves(text: &str) -> Vec<String> {
        Self::extract_cve_ids(text)
    }

    /// Extract CWE IDs from text
    pub fn extract_cwe_ids(text: &str) -> Vec<String> {
        let re = regex::Regex::new(r"CWE-\d+").unwrap();
        re.find_iter(text).map(|m| m.as_str().to_string()).collect()
    }

    /// Alias for extract_cwe_ids
    pub fn extract_cwes(text: &str) -> Vec<String> {
        Self::extract_cwe_ids(text)
    }

    /// Generate unique finding ID
    pub fn generate_finding_id(vendor: &str, vendor_id: &str, asset_id: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        vendor.hash(&mut hasher);
        vendor_id.hash(&mut hasher);
        asset_id.hash(&mut hasher);

        format!("FND-{:016x}", hasher.finish())
    }

    /// Generate unique asset ID
    pub fn generate_asset_id(hostname: Option<&str>, ips: &[String]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        if let Some(h) = hostname {
            h.hash(&mut hasher);
        }

        for ip in ips {
            ip.hash(&mut hasher);
        }

        format!("AST-{:016x}", hasher.finish())
    }

    /// Detect asset type from OS string
    pub fn detect_asset_type(os: Option<&str>, hostname: Option<&str>) -> AssetType {
        let os_lower = os.map(|s| s.to_lowercase()).unwrap_or_default();
        let host_lower = hostname.map(|s| s.to_lowercase()).unwrap_or_default();

        // Check for network devices
        if os_lower.contains("cisco")
            || os_lower.contains("juniper")
            || os_lower.contains("arista")
            || os_lower.contains("fortinet")
            || os_lower.contains("palo alto")
        {
            return AssetType::NetworkDevice;
        }

        // Check for containers
        if os_lower.contains("container") || host_lower.contains("docker") {
            return AssetType::Container;
        }

        // Check for servers vs workstations
        if os_lower.contains("server") {
            return AssetType::Server;
        }

        if os_lower.contains("windows 10")
            || os_lower.contains("windows 11")
            || os_lower.contains("macos")
            || os_lower.contains("ubuntu desktop")
        {
            return AssetType::Workstation;
        }

        // Cloud instances
        if host_lower.contains("ec2")
            || host_lower.contains("compute")
            || host_lower.contains("vm-")
        {
            return AssetType::CloudInstance;
        }

        // Default to server for Linux
        if os_lower.contains("linux") || os_lower.contains("unix") {
            return AssetType::Server;
        }

        AssetType::Unknown
    }

    /// Parse CVSS vector to extract severity components
    pub fn parse_cvss_vector(vector: &str) -> HashMap<String, String> {
        let mut components = HashMap::new();

        // Handle both CVSS 2.0 and 3.x vectors
        for part in vector.split('/') {
            if let Some((key, value)) = part.split_once(':') {
                components.insert(key.to_string(), value.to_string());
            }
        }

        components
    }

    /// Deduplicate findings by generating a signature
    pub fn finding_signature(finding: &NormalizedFinding) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        finding.vendor_id.hash(&mut hasher);
        finding.asset.id.hash(&mut hasher);
        finding.port.hash(&mut hasher);

        format!("{:016x}", hasher.finish())
    }
}

/// Builder for normalized findings
pub struct NormalizedFindingBuilder {
    finding: NormalizedFinding,
}

impl NormalizedFindingBuilder {
    pub fn new(vendor: &str, vendor_id: &str, title: &str) -> Self {
        Self {
            finding: NormalizedFinding {
                id: String::new(),
                vendor_id: vendor_id.to_string(),
                vendor: vendor.to_string(),
                title: title.to_string(),
                description: String::new(),
                severity: Severity::Medium,
                cvss_score: None,
                cvss_vector: None,
                cve_ids: Vec::new(),
                cwe_ids: Vec::new(),
                asset: NormalizedAsset {
                    id: String::new(),
                    vendor_id: None,
                    hostname: None,
                    fqdn: None,
                    ip_addresses: Vec::new(),
                    mac_addresses: Vec::new(),
                    os: None,
                    os_version: None,
                    asset_type: AssetType::Unknown,
                    network_zone: None,
                    tags: Vec::new(),
                    first_seen: None,
                    last_seen: None,
                    authenticated: false,
                    has_agent: false,
                    attributes: HashMap::new(),
                },
                port: None,
                protocol: None,
                service: None,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                state: FindingState::Open,
                family: None,
                solution: None,
                references: Vec::new(),
                evidence: None,
                exploit_available: false,
                metadata: HashMap::new(),
            },
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.finding.description = desc.to_string();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.finding.severity = severity;
        self
    }

    pub fn cvss(mut self, score: f32, vector: Option<&str>) -> Self {
        self.finding.cvss_score = Some(score);
        self.finding.cvss_vector = vector.map(String::from);
        self
    }

    pub fn cve(mut self, cve_id: &str) -> Self {
        self.finding.cve_ids.push(cve_id.to_string());
        self
    }

    pub fn cves(mut self, cve_ids: Vec<String>) -> Self {
        self.finding.cve_ids = cve_ids;
        self
    }

    pub fn cwe(mut self, cwe_id: &str) -> Self {
        self.finding.cwe_ids.push(cwe_id.to_string());
        self
    }

    pub fn cwes(mut self, cwe_ids: Vec<String>) -> Self {
        self.finding.cwe_ids = cwe_ids;
        self
    }

    pub fn asset_ip(mut self, ip: &str) -> Self {
        self.finding.asset.ip_addresses.push(ip.to_string());
        self
    }

    pub fn asset_hostname(mut self, hostname: &str) -> Self {
        self.finding.asset.hostname = Some(hostname.to_string());
        self
    }

    pub fn port(mut self, port: u16, protocol: Option<&str>) -> Self {
        self.finding.port = Some(port);
        self.finding.protocol = protocol.map(String::from);
        self
    }

    pub fn service(mut self, service: &str) -> Self {
        self.finding.service = Some(service.to_string());
        self
    }

    pub fn solution(mut self, solution: &str) -> Self {
        self.finding.solution = Some(solution.to_string());
        self
    }

    pub fn evidence(mut self, evidence: &str) -> Self {
        self.finding.evidence = Some(evidence.to_string());
        self
    }

    pub fn exploit_available(mut self, available: bool) -> Self {
        self.finding.exploit_available = available;
        self
    }

    pub fn reference(mut self, url: &str) -> Self {
        self.finding.references.push(url.to_string());
        self
    }

    pub fn family(mut self, family: &str) -> Self {
        self.finding.family = Some(family.to_string());
        self
    }

    pub fn first_seen(mut self, when: DateTime<Utc>) -> Self {
        self.finding.first_seen = when;
        self
    }

    pub fn last_seen(mut self, when: DateTime<Utc>) -> Self {
        self.finding.last_seen = when;
        self
    }

    pub fn build(mut self) -> NormalizedFinding {
        // Generate IDs
        self.finding.asset.id = Normalizer::generate_asset_id(
            self.finding.asset.hostname.as_deref(),
            &self.finding.asset.ip_addresses,
        );

        self.finding.id = Normalizer::generate_finding_id(
            &self.finding.vendor,
            &self.finding.vendor_id,
            &self.finding.asset.id,
        );

        // Detect asset type
        self.finding.asset.asset_type = Normalizer::detect_asset_type(
            self.finding.asset.os.as_deref(),
            self.finding.asset.hostname.as_deref(),
        );

        self.finding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_severity() {
        assert_eq!(
            Normalizer::normalize_severity("tenable", "critical", None),
            Severity::Critical
        );
        assert_eq!(
            Normalizer::normalize_severity("qualys", "4", None),
            Severity::Critical
        );
        assert_eq!(
            Normalizer::normalize_severity("any", "", Some(9.5)),
            Severity::Critical
        );
    }

    #[test]
    fn test_extract_cve_ids() {
        let text = "This vulnerability is tracked as CVE-2023-1234 and CVE-2023-5678.";
        let cves = Normalizer::extract_cve_ids(text);
        assert_eq!(cves.len(), 2);
        assert!(cves.contains(&"CVE-2023-1234".to_string()));
        assert!(cves.contains(&"CVE-2023-5678".to_string()));
    }

    #[test]
    fn test_finding_builder() {
        let finding = NormalizedFindingBuilder::new("tenable", "12345", "Test Finding")
            .description("A test finding")
            .severity(Severity::High)
            .cvss(8.5, Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
            .asset_ip("192.168.1.1")
            .port(443, Some("tcp"))
            .build();

        assert!(!finding.id.is_empty());
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.port, Some(443));
    }
}
