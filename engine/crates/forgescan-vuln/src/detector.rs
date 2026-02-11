//! Vulnerability detector - correlates detected services with CVE database
//!
//! The main detection engine that takes scan results and produces vulnerability findings.

use std::collections::HashMap;
use forgescan_core::{CveInfo, Finding, Severity};
use forgescan_nvd::{Cpe, NvdDb};
use tracing::{debug, info};

use crate::frs::{FrsCalculator, FrsScore};
use crate::matcher::{VersionMatcher, MatchResult};

/// Vulnerability detector engine
pub struct VulnDetector {
    matcher: VersionMatcher,
    frs_calculator: FrsCalculator,
    db: NvdDb,
}

/// Result of vulnerability detection
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Detected vulnerabilities
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    /// Total count by severity
    pub severity_counts: SeverityCounts,
    /// Highest FRS score
    pub max_frs: f64,
}

/// A detected vulnerability
#[derive(Debug, Clone)]
pub struct VulnerabilityFinding {
    /// CVE information
    pub cve: CveInfo,
    /// Affected asset
    pub asset: String,
    /// Affected service/port
    pub service: String,
    /// Detected version
    pub version: String,
    /// CPE string
    pub cpe: String,
    /// Forge Risk Score
    pub frs: FrsScore,
    /// Detection confidence (0-100)
    pub confidence: u8,
    /// Is in CISA KEV
    pub is_kev: bool,
}

/// Severity counts
#[derive(Debug, Clone, Default)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

/// Detected service information
#[derive(Debug, Clone)]
pub struct DetectedService {
    /// Target IP/hostname
    pub target: String,
    /// Port number
    pub port: u16,
    /// Service name
    pub service: String,
    /// Product name (if detected)
    pub product: Option<String>,
    /// Version (if detected)
    pub version: Option<String>,
    /// CPE (if generated)
    pub cpe: Option<String>,
    /// Additional info
    pub extra_info: Option<String>,
}

impl VulnDetector {
    /// Create a new vulnerability detector
    pub fn new(db: NvdDb) -> Self {
        Self {
            matcher: VersionMatcher::new(db.clone()),
            frs_calculator: FrsCalculator::new(),
            db,
        }
    }

    /// Detect vulnerabilities for a list of discovered services
    pub fn detect(&self, services: &[DetectedService]) -> DetectionResult {
        let mut vulnerabilities = Vec::new();
        let mut severity_counts = SeverityCounts::default();
        let mut max_frs = 0.0;

        for service in services {
            let findings = self.check_service(service);

            for finding in findings {
                // Update severity counts
                match finding.cve.cvss_v3_score {
                    Some(s) if s >= 9.0 => severity_counts.critical += 1,
                    Some(s) if s >= 7.0 => severity_counts.high += 1,
                    Some(s) if s >= 4.0 => severity_counts.medium += 1,
                    Some(s) if s >= 0.1 => severity_counts.low += 1,
                    _ => severity_counts.info += 1,
                }

                // Track max FRS
                if finding.frs.score > max_frs {
                    max_frs = finding.frs.score;
                }

                vulnerabilities.push(finding);
            }
        }

        info!(
            "Detected {} vulnerabilities (Critical: {}, High: {}, Medium: {}, Low: {})",
            vulnerabilities.len(),
            severity_counts.critical,
            severity_counts.high,
            severity_counts.medium,
            severity_counts.low
        );

        DetectionResult {
            vulnerabilities,
            severity_counts,
            max_frs,
        }
    }

    /// Check a single service for vulnerabilities
    fn check_service(&self, service: &DetectedService) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        // Need product and version for vulnerability matching
        let product = match &service.product {
            Some(p) => p,
            None => return findings,
        };

        let version = match &service.version {
            Some(v) => v,
            None => return findings,
        };

        // Generate or use existing CPE
        let cpe_string = service.cpe.clone().unwrap_or_else(|| {
            self.generate_cpe(&service.service, product, version)
        });

        debug!(
            "Checking {} on {}:{} (CPE: {})",
            product, service.target, service.port, cpe_string
        );

        // Match against NVD
        let match_result = self.matcher.match_cpe(&cpe_string);

        if match_result.is_vulnerable {
            for cve in match_result.cves {
                let is_kev = self.db.is_cisa_kev(&cve.cve_id);

                // Calculate FRS
                let frs = self.frs_calculator.calculate(
                    cve.cvss_v3_score.unwrap_or(5.0),
                    is_kev,
                    self.is_internet_facing(service),
                    self.has_exploit_available(&cve.cve_id),
                    self.asset_criticality(&service.target),
                );

                findings.push(VulnerabilityFinding {
                    cve,
                    asset: service.target.clone(),
                    service: format!("{}:{}", service.service, service.port),
                    version: version.clone(),
                    cpe: cpe_string.clone(),
                    frs,
                    confidence: match_result.confidence,
                    is_kev,
                });
            }
        }

        findings
    }

    /// Generate CPE string from service information
    fn generate_cpe(&self, service: &str, product: &str, version: &str) -> String {
        // Normalize product name for CPE
        let (vendor, prod) = self.normalize_product(service, product);

        Cpe::application(&vendor, &prod, version).to_cpe_string()
    }

    /// Normalize product name to CPE vendor/product format
    fn normalize_product(&self, service: &str, product: &str) -> (String, String) {
        let product_lower = product.to_lowercase();

        // Known mappings
        if product_lower.contains("openssh") {
            return ("openbsd".into(), "openssh".into());
        }
        if product_lower.contains("apache") && service == "http" {
            return ("apache".into(), "http_server".into());
        }
        if product_lower.contains("nginx") {
            return ("nginx".into(), "nginx".into());
        }
        if product_lower.contains("mysql") {
            return ("oracle".into(), "mysql".into());
        }
        if product_lower.contains("mariadb") {
            return ("mariadb".into(), "mariadb".into());
        }
        if product_lower.contains("postgresql") || product_lower.contains("postgres") {
            return ("postgresql".into(), "postgresql".into());
        }
        if product_lower.contains("redis") {
            return ("redis".into(), "redis".into());
        }
        if product_lower.contains("mongodb") {
            return ("mongodb".into(), "mongodb".into());
        }
        if product_lower.contains("iis") || product_lower.contains("microsoft-iis") {
            return ("microsoft".into(), "internet_information_services".into());
        }
        if product_lower.contains("vsftpd") {
            return ("vsftpd_project".into(), "vsftpd".into());
        }
        if product_lower.contains("proftpd") {
            return ("proftpd_project".into(), "proftpd".into());
        }
        if product_lower.contains("postfix") {
            return ("postfix".into(), "postfix".into());
        }
        if product_lower.contains("exim") {
            return ("exim".into(), "exim".into());
        }

        // Default: use product name as both vendor and product
        let normalized = product_lower.replace(' ', "_");
        (normalized.clone(), normalized)
    }

    /// Check if service is internet-facing (placeholder)
    fn is_internet_facing(&self, _service: &DetectedService) -> bool {
        // TODO: Implement based on network topology data
        true
    }

    /// Check if exploit is publicly available (placeholder)
    fn has_exploit_available(&self, _cve_id: &str) -> bool {
        // TODO: Check exploit databases (Exploit-DB, Metasploit, etc.)
        false
    }

    /// Get asset criticality (placeholder)
    fn asset_criticality(&self, _asset: &str) -> f64 {
        // TODO: Look up from asset registry
        0.5 // Default: medium criticality
    }

    /// Convert a VulnerabilityFinding to a core Finding
    pub fn to_finding(&self, vuln: &VulnerabilityFinding) -> Finding {
        let severity = match vuln.cve.cvss_v3_score {
            Some(s) if s >= 9.0 => Severity::Critical,
            Some(s) if s >= 7.0 => Severity::High,
            Some(s) if s >= 4.0 => Severity::Medium,
            Some(s) if s >= 0.1 => Severity::Low,
            _ => Severity::Info,
        };

        Finding::new(
            &format!("FSC-CVE-{}", vuln.cve.cve_id.replace("CVE-", "")),
            &format!("{}: {}", vuln.cve.cve_id, self.truncate_description(&vuln.cve.description, 100)),
            severity,
        )
        .with_description(&vuln.cve.description)
        .with_cve(&vuln.cve.cve_id)
        .with_evidence(&format!(
            "Detected {} version {} on {}",
            vuln.service, vuln.version, vuln.asset
        ))
        .with_remediation(&format!(
            "Update {} to a non-vulnerable version. See {} for details.",
            vuln.service,
            vuln.cve.references.first().map(|s| s.as_str()).unwrap_or("NVD")
        ))
    }

    fn truncate_description(&self, desc: &str, max_len: usize) -> String {
        if desc.len() <= max_len {
            desc.to_string()
        } else {
            format!("{}...", &desc[..max_len - 3])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_product() {
        let db = NvdDb::in_memory().unwrap();
        let detector = VulnDetector::new(db);

        assert_eq!(
            detector.normalize_product("ssh", "OpenSSH"),
            ("openbsd".into(), "openssh".into())
        );
        assert_eq!(
            detector.normalize_product("http", "Apache"),
            ("apache".into(), "http_server".into())
        );
        assert_eq!(
            detector.normalize_product("http", "nginx"),
            ("nginx".into(), "nginx".into())
        );
    }

    #[test]
    fn test_generate_cpe() {
        let db = NvdDb::in_memory().unwrap();
        let detector = VulnDetector::new(db);

        let cpe = detector.generate_cpe("ssh", "OpenSSH", "8.9p1");
        assert!(cpe.contains("openbsd"));
        assert!(cpe.contains("openssh"));
        assert!(cpe.contains("8.9p1"));
    }
}
