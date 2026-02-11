//! Finding definitions - vulnerabilities and misconfigurations discovered during scanning

use crate::severity::{CheckCategory, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A vulnerability or misconfiguration finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID
    pub id: Uuid,

    /// Check that generated this finding
    pub check_id: String,
    pub check_name: String,

    /// Target information
    pub target: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub service_version: Option<String>,

    /// Finding details
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: CheckCategory,

    /// CVE/CWE references
    #[serde(default)]
    pub cve_ids: Vec<String>,
    #[serde(default)]
    pub cwe_ids: Vec<String>,

    /// CVSS scoring
    pub cvss_v3_score: Option<f32>,
    pub cvss_v3_vector: Option<String>,

    /// Exploit information
    pub exploit_maturity: ExploitMaturity,
    pub cisa_kev: bool,

    /// CPE (Common Platform Enumeration)
    pub affected_cpe: Option<String>,

    /// Evidence and remediation
    pub evidence: String,
    pub remediation: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,

    /// Compliance mappings
    #[serde(default)]
    pub compliance_mappings: Vec<ComplianceRef>,

    /// Detection metadata
    pub detection_method: String,
    pub detected_at: DateTime<Utc>,

    /// Raw evidence data (for detailed analysis)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_evidence: Option<Vec<u8>>,
}

impl Finding {
    /// Create a new finding builder
    pub fn builder(check_id: impl Into<String>, target: impl Into<String>) -> FindingBuilder {
        FindingBuilder::new(check_id, target)
    }
}

/// Builder for constructing findings
pub struct FindingBuilder {
    finding: Finding,
}

impl FindingBuilder {
    pub fn new(check_id: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            finding: Finding {
                id: Uuid::new_v4(),
                check_id: check_id.into(),
                check_name: String::new(),
                target: target.into(),
                port: None,
                protocol: None,
                service: None,
                service_version: None,
                title: String::new(),
                description: String::new(),
                severity: Severity::Info,
                category: CheckCategory::Vulnerability,
                cve_ids: Vec::new(),
                cwe_ids: Vec::new(),
                cvss_v3_score: None,
                cvss_v3_vector: None,
                exploit_maturity: ExploitMaturity::None,
                cisa_kev: false,
                affected_cpe: None,
                evidence: String::new(),
                remediation: None,
                references: Vec::new(),
                compliance_mappings: Vec::new(),
                detection_method: String::from("unknown"),
                detected_at: Utc::now(),
                raw_evidence: None,
            },
        }
    }

    pub fn check_name(mut self, name: impl Into<String>) -> Self {
        self.finding.check_name = name.into();
        self
    }

    pub fn port(mut self, port: u16, protocol: impl Into<String>) -> Self {
        self.finding.port = Some(port);
        self.finding.protocol = Some(protocol.into());
        self
    }

    pub fn service(mut self, service: impl Into<String>, version: Option<String>) -> Self {
        self.finding.service = Some(service.into());
        self.finding.service_version = version;
        self
    }

    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.finding.title = title.into();
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.finding.description = desc.into();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.finding.severity = severity;
        self
    }

    pub fn category(mut self, category: CheckCategory) -> Self {
        self.finding.category = category;
        self
    }

    pub fn cve(mut self, cve_id: impl Into<String>) -> Self {
        self.finding.cve_ids.push(cve_id.into());
        self
    }

    pub fn cves(mut self, cve_ids: Vec<String>) -> Self {
        self.finding.cve_ids = cve_ids;
        self
    }

    pub fn cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.finding.cwe_ids.push(cwe_id.into());
        self
    }

    pub fn cvss(mut self, score: f32, vector: impl Into<String>) -> Self {
        self.finding.cvss_v3_score = Some(score);
        self.finding.cvss_v3_vector = Some(vector.into());
        self
    }

    pub fn exploit_maturity(mut self, maturity: ExploitMaturity) -> Self {
        self.finding.exploit_maturity = maturity;
        self
    }

    pub fn cisa_kev(mut self, in_kev: bool) -> Self {
        self.finding.cisa_kev = in_kev;
        self
    }

    pub fn cpe(mut self, cpe: impl Into<String>) -> Self {
        self.finding.affected_cpe = Some(cpe.into());
        self
    }

    pub fn evidence(mut self, evidence: impl Into<String>) -> Self {
        self.finding.evidence = evidence.into();
        self
    }

    pub fn raw_evidence(mut self, data: Vec<u8>) -> Self {
        self.finding.raw_evidence = Some(data);
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.finding.remediation = Some(remediation.into());
        self
    }

    pub fn reference(mut self, url: impl Into<String>) -> Self {
        self.finding.references.push(url.into());
        self
    }

    pub fn compliance(mut self, mapping: ComplianceRef) -> Self {
        self.finding.compliance_mappings.push(mapping);
        self
    }

    pub fn detection_method(mut self, method: impl Into<String>) -> Self {
        self.finding.detection_method = method.into();
        self
    }

    pub fn build(self) -> Finding {
        self.finding
    }
}

/// Exploit maturity levels (aligned with CVSS temporal metrics)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExploitMaturity {
    /// No known exploit
    #[default]
    None,
    /// Proof of concept exists
    Poc,
    /// Functional exploit available
    Functional,
    /// Weaponized exploit in active use
    Weaponized,
}

impl ExploitMaturity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExploitMaturity::None => "none",
            ExploitMaturity::Poc => "poc",
            ExploitMaturity::Functional => "functional",
            ExploitMaturity::Weaponized => "weaponized",
        }
    }

    /// Get a risk multiplier for FRS calculation
    pub fn risk_multiplier(&self) -> f32 {
        match self {
            ExploitMaturity::None => 1.0,
            ExploitMaturity::Poc => 1.2,
            ExploitMaturity::Functional => 1.5,
            ExploitMaturity::Weaponized => 2.0,
        }
    }
}

/// Compliance framework reference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceRef {
    /// Framework name (e.g., "NIST-800-53", "CIS", "DISA-STIG", "PCI-DSS")
    pub framework: String,
    /// Control identifier (e.g., "SI-2", "1.1.1", "V-12345")
    pub control_id: String,
    /// Human-readable control name
    pub control_name: Option<String>,
    /// Level (for CIS: 1 or 2)
    pub level: Option<u8>,
}

impl ComplianceRef {
    pub fn new(framework: impl Into<String>, control_id: impl Into<String>) -> Self {
        Self {
            framework: framework.into(),
            control_id: control_id.into(),
            control_name: None,
            level: None,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.control_name = Some(name.into());
        self
    }

    pub fn with_level(mut self, level: u8) -> Self {
        self.level = Some(level);
        self
    }
}

/// Information about an open port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
}

/// Port state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_builder() {
        let finding = Finding::builder("CVE-2021-44228", "192.168.1.1")
            .check_name("Log4Shell Detection")
            .title("Apache Log4j Remote Code Execution")
            .severity(Severity::Critical)
            .cve("CVE-2021-44228")
            .cvss(10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
            .exploit_maturity(ExploitMaturity::Weaponized)
            .cisa_kev(true)
            .evidence("Detected vulnerable Log4j version 2.14.0")
            .remediation("Upgrade to Log4j 2.17.1 or later")
            .compliance(ComplianceRef::new("NIST-800-53", "SI-2"))
            .detection_method("version-match")
            .build();

        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.cve_ids, vec!["CVE-2021-44228"]);
        assert!(finding.cisa_kev);
    }
}
