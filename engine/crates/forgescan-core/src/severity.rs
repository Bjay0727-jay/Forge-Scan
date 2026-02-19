//! Severity levels and check categories

use serde::{Deserialize, Serialize};

/// Severity level for findings
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding, no security impact
    #[default]
    Info,
    /// Low severity, minimal risk
    Low,
    /// Medium severity, moderate risk
    Medium,
    /// High severity, significant risk
    High,
    /// Critical severity, immediate action required
    Critical,
}

impl Severity {
    /// Convert CVSS 3.x score to severity
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s >= 0.1 => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Get numeric value for sorting/comparison
    pub fn as_number(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Get display string
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Category of vulnerability check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckCategory {
    /// Network discovery (host, port, service detection)
    Network,
    /// Vulnerability detection (CVE matching, version checks)
    Vulnerability,
    /// Configuration auditing (CIS, STIG, compliance)
    Configuration,
    /// Web application security (OWASP Top 10)
    WebApp,
    /// Cloud misconfiguration (AWS, Azure, GCP)
    Cloud,
}

impl CheckCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckCategory::Network => "network",
            CheckCategory::Vulnerability => "vulnerability",
            CheckCategory::Configuration => "configuration",
            CheckCategory::WebApp => "webapp",
            CheckCategory::Cloud => "cloud",
        }
    }
}

impl std::fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_to_severity() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
