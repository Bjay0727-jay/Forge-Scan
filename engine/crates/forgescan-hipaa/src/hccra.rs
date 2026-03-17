//! Health Care Cybersecurity and Resiliency Act of 2025 (HCCRA)
//!
//! Defines the 7 mandatory cybersecurity controls required by the Act and
//! their mapping to HIPAA technical safeguards and scan finding categories.

use crate::safeguards::TechnicalSafeguard;
use serde::{Deserialize, Serialize};

/// The 7 mandatory controls from the Health Care Cybersecurity and Resiliency Act of 2025
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HccraControl {
    /// Control 1: Multi-Factor Authentication
    /// Require MFA for all remote access to ePHI systems.
    MultiFactorAuth,
    /// Control 2: Encryption of ePHI
    /// Encrypt ePHI at rest and in transit.
    Encryption,
    /// Control 3: Network Segmentation
    /// Segment networks to isolate systems containing ePHI.
    NetworkSegmentation,
    /// Control 4: Vulnerability Management
    /// Conduct regular vulnerability assessments and timely patching.
    VulnerabilityManagement,
    /// Control 5: Incident Response Planning
    /// Maintain and test an incident response plan for cyber incidents.
    IncidentResponse,
    /// Control 6: Audit Logging and Monitoring
    /// Implement continuous monitoring and logging of ePHI access.
    AuditLogging,
    /// Control 7: Supply Chain Risk Management
    /// Assess and manage cybersecurity risks from third-party vendors.
    SupplyChainRisk,
}

impl HccraControl {
    /// Human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::MultiFactorAuth => "Multi-Factor Authentication",
            Self::Encryption => "Encryption of ePHI",
            Self::NetworkSegmentation => "Network Segmentation",
            Self::VulnerabilityManagement => "Vulnerability Management",
            Self::IncidentResponse => "Incident Response Planning",
            Self::AuditLogging => "Audit Logging and Monitoring",
            Self::SupplyChainRisk => "Supply Chain Risk Management",
        }
    }

    /// Control number (1-7)
    pub fn number(&self) -> u8 {
        match self {
            Self::MultiFactorAuth => 1,
            Self::Encryption => 2,
            Self::NetworkSegmentation => 3,
            Self::VulnerabilityManagement => 4,
            Self::IncidentResponse => 5,
            Self::AuditLogging => 6,
            Self::SupplyChainRisk => 7,
        }
    }

    /// Control identifier string
    pub fn control_id(&self) -> &'static str {
        match self {
            Self::MultiFactorAuth => "HCCRA-1",
            Self::Encryption => "HCCRA-2",
            Self::NetworkSegmentation => "HCCRA-3",
            Self::VulnerabilityManagement => "HCCRA-4",
            Self::IncidentResponse => "HCCRA-5",
            Self::AuditLogging => "HCCRA-6",
            Self::SupplyChainRisk => "HCCRA-7",
        }
    }

    /// Full regulatory description
    pub fn description(&self) -> &'static str {
        match self {
            Self::MultiFactorAuth => {
                "Covered entities and business associates must implement multi-factor \
                 authentication for all remote access to information systems that create, \
                 receive, maintain, or transmit electronic protected health information."
            }
            Self::Encryption => {
                "Covered entities and business associates must encrypt all electronic \
                 protected health information at rest and in transit using standards \
                 recognized by NIST."
            }
            Self::NetworkSegmentation => {
                "Covered entities and business associates must implement network \
                 segmentation to isolate information systems containing electronic \
                 protected health information from other network segments."
            }
            Self::VulnerabilityManagement => {
                "Covered entities and business associates must conduct vulnerability \
                 assessments at least every 6 months and apply critical security patches \
                 within 30 days of availability."
            }
            Self::IncidentResponse => {
                "Covered entities and business associates must maintain and test a \
                 cybersecurity incident response plan at least annually, and report \
                 significant incidents to HHS within 72 hours."
            }
            Self::AuditLogging => {
                "Covered entities and business associates must implement continuous \
                 monitoring and logging of all access to electronic protected health \
                 information, with log retention of at least 6 years."
            }
            Self::SupplyChainRisk => {
                "Covered entities and business associates must assess cybersecurity \
                 risks posed by third-party vendors and business associates with access \
                 to electronic protected health information."
            }
        }
    }

    /// Which HIPAA technical safeguards this HCCRA control maps to
    pub fn mapped_safeguards(&self) -> Vec<TechnicalSafeguard> {
        match self {
            Self::MultiFactorAuth => vec![TechnicalSafeguard::AccessControl],
            Self::Encryption => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::TransmissionSecurity,
            ],
            Self::NetworkSegmentation => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::TransmissionSecurity,
            ],
            Self::VulnerabilityManagement => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::Integrity,
            ],
            Self::IncidentResponse => vec![
                TechnicalSafeguard::AuditControls,
                TechnicalSafeguard::Integrity,
            ],
            Self::AuditLogging => vec![TechnicalSafeguard::AuditControls],
            Self::SupplyChainRisk => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::Integrity,
                TechnicalSafeguard::TransmissionSecurity,
            ],
        }
    }

    /// All 7 mandatory controls
    pub fn all() -> &'static [HccraControl] {
        &[
            Self::MultiFactorAuth,
            Self::Encryption,
            Self::NetworkSegmentation,
            Self::VulnerabilityManagement,
            Self::IncidentResponse,
            Self::AuditLogging,
            Self::SupplyChainRisk,
        ]
    }
}

impl std::fmt::Display for HccraControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.control_id(), self.name())
    }
}

/// Compliance status for a single HCCRA control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HccraControlStatus {
    /// The control being assessed
    pub control: HccraControl,
    /// Overall compliance status
    pub status: ComplianceStatus,
    /// Number of findings that impact this control
    pub finding_count: u32,
    /// Number of critical/high findings
    pub critical_high_count: u32,
    /// Evidence items supporting the assessment
    pub evidence: Vec<String>,
    /// Recommended actions
    pub recommendations: Vec<String>,
}

/// Compliance status for a control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Fully compliant — no findings
    Compliant,
    /// Partially compliant — some findings, none critical
    PartiallyCompliant,
    /// Non-compliant — critical or high findings present
    NonCompliant,
    /// Unable to assess — insufficient evidence
    NotAssessed,
}

impl ComplianceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compliant => "Compliant",
            Self::PartiallyCompliant => "Partially Compliant",
            Self::NonCompliant => "Non-Compliant",
            Self::NotAssessed => "Not Assessed",
        }
    }
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seven_controls() {
        assert_eq!(HccraControl::all().len(), 7);
    }

    #[test]
    fn test_control_numbers() {
        for (i, control) in HccraControl::all().iter().enumerate() {
            assert_eq!(control.number() as usize, i + 1);
        }
    }

    #[test]
    fn test_all_controls_map_to_safeguards() {
        for control in HccraControl::all() {
            assert!(
                !control.mapped_safeguards().is_empty(),
                "{} has no mapped safeguards",
                control
            );
        }
    }

    #[test]
    fn test_control_ids_unique() {
        let ids: Vec<_> = HccraControl::all().iter().map(|c| c.control_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }
}
