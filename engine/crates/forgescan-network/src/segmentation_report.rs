//! Segmentation Compliance Report Generator
//!
//! Generates compliance reports mapping network segmentation assessment results
//! to HIPAA Security Rule requirements and NIST 800-171 controls.
//!
//! Report formats:
//! - Structured report with per-control compliance status
//! - Executive summary text for board/CISO presentation
//! - JSON for ForgeComply 360 integration

use crate::segmentation::{
    AssessmentSummary, NetworkZone, SegmentationAssessment, SegmentationViolation, ViolationType,
};
use chrono::{DateTime, Utc};
use forgescan_core::Severity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Compliance Control Definitions ────────────────────────────────────────

/// HIPAA controls related to network segmentation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HipaaSegmentationControl {
    /// §164.312(a)(1) — Access Control (network-level)
    AccessControl,
    /// §164.312(e)(1) — Transmission Security
    TransmissionSecurity,
    /// §164.308(a)(1)(ii)(B) — Risk Management (network risk)
    RiskManagement,
    /// §164.310(b) — Workstation Use (network access from workstations)
    WorkstationUse,
}

impl HipaaSegmentationControl {
    pub fn cfr_citation(&self) -> &'static str {
        match self {
            Self::AccessControl => "§164.312(a)(1)",
            Self::TransmissionSecurity => "§164.312(e)(1)",
            Self::RiskManagement => "§164.308(a)(1)(ii)(B)",
            Self::WorkstationUse => "§164.310(b)",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AccessControl => "Access Control (Network Segmentation)",
            Self::TransmissionSecurity => "Transmission Security (Zone Isolation)",
            Self::RiskManagement => "Risk Management (Network Architecture)",
            Self::WorkstationUse => "Workstation Use (Zone Assignment)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::AccessControl => {
                "Technical policies and procedures to control access to ePHI \
                 through network segmentation and zone-based access controls."
            }
            Self::TransmissionSecurity => {
                "Technical security measures to protect ePHI transmitted between \
                 network zones from unauthorized interception or modification."
            }
            Self::RiskManagement => {
                "Security measures to reduce risks from network architecture, \
                 including segmentation validation and lateral movement prevention."
            }
            Self::WorkstationUse => {
                "Policies specifying network zones from which workstations may \
                 access ePHI and the security controls required for each zone."
            }
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::AccessControl,
            Self::TransmissionSecurity,
            Self::RiskManagement,
            Self::WorkstationUse,
        ]
    }
}

impl std::fmt::Display for HipaaSegmentationControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.cfr_citation())
    }
}

/// NIST 800-171 controls related to network segmentation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Nist800171Control {
    /// 3.13.1 — Boundary Protection
    BoundaryProtection,
    /// 3.13.2 — Architectural Designs and Techniques
    ArchitecturalDesigns,
    /// 3.13.5 — Subnetwork Separation
    SubnetworkSeparation,
    /// 3.13.6 — Network Communication by Exception
    NetworkByException,
    /// 3.13.8 — CUI in Transit
    CuiInTransit,
    /// 3.14.6 — Monitor Communications at Boundaries
    MonitorBoundaries,
}

impl Nist800171Control {
    pub fn control_id(&self) -> &'static str {
        match self {
            Self::BoundaryProtection => "3.13.1",
            Self::ArchitecturalDesigns => "3.13.2",
            Self::SubnetworkSeparation => "3.13.5",
            Self::NetworkByException => "3.13.6",
            Self::CuiInTransit => "3.13.8",
            Self::MonitorBoundaries => "3.14.6",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::BoundaryProtection => "Boundary Protection",
            Self::ArchitecturalDesigns => {
                "Architectural Designs, Software Development, and Systems Engineering"
            }
            Self::SubnetworkSeparation => {
                "Implement Subnetworks for Publicly Accessible Components"
            }
            Self::NetworkByException => "Deny Network Communication by Default",
            Self::CuiInTransit => "Implement Cryptographic Mechanisms to Protect CUI in Transit",
            Self::MonitorBoundaries => {
                "Monitor Communications at External and Key Internal Boundaries"
            }
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::BoundaryProtection => {
                "Monitor, control, and protect organizational communications \
                 at the external boundaries and key internal boundaries of \
                 information systems."
            }
            Self::ArchitecturalDesigns => {
                "Employ architectural designs, software development techniques, \
                 and systems engineering principles that promote effective \
                 information security."
            }
            Self::SubnetworkSeparation => {
                "Implement subnetworks for publicly accessible system components \
                 that are physically or logically separated from internal networks."
            }
            Self::NetworkByException => {
                "Deny network communications traffic by default and allow by \
                 exception (deny-all, allow-by-exception)."
            }
            Self::CuiInTransit => {
                "Implement cryptographic mechanisms to prevent unauthorized \
                 disclosure of CUI during transmission."
            }
            Self::MonitorBoundaries => {
                "Monitor, control, and protect communications at key internal \
                 boundaries of the information system."
            }
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::BoundaryProtection,
            Self::ArchitecturalDesigns,
            Self::SubnetworkSeparation,
            Self::NetworkByException,
            Self::CuiInTransit,
            Self::MonitorBoundaries,
        ]
    }
}

impl std::fmt::Display for Nist800171Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} — {}", self.control_id(), self.name())
    }
}

// ─── Compliance Status ─────────────────────────────────────────────────────

/// Compliance status for a control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotAssessed,
}

impl ControlStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compliant => "Compliant",
            Self::PartiallyCompliant => "Partially Compliant",
            Self::NonCompliant => "Non-Compliant",
            Self::NotAssessed => "Not Assessed",
        }
    }
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Compliance Report ─────────────────────────────────────────────────────

/// Complete segmentation compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationComplianceReport {
    /// Report ID
    pub id: Uuid,
    /// Report title
    pub title: String,
    /// Organization name
    pub organization: String,
    /// When the report was generated
    pub generated_at: DateTime<Utc>,
    /// Assessment period
    pub assessment_period: AssessmentPeriod,
    /// Overall segmentation compliance score (0-100)
    pub overall_score: f64,
    /// HIPAA control compliance statuses
    pub hipaa_controls: Vec<ControlAssessment<HipaaSegmentationControl>>,
    /// NIST 800-171 control compliance statuses
    pub nist_controls: Vec<ControlAssessment<Nist800171Control>>,
    /// HCCRA Control 3 (Network Segmentation) detailed status
    pub hccra_network_segmentation: HccraNetSegStatus,
    /// Zone isolation matrix
    pub zone_isolation_matrix: Vec<ZoneIsolationEntry>,
    /// Key findings summary
    pub key_findings: Vec<String>,
    /// Remediation priorities
    pub remediation_priorities: Vec<RemediationPriority>,
    /// Assessment summary from the segmentation engine
    pub assessment_summary: AssessmentSummary,
}

/// Assessment time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentPeriod {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Per-control assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAssessment<C: Serialize> {
    /// The control
    pub control: C,
    /// Compliance status
    pub status: ControlStatus,
    /// Score for this control (0-100)
    pub score: f64,
    /// Number of related violations
    pub violation_count: u32,
    /// Evidence supporting the assessment
    pub evidence: Vec<String>,
    /// Gaps identified
    pub gaps: Vec<String>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// HCCRA Control 3 detailed assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HccraNetSegStatus {
    pub control_id: String,
    pub control_name: String,
    pub status: ControlStatus,
    pub score: f64,
    pub zones_defined: u32,
    pub zones_verified: u32,
    pub isolation_tests_passed: u32,
    pub isolation_tests_total: u32,
    pub lateral_paths_found: u32,
    pub critical_violations: u32,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Zone-to-zone isolation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneIsolationEntry {
    pub source_zone: NetworkZone,
    pub destination_zone: NetworkZone,
    pub expected: String, // "Isolated" or "Allowed (ports: ...)"
    pub actual: String,   // "Isolated" or "Reachable (ports: ...)"
    pub compliant: bool,
}

/// Prioritized remediation item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPriority {
    pub priority: u32,
    pub title: String,
    pub severity: Severity,
    pub affected_controls: Vec<String>,
    pub action: String,
    pub sla_days: u32,
}

// ─── Report Generator ──────────────────────────────────────────────────────

/// Generates compliance reports from segmentation assessments
pub struct SegmentationReportGenerator {
    organization: String,
}

impl SegmentationReportGenerator {
    pub fn new(organization: impl Into<String>) -> Self {
        Self {
            organization: organization.into(),
        }
    }

    /// Generate a complete compliance report from a segmentation assessment
    pub fn generate(&self, assessment: &SegmentationAssessment) -> SegmentationComplianceReport {
        let hipaa_controls = self.assess_hipaa_controls(assessment);
        let nist_controls = self.assess_nist_controls(assessment);
        let hccra_status = self.assess_hccra_netseg(assessment);
        let zone_matrix = self.build_zone_matrix(assessment);
        let key_findings = self.extract_key_findings(assessment);
        let remediation = self.build_remediation_plan(assessment);

        let overall_score =
            self.calculate_overall_score(&hipaa_controls, &nist_controls, &hccra_status);

        SegmentationComplianceReport {
            id: Uuid::new_v4(),
            title: "Network Segmentation Compliance Assessment".into(),
            organization: self.organization.clone(),
            generated_at: Utc::now(),
            assessment_period: AssessmentPeriod {
                start: assessment.assessed_at,
                end: assessment.assessed_at,
            },
            overall_score,
            hipaa_controls,
            nist_controls,
            hccra_network_segmentation: hccra_status,
            zone_isolation_matrix: zone_matrix,
            key_findings,
            remediation_priorities: remediation,
            assessment_summary: assessment.summary.clone(),
        }
    }

    /// Assess HIPAA segmentation controls
    fn assess_hipaa_controls(
        &self,
        assessment: &SegmentationAssessment,
    ) -> Vec<ControlAssessment<HipaaSegmentationControl>> {
        HipaaSegmentationControl::all()
            .iter()
            .map(|&control| {
                let (status, score, violations, evidence, gaps, recommendations) =
                    self.evaluate_hipaa_control(control, assessment);

                ControlAssessment {
                    control,
                    status,
                    score,
                    violation_count: violations,
                    evidence,
                    gaps,
                    recommendations,
                }
            })
            .collect()
    }

    /// Evaluate a single HIPAA control
    fn evaluate_hipaa_control(
        &self,
        control: HipaaSegmentationControl,
        assessment: &SegmentationAssessment,
    ) -> (
        ControlStatus,
        f64,
        u32,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    ) {
        let relevant_violations: Vec<&SegmentationViolation> = match control {
            HipaaSegmentationControl::AccessControl => assessment
                .violations
                .iter()
                .filter(|v| {
                    matches!(
                        v.violation_type,
                        ViolationType::UntrustedToEphi
                            | ViolationType::GuestEscalation
                            | ViolationType::MedDeviceExposure
                    )
                })
                .collect(),
            HipaaSegmentationControl::TransmissionSecurity => assessment
                .violations
                .iter()
                .filter(|v| v.source_zone.is_untrusted() || v.destination_zone.handles_ephi())
                .collect(),
            HipaaSegmentationControl::RiskManagement => assessment
                .violations
                .iter()
                .filter(|v| {
                    matches!(
                        v.violation_type,
                        ViolationType::FlatNetwork | ViolationType::LateralMovementPath
                    )
                })
                .collect(),
            HipaaSegmentationControl::WorkstationUse => assessment
                .violations
                .iter()
                .filter(|v| matches!(v.violation_type, ViolationType::UnauthorizedCrossZone))
                .collect(),
        };

        let violation_count = relevant_violations.len() as u32;
        let has_critical = relevant_violations
            .iter()
            .any(|v| v.severity == Severity::Critical);
        let status = if violation_count == 0 {
            ControlStatus::Compliant
        } else if has_critical {
            ControlStatus::NonCompliant
        } else {
            ControlStatus::PartiallyCompliant
        };

        let score = if violation_count == 0 {
            100.0
        } else {
            let penalty: f64 = relevant_violations
                .iter()
                .map(|v| match v.severity {
                    Severity::Critical => 25.0,
                    Severity::High => 15.0,
                    Severity::Medium => 8.0,
                    Severity::Low => 3.0,
                    Severity::Info => 1.0,
                })
                .sum();
            (100.0 - penalty).max(0.0)
        };

        let evidence = if violation_count == 0 {
            vec![format!(
                "No segmentation violations detected for {} — zone isolation verified",
                control.name(),
            )]
        } else {
            relevant_violations
                .iter()
                .take(5)
                .map(|v| v.description.clone())
                .collect()
        };

        let gaps = self.identify_hipaa_gaps(control, &relevant_violations);
        let recommendations = self.recommend_hipaa(control, violation_count);

        (
            status,
            score,
            violation_count,
            evidence,
            gaps,
            recommendations,
        )
    }

    /// Identify gaps for a HIPAA control
    fn identify_hipaa_gaps(
        &self,
        control: HipaaSegmentationControl,
        violations: &[&SegmentationViolation],
    ) -> Vec<String> {
        if violations.is_empty() {
            return vec![];
        }
        match control {
            HipaaSegmentationControl::AccessControl => vec![
                "Network access controls do not prevent unauthorized zone traversal".into(),
                "ePHI systems are accessible from unauthorized network segments".into(),
            ],
            HipaaSegmentationControl::TransmissionSecurity => vec![
                "Zone boundaries do not enforce transmission security controls".into(),
                "Cross-zone traffic is not restricted to authorized protocols".into(),
            ],
            HipaaSegmentationControl::RiskManagement => vec![
                "Network architecture allows lateral movement between zones".into(),
                "Segmentation gaps create unacceptable risk to ePHI".into(),
            ],
            HipaaSegmentationControl::WorkstationUse => {
                vec!["Workstations in unauthorized zones can access protected resources".into()]
            }
        }
    }

    /// Generate HIPAA recommendations
    fn recommend_hipaa(
        &self,
        control: HipaaSegmentationControl,
        violation_count: u32,
    ) -> Vec<String> {
        if violation_count == 0 {
            return vec!["Maintain current network segmentation posture".into()];
        }
        match control {
            HipaaSegmentationControl::AccessControl => vec![
                "Implement deny-all, allow-by-exception firewall rules at zone boundaries".into(),
                "Deploy network access control (NAC) to enforce zone assignments".into(),
                "Enable 802.1X port-based authentication on all switch ports".into(),
            ],
            HipaaSegmentationControl::TransmissionSecurity => vec![
                "Encrypt all cross-zone ePHI traffic using TLS 1.2+".into(),
                "Deploy IDS/IPS at zone boundaries to detect unauthorized protocols".into(),
                "Implement mutual TLS for medical device communications".into(),
            ],
            HipaaSegmentationControl::RiskManagement => vec![
                "Conduct quarterly network segmentation penetration testing".into(),
                "Implement micro-segmentation for medical device networks".into(),
                "Deploy network detection and response (NDR) for lateral movement detection".into(),
            ],
            HipaaSegmentationControl::WorkstationUse => vec![
                "Enforce zone-based workstation policies via group policy".into(),
                "Implement VLAN assignment based on device certificate/identity".into(),
            ],
        }
    }

    /// Assess NIST 800-171 controls
    fn assess_nist_controls(
        &self,
        assessment: &SegmentationAssessment,
    ) -> Vec<ControlAssessment<Nist800171Control>> {
        Nist800171Control::all()
            .iter()
            .map(|&control| {
                let (status, score, violations, evidence, gaps, recommendations) =
                    self.evaluate_nist_control(control, assessment);

                ControlAssessment {
                    control,
                    status,
                    score,
                    violation_count: violations,
                    evidence,
                    gaps,
                    recommendations,
                }
            })
            .collect()
    }

    /// Evaluate a single NIST 800-171 control
    fn evaluate_nist_control(
        &self,
        control: Nist800171Control,
        assessment: &SegmentationAssessment,
    ) -> (
        ControlStatus,
        f64,
        u32,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    ) {
        let relevant_violations: Vec<&SegmentationViolation> = match control {
            Nist800171Control::BoundaryProtection => assessment
                .violations
                .iter()
                .filter(|v| {
                    matches!(
                        v.violation_type,
                        ViolationType::UntrustedToEphi
                            | ViolationType::UnauthorizedCrossZone
                            | ViolationType::GuestEscalation
                    )
                })
                .collect(),
            Nist800171Control::SubnetworkSeparation => assessment
                .violations
                .iter()
                .filter(|v| {
                    matches!(
                        v.violation_type,
                        ViolationType::FlatNetwork | ViolationType::MedDeviceExposure
                    )
                })
                .collect(),
            Nist800171Control::NetworkByException => {
                // Check if policy is deny-by-default
                // Any violation is a gap in deny-by-exception posture
                assessment
                    .violations
                    .iter()
                    .filter(|v| {
                        matches!(
                            v.violation_type,
                            ViolationType::UnauthorizedCrossZone | ViolationType::FlatNetwork
                        )
                    })
                    .collect()
            }
            Nist800171Control::MonitorBoundaries => {
                // Lateral movement detection is the evidence
                assessment
                    .violations
                    .iter()
                    .filter(|v| matches!(v.violation_type, ViolationType::LateralMovementPath))
                    .collect()
            }
            _ => assessment.violations.iter().collect(),
        };

        let violation_count = relevant_violations.len() as u32;
        let has_critical = relevant_violations
            .iter()
            .any(|v| v.severity == Severity::Critical);

        let status = if violation_count == 0 {
            ControlStatus::Compliant
        } else if has_critical {
            ControlStatus::NonCompliant
        } else {
            ControlStatus::PartiallyCompliant
        };

        let score = if violation_count == 0 {
            100.0
        } else {
            let penalty: f64 = relevant_violations
                .iter()
                .map(|v| match v.severity {
                    Severity::Critical => 25.0,
                    Severity::High => 15.0,
                    Severity::Medium => 8.0,
                    _ => 2.0,
                })
                .sum();
            (100.0 - penalty).max(0.0)
        };

        let evidence = if violation_count == 0 {
            vec![format!(
                "NIST {} requirements met — no violations detected",
                control.control_id()
            )]
        } else {
            relevant_violations
                .iter()
                .take(3)
                .map(|v| v.description.clone())
                .collect()
        };

        let gaps = if violation_count > 0 {
            vec![format!(
                "{} — {} violation(s) indicate control gap",
                control.name(),
                violation_count,
            )]
        } else {
            vec![]
        };

        let recommendations = if violation_count > 0 {
            vec![
                format!(
                    "Address {} violations to restore {} compliance",
                    violation_count,
                    control.control_id()
                ),
                "Conduct follow-up segmentation assessment after remediation".into(),
            ]
        } else {
            vec!["Continue current monitoring and periodic assessment".into()]
        };

        (
            status,
            score,
            violation_count,
            evidence,
            gaps,
            recommendations,
        )
    }

    /// Assess HCCRA Control 3 (Network Segmentation)
    fn assess_hccra_netseg(&self, assessment: &SegmentationAssessment) -> HccraNetSegStatus {
        let critical = assessment.summary.critical_violations;
        let lateral = assessment.summary.lateral_paths;
        let tests_passed = assessment.summary.isolation_tests_passed;
        let tests_total = assessment.summary.isolation_tests_run;

        let status = if critical > 0 {
            ControlStatus::NonCompliant
        } else if assessment.summary.total_violations > 0 {
            ControlStatus::PartiallyCompliant
        } else {
            ControlStatus::Compliant
        };

        let score = assessment.segmentation_score;

        let verified_zones = assessment.zones.iter().filter(|z| z.verified).count() as u32;

        let mut evidence = Vec::new();
        evidence.push(format!(
            "{} network zones defined, {} verified by scanning",
            assessment.zones.len(),
            verified_zones,
        ));
        evidence.push(format!(
            "{}/{} isolation tests passed",
            tests_passed, tests_total,
        ));
        if lateral > 0 {
            evidence.push(format!(
                "{} lateral movement paths detected ({} reaching ePHI)",
                lateral, assessment.summary.paths_to_ephi,
            ));
        }

        let mut recommendations = Vec::new();
        if critical > 0 {
            recommendations.push(
                "IMMEDIATE: Remediate critical segmentation violations to \
                 achieve HCCRA Control 3 compliance"
                    .into(),
            );
        }
        if tests_total > 0 && tests_passed < tests_total {
            recommendations.push(format!(
                "Fix {} failed isolation tests — review firewall/ACL configuration",
                tests_total - tests_passed,
            ));
        }
        if lateral > 0 {
            recommendations.push(
                "Eliminate lateral movement paths by implementing micro-segmentation \
                 and strict inter-zone ACLs"
                    .into(),
            );
        }
        if recommendations.is_empty() {
            recommendations.push(
                "Network segmentation meets HCCRA requirements. \
                                  Maintain with quarterly validation."
                    .into(),
            );
        }

        HccraNetSegStatus {
            control_id: "HCCRA-3".into(),
            control_name: "Network Segmentation".into(),
            status,
            score,
            zones_defined: assessment.zones.len() as u32,
            zones_verified: verified_zones,
            isolation_tests_passed: tests_passed,
            isolation_tests_total: tests_total,
            lateral_paths_found: lateral,
            critical_violations: critical,
            evidence,
            recommendations,
        }
    }

    /// Build zone-to-zone isolation matrix
    fn build_zone_matrix(&self, assessment: &SegmentationAssessment) -> Vec<ZoneIsolationEntry> {
        let mut entries = Vec::new();

        // Build from isolation test results
        for test in &assessment.isolation_tests {
            let actual = if test.reachable_ports.is_empty() {
                "Isolated".to_string()
            } else {
                let ports: Vec<String> = test
                    .reachable_ports
                    .iter()
                    .map(|p| format!("{}", p.port))
                    .collect();
                format!("Reachable (ports: {})", ports.join(", "))
            };

            entries.push(ZoneIsolationEntry {
                source_zone: test.source_zone,
                destination_zone: test.target_zone,
                expected: "Isolated".into(),
                actual,
                compliant: test.isolated,
            });
        }

        entries
    }

    /// Extract key findings for executive summary
    fn extract_key_findings(&self, assessment: &SegmentationAssessment) -> Vec<String> {
        let mut findings = Vec::new();

        let s = &assessment.summary;

        if s.critical_violations > 0 {
            findings.push(format!(
                "{} CRITICAL segmentation violations detected — ePHI systems \
                 are accessible from unauthorized network zones",
                s.critical_violations,
            ));
        }

        if s.paths_to_ephi > 0 {
            findings.push(format!(
                "{} lateral movement path(s) reach ePHI zones, enabling \
                 potential unauthorized access to patient data",
                s.paths_to_ephi,
            ));
        }

        if s.paths_to_meddevices > 0 {
            findings.push(format!(
                "{} lateral movement path(s) reach medical device networks, \
                 creating patient safety risk",
                s.paths_to_meddevices,
            ));
        }

        if s.isolation_tests_run > 0 {
            let pass_rate = if s.isolation_tests_run > 0 {
                (s.isolation_tests_passed as f64 / s.isolation_tests_run as f64) * 100.0
            } else {
                0.0
            };
            findings.push(format!(
                "Zone isolation test pass rate: {:.0}% ({}/{} passed)",
                pass_rate, s.isolation_tests_passed, s.isolation_tests_run,
            ));
        }

        if s.total_violations == 0 {
            findings.push(
                "No segmentation violations detected — network architecture \
                 meets compliance requirements"
                    .into(),
            );
        }

        findings
    }

    /// Build prioritized remediation plan
    fn build_remediation_plan(
        &self,
        assessment: &SegmentationAssessment,
    ) -> Vec<RemediationPriority> {
        let mut items = Vec::new();
        let mut priority = 1u32;

        // Critical violations first
        for v in assessment
            .violations
            .iter()
            .filter(|v| v.severity == Severity::Critical)
        {
            items.push(RemediationPriority {
                priority,
                title: format!(
                    "{}: {} → {}",
                    v.violation_type, v.source_zone, v.destination_zone,
                ),
                severity: v.severity,
                affected_controls: vec![
                    "HIPAA §164.312(a)(1)".into(),
                    "HCCRA-3".into(),
                    "NIST 3.13.1".into(),
                ],
                action: v.remediation.clone(),
                sla_days: 1,
            });
            priority += 1;
        }

        // High violations
        for v in assessment
            .violations
            .iter()
            .filter(|v| v.severity == Severity::High)
        {
            items.push(RemediationPriority {
                priority,
                title: format!(
                    "{}: {} → {}",
                    v.violation_type, v.source_zone, v.destination_zone,
                ),
                severity: v.severity,
                affected_controls: vec!["HCCRA-3".into(), "NIST 3.13.5".into()],
                action: v.remediation.clone(),
                sla_days: 7,
            });
            priority += 1;
        }

        // Lateral movement paths
        for path in &assessment.lateral_movement_paths {
            if path.reaches_ephi {
                items.push(RemediationPriority {
                    priority,
                    title: format!(
                        "Lateral path: {} → {} ({} hops)",
                        path.origin_zone,
                        path.target_zone,
                        path.hops.len(),
                    ),
                    severity: path.severity,
                    affected_controls: vec![
                        "HIPAA §164.308(a)(1)(ii)(B)".into(),
                        "NIST 3.13.1".into(),
                    ],
                    action: path.mitigations.join("; "),
                    sla_days: if path.severity == Severity::Critical {
                        1
                    } else {
                        14
                    },
                });
                priority += 1;
            }
        }

        items
    }

    /// Calculate overall compliance score
    fn calculate_overall_score(
        &self,
        hipaa: &[ControlAssessment<HipaaSegmentationControl>],
        nist: &[ControlAssessment<Nist800171Control>],
        hccra: &HccraNetSegStatus,
    ) -> f64 {
        let hipaa_avg: f64 = if hipaa.is_empty() {
            100.0
        } else {
            hipaa.iter().map(|c| c.score).sum::<f64>() / hipaa.len() as f64
        };

        let nist_avg: f64 = if nist.is_empty() {
            100.0
        } else {
            nist.iter().map(|c| c.score).sum::<f64>() / nist.len() as f64
        };

        // Weighted: HIPAA 40%, NIST 30%, HCCRA 30%
        hipaa_avg * 0.4 + nist_avg * 0.3 + hccra.score * 0.3
    }

    /// Render the report as executive summary text
    pub fn render_executive_text(&self, report: &SegmentationComplianceReport) -> String {
        let mut out = String::new();

        out.push_str("═══════════════════════════════════════════════════════════════════\n");
        out.push_str("  NETWORK SEGMENTATION COMPLIANCE REPORT\n");
        out.push_str(&format!("  Organization: {}\n", report.organization));
        out.push_str(&format!(
            "  Assessment Date: {}\n",
            report.generated_at.format("%B %d, %Y"),
        ));
        out.push_str("  Frameworks: HIPAA Security Rule, NIST 800-171, HCCRA\n");
        out.push_str("═══════════════════════════════════════════════════════════════════\n\n");

        // Overall Score
        let posture = if report.overall_score >= 95.0 {
            "STRONG"
        } else if report.overall_score >= 75.0 {
            "ADEQUATE"
        } else if report.overall_score >= 50.0 {
            "NEEDS IMPROVEMENT"
        } else {
            "AT RISK"
        };

        out.push_str(&format!(
            "  OVERALL SCORE: {:.0}/100 — {}\n\n",
            report.overall_score, posture
        ));

        // Assessment Summary
        let s = &report.assessment_summary;
        out.push_str("  ─── ASSESSMENT SUMMARY ─────────────────────────────────────────\n");
        out.push_str(&format!("  Network Zones:       {}\n", s.total_zones));
        out.push_str(&format!("  Hosts Scanned:       {}\n", s.total_hosts));
        out.push_str(&format!("  Total Violations:    {}\n", s.total_violations));
        out.push_str(&format!(
            "  Critical:            {}\n",
            s.critical_violations
        ));
        out.push_str(&format!("  High:                {}\n", s.high_violations));
        out.push_str(&format!("  Lateral Move Paths:  {}\n", s.lateral_paths));
        out.push_str(&format!("  Paths to ePHI:       {}\n", s.paths_to_ephi));
        out.push_str(&format!(
            "  Isolation Tests:     {}/{} passed\n\n",
            s.isolation_tests_passed, s.isolation_tests_run,
        ));

        // HIPAA Controls
        out.push_str("  ─── HIPAA SECURITY RULE CONTROLS ───────────────────────────────\n");
        out.push_str(&format!(
            "  {:<45} {:<18} {:>6}\n",
            "CONTROL", "STATUS", "SCORE"
        ));
        out.push_str(&format!("  {}\n", "─".repeat(72)));
        for ctrl in &report.hipaa_controls {
            out.push_str(&format!(
                "  {:<45} {:<18} {:>5.0}%\n",
                ctrl.control.name(),
                ctrl.status,
                ctrl.score,
            ));
        }
        out.push('\n');

        // NIST 800-171 Controls
        out.push_str("  ─── NIST 800-171 CONTROLS ──────────────────────────────────────\n");
        out.push_str(&format!(
            "  {:<8} {:<50} {:<18} {:>6}\n",
            "CTRL", "CONTROL NAME", "STATUS", "SCORE"
        ));
        out.push_str(&format!("  {}\n", "─".repeat(86)));
        for ctrl in &report.nist_controls {
            let name = if ctrl.control.name().len() > 48 {
                format!("{}...", &ctrl.control.name()[..45])
            } else {
                ctrl.control.name().to_string()
            };
            out.push_str(&format!(
                "  {:<8} {:<50} {:<18} {:>5.0}%\n",
                ctrl.control.control_id(),
                name,
                ctrl.status,
                ctrl.score,
            ));
        }
        out.push('\n');

        // HCCRA Control 3
        let hccra = &report.hccra_network_segmentation;
        out.push_str("  ─── HCCRA CONTROL 3: NETWORK SEGMENTATION ─────────────────────\n");
        out.push_str(&format!("  Status:              {}\n", hccra.status));
        out.push_str(&format!("  Score:               {:.0}/100\n", hccra.score));
        out.push_str(&format!(
            "  Zones Defined:       {} ({} verified)\n",
            hccra.zones_defined, hccra.zones_verified,
        ));
        out.push_str(&format!(
            "  Isolation Tests:     {}/{} passed\n",
            hccra.isolation_tests_passed, hccra.isolation_tests_total,
        ));
        out.push_str(&format!(
            "  Lateral Paths:       {}\n",
            hccra.lateral_paths_found,
        ));
        out.push_str(&format!(
            "  Critical Violations: {}\n\n",
            hccra.critical_violations,
        ));

        // Key Findings
        if !report.key_findings.is_empty() {
            out.push_str("  ─── KEY FINDINGS ───────────────────────────────────────────────\n");
            for (i, finding) in report.key_findings.iter().enumerate() {
                out.push_str(&format!("  {}. {}\n", i + 1, finding));
            }
            out.push('\n');
        }

        // Zone Isolation Matrix
        if !report.zone_isolation_matrix.is_empty() {
            out.push_str("  ─── ZONE ISOLATION MATRIX ──────────────────────────────────────\n");
            out.push_str(&format!(
                "  {:<20} {:<20} {:<15} {}\n",
                "SOURCE", "DESTINATION", "STATUS", "COMPLIANT"
            ));
            out.push_str(&format!("  {}\n", "─".repeat(65)));
            for entry in &report.zone_isolation_matrix {
                out.push_str(&format!(
                    "  {:<20} {:<20} {:<15} {}\n",
                    entry.source_zone,
                    entry.destination_zone,
                    if entry.compliant {
                        "Isolated"
                    } else {
                        "BREACH"
                    },
                    if entry.compliant { "Yes" } else { "NO" },
                ));
            }
            out.push('\n');
        }

        // Remediation Priorities
        if !report.remediation_priorities.is_empty() {
            out.push_str("  ─── REMEDIATION PRIORITIES ─────────────────────────────────────\n");
            for item in &report.remediation_priorities {
                out.push_str(&format!(
                    "  P{} [{}] {} (SLA: {} days)\n",
                    item.priority, item.severity, item.title, item.sla_days,
                ));
                out.push_str(&format!("     Action: {}\n", item.action));
                out.push_str(&format!(
                    "     Controls: {}\n\n",
                    item.affected_controls.join(", "),
                ));
            }
        }

        out.push_str("═══════════════════════════════════════════════════════════════════\n");

        out
    }

    /// Render the report as JSON
    pub fn to_json(
        &self,
        report: &SegmentationComplianceReport,
    ) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segmentation::*;
    use std::collections::HashMap;

    fn make_assessment_with_violations() -> SegmentationAssessment {
        let zones = vec![
            ZoneSubnet::new("10.10.1.0/24", NetworkZone::Clinical, "Clinical"),
            ZoneSubnet::new("10.10.2.0/24", NetworkZone::MedicalDevice, "MedDev"),
            ZoneSubnet::new("10.10.3.0/24", NetworkZone::Administrative, "Admin"),
            ZoneSubnet::new("10.10.4.0/24", NetworkZone::Guest, "Guest"),
        ];

        let violations = vec![
            SegmentationViolation {
                id: Uuid::new_v4(),
                violation_type: ViolationType::GuestEscalation,
                severity: Severity::Critical,
                source_ip: "10.10.4.40".parse().unwrap(),
                destination_ip: "10.10.1.10".parse().unwrap(),
                destination_port: 443,
                source_zone: NetworkZone::Guest,
                destination_zone: NetworkZone::Clinical,
                description: "Guest→Clinical access detected".into(),
                compliance_impact: "HIPAA violation".into(),
                remediation: "Block guest access to clinical VLAN".into(),
                detected_at: Utc::now(),
                flow_successful: true,
            },
            SegmentationViolation {
                id: Uuid::new_v4(),
                violation_type: ViolationType::MedDeviceExposure,
                severity: Severity::Critical,
                source_ip: "10.10.3.30".parse().unwrap(),
                destination_ip: "10.10.2.20".parse().unwrap(),
                destination_port: 104,
                source_zone: NetworkZone::Administrative,
                destination_zone: NetworkZone::MedicalDevice,
                description: "Admin→MedDevice DICOM access".into(),
                compliance_impact: "Medical device exposure".into(),
                remediation: "Restrict DICOM access to clinical systems only".into(),
                detected_at: Utc::now(),
                flow_successful: true,
            },
        ];

        let lateral_paths = vec![LateralMovementPath {
            id: Uuid::new_v4(),
            hops: vec![
                PathHop {
                    ip: "10.10.4.40".parse().unwrap(),
                    zone: NetworkZone::Guest,
                    port: 0,
                    service: None,
                    device_class: None,
                    description: "Guest host".into(),
                },
                PathHop {
                    ip: "10.10.3.30".parse().unwrap(),
                    zone: NetworkZone::Administrative,
                    port: 22,
                    service: Some("ssh".into()),
                    device_class: None,
                    description: "Admin workstation".into(),
                },
                PathHop {
                    ip: "10.10.1.10".parse().unwrap(),
                    zone: NetworkZone::Clinical,
                    port: 3389,
                    service: Some("rdp".into()),
                    device_class: None,
                    description: "Clinical workstation".into(),
                },
            ],
            origin_zone: NetworkZone::Guest,
            target_zone: NetworkZone::Clinical,
            severity: Severity::Critical,
            zone_crossings: 2,
            reaches_ephi: true,
            involves_medical_devices: false,
            attack_scenario: "Guest → Admin → Clinical lateral path".into(),
            mitigations: vec!["Block guest→admin SSH".into()],
        }];

        let isolation_tests = vec![
            IsolationTestResult {
                source_zone: NetworkZone::Guest,
                target_zone: NetworkZone::Clinical,
                isolated: false,
                reachable_ports: vec![ReachablePort {
                    port: 443,
                    protocol: "tcp".into(),
                    service: Some("https".into()),
                    banner: None,
                }],
                source_ip: "10.10.4.40".parse().unwrap(),
                target_ip: "10.10.1.10".parse().unwrap(),
                test_duration_ms: 150,
                tested_at: Utc::now(),
            },
            IsolationTestResult {
                source_zone: NetworkZone::Guest,
                target_zone: NetworkZone::MedicalDevice,
                isolated: true,
                reachable_ports: vec![],
                source_ip: "10.10.4.40".parse().unwrap(),
                target_ip: "10.10.2.20".parse().unwrap(),
                test_duration_ms: 200,
                tested_at: Utc::now(),
            },
        ];

        SegmentationAssessment {
            id: Uuid::new_v4(),
            assessed_at: Utc::now(),
            zones,
            violations,
            lateral_movement_paths: lateral_paths,
            isolation_tests,
            zone_host_counts: HashMap::from([
                ("Clinical".into(), 10),
                ("Medical Device".into(), 15),
                ("Administrative".into(), 50),
                ("Guest".into(), 20),
            ]),
            segmentation_score: 40.0,
            summary: AssessmentSummary {
                total_zones: 4,
                total_hosts: 95,
                total_violations: 2,
                critical_violations: 2,
                high_violations: 0,
                medium_violations: 0,
                lateral_paths: 1,
                paths_to_ephi: 1,
                paths_to_meddevices: 0,
                isolation_tests_run: 2,
                isolation_tests_passed: 1,
            },
        }
    }

    fn make_clean_assessment() -> SegmentationAssessment {
        SegmentationAssessment {
            id: Uuid::new_v4(),
            assessed_at: Utc::now(),
            zones: vec![
                ZoneSubnet::new("10.10.1.0/24", NetworkZone::Clinical, "Clinical"),
                ZoneSubnet::new("10.10.2.0/24", NetworkZone::MedicalDevice, "MedDev"),
            ],
            violations: vec![],
            lateral_movement_paths: vec![],
            isolation_tests: vec![],
            zone_host_counts: HashMap::new(),
            segmentation_score: 100.0,
            summary: AssessmentSummary {
                total_zones: 2,
                total_hosts: 10,
                total_violations: 0,
                critical_violations: 0,
                high_violations: 0,
                medium_violations: 0,
                lateral_paths: 0,
                paths_to_ephi: 0,
                paths_to_meddevices: 0,
                isolation_tests_run: 0,
                isolation_tests_passed: 0,
            },
        }
    }

    #[test]
    fn test_generate_report_with_violations() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Test Hospital");
        let report = gen.generate(&assessment);

        assert_eq!(report.organization, "Test Hospital");
        assert!(report.overall_score < 100.0);
        assert_eq!(report.hipaa_controls.len(), 4);
        assert_eq!(report.nist_controls.len(), 6);
        assert_eq!(report.hccra_network_segmentation.control_id, "HCCRA-3");

        // Should have non-compliant controls
        assert!(report
            .hipaa_controls
            .iter()
            .any(|c| c.status == ControlStatus::NonCompliant));
    }

    #[test]
    fn test_generate_clean_report() {
        let assessment = make_clean_assessment();
        let gen = SegmentationReportGenerator::new("Clean Clinic");
        let report = gen.generate(&assessment);

        assert_eq!(report.overall_score, 100.0);
        assert!(report
            .hipaa_controls
            .iter()
            .all(|c| c.status == ControlStatus::Compliant));
    }

    #[test]
    fn test_hccra_netseg_assessment() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Test");
        let report = gen.generate(&assessment);

        let hccra = &report.hccra_network_segmentation;
        assert_eq!(hccra.status, ControlStatus::NonCompliant);
        assert_eq!(hccra.critical_violations, 2);
        assert_eq!(hccra.lateral_paths_found, 1);
        assert!(!hccra.recommendations.is_empty());
    }

    #[test]
    fn test_zone_isolation_matrix() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Test");
        let report = gen.generate(&assessment);

        assert!(!report.zone_isolation_matrix.is_empty());
        let failed = report.zone_isolation_matrix.iter().find(|e| !e.compliant);
        assert!(failed.is_some());
    }

    #[test]
    fn test_remediation_priorities() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Test");
        let report = gen.generate(&assessment);

        assert!(!report.remediation_priorities.is_empty());
        // First item should be critical with SLA=1 day
        let first = &report.remediation_priorities[0];
        assert_eq!(first.severity, Severity::Critical);
        assert_eq!(first.sla_days, 1);
    }

    #[test]
    fn test_executive_text_render() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Acme Medical Center");
        let report = gen.generate(&assessment);
        let text = gen.render_executive_text(&report);

        assert!(text.contains("NETWORK SEGMENTATION COMPLIANCE REPORT"));
        assert!(text.contains("Acme Medical Center"));
        assert!(text.contains("HIPAA SECURITY RULE"));
        assert!(text.contains("NIST 800-171"));
        assert!(text.contains("HCCRA CONTROL 3"));
        assert!(text.contains("KEY FINDINGS"));
        assert!(text.contains("REMEDIATION PRIORITIES"));
    }

    #[test]
    fn test_json_serialization() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Test");
        let report = gen.generate(&assessment);
        let json = gen.to_json(&report);

        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("hipaa_controls"));
        assert!(json_str.contains("nist_controls"));
        assert!(json_str.contains("hccra_network_segmentation"));
    }

    #[test]
    fn test_key_findings_extraction() {
        let assessment = make_assessment_with_violations();
        let gen = SegmentationReportGenerator::new("Test");
        let report = gen.generate(&assessment);

        assert!(!report.key_findings.is_empty());
        // Should mention critical violations
        assert!(report.key_findings.iter().any(|f| f.contains("CRITICAL")));
    }

    #[test]
    fn test_hipaa_control_definitions() {
        assert_eq!(HipaaSegmentationControl::all().len(), 4);
        for ctrl in HipaaSegmentationControl::all() {
            assert!(!ctrl.cfr_citation().is_empty());
            assert!(!ctrl.name().is_empty());
            assert!(!ctrl.description().is_empty());
        }
    }

    #[test]
    fn test_nist_control_definitions() {
        assert_eq!(Nist800171Control::all().len(), 6);
        for ctrl in Nist800171Control::all() {
            assert!(!ctrl.control_id().is_empty());
            assert!(!ctrl.name().is_empty());
            assert!(!ctrl.description().is_empty());
        }
    }
}
