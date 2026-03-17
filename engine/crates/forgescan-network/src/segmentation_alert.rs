//! ForgeSOC Alert Integration for Network Segmentation Violations
//!
//! Generates real-time security alerts from segmentation violations for
//! integration with ForgeSOC (Security Operations Center) and SIEM systems.
//!
//! Alert channels:
//! - ForgeSOC REST API (push alerts)
//! - Syslog (CEF format for SIEM ingestion)
//! - Structured JSON (for log aggregation)

use crate::segmentation::{
    LateralMovementPath, NetworkZone, SegmentationAssessment, SegmentationViolation, ViolationType,
};
use chrono::{DateTime, Utc};
use forgescan_core::Severity;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

// ─── Alert Types ───────────────────────────────────────────────────────────

/// A security alert generated from a segmentation violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationAlert {
    /// Unique alert ID
    pub alert_id: Uuid,
    /// Alert type
    pub alert_type: AlertType,
    /// Severity (maps from violation severity)
    pub severity: AlertSeverity,
    /// Short summary
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Source of the violation
    pub source: AlertEndpoint,
    /// Destination of the violation
    pub destination: AlertEndpoint,
    /// MITRE ATT&CK technique reference
    pub mitre_technique: Option<String>,
    /// Compliance frameworks impacted
    pub compliance_refs: Vec<ComplianceReference>,
    /// Recommended response actions
    pub response_actions: Vec<String>,
    /// When the alert was generated
    pub generated_at: DateTime<Utc>,
    /// When the underlying violation was observed
    pub observed_at: DateTime<Utc>,
    /// Raw violation ID for correlation
    pub violation_id: Uuid,
    /// Whether this alert requires immediate SOC response
    pub requires_immediate_response: bool,
    /// ForgeSOC correlation tags
    pub tags: Vec<String>,
}

/// Alert severity levels (aligned with ForgeSOC/SIEM conventions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    /// Critical: Immediate SOC response required
    Critical,
    /// High: SOC response within 1 hour
    High,
    /// Medium: SOC triage within 4 hours
    Medium,
    /// Low: Logged for trend analysis
    Low,
    /// Informational: Audit trail only
    Info,
}

impl AlertSeverity {
    pub fn from_finding_severity(severity: Severity) -> Self {
        match severity {
            Severity::Critical => Self::Critical,
            Severity::High => Self::High,
            Severity::Medium => Self::Medium,
            Severity::Low => Self::Low,
            Severity::Info => Self::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        }
    }

    /// CEF severity level (0-10)
    pub fn cef_level(&self) -> u8 {
        match self {
            Self::Critical => 10,
            Self::High => 8,
            Self::Medium => 5,
            Self::Low => 3,
            Self::Info => 1,
        }
    }

    /// Response SLA in minutes
    pub fn response_sla_minutes(&self) -> u32 {
        match self {
            Self::Critical => 15,
            Self::High => 60,
            Self::Medium => 240,
            Self::Low => 1440,
            Self::Info => 0,
        }
    }
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Alert type classification for SOC triage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    /// Network segmentation bypass detected
    SegmentationBypass,
    /// Lateral movement attempt
    LateralMovement,
    /// Medical device network exposed
    MedicalDeviceExposure,
    /// Guest network escalation to internal
    GuestNetworkEscalation,
    /// Flat network (no segmentation) detected
    FlatNetworkDetected,
    /// Policy violation on cross-zone flow
    PolicyViolation,
}

impl AlertType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SegmentationBypass => "SEGMENTATION_BYPASS",
            Self::LateralMovement => "LATERAL_MOVEMENT",
            Self::MedicalDeviceExposure => "MEDDEVICE_EXPOSURE",
            Self::GuestNetworkEscalation => "GUEST_ESCALATION",
            Self::FlatNetworkDetected => "FLAT_NETWORK",
            Self::PolicyViolation => "POLICY_VIOLATION",
        }
    }

    /// Map from violation type to alert type
    pub fn from_violation(violation_type: ViolationType) -> Self {
        match violation_type {
            ViolationType::UntrustedToEphi => Self::SegmentationBypass,
            ViolationType::UnauthorizedCrossZone => Self::PolicyViolation,
            ViolationType::MedDeviceExposure => Self::MedicalDeviceExposure,
            ViolationType::FlatNetwork => Self::FlatNetworkDetected,
            ViolationType::LateralMovementPath => Self::LateralMovement,
            ViolationType::GuestEscalation => Self::GuestNetworkEscalation,
        }
    }
}

impl std::fmt::Display for AlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Network endpoint information in an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEndpoint {
    /// IP address
    pub ip: IpAddr,
    /// Network zone
    pub zone: NetworkZone,
    /// Port (for destination)
    pub port: Option<u16>,
    /// Service name if known
    pub service: Option<String>,
}

/// Compliance framework reference for alert enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReference {
    /// Framework name
    pub framework: String,
    /// Control ID
    pub control_id: String,
    /// Control description
    pub description: String,
}

// ─── Alert Generator ───────────────────────────────────────────────────────

/// Generates ForgeSOC alerts from segmentation assessment results
pub struct AlertGenerator {
    /// Organization identifier for alert routing
    org_id: String,
    /// Scanner/sensor identifier
    sensor_id: String,
}

impl AlertGenerator {
    pub fn new(org_id: impl Into<String>, sensor_id: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            sensor_id: sensor_id.into(),
        }
    }

    /// Generate alerts from a complete segmentation assessment
    pub fn generate_alerts(&self, assessment: &SegmentationAssessment) -> Vec<SegmentationAlert> {
        let mut alerts = Vec::new();

        // Generate alerts from violations
        for violation in &assessment.violations {
            alerts.push(self.violation_to_alert(violation));
        }

        // Generate alerts from dangerous lateral movement paths
        for path in &assessment.lateral_movement_paths {
            if path.reaches_ephi || path.involves_medical_devices {
                alerts.push(self.lateral_path_to_alert(path));
            }
        }

        // Sort by severity (critical first)
        alerts.sort_by(|a, b| {
            a.severity
                .cef_level()
                .cmp(&b.severity.cef_level())
                .reverse()
        });

        alerts
    }

    /// Convert a segmentation violation to a ForgeSOC alert
    fn violation_to_alert(&self, violation: &SegmentationViolation) -> SegmentationAlert {
        let alert_type = AlertType::from_violation(violation.violation_type);
        let severity = AlertSeverity::from_finding_severity(violation.severity);

        let mitre = self.map_to_mitre(violation.violation_type);
        let compliance_refs = self.build_compliance_refs(violation);
        let response_actions = self.build_response_actions(violation);
        let tags = self.build_tags(violation);

        SegmentationAlert {
            alert_id: Uuid::new_v4(),
            alert_type,
            severity,
            title: format!(
                "[{}] {} — {} → {}",
                severity,
                violation.violation_type,
                violation.source_zone,
                violation.destination_zone,
            ),
            description: violation.description.clone(),
            source: AlertEndpoint {
                ip: violation.source_ip,
                zone: violation.source_zone,
                port: None,
                service: None,
            },
            destination: AlertEndpoint {
                ip: violation.destination_ip,
                zone: violation.destination_zone,
                port: Some(violation.destination_port),
                service: None,
            },
            mitre_technique: mitre,
            compliance_refs,
            response_actions,
            generated_at: Utc::now(),
            observed_at: violation.detected_at,
            violation_id: violation.id,
            requires_immediate_response: matches!(severity, AlertSeverity::Critical),
            tags,
        }
    }

    /// Convert a lateral movement path to a ForgeSOC alert
    fn lateral_path_to_alert(&self, path: &LateralMovementPath) -> SegmentationAlert {
        let severity = AlertSeverity::from_finding_severity(path.severity);
        let src_ip = path
            .hops
            .first()
            .map(|h| h.ip)
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let dst_ip = path
            .hops
            .last()
            .map(|h| h.ip)
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let dst_port = path.hops.last().map(|h| h.port).unwrap_or(0);

        let mut compliance_refs = vec![
            ComplianceReference {
                framework: "HIPAA".into(),
                control_id: "§164.312(a)(1)".into(),
                description: "Access Control — lateral path enables unauthorized ePHI access"
                    .into(),
            },
            ComplianceReference {
                framework: "HCCRA".into(),
                control_id: "HCCRA-3".into(),
                description: "Network Segmentation — cross-zone movement path exists".into(),
            },
            ComplianceReference {
                framework: "NIST 800-171".into(),
                control_id: "3.13.1".into(),
                description: "Boundary Protection — zone boundary not enforcing isolation".into(),
            },
        ];

        if path.involves_medical_devices {
            compliance_refs.push(ComplianceReference {
                framework: "NIST 800-171".into(),
                control_id: "3.13.5".into(),
                description: "Subnet segmentation required for medical device networks".into(),
            });
        }

        let hop_summary: Vec<String> = path
            .hops
            .iter()
            .map(|h| format!("{} ({})", h.ip, h.zone))
            .collect();

        SegmentationAlert {
            alert_id: Uuid::new_v4(),
            alert_type: AlertType::LateralMovement,
            severity,
            title: format!(
                "[{}] Lateral Movement Path: {} → {} ({} hops)",
                severity,
                path.origin_zone,
                path.target_zone,
                path.hops.len(),
            ),
            description: format!(
                "{}. Path: {}",
                path.attack_scenario,
                hop_summary.join(" → "),
            ),
            source: AlertEndpoint {
                ip: src_ip,
                zone: path.origin_zone,
                port: None,
                service: None,
            },
            destination: AlertEndpoint {
                ip: dst_ip,
                zone: path.target_zone,
                port: Some(dst_port),
                service: None,
            },
            mitre_technique: Some("T1021 — Remote Services (Lateral Movement)".into()),
            compliance_refs,
            response_actions: path.mitigations.clone(),
            generated_at: Utc::now(),
            observed_at: Utc::now(),
            violation_id: path.id,
            requires_immediate_response: path.reaches_ephi
                && matches!(severity, AlertSeverity::Critical),
            tags: vec![
                "lateral-movement".into(),
                format!("zone:{}", path.origin_zone),
                format!("target-zone:{}", path.target_zone),
                format!("hops:{}", path.hops.len()),
                if path.reaches_ephi {
                    "ephi-risk".into()
                } else {
                    "cross-zone".into()
                },
                if path.involves_medical_devices {
                    "meddevice".into()
                } else {
                    "it-network".into()
                },
                format!("org:{}", self.org_id),
            ],
        }
    }

    /// Map violation type to MITRE ATT&CK technique
    fn map_to_mitre(&self, violation_type: ViolationType) -> Option<String> {
        match violation_type {
            ViolationType::UntrustedToEphi => {
                Some("T1190 — Exploit Public-Facing Application".into())
            }
            ViolationType::LateralMovementPath => {
                Some("T1021 — Remote Services (Lateral Movement)".into())
            }
            ViolationType::GuestEscalation => Some("T1078 — Valid Accounts / Network Pivot".into()),
            ViolationType::MedDeviceExposure => {
                Some("T1557 — Adversary-in-the-Middle (Medical Protocol)".into())
            }
            ViolationType::FlatNetwork => {
                Some("T1046 — Network Service Discovery (Flat Network)".into())
            }
            ViolationType::UnauthorizedCrossZone => None,
        }
    }

    /// Build compliance references for a violation
    fn build_compliance_refs(&self, violation: &SegmentationViolation) -> Vec<ComplianceReference> {
        let mut refs = Vec::new();

        // HIPAA references
        if violation.destination_zone.handles_ephi() {
            refs.push(ComplianceReference {
                framework: "HIPAA".into(),
                control_id: "§164.312(a)(1)".into(),
                description: "Access Control — unauthorized network access to ePHI systems".into(),
            });
        }

        if violation.source_zone.is_untrusted() {
            refs.push(ComplianceReference {
                framework: "HIPAA".into(),
                control_id: "§164.312(e)(1)".into(),
                description: "Transmission Security — untrusted network path to protected systems"
                    .into(),
            });
        }

        // HCCRA
        refs.push(ComplianceReference {
            framework: "HCCRA".into(),
            control_id: "HCCRA-3".into(),
            description: "Network Segmentation — systems not properly isolated".into(),
        });

        // NIST 800-171
        refs.push(ComplianceReference {
            framework: "NIST 800-171".into(),
            control_id: "3.13.1".into(),
            description: "Monitor, control, and protect communications at external and key \
                          internal boundaries"
                .into(),
        });

        if violation.destination_zone == NetworkZone::MedicalDevice {
            refs.push(ComplianceReference {
                framework: "NIST 800-171".into(),
                control_id: "3.13.5".into(),
                description: "Implement subnetworks for publicly accessible system components \
                              that are physically or logically separated"
                    .into(),
            });
        }

        refs
    }

    /// Build recommended response actions
    fn build_response_actions(&self, violation: &SegmentationViolation) -> Vec<String> {
        let mut actions = Vec::new();

        if violation.severity == Severity::Critical {
            actions.push("IMMEDIATE: Isolate affected network segment".into());
            actions.push("IMMEDIATE: Block source IP at perimeter firewall".into());
        }

        actions.push(format!(
            "Investigate traffic from {} to {} on port {}",
            violation.source_ip, violation.destination_ip, violation.destination_port,
        ));

        actions.push(format!(
            "Review ACLs on {} zone boundary for misconfiguration",
            violation.destination_zone,
        ));

        if violation.destination_zone == NetworkZone::MedicalDevice {
            actions.push(
                "Check medical device integrity — verify no unauthorized \
                 configuration changes or data access"
                    .into(),
            );
        }

        if violation.flow_successful {
            actions.push(
                "This flow was SUCCESSFUL — active remediation required. \
                 Verify no data exfiltration occurred"
                    .into(),
            );
        }

        actions.push("Update segmentation policy and firewall rules to prevent recurrence".into());

        actions
    }

    /// Build alert tags for ForgeSOC correlation
    fn build_tags(&self, violation: &SegmentationViolation) -> Vec<String> {
        let mut tags = vec![
            format!("type:{}", violation.violation_type),
            format!("src-zone:{}", violation.source_zone),
            format!("dst-zone:{}", violation.destination_zone),
            format!("severity:{}", violation.severity),
            format!("org:{}", self.org_id),
            format!("sensor:{}", self.sensor_id),
            "network-segmentation".into(),
        ];

        if violation.destination_zone.handles_ephi() {
            tags.push("ephi-risk".into());
        }
        if violation.destination_zone == NetworkZone::MedicalDevice {
            tags.push("meddevice".into());
        }
        if violation.flow_successful {
            tags.push("active-violation".into());
        }

        tags
    }

    /// Format an alert as CEF (Common Event Format) for SIEM ingestion
    pub fn to_cef(&self, alert: &SegmentationAlert) -> String {
        format!(
            "CEF:0|ForgeScan|SegmentationValidator|1.0|{}|{}|{}|src={} dst={} dpt={} \
             cs1={} cs1Label=SourceZone cs2={} cs2Label=DestZone cs3={} cs3Label=ViolationID \
             msg={}",
            alert.alert_type,
            alert.title.replace('|', "\\|"),
            alert.severity.cef_level(),
            alert.source.ip,
            alert.destination.ip,
            alert.destination.port.unwrap_or(0),
            alert.source.zone,
            alert.destination.zone,
            alert.violation_id,
            alert.description.replace('=', "\\=").replace('\n', " "),
        )
    }

    /// Format an alert as structured JSON for log aggregation
    pub fn to_json(&self, alert: &SegmentationAlert) -> Result<String, serde_json::Error> {
        serde_json::to_string(alert)
    }

    /// Generate a summary of all alerts for SOC shift handoff
    pub fn generate_alert_summary(alerts: &[SegmentationAlert]) -> AlertSummary {
        let total = alerts.len() as u32;
        let critical = alerts
            .iter()
            .filter(|a| matches!(a.severity, AlertSeverity::Critical))
            .count() as u32;
        let high = alerts
            .iter()
            .filter(|a| matches!(a.severity, AlertSeverity::High))
            .count() as u32;
        let medium = alerts
            .iter()
            .filter(|a| matches!(a.severity, AlertSeverity::Medium))
            .count() as u32;
        let immediate = alerts
            .iter()
            .filter(|a| a.requires_immediate_response)
            .count() as u32;

        let mut zone_pairs: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for alert in alerts {
            let key = format!("{} → {}", alert.source.zone, alert.destination.zone);
            *zone_pairs.entry(key).or_default() += 1;
        }

        let top_zone_pairs: Vec<(String, u32)> = {
            let mut pairs: Vec<_> = zone_pairs.into_iter().collect();
            pairs.sort_by(|a, b| b.1.cmp(&a.1));
            pairs.into_iter().take(5).collect()
        };

        AlertSummary {
            total_alerts: total,
            critical_alerts: critical,
            high_alerts: high,
            medium_alerts: medium,
            immediate_response_required: immediate,
            top_violation_pairs: top_zone_pairs,
            generated_at: Utc::now(),
        }
    }
}

/// Summary of generated alerts for SOC dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub total_alerts: u32,
    pub critical_alerts: u32,
    pub high_alerts: u32,
    pub medium_alerts: u32,
    pub immediate_response_required: u32,
    pub top_violation_pairs: Vec<(String, u32)>,
    pub generated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segmentation::*;

    fn make_violation(
        vtype: ViolationType,
        src_zone: NetworkZone,
        dst_zone: NetworkZone,
        severity: Severity,
    ) -> SegmentationViolation {
        SegmentationViolation {
            id: Uuid::new_v4(),
            violation_type: vtype,
            severity,
            source_ip: "10.10.4.40".parse().unwrap(),
            destination_ip: "10.10.1.10".parse().unwrap(),
            destination_port: 443,
            source_zone: src_zone,
            destination_zone: dst_zone,
            description: "Test violation".into(),
            compliance_impact: "Test impact".into(),
            remediation: "Test remediation".into(),
            detected_at: Utc::now(),
            flow_successful: true,
        }
    }

    #[test]
    fn test_alert_generation_from_violation() {
        let gen = AlertGenerator::new("org-123", "scanner-01");
        let violation = make_violation(
            ViolationType::GuestEscalation,
            NetworkZone::Guest,
            NetworkZone::Clinical,
            Severity::Critical,
        );

        let alert = gen.violation_to_alert(&violation);
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.alert_type, AlertType::GuestNetworkEscalation);
        assert!(alert.requires_immediate_response);
        assert!(alert.title.contains("CRITICAL"));
        assert!(!alert.compliance_refs.is_empty());
        assert!(!alert.response_actions.is_empty());
    }

    #[test]
    fn test_alert_severity_mapping() {
        assert_eq!(
            AlertSeverity::from_finding_severity(Severity::Critical),
            AlertSeverity::Critical,
        );
        assert_eq!(
            AlertSeverity::from_finding_severity(Severity::High),
            AlertSeverity::High,
        );
        assert_eq!(AlertSeverity::Critical.cef_level(), 10);
        assert_eq!(AlertSeverity::High.cef_level(), 8);
        assert_eq!(AlertSeverity::Medium.cef_level(), 5);
    }

    #[test]
    fn test_cef_format() {
        let gen = AlertGenerator::new("org-123", "scanner-01");
        let violation = make_violation(
            ViolationType::UntrustedToEphi,
            NetworkZone::Dmz,
            NetworkZone::ServerRoom,
            Severity::Critical,
        );
        let alert = gen.violation_to_alert(&violation);
        let cef = gen.to_cef(&alert);

        assert!(cef.starts_with("CEF:0|ForgeScan|"));
        assert!(cef.contains("src="));
        assert!(cef.contains("dst="));
        assert!(cef.contains("SourceZone"));
        assert!(cef.contains("DestZone"));
    }

    #[test]
    fn test_json_format() {
        let gen = AlertGenerator::new("org-123", "scanner-01");
        let violation = make_violation(
            ViolationType::MedDeviceExposure,
            NetworkZone::Administrative,
            NetworkZone::MedicalDevice,
            Severity::Critical,
        );
        let alert = gen.violation_to_alert(&violation);
        let json = gen.to_json(&alert);

        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("alert_id"));
        assert!(json_str.contains("medical_device_exposure"));
    }

    #[test]
    fn test_alert_tags() {
        let gen = AlertGenerator::new("hospital-01", "scan-node-3");
        let violation = make_violation(
            ViolationType::MedDeviceExposure,
            NetworkZone::Guest,
            NetworkZone::MedicalDevice,
            Severity::Critical,
        );
        let alert = gen.violation_to_alert(&violation);

        assert!(alert.tags.contains(&"meddevice".to_string()));
        assert!(alert.tags.contains(&"ephi-risk".to_string()));
        assert!(alert.tags.contains(&"active-violation".to_string()));
        assert!(alert.tags.contains(&"org:hospital-01".to_string()));
    }

    #[test]
    fn test_mitre_mapping() {
        let gen = AlertGenerator::new("org", "sensor");

        assert!(gen
            .map_to_mitre(ViolationType::UntrustedToEphi)
            .unwrap()
            .contains("T1190"));
        assert!(gen
            .map_to_mitre(ViolationType::LateralMovementPath)
            .unwrap()
            .contains("T1021"));
        assert!(gen
            .map_to_mitre(ViolationType::GuestEscalation)
            .unwrap()
            .contains("T1078"));
        assert!(gen
            .map_to_mitre(ViolationType::UnauthorizedCrossZone)
            .is_none());
    }

    #[test]
    fn test_alert_summary() {
        let gen = AlertGenerator::new("org", "sensor");
        let violations = [
            make_violation(
                ViolationType::GuestEscalation,
                NetworkZone::Guest,
                NetworkZone::Clinical,
                Severity::Critical,
            ),
            make_violation(
                ViolationType::UntrustedToEphi,
                NetworkZone::Dmz,
                NetworkZone::ServerRoom,
                Severity::Critical,
            ),
            make_violation(
                ViolationType::UnauthorizedCrossZone,
                NetworkZone::Administrative,
                NetworkZone::MedicalDevice,
                Severity::Medium,
            ),
        ];

        let alerts: Vec<_> = violations
            .iter()
            .map(|v| gen.violation_to_alert(v))
            .collect();
        let summary = AlertGenerator::generate_alert_summary(&alerts);

        assert_eq!(summary.total_alerts, 3);
        assert_eq!(summary.critical_alerts, 2);
        assert_eq!(summary.medium_alerts, 1);
        assert!(summary.immediate_response_required >= 2);
    }

    #[test]
    fn test_response_sla() {
        assert_eq!(AlertSeverity::Critical.response_sla_minutes(), 15);
        assert_eq!(AlertSeverity::High.response_sla_minutes(), 60);
        assert_eq!(AlertSeverity::Medium.response_sla_minutes(), 240);
    }

    #[test]
    fn test_compliance_refs_ephi_zone() {
        let gen = AlertGenerator::new("org", "sensor");
        let violation = make_violation(
            ViolationType::UntrustedToEphi,
            NetworkZone::Guest,
            NetworkZone::Clinical,
            Severity::Critical,
        );
        let refs = gen.build_compliance_refs(&violation);

        let has_hipaa = refs.iter().any(|r| r.framework == "HIPAA");
        let has_hccra = refs.iter().any(|r| r.framework == "HCCRA");
        let has_nist = refs.iter().any(|r| r.framework == "NIST 800-171");

        assert!(has_hipaa, "Should reference HIPAA");
        assert!(has_hccra, "Should reference HCCRA");
        assert!(has_nist, "Should reference NIST 800-171");
    }

    #[test]
    fn test_alert_type_from_violation() {
        assert_eq!(
            AlertType::from_violation(ViolationType::UntrustedToEphi),
            AlertType::SegmentationBypass,
        );
        assert_eq!(
            AlertType::from_violation(ViolationType::GuestEscalation),
            AlertType::GuestNetworkEscalation,
        );
        assert_eq!(
            AlertType::from_violation(ViolationType::MedDeviceExposure),
            AlertType::MedicalDeviceExposure,
        );
        assert_eq!(
            AlertType::from_violation(ViolationType::FlatNetwork),
            AlertType::FlatNetworkDetected,
        );
    }
}
