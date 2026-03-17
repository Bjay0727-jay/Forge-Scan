//! Network Segmentation Validation Engine
//!
//! Validates network zone isolation in healthcare environments, ensuring proper
//! segmentation between clinical, administrative, medical device, and public
//! network segments as required by HIPAA Security Rule and NIST 800-171.
//!
//! Capabilities:
//! - Network zone classification (Clinical, MedDevice, Admin, DMZ, Guest, Unknown)
//! - Automated segmentation testing that validates isolation between zones
//! - Lateral movement path analysis to identify cross-segment violations
//! - Segmentation violation detection with severity classification

use chrono::{DateTime, Utc};
use forgescan_core::{DeviceClass, Severity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

// ─── Network Zone Classification ───────────────────────────────────────────

/// Healthcare network zone classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkZone {
    /// Clinical systems handling ePHI (EHR, clinical workstations)
    Clinical,
    /// Medical device network (IoMT devices, imaging, monitors)
    MedicalDevice,
    /// Administrative/corporate network (email, HR, finance)
    Administrative,
    /// DMZ / internet-facing services
    Dmz,
    /// Guest/public Wi-Fi
    Guest,
    /// Server/data center zone
    ServerRoom,
    /// Unknown or unclassified segment
    Unknown,
}

impl NetworkZone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clinical => "Clinical",
            Self::MedicalDevice => "Medical Device",
            Self::Administrative => "Administrative",
            Self::Dmz => "DMZ",
            Self::Guest => "Guest/Public",
            Self::ServerRoom => "Server Room",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this zone handles ePHI
    pub fn handles_ephi(&self) -> bool {
        matches!(
            self,
            Self::Clinical | Self::MedicalDevice | Self::ServerRoom
        )
    }

    /// Whether this zone is untrusted
    pub fn is_untrusted(&self) -> bool {
        matches!(self, Self::Guest | Self::Dmz | Self::Unknown)
    }

    /// All defined zones
    pub fn all() -> &'static [NetworkZone] {
        &[
            Self::Clinical,
            Self::MedicalDevice,
            Self::Administrative,
            Self::Dmz,
            Self::Guest,
            Self::ServerRoom,
            Self::Unknown,
        ]
    }
}

impl std::fmt::Display for NetworkZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Subnet Definition ────────────────────────────────────────────────────

/// A subnet with its assigned zone and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneSubnet {
    /// Subnet CIDR (e.g., "10.10.1.0/24")
    pub cidr: String,
    /// Assigned network zone
    pub zone: NetworkZone,
    /// Human-readable label (e.g., "ICU Medical Devices")
    pub label: String,
    /// VLAN ID if known
    pub vlan_id: Option<u16>,
    /// Whether this subnet has been verified by scanning
    pub verified: bool,
}

impl ZoneSubnet {
    pub fn new(cidr: impl Into<String>, zone: NetworkZone, label: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            zone,
            label: label.into(),
            vlan_id: None,
            verified: false,
        }
    }

    pub fn with_vlan(mut self, vlan_id: u16) -> Self {
        self.vlan_id = Some(vlan_id);
        self
    }
}

// ─── Observed Communication ────────────────────────────────────────────────

/// An observed communication flow between two hosts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedFlow {
    /// Source IP
    pub source_ip: IpAddr,
    /// Destination IP
    pub destination_ip: IpAddr,
    /// Destination port
    pub destination_port: u16,
    /// Protocol (tcp, udp)
    pub protocol: String,
    /// Source zone (resolved)
    pub source_zone: Option<NetworkZone>,
    /// Destination zone (resolved)
    pub destination_zone: Option<NetworkZone>,
    /// When this flow was observed
    pub observed_at: DateTime<Utc>,
    /// Service name if identified
    pub service: Option<String>,
    /// Whether this flow was successful (connection established)
    pub successful: bool,
}

// ─── Segmentation Policy ───────────────────────────────────────────────────

/// Defines allowed and denied communication between zones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationPolicy {
    /// Policy name
    pub name: String,
    /// Allowed cross-zone communications
    pub allowed_flows: Vec<ZoneFlowRule>,
    /// Explicitly denied cross-zone communications (always generate critical alerts)
    pub denied_flows: Vec<ZoneFlowRule>,
    /// Default action for unlisted zone pairs
    pub default_action: PolicyAction,
}

/// A rule describing allowed/denied traffic between zones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneFlowRule {
    /// Source zone
    pub source_zone: NetworkZone,
    /// Destination zone
    pub destination_zone: NetworkZone,
    /// Allowed ports (empty = all ports subject to action)
    pub ports: Vec<u16>,
    /// Description of why this flow is allowed/denied
    pub justification: String,
}

/// Default policy action for unlisted zone pairs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allow by default (less secure)
    Allow,
    /// Deny by default (more secure, recommended for healthcare)
    Deny,
}

impl SegmentationPolicy {
    /// Create a healthcare-recommended default policy (deny by default)
    pub fn healthcare_default() -> Self {
        let mut policy = Self {
            name: "Healthcare Network Segmentation Policy".into(),
            allowed_flows: Vec::new(),
            denied_flows: Vec::new(),
            default_action: PolicyAction::Deny,
        };

        // Clinical → ServerRoom: allowed for EHR access
        policy.allowed_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Clinical,
            destination_zone: NetworkZone::ServerRoom,
            ports: vec![443, 1433, 5432, 3306],
            justification: "Clinical workstations accessing EHR/database servers".into(),
        });

        // MedicalDevice → ServerRoom: limited ports for DICOM/HL7
        policy.allowed_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::MedicalDevice,
            destination_zone: NetworkZone::ServerRoom,
            ports: vec![104, 2575, 443, 8443],
            justification: "Medical devices sending data to PACS/HL7 servers".into(),
        });

        // Administrative → ServerRoom: general IT services
        policy.allowed_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Administrative,
            destination_zone: NetworkZone::ServerRoom,
            ports: vec![443, 80, 25, 587, 993],
            justification: "Admin access to IT services (email, intranet)".into(),
        });

        // Explicit denials: Guest/DMZ must never reach ePHI zones
        policy.denied_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Guest,
            destination_zone: NetworkZone::Clinical,
            ports: vec![],
            justification: "Guest network must be isolated from clinical systems".into(),
        });
        policy.denied_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Guest,
            destination_zone: NetworkZone::MedicalDevice,
            ports: vec![],
            justification: "Guest network must be isolated from medical devices".into(),
        });
        policy.denied_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Guest,
            destination_zone: NetworkZone::ServerRoom,
            ports: vec![],
            justification: "Guest network must be isolated from data center".into(),
        });
        policy.denied_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Dmz,
            destination_zone: NetworkZone::MedicalDevice,
            ports: vec![],
            justification: "DMZ must never reach medical device networks directly".into(),
        });
        policy.denied_flows.push(ZoneFlowRule {
            source_zone: NetworkZone::Dmz,
            destination_zone: NetworkZone::Clinical,
            ports: vec![],
            justification: "DMZ must not reach clinical networks directly".into(),
        });

        policy
    }

    /// Check if a flow between zones is allowed by policy
    pub fn evaluate_flow(
        &self,
        source_zone: NetworkZone,
        dest_zone: NetworkZone,
        dest_port: u16,
    ) -> FlowVerdict {
        // Same-zone traffic is always allowed
        if source_zone == dest_zone {
            return FlowVerdict::Allowed;
        }

        // Check explicit denials first
        for rule in &self.denied_flows {
            if rule.source_zone == source_zone && rule.destination_zone == dest_zone {
                if rule.ports.is_empty() || rule.ports.contains(&dest_port) {
                    return FlowVerdict::ExplicitlyDenied {
                        reason: rule.justification.clone(),
                    };
                }
            }
        }

        // Check allowed flows
        for rule in &self.allowed_flows {
            if rule.source_zone == source_zone && rule.destination_zone == dest_zone {
                if rule.ports.is_empty() || rule.ports.contains(&dest_port) {
                    return FlowVerdict::Allowed;
                }
            }
        }

        // Apply default action
        match self.default_action {
            PolicyAction::Allow => FlowVerdict::Allowed,
            PolicyAction::Deny => FlowVerdict::DefaultDenied,
        }
    }
}

/// Result of evaluating a flow against segmentation policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowVerdict {
    /// Flow is permitted
    Allowed,
    /// Flow matches an explicit deny rule
    ExplicitlyDenied { reason: String },
    /// Flow is denied by default policy (no matching allow rule)
    DefaultDenied,
}

// ─── Segmentation Violation ────────────────────────────────────────────────

/// A detected segmentation violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationViolation {
    /// Unique violation ID
    pub id: Uuid,
    /// Violation type
    pub violation_type: ViolationType,
    /// Severity
    pub severity: Severity,
    /// Source IP
    pub source_ip: IpAddr,
    /// Destination IP
    pub destination_ip: IpAddr,
    /// Destination port
    pub destination_port: u16,
    /// Source zone
    pub source_zone: NetworkZone,
    /// Destination zone
    pub destination_zone: NetworkZone,
    /// Description of the violation
    pub description: String,
    /// Why this is a compliance concern
    pub compliance_impact: String,
    /// Recommended remediation
    pub remediation: String,
    /// When the violation was detected
    pub detected_at: DateTime<Utc>,
    /// Whether the violating flow was successful
    pub flow_successful: bool,
}

/// Type of segmentation violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    /// Untrusted zone reaching ePHI zone
    UntrustedToEphi,
    /// Cross-zone communication not permitted by policy
    UnauthorizedCrossZone,
    /// Medical device zone accessible from non-clinical network
    MedDeviceExposure,
    /// Flat network detected (no segmentation)
    FlatNetwork,
    /// Lateral movement path exists between zones
    LateralMovementPath,
    /// Guest network can reach internal resources
    GuestEscalation,
}

impl ViolationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UntrustedToEphi => "Untrusted-to-ePHI Access",
            Self::UnauthorizedCrossZone => "Unauthorized Cross-Zone Flow",
            Self::MedDeviceExposure => "Medical Device Network Exposure",
            Self::FlatNetwork => "Flat Network (No Segmentation)",
            Self::LateralMovementPath => "Lateral Movement Path",
            Self::GuestEscalation => "Guest Network Escalation",
        }
    }

    /// Default severity for this violation type
    pub fn default_severity(&self) -> Severity {
        match self {
            Self::UntrustedToEphi => Severity::Critical,
            Self::MedDeviceExposure => Severity::Critical,
            Self::GuestEscalation => Severity::Critical,
            Self::FlatNetwork => Severity::High,
            Self::LateralMovementPath => Severity::High,
            Self::UnauthorizedCrossZone => Severity::Medium,
        }
    }
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Lateral Movement Path ─────────────────────────────────────────────────

/// A potential lateral movement path across network zones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementPath {
    /// Unique path ID
    pub id: Uuid,
    /// Ordered list of hops in the path
    pub hops: Vec<PathHop>,
    /// Starting zone
    pub origin_zone: NetworkZone,
    /// Ending zone
    pub target_zone: NetworkZone,
    /// Overall risk severity
    pub severity: Severity,
    /// Number of zone boundaries crossed
    pub zone_crossings: u32,
    /// Whether this path reaches an ePHI zone
    pub reaches_ephi: bool,
    /// Whether this path involves medical devices
    pub involves_medical_devices: bool,
    /// Description of the attack scenario
    pub attack_scenario: String,
    /// Recommended mitigations
    pub mitigations: Vec<String>,
}

/// A single hop in a lateral movement path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHop {
    /// Host IP at this hop
    pub ip: IpAddr,
    /// Zone this host belongs to
    pub zone: NetworkZone,
    /// Port used to reach this hop
    pub port: u16,
    /// Service running on this port
    pub service: Option<String>,
    /// Device class if IoMT
    pub device_class: Option<DeviceClass>,
    /// Hop description
    pub description: String,
}

// ─── Segmentation Test Result ──────────────────────────────────────────────

/// Results of a zone-to-zone isolation test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationTestResult {
    /// Source zone tested
    pub source_zone: NetworkZone,
    /// Target zone tested
    pub target_zone: NetworkZone,
    /// Whether isolation is properly enforced
    pub isolated: bool,
    /// Ports that were reachable (should be empty if isolated)
    pub reachable_ports: Vec<ReachablePort>,
    /// Source IP used for testing
    pub source_ip: IpAddr,
    /// Target IP tested
    pub target_ip: IpAddr,
    /// Test duration
    pub test_duration_ms: u64,
    /// When the test was performed
    pub tested_at: DateTime<Utc>,
}

/// A port found reachable during isolation testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachablePort {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

// ─── Segmentation Assessment ───────────────────────────────────────────────

/// Complete network segmentation assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationAssessment {
    /// Assessment ID
    pub id: Uuid,
    /// When the assessment was performed
    pub assessed_at: DateTime<Utc>,
    /// Network zones discovered
    pub zones: Vec<ZoneSubnet>,
    /// All detected violations
    pub violations: Vec<SegmentationViolation>,
    /// Lateral movement paths identified
    pub lateral_movement_paths: Vec<LateralMovementPath>,
    /// Zone-to-zone isolation test results
    pub isolation_tests: Vec<IsolationTestResult>,
    /// Per-zone host counts
    pub zone_host_counts: HashMap<String, u32>,
    /// Overall segmentation score (0-100)
    pub segmentation_score: f64,
    /// Summary statistics
    pub summary: AssessmentSummary,
}

/// Summary statistics for a segmentation assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentSummary {
    /// Total zones identified
    pub total_zones: u32,
    /// Total hosts scanned
    pub total_hosts: u32,
    /// Total violations found
    pub total_violations: u32,
    /// Critical violations
    pub critical_violations: u32,
    /// High violations
    pub high_violations: u32,
    /// Medium violations
    pub medium_violations: u32,
    /// Total lateral movement paths
    pub lateral_paths: u32,
    /// Paths reaching ePHI zones
    pub paths_to_ephi: u32,
    /// Paths involving medical devices
    pub paths_to_meddevices: u32,
    /// Zone pairs tested for isolation
    pub isolation_tests_run: u32,
    /// Zone pairs that passed isolation
    pub isolation_tests_passed: u32,
}

// ─── Segmentation Validation Engine ────────────────────────────────────────

/// Network segmentation validation engine for healthcare environments
pub struct SegmentationValidator {
    /// Network zone definitions
    zones: Vec<ZoneSubnet>,
    /// Segmentation policy
    policy: SegmentationPolicy,
    /// Observed network flows
    flows: Vec<ObservedFlow>,
    /// Host-to-zone mapping cache
    host_zone_map: HashMap<IpAddr, NetworkZone>,
    /// Host-to-device-class mapping (for IoMT awareness)
    host_device_map: HashMap<IpAddr, DeviceClass>,
    /// Host connectivity graph: source → Vec<(dest, port)>
    connectivity_graph: HashMap<IpAddr, Vec<(IpAddr, u16)>>,
}

impl SegmentationValidator {
    /// Create a new validator with zone definitions and policy
    pub fn new(zones: Vec<ZoneSubnet>, policy: SegmentationPolicy) -> Self {
        let host_zone_map = HashMap::new();

        Self {
            zones,
            policy,
            flows: Vec::new(),
            host_zone_map,
            host_device_map: HashMap::new(),
            connectivity_graph: HashMap::new(),
        }
    }

    /// Create a validator with the healthcare-default policy
    pub fn with_healthcare_defaults(zones: Vec<ZoneSubnet>) -> Self {
        Self::new(zones, SegmentationPolicy::healthcare_default())
    }

    /// Register a host's zone assignment (from scan results or manual config)
    pub fn register_host(&mut self, ip: IpAddr, zone: NetworkZone) {
        self.host_zone_map.insert(ip, zone);
    }

    /// Register a host as a medical device
    pub fn register_medical_device(&mut self, ip: IpAddr, device_class: DeviceClass) {
        self.host_device_map.insert(ip, device_class);
    }

    /// Add observed network flows (from passive monitoring or active probing)
    pub fn add_flows(&mut self, flows: Vec<ObservedFlow>) {
        for flow in &flows {
            // Update connectivity graph
            self.connectivity_graph
                .entry(flow.source_ip)
                .or_default()
                .push((flow.destination_ip, flow.destination_port));
        }
        self.flows.extend(flows);
    }

    /// Add an isolation test result
    pub fn add_isolation_test(&mut self, source: IpAddr, dest: IpAddr, port: u16, reachable: bool) {
        let src_zone = self.resolve_zone(source);
        let dst_zone = self.resolve_zone(dest);

        if reachable && src_zone != dst_zone {
            // If reachable across zones, add to connectivity graph
            self.connectivity_graph
                .entry(source)
                .or_default()
                .push((dest, port));
        }
    }

    /// Classify host zone based on observed ports and IoMT fingerprinting
    pub fn auto_classify_hosts(&mut self, host_ports: &[(IpAddr, Vec<u16>)]) {
        for (ip, ports) in host_ports {
            if self.host_zone_map.contains_key(ip) {
                continue; // Already classified
            }

            // Check if this looks like a medical device subnet
            let has_medical = ports
                .iter()
                .any(|p| matches!(*p, 104 | 2762 | 2575 | 47808 | 502 | 1883 | 8883));

            let has_clinical = ports
                .iter()
                .any(|p| matches!(*p, 1433 | 5432 | 3306 | 443 | 8443));

            let has_web_facing = ports.iter().any(|p| matches!(*p, 80 | 443 | 8080 | 8443));

            let zone = if has_medical {
                NetworkZone::MedicalDevice
            } else if has_clinical && !has_web_facing {
                NetworkZone::Clinical
            } else if has_web_facing && ports.len() <= 3 {
                NetworkZone::Dmz
            } else {
                NetworkZone::Administrative
            };

            self.host_zone_map.insert(*ip, zone);
        }
    }

    /// Resolve a host's zone
    pub fn resolve_zone(&self, ip: IpAddr) -> NetworkZone {
        self.host_zone_map
            .get(&ip)
            .copied()
            .unwrap_or(NetworkZone::Unknown)
    }

    /// Run the complete segmentation assessment
    pub fn assess(&self) -> SegmentationAssessment {
        let mut violations = Vec::new();
        let mut isolation_tests = Vec::new();

        // 1. Evaluate all observed flows against policy
        violations.extend(self.evaluate_flows());

        // 2. Detect flat network conditions
        violations.extend(self.detect_flat_network());

        // 3. Find lateral movement paths
        let lateral_paths = self.find_lateral_movement_paths();

        // Generate violations for dangerous lateral paths
        for path in &lateral_paths {
            if path.reaches_ephi || path.involves_medical_devices {
                violations.push(SegmentationViolation {
                    id: Uuid::new_v4(),
                    violation_type: ViolationType::LateralMovementPath,
                    severity: path.severity,
                    source_ip: path
                        .hops
                        .first()
                        .map(|h| h.ip)
                        .unwrap_or(IpAddr::from([0, 0, 0, 0])),
                    destination_ip: path
                        .hops
                        .last()
                        .map(|h| h.ip)
                        .unwrap_or(IpAddr::from([0, 0, 0, 0])),
                    destination_port: path.hops.last().map(|h| h.port).unwrap_or(0),
                    source_zone: path.origin_zone,
                    destination_zone: path.target_zone,
                    description: format!(
                        "Lateral movement path detected: {} → {} ({} hops, {} zone crossings)",
                        path.origin_zone,
                        path.target_zone,
                        path.hops.len(),
                        path.zone_crossings,
                    ),
                    compliance_impact: if path.reaches_ephi {
                        "Unauthorized access path to ePHI systems violates HIPAA §164.312(a) \
                         and HCCRA Control 3 (Network Segmentation)"
                            .into()
                    } else {
                        "Cross-zone movement path weakens defense-in-depth posture".into()
                    },
                    remediation: path.mitigations.join("; "),
                    detected_at: Utc::now(),
                    flow_successful: true,
                });
            }
        }

        // 4. Build isolation test results from connectivity data
        isolation_tests.extend(self.build_isolation_results());

        // 5. Calculate scores and summary
        let segmentation_score = self.calculate_score(&violations, &isolation_tests);
        let summary = self.build_summary(&violations, &lateral_paths, &isolation_tests);

        let zone_host_counts = self.count_hosts_per_zone();

        SegmentationAssessment {
            id: Uuid::new_v4(),
            assessed_at: Utc::now(),
            zones: self.zones.clone(),
            violations,
            lateral_movement_paths: lateral_paths,
            isolation_tests,
            zone_host_counts,
            segmentation_score,
            summary,
        }
    }

    /// Evaluate all observed flows against the segmentation policy
    fn evaluate_flows(&self) -> Vec<SegmentationViolation> {
        let mut violations = Vec::new();

        for flow in &self.flows {
            let src_zone = flow
                .source_zone
                .unwrap_or_else(|| self.resolve_zone(flow.source_ip));
            let dst_zone = flow
                .destination_zone
                .unwrap_or_else(|| self.resolve_zone(flow.destination_ip));

            if src_zone == dst_zone {
                continue; // Same-zone traffic is fine
            }

            let verdict = self
                .policy
                .evaluate_flow(src_zone, dst_zone, flow.destination_port);

            match verdict {
                FlowVerdict::Allowed => {} // OK
                FlowVerdict::ExplicitlyDenied { reason } => {
                    let violation_type = self.classify_violation(src_zone, dst_zone);
                    let severity = if src_zone.is_untrusted() && dst_zone.handles_ephi() {
                        Severity::Critical
                    } else {
                        violation_type.default_severity()
                    };

                    violations.push(SegmentationViolation {
                        id: Uuid::new_v4(),
                        violation_type,
                        severity,
                        source_ip: flow.source_ip,
                        destination_ip: flow.destination_ip,
                        destination_port: flow.destination_port,
                        source_zone: src_zone,
                        destination_zone: dst_zone,
                        description: format!(
                            "Explicitly denied flow: {} ({}) → {} ({}) on port {}. Policy: {}",
                            flow.source_ip,
                            src_zone,
                            flow.destination_ip,
                            dst_zone,
                            flow.destination_port,
                            reason,
                        ),
                        compliance_impact: self.compliance_impact_text(src_zone, dst_zone),
                        remediation: self.remediation_text(src_zone, dst_zone),
                        detected_at: flow.observed_at,
                        flow_successful: flow.successful,
                    });
                }
                FlowVerdict::DefaultDenied => {
                    let violation_type = self.classify_violation(src_zone, dst_zone);
                    violations.push(SegmentationViolation {
                        id: Uuid::new_v4(),
                        violation_type,
                        severity: violation_type.default_severity(),
                        source_ip: flow.source_ip,
                        destination_ip: flow.destination_ip,
                        destination_port: flow.destination_port,
                        source_zone: src_zone,
                        destination_zone: dst_zone,
                        description: format!(
                            "Unauthorized cross-zone flow: {} ({}) → {} ({}) on port {}",
                            flow.source_ip,
                            src_zone,
                            flow.destination_ip,
                            dst_zone,
                            flow.destination_port,
                        ),
                        compliance_impact: self.compliance_impact_text(src_zone, dst_zone),
                        remediation: self.remediation_text(src_zone, dst_zone),
                        detected_at: flow.observed_at,
                        flow_successful: flow.successful,
                    });
                }
            }
        }

        violations
    }

    /// Detect flat network conditions (multiple zone types sharing connectivity)
    fn detect_flat_network(&self) -> Vec<SegmentationViolation> {
        let mut violations = Vec::new();

        // Group hosts by zone
        let mut zone_hosts: HashMap<NetworkZone, HashSet<IpAddr>> = HashMap::new();
        for (&ip, &zone) in &self.host_zone_map {
            zone_hosts.entry(zone).or_default().insert(ip);
        }

        // Check if hosts in different zones can all reach each other
        let ephi_zones: Vec<_> = zone_hosts
            .keys()
            .filter(|z| z.handles_ephi())
            .copied()
            .collect();
        let untrusted_zones: Vec<_> = zone_hosts
            .keys()
            .filter(|z| z.is_untrusted())
            .copied()
            .collect();

        // If we see flows from untrusted zones to all ePHI zones, it's a flat network
        for untrusted in &untrusted_zones {
            let untrusted_hosts = match zone_hosts.get(untrusted) {
                Some(h) => h,
                None => continue,
            };

            for ephi_zone in &ephi_zones {
                let ephi_hosts = match zone_hosts.get(ephi_zone) {
                    Some(h) => h,
                    None => continue,
                };

                // Check if any untrusted host can reach any ePHI host
                let mut cross_zone_flows = 0;
                for flow in &self.flows {
                    if untrusted_hosts.contains(&flow.source_ip)
                        && ephi_hosts.contains(&flow.destination_ip)
                        && flow.successful
                    {
                        cross_zone_flows += 1;
                    }
                }

                let total_possible = untrusted_hosts.len().saturating_mul(ephi_hosts.len());
                if total_possible > 0 && cross_zone_flows > total_possible / 2 {
                    // More than half of possible pairs can communicate = flat network
                    let sample_src = untrusted_hosts
                        .iter()
                        .next()
                        .copied()
                        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
                    let sample_dst = ephi_hosts
                        .iter()
                        .next()
                        .copied()
                        .unwrap_or(IpAddr::from([0, 0, 0, 0]));

                    violations.push(SegmentationViolation {
                        id: Uuid::new_v4(),
                        violation_type: ViolationType::FlatNetwork,
                        severity: Severity::High,
                        source_ip: sample_src,
                        destination_ip: sample_dst,
                        destination_port: 0,
                        source_zone: *untrusted,
                        destination_zone: *ephi_zone,
                        description: format!(
                            "Flat network detected: {} zone has broad access to {} zone \
                             ({} of {} possible host pairs can communicate)",
                            untrusted, ephi_zone, cross_zone_flows, total_possible,
                        ),
                        compliance_impact: "Lack of network segmentation violates HIPAA \
                             §164.312(a)(1) Access Control and HCCRA Control 3 \
                             (Network Segmentation). NIST 800-171 3.13.1 requires \
                             boundary protection."
                            .into(),
                        remediation: "Implement VLAN segmentation with ACLs between \
                             network zones. Deploy next-generation firewalls at zone \
                             boundaries. Enable micro-segmentation for medical device \
                             networks."
                            .into(),
                        detected_at: Utc::now(),
                        flow_successful: true,
                    });
                }
            }
        }

        violations
    }

    /// Find all lateral movement paths between zones using BFS
    fn find_lateral_movement_paths(&self) -> Vec<LateralMovementPath> {
        let mut paths = Vec::new();

        // Find paths from untrusted/admin zones to ePHI zones
        let source_zones = [
            NetworkZone::Guest,
            NetworkZone::Dmz,
            NetworkZone::Administrative,
        ];
        let target_zones = [
            NetworkZone::Clinical,
            NetworkZone::MedicalDevice,
            NetworkZone::ServerRoom,
        ];

        for &src_zone in &source_zones {
            for &tgt_zone in &target_zones {
                if src_zone == tgt_zone {
                    continue;
                }

                // Get starting hosts in source zone
                let src_hosts: Vec<IpAddr> = self
                    .host_zone_map
                    .iter()
                    .filter(|(_, &z)| z == src_zone)
                    .map(|(&ip, _)| ip)
                    .collect();

                let tgt_hosts: HashSet<IpAddr> = self
                    .host_zone_map
                    .iter()
                    .filter(|(_, &z)| z == tgt_zone)
                    .map(|(&ip, _)| ip)
                    .collect();

                if src_hosts.is_empty() || tgt_hosts.is_empty() {
                    continue;
                }

                // BFS from each source host
                for src_ip in &src_hosts {
                    if let Some(path) = self.bfs_path(*src_ip, &tgt_hosts, src_zone, tgt_zone) {
                        paths.push(path);
                    }
                }
            }
        }

        // Deduplicate: keep only the shortest path per (origin_zone, target_zone) pair
        let mut best_paths: HashMap<(NetworkZone, NetworkZone), LateralMovementPath> =
            HashMap::new();
        for path in paths {
            let key = (path.origin_zone, path.target_zone);
            let is_better = match best_paths.get(&key) {
                None => true,
                Some(existing) => path.hops.len() < existing.hops.len(),
            };
            if is_better {
                best_paths.insert(key, path);
            }
        }

        best_paths.into_values().collect()
    }

    /// BFS to find shortest path from source to any target host
    fn bfs_path(
        &self,
        start: IpAddr,
        targets: &HashSet<IpAddr>,
        src_zone: NetworkZone,
        tgt_zone: NetworkZone,
    ) -> Option<LateralMovementPath> {
        let mut visited: HashSet<IpAddr> = HashSet::new();
        // Queue: (current_ip, path_so_far)
        let mut queue: std::collections::VecDeque<(IpAddr, Vec<(IpAddr, u16)>)> =
            std::collections::VecDeque::new();

        visited.insert(start);
        queue.push_back((start, vec![(start, 0)]));

        while let Some((current, path)) = queue.pop_front() {
            // Limit path length to prevent explosion
            if path.len() > 6 {
                continue;
            }

            if targets.contains(&current) && current != start {
                // Found a path! Build the LateralMovementPath
                let hops: Vec<PathHop> = path
                    .iter()
                    .map(|(ip, port)| {
                        let zone = self.resolve_zone(*ip);
                        PathHop {
                            ip: *ip,
                            zone,
                            port: *port,
                            service: None,
                            device_class: self.host_device_map.get(ip).copied(),
                            description: format!("{} ({})", ip, zone),
                        }
                    })
                    .collect();

                let zone_crossings =
                    hops.windows(2).filter(|w| w[0].zone != w[1].zone).count() as u32;

                let involves_medical = hops.iter().any(|h| h.device_class.is_some());

                let reaches_ephi = tgt_zone.handles_ephi();

                let severity = if reaches_ephi && src_zone.is_untrusted() {
                    Severity::Critical
                } else if reaches_ephi {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let attack_scenario = format!(
                    "An attacker in the {} zone ({}) could traverse {} hops across {} zone \
                     boundaries to reach the {} zone. {}",
                    src_zone,
                    start,
                    hops.len() - 1,
                    zone_crossings,
                    tgt_zone,
                    if involves_medical {
                        "This path involves medical devices, increasing patient safety risk."
                    } else {
                        ""
                    },
                );

                let mitigations = self.generate_path_mitigations(src_zone, tgt_zone, &hops);

                return Some(LateralMovementPath {
                    id: Uuid::new_v4(),
                    hops,
                    origin_zone: src_zone,
                    target_zone: tgt_zone,
                    severity,
                    zone_crossings,
                    reaches_ephi,
                    involves_medical_devices: involves_medical,
                    attack_scenario,
                    mitigations,
                });
            }

            // Explore neighbors
            if let Some(neighbors) = self.connectivity_graph.get(&current) {
                for &(next_ip, port) in neighbors {
                    if !visited.contains(&next_ip) {
                        visited.insert(next_ip);
                        let mut new_path = path.clone();
                        new_path.push((next_ip, port));
                        queue.push_back((next_ip, new_path));
                    }
                }
            }
        }

        None
    }

    /// Generate mitigations for a lateral movement path
    fn generate_path_mitigations(
        &self,
        src_zone: NetworkZone,
        tgt_zone: NetworkZone,
        hops: &[PathHop],
    ) -> Vec<String> {
        let mut mitigations = Vec::new();

        mitigations.push(format!(
            "Implement firewall rules to block traffic from {} to {} zone",
            src_zone, tgt_zone,
        ));

        // Check for zone transitions and recommend ACLs at each boundary
        for window in hops.windows(2) {
            if window[0].zone != window[1].zone {
                mitigations.push(format!(
                    "Add ACL at {}/{} boundary to block port {} from {} to {}",
                    window[0].zone, window[1].zone, window[1].port, window[0].ip, window[1].ip,
                ));
            }
        }

        if hops.iter().any(|h| h.device_class.is_some()) {
            mitigations.push(
                "Deploy micro-segmentation for medical devices to restrict \
                 communication to only authorized clinical systems"
                    .into(),
            );
        }

        if src_zone == NetworkZone::Guest {
            mitigations.push(
                "Ensure guest Wi-Fi network is on a physically separate \
                 VLAN with no routes to internal networks"
                    .into(),
            );
        }

        mitigations
    }

    /// Build isolation test results from known connectivity
    fn build_isolation_results(&self) -> Vec<IsolationTestResult> {
        let mut results = Vec::new();

        // For each zone pair that should be isolated, check connectivity
        let zone_pairs: Vec<(NetworkZone, NetworkZone)> = self
            .policy
            .denied_flows
            .iter()
            .map(|r| (r.source_zone, r.destination_zone))
            .collect();

        for (src_zone, dst_zone) in &zone_pairs {
            let src_hosts: Vec<IpAddr> = self
                .host_zone_map
                .iter()
                .filter(|(_, &z)| z == *src_zone)
                .map(|(&ip, _)| ip)
                .take(1)
                .collect();
            let dst_hosts: Vec<IpAddr> = self
                .host_zone_map
                .iter()
                .filter(|(_, &z)| z == *dst_zone)
                .map(|(&ip, _)| ip)
                .take(1)
                .collect();

            if let (Some(&src_ip), Some(&dst_ip)) = (src_hosts.first(), dst_hosts.first()) {
                // Check if there are any successful flows between these hosts
                let reachable: Vec<ReachablePort> = self
                    .flows
                    .iter()
                    .filter(|f| f.source_ip == src_ip && f.destination_ip == dst_ip && f.successful)
                    .map(|f| ReachablePort {
                        port: f.destination_port,
                        protocol: f.protocol.clone(),
                        service: f.service.clone(),
                        banner: None,
                    })
                    .collect();

                results.push(IsolationTestResult {
                    source_zone: *src_zone,
                    target_zone: *dst_zone,
                    isolated: reachable.is_empty(),
                    reachable_ports: reachable,
                    source_ip: src_ip,
                    target_ip: dst_ip,
                    test_duration_ms: 0,
                    tested_at: Utc::now(),
                });
            }
        }

        results
    }

    /// Classify the type of violation based on zone pair
    fn classify_violation(&self, src: NetworkZone, dst: NetworkZone) -> ViolationType {
        if src == NetworkZone::Guest {
            if dst.handles_ephi() {
                return ViolationType::GuestEscalation;
            }
        }
        if src.is_untrusted() && dst.handles_ephi() {
            return ViolationType::UntrustedToEphi;
        }
        if dst == NetworkZone::MedicalDevice
            && !matches!(src, NetworkZone::Clinical | NetworkZone::ServerRoom)
        {
            return ViolationType::MedDeviceExposure;
        }
        ViolationType::UnauthorizedCrossZone
    }

    /// Generate compliance impact text for a zone pair violation
    fn compliance_impact_text(&self, src: NetworkZone, dst: NetworkZone) -> String {
        let mut impacts = Vec::new();

        if dst.handles_ephi() {
            impacts.push(
                "HIPAA §164.312(a)(1): Access Control — unauthorized access path to ePHI systems",
            );
            impacts
                .push("HCCRA Control 3: Network Segmentation — ePHI systems not properly isolated");
        }

        if src.is_untrusted() {
            impacts.push(
                "HIPAA §164.312(e)(1): Transmission Security — untrusted network can reach protected systems",
            );
        }

        if dst == NetworkZone::MedicalDevice {
            impacts.push(
                "NIST 800-171 3.13.1: Boundary Protection — medical device network boundary not enforced",
            );
        }

        impacts.push("NIST 800-171 3.13.5: Network segmentation required for CUI systems");

        impacts.join(". ")
    }

    /// Generate remediation text for a zone pair violation
    fn remediation_text(&self, src: NetworkZone, dst: NetworkZone) -> String {
        let mut steps = Vec::new();

        steps.push(format!(
            "Configure firewall/ACL to deny traffic from {} to {} zone",
            src, dst
        ));

        if dst == NetworkZone::MedicalDevice {
            steps.push(
                "Implement micro-segmentation for medical device network using \
                 next-generation firewall or NAC"
                    .into(),
            );
            steps.push(
                "Restrict medical device communication to only authorized \
                 clinical servers via allowlist"
                    .into(),
            );
        }

        if src == NetworkZone::Guest {
            steps.push(
                "Ensure guest network is on separate physical or logical \
                 infrastructure with no internal routes"
                    .into(),
            );
        }

        if dst.handles_ephi() {
            steps.push(
                "Verify VLAN tagging and inter-VLAN routing ACLs at layer-3 \
                 switch/router boundaries"
                    .into(),
            );
        }

        steps.join(". ")
    }

    /// Calculate overall segmentation score
    fn calculate_score(
        &self,
        violations: &[SegmentationViolation],
        isolation_tests: &[IsolationTestResult],
    ) -> f64 {
        let mut score = 100.0_f64;

        // Penalize for violations
        for v in violations {
            match v.severity {
                Severity::Critical => score -= 20.0,
                Severity::High => score -= 10.0,
                Severity::Medium => score -= 5.0,
                Severity::Low => score -= 2.0,
                Severity::Info => score -= 0.5,
            }
        }

        // Penalize for failed isolation tests
        for test in isolation_tests {
            if !test.isolated {
                score -= 15.0;
            }
        }

        score.max(0.0).min(100.0)
    }

    /// Build assessment summary
    fn build_summary(
        &self,
        violations: &[SegmentationViolation],
        lateral_paths: &[LateralMovementPath],
        isolation_tests: &[IsolationTestResult],
    ) -> AssessmentSummary {
        let unique_zones: HashSet<NetworkZone> = self.host_zone_map.values().copied().collect();

        AssessmentSummary {
            total_zones: unique_zones.len() as u32,
            total_hosts: self.host_zone_map.len() as u32,
            total_violations: violations.len() as u32,
            critical_violations: violations
                .iter()
                .filter(|v| v.severity == Severity::Critical)
                .count() as u32,
            high_violations: violations
                .iter()
                .filter(|v| v.severity == Severity::High)
                .count() as u32,
            medium_violations: violations
                .iter()
                .filter(|v| v.severity == Severity::Medium)
                .count() as u32,
            lateral_paths: lateral_paths.len() as u32,
            paths_to_ephi: lateral_paths.iter().filter(|p| p.reaches_ephi).count() as u32,
            paths_to_meddevices: lateral_paths
                .iter()
                .filter(|p| p.involves_medical_devices)
                .count() as u32,
            isolation_tests_run: isolation_tests.len() as u32,
            isolation_tests_passed: isolation_tests.iter().filter(|t| t.isolated).count() as u32,
        }
    }

    /// Count hosts per zone
    fn count_hosts_per_zone(&self) -> HashMap<String, u32> {
        let mut counts: HashMap<String, u32> = HashMap::new();
        for zone in self.host_zone_map.values() {
            *counts.entry(zone.as_str().to_string()).or_default() += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_zones() -> Vec<ZoneSubnet> {
        vec![
            ZoneSubnet::new(
                "10.10.1.0/24",
                NetworkZone::Clinical,
                "Clinical Workstations",
            )
            .with_vlan(100),
            ZoneSubnet::new(
                "10.10.2.0/24",
                NetworkZone::MedicalDevice,
                "ICU Medical Devices",
            )
            .with_vlan(200),
            ZoneSubnet::new("10.10.3.0/24", NetworkZone::Administrative, "Admin Network")
                .with_vlan(300),
            ZoneSubnet::new("10.10.4.0/24", NetworkZone::Guest, "Guest Wi-Fi").with_vlan(400),
            ZoneSubnet::new("10.10.5.0/24", NetworkZone::ServerRoom, "Data Center").with_vlan(500),
            ZoneSubnet::new("172.16.0.0/24", NetworkZone::Dmz, "DMZ").with_vlan(600),
        ]
    }

    fn setup_validator() -> SegmentationValidator {
        let zones = sample_zones();
        let mut validator = SegmentationValidator::with_healthcare_defaults(zones);

        // Register hosts
        let clinical_ip: IpAddr = "10.10.1.10".parse().unwrap();
        let meddev_ip: IpAddr = "10.10.2.20".parse().unwrap();
        let admin_ip: IpAddr = "10.10.3.30".parse().unwrap();
        let guest_ip: IpAddr = "10.10.4.40".parse().unwrap();
        let server_ip: IpAddr = "10.10.5.50".parse().unwrap();
        let dmz_ip: IpAddr = "172.16.0.10".parse().unwrap();

        validator.register_host(clinical_ip, NetworkZone::Clinical);
        validator.register_host(meddev_ip, NetworkZone::MedicalDevice);
        validator.register_host(admin_ip, NetworkZone::Administrative);
        validator.register_host(guest_ip, NetworkZone::Guest);
        validator.register_host(server_ip, NetworkZone::ServerRoom);
        validator.register_host(dmz_ip, NetworkZone::Dmz);

        validator.register_medical_device(meddev_ip, DeviceClass::PatientMonitor);

        validator
    }

    #[test]
    fn test_zone_properties() {
        assert!(NetworkZone::Clinical.handles_ephi());
        assert!(NetworkZone::MedicalDevice.handles_ephi());
        assert!(NetworkZone::ServerRoom.handles_ephi());
        assert!(!NetworkZone::Administrative.handles_ephi());
        assert!(!NetworkZone::Guest.handles_ephi());

        assert!(NetworkZone::Guest.is_untrusted());
        assert!(NetworkZone::Dmz.is_untrusted());
        assert!(!NetworkZone::Clinical.is_untrusted());
    }

    #[test]
    fn test_healthcare_default_policy() {
        let policy = SegmentationPolicy::healthcare_default();

        // Clinical → ServerRoom on 443 should be allowed
        assert_eq!(
            policy.evaluate_flow(NetworkZone::Clinical, NetworkZone::ServerRoom, 443),
            FlowVerdict::Allowed,
        );

        // Guest → Clinical should be explicitly denied
        assert!(matches!(
            policy.evaluate_flow(NetworkZone::Guest, NetworkZone::Clinical, 80),
            FlowVerdict::ExplicitlyDenied { .. },
        ));

        // Guest → MedicalDevice should be explicitly denied
        assert!(matches!(
            policy.evaluate_flow(NetworkZone::Guest, NetworkZone::MedicalDevice, 104),
            FlowVerdict::ExplicitlyDenied { .. },
        ));

        // DMZ → MedicalDevice should be explicitly denied
        assert!(matches!(
            policy.evaluate_flow(NetworkZone::Dmz, NetworkZone::MedicalDevice, 80),
            FlowVerdict::ExplicitlyDenied { .. },
        ));

        // Admin → MedicalDevice should be default denied
        assert_eq!(
            policy.evaluate_flow(NetworkZone::Administrative, NetworkZone::MedicalDevice, 22),
            FlowVerdict::DefaultDenied,
        );

        // Same-zone should always be allowed
        assert_eq!(
            policy.evaluate_flow(NetworkZone::Guest, NetworkZone::Guest, 80),
            FlowVerdict::Allowed,
        );
    }

    #[test]
    fn test_guest_to_ephi_violation() {
        let mut validator = setup_validator();

        let guest_ip: IpAddr = "10.10.4.40".parse().unwrap();
        let clinical_ip: IpAddr = "10.10.1.10".parse().unwrap();

        validator.add_flows(vec![ObservedFlow {
            source_ip: guest_ip,
            destination_ip: clinical_ip,
            destination_port: 443,
            protocol: "tcp".into(),
            source_zone: Some(NetworkZone::Guest),
            destination_zone: Some(NetworkZone::Clinical),
            observed_at: Utc::now(),
            service: Some("https".into()),
            successful: true,
        }]);

        let assessment = validator.assess();
        assert!(!assessment.violations.is_empty());

        let critical = assessment
            .violations
            .iter()
            .find(|v| v.severity == Severity::Critical);
        assert!(
            critical.is_some(),
            "Should have critical violation for guest→clinical"
        );

        let v = critical.unwrap();
        assert!(matches!(
            v.violation_type,
            ViolationType::GuestEscalation | ViolationType::UntrustedToEphi
        ));
    }

    #[test]
    fn test_dmz_to_meddevice_violation() {
        let mut validator = setup_validator();

        let dmz_ip: IpAddr = "172.16.0.10".parse().unwrap();
        let meddev_ip: IpAddr = "10.10.2.20".parse().unwrap();

        validator.add_flows(vec![ObservedFlow {
            source_ip: dmz_ip,
            destination_ip: meddev_ip,
            destination_port: 104,
            protocol: "tcp".into(),
            source_zone: Some(NetworkZone::Dmz),
            destination_zone: Some(NetworkZone::MedicalDevice),
            observed_at: Utc::now(),
            service: Some("dicom".into()),
            successful: true,
        }]);

        let assessment = validator.assess();
        let has_meddev_violation = assessment.violations.iter().any(|v| {
            matches!(
                v.violation_type,
                ViolationType::MedDeviceExposure | ViolationType::UntrustedToEphi
            )
        });
        assert!(
            has_meddev_violation,
            "Should detect DMZ→MedDevice violation"
        );
    }

    #[test]
    fn test_allowed_flow_no_violation() {
        let mut validator = setup_validator();

        let clinical_ip: IpAddr = "10.10.1.10".parse().unwrap();
        let server_ip: IpAddr = "10.10.5.50".parse().unwrap();

        validator.add_flows(vec![ObservedFlow {
            source_ip: clinical_ip,
            destination_ip: server_ip,
            destination_port: 443,
            protocol: "tcp".into(),
            source_zone: Some(NetworkZone::Clinical),
            destination_zone: Some(NetworkZone::ServerRoom),
            observed_at: Utc::now(),
            service: Some("https".into()),
            successful: true,
        }]);

        let assessment = validator.assess();
        // Should have no flow-based violations for this allowed flow
        let flow_violations: Vec<_> = assessment
            .violations
            .iter()
            .filter(|v| !matches!(v.violation_type, ViolationType::LateralMovementPath))
            .collect();
        assert!(
            flow_violations.is_empty(),
            "Clinical→ServerRoom on 443 should be allowed, got {} violations",
            flow_violations.len(),
        );
    }

    #[test]
    fn test_lateral_movement_detection() {
        let mut validator = setup_validator();

        let guest_ip: IpAddr = "10.10.4.40".parse().unwrap();
        let admin_ip: IpAddr = "10.10.3.30".parse().unwrap();
        let clinical_ip: IpAddr = "10.10.1.10".parse().unwrap();

        // Create multi-hop path: Guest → Admin → Clinical
        validator.add_flows(vec![
            ObservedFlow {
                source_ip: guest_ip,
                destination_ip: admin_ip,
                destination_port: 22,
                protocol: "tcp".into(),
                source_zone: Some(NetworkZone::Guest),
                destination_zone: Some(NetworkZone::Administrative),
                observed_at: Utc::now(),
                service: Some("ssh".into()),
                successful: true,
            },
            ObservedFlow {
                source_ip: admin_ip,
                destination_ip: clinical_ip,
                destination_port: 3389,
                protocol: "tcp".into(),
                source_zone: Some(NetworkZone::Administrative),
                destination_zone: Some(NetworkZone::Clinical),
                observed_at: Utc::now(),
                service: Some("rdp".into()),
                successful: true,
            },
        ]);

        let assessment = validator.assess();

        // Should find lateral movement path from Guest→Clinical via Admin
        let guest_to_clinical = assessment.lateral_movement_paths.iter().find(|p| {
            p.origin_zone == NetworkZone::Guest && p.target_zone == NetworkZone::Clinical
        });
        assert!(
            guest_to_clinical.is_some(),
            "Should detect Guest→Admin→Clinical lateral path"
        );

        let path = guest_to_clinical.unwrap();
        assert!(path.reaches_ephi);
        assert!(path.zone_crossings >= 2);
        assert_eq!(path.severity, Severity::Critical);
    }

    #[test]
    fn test_auto_classify_hosts() {
        let zones = sample_zones();
        let mut validator = SegmentationValidator::with_healthcare_defaults(zones);

        let host_ports: Vec<(IpAddr, Vec<u16>)> = vec![
            ("10.10.2.21".parse().unwrap(), vec![104, 80]), // DICOM = MedDevice
            ("10.10.3.31".parse().unwrap(), vec![22, 80, 443, 3389]), // Admin
            ("10.10.2.22".parse().unwrap(), vec![2575, 8080]), // HL7 = MedDevice
        ];

        validator.auto_classify_hosts(&host_ports);

        assert_eq!(
            validator.resolve_zone("10.10.2.21".parse().unwrap()),
            NetworkZone::MedicalDevice,
        );
        assert_eq!(
            validator.resolve_zone("10.10.2.22".parse().unwrap()),
            NetworkZone::MedicalDevice,
        );
    }

    #[test]
    fn test_segmentation_score() {
        let validator = setup_validator();
        let assessment = validator.assess();
        // No violations = perfect score
        assert_eq!(assessment.segmentation_score, 100.0);
    }

    #[test]
    fn test_segmentation_score_with_violations() {
        let mut validator = setup_validator();

        let guest_ip: IpAddr = "10.10.4.40".parse().unwrap();
        let server_ip: IpAddr = "10.10.5.50".parse().unwrap();

        validator.add_flows(vec![ObservedFlow {
            source_ip: guest_ip,
            destination_ip: server_ip,
            destination_port: 3306,
            protocol: "tcp".into(),
            source_zone: Some(NetworkZone::Guest),
            destination_zone: Some(NetworkZone::ServerRoom),
            observed_at: Utc::now(),
            service: Some("mysql".into()),
            successful: true,
        }]);

        let assessment = validator.assess();
        assert!(assessment.segmentation_score < 100.0);
    }

    #[test]
    fn test_isolation_test_results() {
        let mut validator = setup_validator();

        let guest_ip: IpAddr = "10.10.4.40".parse().unwrap();
        let clinical_ip: IpAddr = "10.10.1.10".parse().unwrap();

        // Add a successful flow that violates isolation
        validator.add_flows(vec![ObservedFlow {
            source_ip: guest_ip,
            destination_ip: clinical_ip,
            destination_port: 80,
            protocol: "tcp".into(),
            source_zone: Some(NetworkZone::Guest),
            destination_zone: Some(NetworkZone::Clinical),
            observed_at: Utc::now(),
            service: Some("http".into()),
            successful: true,
        }]);

        let assessment = validator.assess();
        let guest_clinical_test = assessment.isolation_tests.iter().find(|t| {
            t.source_zone == NetworkZone::Guest && t.target_zone == NetworkZone::Clinical
        });

        assert!(guest_clinical_test.is_some());
        let test = guest_clinical_test.unwrap();
        assert!(!test.isolated, "Guest→Clinical should not be isolated");
        assert!(!test.reachable_ports.is_empty());
    }

    #[test]
    fn test_assessment_summary() {
        let validator = setup_validator();
        let assessment = validator.assess();

        assert_eq!(assessment.summary.total_zones, 6);
        assert_eq!(assessment.summary.total_hosts, 6);
    }

    #[test]
    fn test_violation_type_severity() {
        assert_eq!(
            ViolationType::UntrustedToEphi.default_severity(),
            Severity::Critical
        );
        assert_eq!(
            ViolationType::GuestEscalation.default_severity(),
            Severity::Critical
        );
        assert_eq!(
            ViolationType::FlatNetwork.default_severity(),
            Severity::High
        );
        assert_eq!(
            ViolationType::UnauthorizedCrossZone.default_severity(),
            Severity::Medium
        );
    }

    #[test]
    fn test_zone_subnet_builder() {
        let subnet = ZoneSubnet::new("10.10.1.0/24", NetworkZone::Clinical, "ICU").with_vlan(100);
        assert_eq!(subnet.vlan_id, Some(100));
        assert_eq!(subnet.zone, NetworkZone::Clinical);
    }

    #[test]
    fn test_empty_assessment() {
        let validator = SegmentationValidator::with_healthcare_defaults(vec![]);
        let assessment = validator.assess();
        assert_eq!(assessment.violations.len(), 0);
        assert_eq!(assessment.segmentation_score, 100.0);
    }

    #[test]
    fn test_compliance_impact_text() {
        let validator = setup_validator();
        let text = validator.compliance_impact_text(NetworkZone::Guest, NetworkZone::Clinical);
        assert!(text.contains("HIPAA"));
        assert!(text.contains("HCCRA"));
        assert!(text.contains("164.312"));
    }
}
