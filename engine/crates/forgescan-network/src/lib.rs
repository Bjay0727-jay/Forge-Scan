//! ForgeScan Network - Network discovery, port scanning, service detection
//!
//! This crate provides the core network scanning capabilities:
//! - Host discovery (ARP, ICMP, TCP SYN probes)
//! - Port scanning (SYN scan, connect scan, UDP scan)
//! - Service detection (banner grabbing, protocol identification)
//! - OS fingerprinting

pub mod banner;
pub mod capture;
pub mod discovery;
pub mod fingerprint;
pub mod iomt_fingerprint;
pub mod passive;
pub mod port_scan;
pub mod segmentation;
pub mod segmentation_alert;
pub mod segmentation_report;
pub mod service_detect;

pub use banner::{BannerGrabber, BannerResult, ProbeType};
pub use capture::{
    build_evidence_summary, build_host_filter, cleanup_old_captures, extract_packet_evidence,
    CaptureConfig, CaptureError, CaptureSession, CaptureStats, PacketSummary,
};
pub use discovery::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
pub use fingerprint::{Fingerprinter, HostFingerprint, OsFamily, OsFingerprint};
pub use iomt_fingerprint::{is_medical_network_segment, IoMTFingerprint, IoMTFingerprinter};
pub use passive::{
    EventBuffer, EventCategory, EventSeverity, PassiveConfig, PassiveMonitor, PassiveStats,
    ProtocolAnalyzer, RingPcapWriter, SecurityEvent,
};
pub use port_scan::{PortResult, PortScanner, PortState, ScanType};
pub use segmentation::{
    FlowVerdict, IsolationTestResult, LateralMovementPath, NetworkZone, ObservedFlow, PathHop,
    PolicyAction, ReachablePort, SegmentationAssessment, SegmentationPolicy, SegmentationValidator,
    SegmentationViolation, ViolationType, ZoneSubnet,
};
pub use segmentation_alert::{
    AlertGenerator, AlertSeverity, AlertSummary, AlertType, ComplianceReference,
    SegmentationAlert,
};
pub use segmentation_report::{
    ControlStatus, HipaaSegmentationControl, Nist800171Control, SegmentationComplianceReport,
    SegmentationReportGenerator,
};
pub use service_detect::{ServiceDetector, ServiceInfo};
