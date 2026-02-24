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
pub mod port_scan;
pub mod service_detect;

pub use banner::{BannerGrabber, BannerResult, ProbeType};
pub use capture::{
    build_evidence_summary, build_host_filter, cleanup_old_captures, extract_packet_evidence,
    CaptureConfig, CaptureError, CaptureSession, CaptureStats, PacketSummary,
};
pub use discovery::{DiscoveryMethod, DiscoveryResult, HostDiscovery};
pub use fingerprint::{Fingerprinter, HostFingerprint, OsFamily, OsFingerprint};
pub use port_scan::{PortResult, PortScanner, PortState, ScanType};
pub use service_detect::{ServiceDetector, ServiceInfo};
