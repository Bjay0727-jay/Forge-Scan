//! ForgeScan Network - Network discovery, port scanning, service detection
//!
//! This crate provides the core network scanning capabilities:
//! - Host discovery (ARP, ICMP, TCP SYN probes)
//! - Port scanning (SYN scan, connect scan, UDP scan)
//! - Service detection (banner grabbing, protocol identification)
//! - OS fingerprinting

pub mod discovery;
pub mod port_scan;
pub mod service_detect;
pub mod banner;
pub mod fingerprint;

pub use discovery::{HostDiscovery, DiscoveryMethod, DiscoveryResult};
pub use port_scan::{PortScanner, ScanType, PortResult, PortState};
pub use service_detect::{ServiceDetector, ServiceInfo};
pub use banner::{BannerGrabber, BannerResult, ProbeType};
pub use fingerprint::{Fingerprinter, OsFingerprint, OsFamily, HostFingerprint};
