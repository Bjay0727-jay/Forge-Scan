//! Scan target definitions

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A target to scan
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ScanTarget {
    /// Single IP address
    Ip(IpAddr),

    /// CIDR notation (e.g., "192.168.1.0/24")
    Cidr(String),

    /// Hostname (e.g., "server.example.com")
    Hostname(String),

    /// URL for web application scanning
    Url(String),

    /// IP range (e.g., 192.168.1.1 - 192.168.1.254)
    Range(IpRange),
}

impl ScanTarget {
    /// Create a target from an IP address
    pub fn ip(addr: IpAddr) -> Self {
        ScanTarget::Ip(addr)
    }

    /// Create a target from a CIDR string
    pub fn cidr(cidr: impl Into<String>) -> Self {
        ScanTarget::Cidr(cidr.into())
    }

    /// Create a target from a hostname
    pub fn hostname(name: impl Into<String>) -> Self {
        ScanTarget::Hostname(name.into())
    }

    /// Create a target from a URL
    pub fn url(url: impl Into<String>) -> Self {
        ScanTarget::Url(url.into())
    }

    /// Create a target from an IP range
    pub fn range(start: IpAddr, end: IpAddr) -> Self {
        ScanTarget::Range(IpRange { start, end })
    }

    /// Parse a target from a string, auto-detecting the type
    pub fn parse(s: &str) -> Result<Self, TargetParseError> {
        let s = s.trim();

        // Check for URL
        if s.starts_with("http://") || s.starts_with("https://") {
            return Ok(ScanTarget::Url(s.to_string()));
        }

        // Check for CIDR
        if s.contains('/') {
            return Ok(ScanTarget::Cidr(s.to_string()));
        }

        // Check for IP range
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 2 {
                let start: IpAddr = parts[0]
                    .trim()
                    .parse()
                    .map_err(|_| TargetParseError::InvalidIpRange)?;
                let end: IpAddr = parts[1]
                    .trim()
                    .parse()
                    .map_err(|_| TargetParseError::InvalidIpRange)?;
                return Ok(ScanTarget::Range(IpRange { start, end }));
            }
        }

        // Try to parse as IP address
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ScanTarget::Ip(ip));
        }

        // Assume hostname
        Ok(ScanTarget::Hostname(s.to_string()))
    }

    /// Get a display string for the target
    pub fn display(&self) -> String {
        match self {
            ScanTarget::Ip(ip) => ip.to_string(),
            ScanTarget::Cidr(cidr) => cidr.clone(),
            ScanTarget::Hostname(host) => host.clone(),
            ScanTarget::Url(url) => url.clone(),
            ScanTarget::Range(range) => format!("{}-{}", range.start, range.end),
        }
    }
}

impl std::fmt::Display for ScanTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// An IP address range
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

impl IpRange {
    /// Create a new IP range
    pub fn new(start: IpAddr, end: IpAddr) -> Self {
        Self { start, end }
    }

    /// Iterate over all IPs in the range (IPv4 only for now)
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> {
        let (start, end) = match (&self.start, &self.end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => (u32::from(*s), u32::from(*e)),
            _ => (0, 0), // IPv6 ranges not supported yet
        };

        (start..=end).map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n)))
    }
}

/// Error parsing a scan target
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetParseError {
    InvalidIpRange,
    InvalidCidr,
    InvalidUrl,
    Empty,
}

impl std::fmt::Display for TargetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetParseError::InvalidIpRange => write!(f, "Invalid IP range"),
            TargetParseError::InvalidCidr => write!(f, "Invalid CIDR notation"),
            TargetParseError::InvalidUrl => write!(f, "Invalid URL"),
            TargetParseError::Empty => write!(f, "Empty target"),
        }
    }
}

impl std::error::Error for TargetParseError {}

/// Scanning mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Network-based scanning from central scanner
    #[default]
    Agentless,
    /// Local scanning via deployed agent
    Agent,
    /// Both agentless and agent scanning
    Hybrid,
    /// Safe-scan: non-disruptive passive detection for life-critical devices
    #[serde(alias = "safe-scan")]
    SafeScan,
}

impl ScanMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanMode::Agentless => "agentless",
            ScanMode::Agent => "agent",
            ScanMode::Hybrid => "hybrid",
            ScanMode::SafeScan => "safe-scan",
        }
    }

    /// Whether this mode restricts scanning to passive-only techniques
    pub fn is_passive_only(&self) -> bool {
        matches!(self, ScanMode::SafeScan)
    }
}

/// Safe-scan profile controlling how aggressively to probe medical/IoT devices
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeScanProfile {
    /// Passive only: DNS queries, SNMP reads, passive traffic analysis
    #[default]
    PassiveOnly,
    /// Lightweight: TCP connect probes on known-safe ports, no payload injection
    Lightweight,
    /// Medical device: Optimized for healthcare equipment (passive + safe service ID)
    MedicalDevice,
    /// Industrial: For SCADA/ICS/BACnet/Modbus (minimal probing, no writes)
    Industrial,
}

impl SafeScanProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            SafeScanProfile::PassiveOnly => "passive_only",
            SafeScanProfile::Lightweight => "lightweight",
            SafeScanProfile::MedicalDevice => "medical_device",
            SafeScanProfile::Industrial => "industrial",
        }
    }

    /// Maximum number of concurrent connections allowed for this profile
    pub fn max_concurrent_connections(&self) -> u32 {
        match self {
            SafeScanProfile::PassiveOnly => 0,
            SafeScanProfile::Lightweight => 5,
            SafeScanProfile::MedicalDevice => 3,
            SafeScanProfile::Industrial => 2,
        }
    }

    /// Ports that are safe to probe under this profile
    pub fn safe_ports(&self) -> &[u16] {
        match self {
            SafeScanProfile::PassiveOnly => &[],
            SafeScanProfile::Lightweight => &[22, 80, 443, 161],
            SafeScanProfile::MedicalDevice => &[22, 80, 443, 161, 104, 2575, 8080, 8443],
            SafeScanProfile::Industrial => &[22, 80, 443, 161, 502, 47808, 1883, 8883],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip() {
        let target = ScanTarget::parse("192.168.1.1").unwrap();
        assert!(matches!(target, ScanTarget::Ip(_)));
    }

    #[test]
    fn test_parse_cidr() {
        let target = ScanTarget::parse("192.168.1.0/24").unwrap();
        assert!(matches!(target, ScanTarget::Cidr(_)));
    }

    #[test]
    fn test_parse_hostname() {
        let target = ScanTarget::parse("server.example.com").unwrap();
        assert!(matches!(target, ScanTarget::Hostname(_)));
    }

    #[test]
    fn test_parse_url() {
        let target = ScanTarget::parse("https://app.example.com").unwrap();
        assert!(matches!(target, ScanTarget::Url(_)));
    }

    #[test]
    fn test_parse_range() {
        let target = ScanTarget::parse("192.168.1.1-192.168.1.10").unwrap();
        assert!(matches!(target, ScanTarget::Range(_)));
    }

    #[test]
    fn test_parse_ipv6() {
        let target = ScanTarget::parse("::1").unwrap();
        assert!(matches!(target, ScanTarget::Ip(_)));
        if let ScanTarget::Ip(addr) = target {
            assert!(addr.is_loopback());
        }
    }

    #[test]
    fn test_parse_http_url() {
        let target = ScanTarget::parse("http://example.com").unwrap();
        assert!(matches!(target, ScanTarget::Url(_)));
        if let ScanTarget::Url(url) = target {
            assert_eq!(url, "http://example.com");
        }
    }

    #[test]
    fn test_scan_target_display() {
        assert_eq!(
            ScanTarget::parse("192.168.1.1").unwrap().display(),
            "192.168.1.1"
        );
        assert_eq!(
            ScanTarget::parse("10.0.0.0/8").unwrap().display(),
            "10.0.0.0/8"
        );
        assert_eq!(
            ScanTarget::parse("example.com").unwrap().display(),
            "example.com"
        );
        assert_eq!(
            ScanTarget::parse("https://example.com").unwrap().display(),
            "https://example.com"
        );
        assert_eq!(
            ScanTarget::parse("192.168.1.1-192.168.1.3")
                .unwrap()
                .display(),
            "192.168.1.1-192.168.1.3"
        );
    }

    #[test]
    fn test_scan_target_factory_methods() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t = ScanTarget::ip(ip);
        assert!(matches!(t, ScanTarget::Ip(_)));

        let t = ScanTarget::cidr("10.0.0.0/24");
        assert!(matches!(t, ScanTarget::Cidr(_)));

        let t = ScanTarget::hostname("server.local");
        assert!(matches!(t, ScanTarget::Hostname(_)));

        let t = ScanTarget::url("https://app.local");
        assert!(matches!(t, ScanTarget::Url(_)));

        let start: IpAddr = "10.0.0.1".parse().unwrap();
        let end: IpAddr = "10.0.0.5".parse().unwrap();
        let t = ScanTarget::range(start, end);
        assert!(matches!(t, ScanTarget::Range(_)));
    }

    #[test]
    fn test_ip_range_new() {
        let start: IpAddr = "192.168.1.1".parse().unwrap();
        let end: IpAddr = "192.168.1.10".parse().unwrap();
        let range = IpRange::new(start, end);
        assert_eq!(range.start, start);
        assert_eq!(range.end, end);
    }

    #[test]
    fn test_ip_range_iter() {
        let start: IpAddr = "192.168.1.1".parse().unwrap();
        let end: IpAddr = "192.168.1.3".parse().unwrap();
        let range = IpRange::new(start, end);
        let ips: Vec<IpAddr> = range.iter().collect();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "192.168.1.2".parse::<IpAddr>().unwrap());
        assert_eq!(ips[2], "192.168.1.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_scan_mode_as_str() {
        assert_eq!(ScanMode::Agentless.as_str(), "agentless");
        assert_eq!(ScanMode::Agent.as_str(), "agent");
        assert_eq!(ScanMode::Hybrid.as_str(), "hybrid");
        assert_eq!(ScanMode::SafeScan.as_str(), "safe-scan");
    }

    #[test]
    fn test_scan_mode_is_passive_only() {
        assert!(ScanMode::SafeScan.is_passive_only());
        assert!(!ScanMode::Agentless.is_passive_only());
        assert!(!ScanMode::Agent.is_passive_only());
        assert!(!ScanMode::Hybrid.is_passive_only());
    }

    #[test]
    fn test_safe_scan_profile_as_str() {
        assert_eq!(SafeScanProfile::PassiveOnly.as_str(), "passive_only");
        assert_eq!(SafeScanProfile::Lightweight.as_str(), "lightweight");
        assert_eq!(SafeScanProfile::MedicalDevice.as_str(), "medical_device");
        assert_eq!(SafeScanProfile::Industrial.as_str(), "industrial");
    }

    #[test]
    fn test_safe_scan_profile_max_concurrent() {
        assert_eq!(SafeScanProfile::PassiveOnly.max_concurrent_connections(), 0);
        assert_eq!(SafeScanProfile::Lightweight.max_concurrent_connections(), 5);
        assert_eq!(
            SafeScanProfile::MedicalDevice.max_concurrent_connections(),
            3
        );
        assert_eq!(SafeScanProfile::Industrial.max_concurrent_connections(), 2);
    }

    #[test]
    fn test_safe_scan_profile_safe_ports() {
        assert!(SafeScanProfile::PassiveOnly.safe_ports().is_empty());
        assert!(!SafeScanProfile::Lightweight.safe_ports().is_empty());
        assert!(!SafeScanProfile::MedicalDevice.safe_ports().is_empty());
        assert!(!SafeScanProfile::Industrial.safe_ports().is_empty());
    }

    #[test]
    fn test_target_parse_error_display() {
        assert_eq!(
            format!("{}", TargetParseError::InvalidIpRange),
            "Invalid IP range"
        );
        assert_eq!(
            format!("{}", TargetParseError::InvalidCidr),
            "Invalid CIDR notation"
        );
        assert_eq!(format!("{}", TargetParseError::InvalidUrl), "Invalid URL");
        assert_eq!(format!("{}", TargetParseError::Empty), "Empty target");
    }
}
