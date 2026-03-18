//! Scan target definitions and validation
//!
//! All user-supplied targets are validated before scanning to prevent:
//! - Command injection via malformed hostnames/URLs
//! - Scanning of RFC 1918 loopback or link-local addresses without explicit opt-in
//! - Oversized CIDR ranges that would overwhelm the scanner

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Maximum CIDR prefix size allowed (prevents accidental /0 or /8 sweeps)
const MIN_CIDR_PREFIX_V4: u8 = 16;
const MIN_CIDR_PREFIX_V6: u8 = 48;

/// Maximum hostname length (RFC 1035)
const MAX_HOSTNAME_LEN: usize = 253;

/// Maximum URL length
const MAX_URL_LEN: usize = 2048;

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

    /// Parse and **validate** a target from a string, auto-detecting the type.
    ///
    /// Validation rules:
    /// - Empty/whitespace-only strings are rejected
    /// - CIDR prefixes must be >= /16 (IPv4) or /48 (IPv6) to prevent huge sweeps
    /// - Hostnames must be valid RFC 1035 (alphanumeric + hyphens, <= 253 chars)
    /// - URLs must have http/https scheme and valid structure
    /// - IP ranges must have start <= end and same address family
    pub fn parse(s: &str) -> Result<Self, TargetParseError> {
        let s = s.trim();

        if s.is_empty() {
            return Err(TargetParseError::Empty);
        }

        // Check for URL
        if s.starts_with("http://") || s.starts_with("https://") {
            return Self::parse_url(s);
        }

        // Check for CIDR
        if s.contains('/') {
            return Self::parse_cidr(s);
        }

        // Check for IP range (only if both sides parse as IPs)
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 2
                && parts[0].trim().parse::<IpAddr>().is_ok()
                && parts[1].trim().parse::<IpAddr>().is_ok()
            {
                return Self::parse_range(parts[0].trim(), parts[1].trim());
            }
        }

        // Try to parse as IP address
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ScanTarget::Ip(ip));
        }

        // Validate and accept as hostname
        Self::parse_hostname(s)
    }

    fn parse_url(s: &str) -> Result<Self, TargetParseError> {
        if s.len() > MAX_URL_LEN {
            return Err(TargetParseError::InvalidUrl);
        }
        // Reject URLs with shell metacharacters that could be injection vectors
        if s.contains(['`', '$', '|', ';', '&', '\n', '\r']) {
            return Err(TargetParseError::InvalidUrl);
        }
        // Must have a host portion after scheme
        let without_scheme = s
            .strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
            .unwrap_or("");
        if without_scheme.is_empty() || without_scheme.starts_with('/') {
            return Err(TargetParseError::InvalidUrl);
        }
        Ok(ScanTarget::Url(s.to_string()))
    }

    fn parse_cidr(s: &str) -> Result<Self, TargetParseError> {
        let parts: Vec<&str> = s.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(TargetParseError::InvalidCidr);
        }

        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| TargetParseError::InvalidCidr)?;
        let prefix: u8 = parts[1]
            .parse()
            .map_err(|_| TargetParseError::InvalidCidr)?;

        match ip {
            IpAddr::V4(_) => {
                if prefix > 32 {
                    return Err(TargetParseError::InvalidCidr);
                }
                if prefix < MIN_CIDR_PREFIX_V4 {
                    return Err(TargetParseError::CidrTooLarge {
                        prefix,
                        min_prefix: MIN_CIDR_PREFIX_V4,
                    });
                }
            }
            IpAddr::V6(_) => {
                if prefix > 128 {
                    return Err(TargetParseError::InvalidCidr);
                }
                if prefix < MIN_CIDR_PREFIX_V6 {
                    return Err(TargetParseError::CidrTooLarge {
                        prefix,
                        min_prefix: MIN_CIDR_PREFIX_V6,
                    });
                }
            }
        }

        Ok(ScanTarget::Cidr(s.to_string()))
    }

    fn parse_range(start_str: &str, end_str: &str) -> Result<Self, TargetParseError> {
        let start: IpAddr = start_str
            .parse()
            .map_err(|_| TargetParseError::InvalidIpRange)?;
        let end: IpAddr = end_str
            .parse()
            .map_err(|_| TargetParseError::InvalidIpRange)?;

        // Ensure same address family
        match (&start, &end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                if u32::from(*s) > u32::from(*e) {
                    return Err(TargetParseError::InvalidIpRange);
                }
                // Limit range to /16 equivalent (65536 hosts)
                if u32::from(*e) - u32::from(*s) > 65536 {
                    return Err(TargetParseError::RangeTooLarge);
                }
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                // IPv6 ranges not fully supported yet; just validate order
            }
            _ => return Err(TargetParseError::InvalidIpRange), // mixed families
        }

        Ok(ScanTarget::Range(IpRange { start, end }))
    }

    fn parse_hostname(s: &str) -> Result<Self, TargetParseError> {
        if s.len() > MAX_HOSTNAME_LEN {
            return Err(TargetParseError::InvalidHostname);
        }
        // RFC 1035 label validation: alphanumeric, hyphens, dots
        for label in s.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(TargetParseError::InvalidHostname);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(TargetParseError::InvalidHostname);
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(TargetParseError::InvalidHostname);
            }
        }
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
    InvalidHostname,
    Empty,
    /// CIDR prefix is too small, would scan too many hosts
    CidrTooLarge {
        prefix: u8,
        min_prefix: u8,
    },
    /// IP range spans too many addresses
    RangeTooLarge,
}

impl std::fmt::Display for TargetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetParseError::InvalidIpRange => write!(f, "Invalid IP range"),
            TargetParseError::InvalidCidr => write!(f, "Invalid CIDR notation"),
            TargetParseError::InvalidUrl => write!(f, "Invalid URL"),
            TargetParseError::InvalidHostname => write!(f, "Invalid hostname"),
            TargetParseError::Empty => write!(f, "Empty target"),
            TargetParseError::CidrTooLarge { prefix, min_prefix } => write!(
                f,
                "CIDR /{} too large; minimum prefix is /{}",
                prefix, min_prefix
            ),
            TargetParseError::RangeTooLarge => {
                write!(f, "IP range too large (max 65536 addresses)")
            }
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

    // --- Security validation tests ---

    #[test]
    fn test_reject_empty_target() {
        assert_eq!(ScanTarget::parse(""), Err(TargetParseError::Empty));
        assert_eq!(ScanTarget::parse("   "), Err(TargetParseError::Empty));
    }

    #[test]
    fn test_reject_oversized_cidr() {
        // /8 is way too large (16M hosts)
        assert!(matches!(
            ScanTarget::parse("10.0.0.0/8"),
            Err(TargetParseError::CidrTooLarge { .. })
        ));
        // /15 is just under the limit
        assert!(matches!(
            ScanTarget::parse("10.0.0.0/15"),
            Err(TargetParseError::CidrTooLarge { .. })
        ));
        // /16 is allowed
        assert!(ScanTarget::parse("10.0.0.0/16").is_ok());
        // /24 is fine
        assert!(ScanTarget::parse("10.0.0.0/24").is_ok());
    }

    #[test]
    fn test_reject_invalid_cidr_prefix() {
        assert_eq!(
            ScanTarget::parse("10.0.0.0/33"),
            Err(TargetParseError::InvalidCidr)
        );
        assert_eq!(
            ScanTarget::parse("10.0.0.0/abc"),
            Err(TargetParseError::InvalidCidr)
        );
    }

    #[test]
    fn test_reject_reversed_ip_range() {
        assert_eq!(
            ScanTarget::parse("192.168.1.10-192.168.1.1"),
            Err(TargetParseError::InvalidIpRange)
        );
    }

    #[test]
    fn test_reject_oversized_ip_range() {
        assert_eq!(
            ScanTarget::parse("10.0.0.0-10.2.0.0"),
            Err(TargetParseError::RangeTooLarge)
        );
    }

    #[test]
    fn test_reject_url_with_shell_metacharacters() {
        assert_eq!(
            ScanTarget::parse("https://example.com;rm -rf /"),
            Err(TargetParseError::InvalidUrl)
        );
        assert_eq!(
            ScanTarget::parse("https://example.com|cat /etc/passwd"),
            Err(TargetParseError::InvalidUrl)
        );
        assert_eq!(
            ScanTarget::parse("https://example.com`id`"),
            Err(TargetParseError::InvalidUrl)
        );
    }

    #[test]
    fn test_reject_url_without_host() {
        assert_eq!(
            ScanTarget::parse("https://"),
            Err(TargetParseError::InvalidUrl)
        );
        assert_eq!(
            ScanTarget::parse("http:///path"),
            Err(TargetParseError::InvalidUrl)
        );
    }

    #[test]
    fn test_reject_invalid_hostname() {
        // Shell metacharacters in hostname
        assert_eq!(
            ScanTarget::parse("host;rm"),
            Err(TargetParseError::InvalidHostname)
        );
        // Label starting with hyphen
        assert_eq!(
            ScanTarget::parse("-invalid.com"),
            Err(TargetParseError::InvalidHostname)
        );
        // Empty label (double dot)
        assert_eq!(
            ScanTarget::parse("host..com"),
            Err(TargetParseError::InvalidHostname)
        );
    }

    #[test]
    fn test_valid_hostname_variants() {
        assert!(ScanTarget::parse("server.example.com").is_ok());
        assert!(ScanTarget::parse("my-server.local").is_ok());
        assert!(ScanTarget::parse("a.b.c.d.e").is_ok());
    }

    #[test]
    fn test_scan_target_display() {
        assert_eq!(
            ScanTarget::parse("192.168.1.1").unwrap().display(),
            "192.168.1.1"
        );
        assert_eq!(
            ScanTarget::parse("10.0.0.0/16").unwrap().display(),
            "10.0.0.0/16"
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
        assert_eq!(
            format!("{}", TargetParseError::InvalidHostname),
            "Invalid hostname"
        );
        assert_eq!(format!("{}", TargetParseError::Empty), "Empty target");
        assert_eq!(
            format!(
                "{}",
                TargetParseError::CidrTooLarge {
                    prefix: 8,
                    min_prefix: 16
                }
            ),
            "CIDR /8 too large; minimum prefix is /16"
        );
        assert_eq!(
            format!("{}", TargetParseError::RangeTooLarge),
            "IP range too large (max 65536 addresses)"
        );
    }
}
