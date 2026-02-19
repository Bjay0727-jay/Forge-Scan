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
}

impl ScanMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanMode::Agentless => "agentless",
            ScanMode::Agent => "agent",
            ScanMode::Hybrid => "hybrid",
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
}
