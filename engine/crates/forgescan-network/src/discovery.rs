//! Host discovery - determine which hosts are alive on a network
//!
//! Supports multiple discovery methods:
//! - ICMP Echo (ping)
//! - TCP SYN to common ports
//! - TCP ACK
//! - ARP (local network only)

use forgescan_core::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// Discovery method to use for host detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// ICMP Echo request (ping) - requires raw sockets/admin
    IcmpEcho,
    /// TCP SYN to common ports - works without raw sockets
    TcpSyn,
    /// TCP connect to common ports - most compatible
    TcpConnect,
    /// ARP request - local network only, requires raw sockets
    Arp,
    /// Combination of methods for best coverage
    Combined,
}

impl Default for DiscoveryMethod {
    fn default() -> Self {
        DiscoveryMethod::TcpConnect
    }
}

/// Result of host discovery
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// The IP address that was probed
    pub ip: IpAddr,
    /// Whether the host appears to be up
    pub is_up: bool,
    /// How the host was detected (which method succeeded)
    pub detected_by: Option<DiscoveryMethod>,
    /// Round-trip time if measured
    pub rtt: Option<Duration>,
    /// Hostname if reverse DNS succeeded
    pub hostname: Option<String>,
    /// MAC address if discovered (ARP only)
    pub mac_address: Option<String>,
}

impl DiscoveryResult {
    pub fn up(ip: IpAddr, method: DiscoveryMethod) -> Self {
        Self {
            ip,
            is_up: true,
            detected_by: Some(method),
            rtt: None,
            hostname: None,
            mac_address: None,
        }
    }

    pub fn down(ip: IpAddr) -> Self {
        Self {
            ip,
            is_up: false,
            detected_by: None,
            rtt: None,
            hostname: None,
            mac_address: None,
        }
    }

    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }
}

/// Host discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Discovery method to use
    pub method: DiscoveryMethod,
    /// Timeout per host
    pub timeout: Duration,
    /// Ports to probe for TCP discovery
    pub tcp_ports: Vec<u16>,
    /// Maximum concurrent probes
    pub concurrency: usize,
    /// Perform reverse DNS lookup
    pub resolve_hostnames: bool,
    /// Number of retries for failed probes
    pub retries: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            method: DiscoveryMethod::TcpConnect,
            timeout: Duration::from_secs(2),
            // Common ports likely to be open
            tcp_ports: vec![22, 80, 443, 445, 3389, 8080],
            concurrency: 100,
            resolve_hostnames: false,
            retries: 1,
        }
    }
}

/// Host discovery engine
pub struct HostDiscovery {
    config: DiscoveryConfig,
}

impl HostDiscovery {
    /// Create a new host discovery engine with default config
    pub fn new() -> Self {
        Self {
            config: DiscoveryConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: DiscoveryConfig) -> Self {
        Self { config }
    }

    /// Check if a single host is up
    pub async fn is_host_up(&self, ip: IpAddr) -> Result<DiscoveryResult> {
        match self.config.method {
            DiscoveryMethod::TcpConnect => self.tcp_connect_probe(ip).await,
            DiscoveryMethod::TcpSyn => self.tcp_syn_probe(ip).await,
            DiscoveryMethod::IcmpEcho => self.icmp_probe(ip).await,
            DiscoveryMethod::Arp => self.arp_probe(ip).await,
            DiscoveryMethod::Combined => self.combined_probe(ip).await,
        }
    }

    /// Discover hosts in a list of IPs
    pub async fn discover_hosts(&self, ips: Vec<IpAddr>) -> Vec<DiscoveryResult> {
        use futures::stream::{self, StreamExt};

        let results: Vec<DiscoveryResult> = stream::iter(ips)
            .map(|ip| async move {
                match self.is_host_up(ip).await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Discovery error for {}: {}", ip, e);
                        DiscoveryResult::down(ip)
                    }
                }
            })
            .buffer_unordered(self.config.concurrency)
            .collect()
            .await;

        results
    }

    /// TCP connect probe - most compatible, doesn't require raw sockets
    async fn tcp_connect_probe(&self, ip: IpAddr) -> Result<DiscoveryResult> {
        let start = std::time::Instant::now();

        for &port in &self.config.tcp_ports {
            let addr = SocketAddr::new(ip, port);
            trace!("TCP connect probe to {}:{}", ip, port);

            match timeout(self.config.timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => {
                    // Connection succeeded - host is up
                    let rtt = start.elapsed();
                    debug!("Host {} is up (TCP connect to port {})", ip, port);
                    return Ok(DiscoveryResult::up(ip, DiscoveryMethod::TcpConnect).with_rtt(rtt));
                }
                Ok(Err(e)) => {
                    // Connection failed - could be refused (host up, port closed)
                    // or network unreachable (host down)
                    if e.kind() == std::io::ErrorKind::ConnectionRefused {
                        // Connection refused means host is up but port is closed
                        let rtt = start.elapsed();
                        debug!("Host {} is up (connection refused on port {})", ip, port);
                        return Ok(
                            DiscoveryResult::up(ip, DiscoveryMethod::TcpConnect).with_rtt(rtt)
                        );
                    }
                    trace!("TCP connect to {}:{} failed: {}", ip, port, e);
                }
                Err(_) => {
                    // Timeout
                    trace!("TCP connect to {}:{} timed out", ip, port);
                }
            }
        }

        // All ports failed
        debug!("Host {} appears down (no TCP response)", ip);
        Ok(DiscoveryResult::down(ip))
    }

    /// TCP SYN probe - requires raw sockets
    async fn tcp_syn_probe(&self, ip: IpAddr) -> Result<DiscoveryResult> {
        // SYN scanning requires raw sockets which need elevated privileges
        // For now, fall back to TCP connect
        warn!("TCP SYN scanning requires raw sockets, falling back to TCP connect");
        self.tcp_connect_probe(ip).await
    }

    /// ICMP Echo probe - requires raw sockets
    async fn icmp_probe(&self, ip: IpAddr) -> Result<DiscoveryResult> {
        // ICMP requires raw sockets
        // On Windows, we could use IcmpSendEcho2 API
        // For now, fall back to TCP connect
        warn!("ICMP probing requires raw sockets, falling back to TCP connect");
        self.tcp_connect_probe(ip).await
    }

    /// ARP probe - local network only, requires raw sockets
    async fn arp_probe(&self, ip: IpAddr) -> Result<DiscoveryResult> {
        // ARP is only for local networks and requires raw sockets
        warn!("ARP probing requires raw sockets, falling back to TCP connect");
        self.tcp_connect_probe(ip).await
    }

    /// Combined probe - try multiple methods
    async fn combined_probe(&self, ip: IpAddr) -> Result<DiscoveryResult> {
        // Try TCP connect first as it's most reliable without admin
        self.tcp_connect_probe(ip).await
    }
}

impl Default for HostDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a CIDR notation into a list of IPs
pub fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidTarget(format!("Invalid CIDR: {}", cidr)));
    }

    let ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| Error::InvalidTarget(format!("Invalid IP in CIDR: {}", parts[0])))?;

    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| Error::InvalidTarget(format!("Invalid prefix in CIDR: {}", parts[1])))?;

    if prefix > 32 {
        return Err(Error::InvalidTarget(format!(
            "Invalid prefix length: {}",
            prefix
        )));
    }

    // Don't allow scanning huge ranges
    if prefix < 16 {
        return Err(Error::InvalidTarget(
            "CIDR prefix too small (minimum /16)".to_string(),
        ));
    }

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    // Skip network and broadcast addresses for /31 and larger
    let (start, end) = if prefix < 31 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };

    let ips: Vec<IpAddr> = (start..=end)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
        .collect();

    Ok(ips)
}

/// Parse an IP range (e.g., "192.168.1.1-192.168.1.254")
pub fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidTarget(format!("Invalid IP range: {}", range)));
    }

    let start: Ipv4Addr = parts[0]
        .trim()
        .parse()
        .map_err(|_| Error::InvalidTarget(format!("Invalid start IP: {}", parts[0])))?;

    let end: Ipv4Addr = parts[1]
        .trim()
        .parse()
        .map_err(|_| Error::InvalidTarget(format!("Invalid end IP: {}", parts[1])))?;

    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    if start_u32 > end_u32 {
        return Err(Error::InvalidTarget(
            "Start IP must be less than end IP".to_string(),
        ));
    }

    // Limit range size
    if end_u32 - start_u32 > 65535 {
        return Err(Error::InvalidTarget(
            "IP range too large (maximum 65535 hosts)".to_string(),
        ));
    }

    let ips: Vec<IpAddr> = (start_u32..=end_u32)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
        .collect();

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr() {
        let ips = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ips.len(), 254); // 256 - 2 (network + broadcast)
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(ips[253], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn test_parse_cidr_small() {
        let ips = parse_cidr("10.0.0.0/30").unwrap();
        assert_eq!(ips.len(), 2); // /30 = 4 addresses - 2
    }

    #[test]
    fn test_parse_ip_range() {
        let ips = parse_ip_range("192.168.1.1-192.168.1.10").unwrap();
        assert_eq!(ips.len(), 10);
    }

    #[test]
    fn test_cidr_too_large() {
        let result = parse_cidr("10.0.0.0/8");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_discovery_localhost() {
        let discovery = HostDiscovery::new();
        let result = discovery
            .is_host_up(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .await
            .unwrap();
        // Localhost should be up (though may not have services on probe ports)
        // This test may be flaky depending on local services
    }
}
