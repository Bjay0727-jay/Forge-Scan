//! Port scanning - SYN scan, connect scan, UDP scan
//!
//! This module provides high-performance port scanning with multiple scan types.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// Type of port scan to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanType {
    /// TCP connect scan - most compatible, completes full TCP handshake
    #[default]
    TcpConnect,
    /// TCP SYN scan - stealthier, requires raw sockets
    TcpSyn,
    /// UDP scan - for UDP services, slower due to ICMP rate limiting
    Udp,
}

/// State of a scanned port
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port is open and accepting connections
    Open,
    /// Port is closed (RST received)
    Closed,
    /// Port is filtered (no response, possibly firewalled)
    Filtered,
    /// Port state is ambiguous (open or filtered)
    OpenFiltered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
        }
    }
}

/// Result of scanning a single port
#[derive(Debug, Clone)]
pub struct PortResult {
    /// Port number
    pub port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Port state
    pub state: PortState,
    /// Round-trip time
    pub rtt: Option<Duration>,
    /// Service banner if retrieved
    pub banner: Option<String>,
    /// Detected service name
    pub service: Option<String>,
    /// Detected service version
    pub version: Option<String>,
}

impl PortResult {
    pub fn open(port: u16, protocol: &str) -> Self {
        Self {
            port,
            protocol: protocol.to_string(),
            state: PortState::Open,
            rtt: None,
            banner: None,
            service: None,
            version: None,
        }
    }

    pub fn closed(port: u16, protocol: &str) -> Self {
        Self {
            port,
            protocol: protocol.to_string(),
            state: PortState::Closed,
            rtt: None,
            banner: None,
            service: None,
            version: None,
        }
    }

    pub fn filtered(port: u16, protocol: &str) -> Self {
        Self {
            port,
            protocol: protocol.to_string(),
            state: PortState::Filtered,
            rtt: None,
            banner: None,
            service: None,
            version: None,
        }
    }

    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner);
        self
    }

    pub fn with_service(mut self, service: String, version: Option<String>) -> Self {
        self.service = Some(service);
        self.version = version;
        self
    }
}

/// Port scanner configuration
#[derive(Debug, Clone)]
pub struct PortScanConfig {
    /// Scan type
    pub scan_type: ScanType,
    /// Timeout per port
    pub timeout: Duration,
    /// Maximum concurrent port scans per host
    pub concurrency: usize,
    /// Grab banners from open ports
    pub grab_banners: bool,
    /// Banner grab timeout
    pub banner_timeout: Duration,
    /// Retries for filtered ports
    pub retries: u32,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            scan_type: ScanType::TcpConnect,
            timeout: Duration::from_millis(1500),
            concurrency: 100,
            grab_banners: true,
            banner_timeout: Duration::from_secs(3),
            retries: 0,
        }
    }
}

/// Common port lists
pub mod ports {
    /// Top 100 most common TCP ports
    pub const TOP_100: &[u16] = &[
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
        143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
        631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
        1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008,
        8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
    ];

    /// Top 20 most common TCP ports
    pub const TOP_20: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5900, 8080,
    ];

    /// Well-known ports (0-1023)
    pub fn well_known() -> Vec<u16> {
        (1..=1023).collect()
    }

    /// All ports (1-65535)
    pub fn all() -> Vec<u16> {
        (1..=65535).collect()
    }

    /// Parse a port specification string
    /// Supports: "80", "80,443", "1-1024", "80,443,8000-9000"
    pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
        let mut ports = Vec::new();

        for part in spec.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() != 2 {
                    return Err(format!("Invalid port range: {}", part));
                }
                let start: u16 = range[0]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid port: {}", range[0]))?;
                let end: u16 = range[1]
                    .trim()
                    .parse()
                    .map_err(|_| format!("Invalid port: {}", range[1]))?;
                if start > end {
                    return Err(format!("Invalid range: {} > {}", start, end));
                }
                ports.extend(start..=end);
            } else {
                let port: u16 = part
                    .parse()
                    .map_err(|_| format!("Invalid port: {}", part))?;
                ports.push(port);
            }
        }

        // Remove duplicates and sort
        ports.sort_unstable();
        ports.dedup();

        Ok(ports)
    }
}

/// Port scanner engine
pub struct PortScanner {
    config: PortScanConfig,
}

impl PortScanner {
    /// Create a new port scanner with default configuration
    pub fn new() -> Self {
        Self {
            config: PortScanConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: PortScanConfig) -> Self {
        Self { config }
    }

    /// Scan a single port on a target
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> PortResult {
        match self.config.scan_type {
            ScanType::TcpConnect => self.tcp_connect_scan(target, port).await,
            ScanType::TcpSyn => self.tcp_syn_scan(target, port).await,
            ScanType::Udp => self.udp_scan(target, port).await,
        }
    }

    /// Scan multiple ports on a target
    pub async fn scan_ports(&self, target: IpAddr, ports: &[u16]) -> Vec<PortResult> {
        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut handles = Vec::with_capacity(ports.len());

        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                let scanner = PortScanner::with_config(config);
                let result = scanner.scan_port(target, port).await;
                drop(permit);
                result
            });

            handles.push(handle);
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }

        // Sort by port number
        results.sort_by_key(|r| r.port);
        results
    }

    /// Scan ports and return only open ports
    pub async fn scan_ports_open_only(&self, target: IpAddr, ports: &[u16]) -> Vec<PortResult> {
        self.scan_ports(target, ports)
            .await
            .into_iter()
            .filter(|r| r.state == PortState::Open)
            .collect()
    }

    /// TCP connect scan - completes full handshake
    async fn tcp_connect_scan(&self, target: IpAddr, port: u16) -> PortResult {
        let addr = SocketAddr::new(target, port);
        let start = std::time::Instant::now();

        trace!("TCP connect scan {}:{}", target, port);

        match timeout(self.config.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let rtt = start.elapsed();
                debug!("Port {}:{} is open", target, port);

                let mut result = PortResult::open(port, "tcp").with_rtt(rtt);

                // Optionally grab banner
                if self.config.grab_banners {
                    if let Some(banner) = self.grab_banner_from_stream(stream, port).await {
                        result = result.with_banner(banner);
                    }
                }

                result
            }
            Ok(Err(e)) => {
                let rtt = start.elapsed();
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    trace!("Port {}:{} is closed (RST)", target, port);
                    PortResult::closed(port, "tcp").with_rtt(rtt)
                } else {
                    trace!("Port {}:{} error: {}", target, port, e);
                    PortResult::filtered(port, "tcp")
                }
            }
            Err(_) => {
                trace!("Port {}:{} timeout (filtered)", target, port);
                PortResult::filtered(port, "tcp")
            }
        }
    }

    /// TCP SYN scan - half-open scan, requires raw sockets
    async fn tcp_syn_scan(&self, target: IpAddr, port: u16) -> PortResult {
        // SYN scanning requires raw sockets and elevated privileges
        // Fall back to connect scan for now
        warn!("SYN scan requires raw sockets, using connect scan");
        self.tcp_connect_scan(target, port).await
    }

    /// UDP scan
    async fn udp_scan(&self, target: IpAddr, port: u16) -> PortResult {
        use tokio::net::UdpSocket;

        let local_addr: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = match UdpSocket::bind(local_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to bind UDP socket: {}", e);
                return PortResult::filtered(port, "udp");
            }
        };

        let target_addr = SocketAddr::new(target, port);

        // Send empty UDP packet (some services won't respond to this)
        let _ = socket.send_to(&[], target_addr).await;

        // Try to receive a response
        let mut buf = [0u8; 1024];
        match timeout(self.config.timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                // Got a response - port is open
                let banner = if len > 0 {
                    Some(String::from_utf8_lossy(&buf[..len]).to_string())
                } else {
                    None
                };
                let mut result = PortResult::open(port, "udp");
                if let Some(b) = banner {
                    result = result.with_banner(b);
                }
                result
            }
            Ok(Err(_)) | Err(_) => {
                // No response - could be open or filtered
                PortResult {
                    port,
                    protocol: "udp".to_string(),
                    state: PortState::OpenFiltered,
                    rtt: None,
                    banner: None,
                    service: None,
                    version: None,
                }
            }
        }
    }

    /// Grab banner from an open TCP connection
    async fn grab_banner_from_stream(&self, mut stream: TcpStream, port: u16) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Some services send banner immediately, others need a probe
        let probe = get_probe_for_port(port);

        if let Some(probe_data) = probe {
            let _ = stream.write_all(probe_data).await;
        }

        let mut buf = vec![0u8; 4096];
        match timeout(self.config.banner_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                // Clean up banner - remove null bytes and trim
                let banner = String::from_utf8_lossy(&buf[..n])
                    .replace('\0', "")
                    .trim()
                    .to_string();

                if !banner.is_empty() {
                    Some(banner)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl Default for PortScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Get probe data to send for banner grabbing on specific ports
fn get_probe_for_port(port: u16) -> Option<&'static [u8]> {
    match port {
        // HTTP
        80 | 8080 | 8000 | 8008 | 8443 | 443 => Some(b"GET / HTTP/1.0\r\n\r\n"),
        // FTP
        21 => None, // FTP sends banner automatically
        // SSH
        22 => None, // SSH sends banner automatically
        // SMTP
        25 | 465 | 587 => None, // SMTP sends banner automatically
        // POP3
        110 | 995 => None, // POP3 sends banner automatically
        // IMAP
        143 | 993 => None, // IMAP sends banner automatically
        // MySQL
        3306 => None, // MySQL sends greeting automatically
        // PostgreSQL
        5432 => None, // We'd need proper protocol handshake
        // Redis
        6379 => Some(b"PING\r\n"),
        // Memcached
        11211 => Some(b"version\r\n"),
        // MongoDB
        27017 => None, // Binary protocol
        // Default - send newline to prompt response
        _ => Some(b"\r\n"),
    }
}

/// Scan result summary for multiple hosts
#[derive(Debug, Default)]
pub struct ScanSummary {
    /// Total hosts scanned
    pub hosts_scanned: usize,
    /// Hosts that are up
    pub hosts_up: usize,
    /// Total ports scanned
    pub ports_scanned: usize,
    /// Open ports found
    pub open_ports: usize,
    /// Closed ports found
    pub closed_ports: usize,
    /// Filtered ports found
    pub filtered_ports: usize,
    /// Per-host results
    pub host_results: HashMap<IpAddr, Vec<PortResult>>,
}

impl ScanSummary {
    pub fn add_host_results(&mut self, host: IpAddr, results: Vec<PortResult>) {
        self.hosts_scanned += 1;
        self.ports_scanned += results.len();

        let has_open = results.iter().any(|r| r.state == PortState::Open);
        if has_open {
            self.hosts_up += 1;
        }

        for result in &results {
            match result.state {
                PortState::Open => self.open_ports += 1,
                PortState::Closed => self.closed_ports += 1,
                PortState::Filtered | PortState::OpenFiltered => self.filtered_ports += 1,
            }
        }

        self.host_results.insert(host, results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_spec_single() {
        let ports = ports::parse_port_spec("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_port_spec_list() {
        let ports = ports::parse_port_spec("80,443,8080").unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_port_spec_range() {
        let ports = ports::parse_port_spec("1-5").unwrap();
        assert_eq!(ports, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_port_spec_mixed() {
        let ports = ports::parse_port_spec("22,80,443,8000-8002").unwrap();
        assert_eq!(ports, vec![22, 80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn test_parse_port_spec_dedup() {
        let ports = ports::parse_port_spec("80,80,443").unwrap();
        assert_eq!(ports, vec![80, 443]);
    }

    #[tokio::test]
    async fn test_scan_localhost() {
        let scanner = PortScanner::new();
        // This test depends on local services
        let result = scanner
            .scan_port(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 12345)
            .await;
        // Port 12345 is unlikely to be open
        assert!(result.state == PortState::Closed || result.state == PortState::Filtered);
    }
}
