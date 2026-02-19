//! Banner grabbing - protocol-specific probes to elicit service banners
//!
//! This module provides various probe methods for different protocols
//! to grab banners and identify services running on open ports.

use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

/// Banner grabber with protocol-specific probes
pub struct BannerGrabber {
    /// Timeout for each connection attempt
    connect_timeout: Duration,
    /// Timeout for reading data
    read_timeout: Duration,
    /// Maximum banner size to read
    max_banner_size: usize,
}

impl Default for BannerGrabber {
    fn default() -> Self {
        Self::new()
    }
}

impl BannerGrabber {
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(3),
            max_banner_size: 4096,
        }
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Grab banner from a specific port using appropriate probe
    pub async fn grab(&self, target: IpAddr, port: u16) -> Option<BannerResult> {
        let probe = self.get_probe_for_port(port);
        self.grab_with_probe(target, port, probe).await
    }

    /// Grab banner using a specific probe type
    pub async fn grab_with_probe(
        &self,
        target: IpAddr,
        port: u16,
        probe: ProbeType,
    ) -> Option<BannerResult> {
        let addr = format!("{}:{}", target, port);

        let stream = match timeout(self.connect_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                trace!("Failed to connect to {}: {}", addr, e);
                return None;
            }
            Err(_) => {
                trace!("Connection timeout to {}", addr);
                return None;
            }
        };

        match probe {
            ProbeType::Null => self.null_probe(stream).await,
            ProbeType::Http => self.http_probe(stream).await,
            ProbeType::Https => None, // TLS requires special handling
            ProbeType::Smtp => self.smtp_probe(stream).await,
            ProbeType::Ftp => self.null_probe(stream).await, // FTP sends banner on connect
            ProbeType::Ssh => self.null_probe(stream).await, // SSH sends banner on connect
            ProbeType::Pop3 => self.null_probe(stream).await,
            ProbeType::Imap => self.null_probe(stream).await,
            ProbeType::Mysql => self.null_probe(stream).await,
            ProbeType::Redis => self.redis_probe(stream).await,
            ProbeType::Mongodb => self.mongodb_probe(stream).await,
            ProbeType::Rtsp => self.rtsp_probe(stream).await,
            ProbeType::Sip => self.sip_probe(stream).await,
            ProbeType::Dns => None, // UDP protocol
            ProbeType::Generic => self.generic_probe(stream).await,
        }
    }

    /// Determine the best probe for a given port
    fn get_probe_for_port(&self, port: u16) -> ProbeType {
        match port {
            21 => ProbeType::Ftp,
            22 => ProbeType::Ssh,
            23 => ProbeType::Null, // Telnet
            25 | 465 | 587 => ProbeType::Smtp,
            53 => ProbeType::Dns,
            80 | 8000 | 8080 | 8888 => ProbeType::Http,
            110 => ProbeType::Pop3,
            143 => ProbeType::Imap,
            443 | 8443 => ProbeType::Https,
            554 => ProbeType::Rtsp,
            3306 => ProbeType::Mysql,
            5060 | 5061 => ProbeType::Sip,
            6379 => ProbeType::Redis,
            27017 => ProbeType::Mongodb,
            _ => ProbeType::Generic,
        }
    }

    /// Null probe - just wait for banner without sending anything
    async fn null_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let mut buffer = vec![0u8; self.max_banner_size];

        match timeout(self.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Null,
                })
            }
            _ => None,
        }
    }

    /// HTTP probe - send GET request
    async fn http_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let request = "GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: ForgeScan/1.0\r\n\r\n";

        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }

        let mut buffer = vec![0u8; self.max_banner_size];
        match timeout(self.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Http,
                })
            }
            _ => None,
        }
    }

    /// SMTP probe - wait for greeting, send EHLO
    async fn smtp_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let mut buffer = vec![0u8; self.max_banner_size];
        let mut full_response = Vec::new();

        // Read initial greeting
        if let Ok(Ok(n)) = timeout(self.read_timeout, stream.read(&mut buffer)).await {
            full_response.extend_from_slice(&buffer[..n]);
        }

        // Send EHLO
        let ehlo = "EHLO forgescan.local\r\n";
        if stream.write_all(ehlo.as_bytes()).await.is_ok() {
            if let Ok(Ok(n)) = timeout(self.read_timeout, stream.read(&mut buffer)).await {
                full_response.extend_from_slice(&buffer[..n]);
            }
        }

        // Send QUIT
        let _ = stream.write_all(b"QUIT\r\n").await;

        if !full_response.is_empty() {
            Some(BannerResult {
                raw: full_response.clone(),
                text: String::from_utf8_lossy(&full_response).to_string(),
                probe_used: ProbeType::Smtp,
            })
        } else {
            None
        }
    }

    /// Redis probe - send PING command
    async fn redis_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let ping = "*1\r\n$4\r\nPING\r\n";

        if stream.write_all(ping.as_bytes()).await.is_err() {
            return None;
        }

        let mut buffer = vec![0u8; self.max_banner_size];
        match timeout(self.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);

                // Also try INFO command for version
                let info = "*1\r\n$4\r\nINFO\r\n";
                if stream.write_all(info.as_bytes()).await.is_ok() {
                    let mut info_buffer = vec![0u8; self.max_banner_size];
                    if let Ok(Ok(n2)) =
                        timeout(self.read_timeout, stream.read(&mut info_buffer)).await
                    {
                        buffer.extend_from_slice(&info_buffer[..n2]);
                    }
                }

                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Redis,
                })
            }
            _ => None,
        }
    }

    /// MongoDB probe - send isMaster command
    async fn mongodb_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        // MongoDB wire protocol: OP_MSG with isMaster command
        // This is a simplified probe that just checks if port responds
        let mut buffer = vec![0u8; self.max_banner_size];

        // MongoDB servers typically don't send banner on connect
        // We need to send a proper MongoDB message
        // For now, just check if connection is accepted
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Mongodb,
                })
            }
            _ => {
                // Connection succeeded but no data - still indicates MongoDB
                Some(BannerResult {
                    raw: vec![],
                    text: String::new(),
                    probe_used: ProbeType::Mongodb,
                })
            }
        }
    }

    /// RTSP probe - send OPTIONS request
    async fn rtsp_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let request = "OPTIONS rtsp://target/ RTSP/1.0\r\nCSeq: 1\r\n\r\n";

        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }

        let mut buffer = vec![0u8; self.max_banner_size];
        match timeout(self.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Rtsp,
                })
            }
            _ => None,
        }
    }

    /// SIP probe - send OPTIONS request
    async fn sip_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let request = concat!(
            "OPTIONS sip:nm SIP/2.0\r\n",
            "Via: SIP/2.0/TCP nm;branch=z9hG4bK\r\n",
            "From: <sip:nm@nm>;tag=root\r\n",
            "To: <sip:nm@nm>\r\n",
            "Call-ID: 1234@nm\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        if stream.write_all(request.as_bytes()).await.is_err() {
            return None;
        }

        let mut buffer = vec![0u8; self.max_banner_size];
        match timeout(self.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Sip,
                })
            }
            _ => None,
        }
    }

    /// Generic probe - try null first, then HTTP-like
    async fn generic_probe(&self, mut stream: TcpStream) -> Option<BannerResult> {
        let mut buffer = vec![0u8; self.max_banner_size];

        // First, try reading without sending anything (many services send banners)
        match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                return Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Generic,
                });
            }
            _ => {}
        }

        // If no banner, send a generic probe
        let probe = "\r\n\r\n";
        if stream.write_all(probe.as_bytes()).await.is_err() {
            return None;
        }

        match timeout(self.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(BannerResult {
                    raw: buffer.clone(),
                    text: String::from_utf8_lossy(&buffer).to_string(),
                    probe_used: ProbeType::Generic,
                })
            }
            _ => None,
        }
    }
}

/// Types of probes available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeType {
    /// No probe - just wait for banner
    Null,
    /// HTTP GET request
    Http,
    /// HTTPS (TLS wrapped HTTP)
    Https,
    /// SMTP EHLO
    Smtp,
    /// FTP (wait for banner)
    Ftp,
    /// SSH (wait for banner)
    Ssh,
    /// POP3 (wait for banner)
    Pop3,
    /// IMAP (wait for banner)
    Imap,
    /// MySQL (wait for handshake)
    Mysql,
    /// Redis PING/INFO
    Redis,
    /// MongoDB isMaster
    Mongodb,
    /// RTSP OPTIONS
    Rtsp,
    /// SIP OPTIONS
    Sip,
    /// DNS query (UDP)
    Dns,
    /// Generic fallback probe
    Generic,
}

/// Result of a banner grab attempt
#[derive(Debug, Clone)]
pub struct BannerResult {
    /// Raw bytes received
    pub raw: Vec<u8>,
    /// Decoded text (lossy UTF-8)
    pub text: String,
    /// Which probe was used
    pub probe_used: ProbeType,
}

impl BannerResult {
    /// Check if banner contains a specific string (case-insensitive)
    pub fn contains(&self, needle: &str) -> bool {
        self.text.to_lowercase().contains(&needle.to_lowercase())
    }

    /// Extract first line of banner
    pub fn first_line(&self) -> &str {
        self.text.lines().next().unwrap_or("")
    }

    /// Check if banner looks like HTTP response
    pub fn is_http(&self) -> bool {
        self.text.starts_with("HTTP/") || self.contains("<!DOCTYPE") || self.contains("<html")
    }

    /// Check if banner looks like SSH
    pub fn is_ssh(&self) -> bool {
        self.text.starts_with("SSH-")
    }

    /// Check if banner looks like FTP
    pub fn is_ftp(&self) -> bool {
        self.text.starts_with("220") && (self.contains("FTP") || self.contains("ftp"))
    }

    /// Check if banner looks like SMTP
    pub fn is_smtp(&self) -> bool {
        self.text.starts_with("220") && (self.contains("SMTP") || self.contains("ESMTP"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_selection() {
        let grabber = BannerGrabber::new();

        assert_eq!(grabber.get_probe_for_port(22), ProbeType::Ssh);
        assert_eq!(grabber.get_probe_for_port(80), ProbeType::Http);
        assert_eq!(grabber.get_probe_for_port(443), ProbeType::Https);
        assert_eq!(grabber.get_probe_for_port(25), ProbeType::Smtp);
        assert_eq!(grabber.get_probe_for_port(3306), ProbeType::Mysql);
        assert_eq!(grabber.get_probe_for_port(6379), ProbeType::Redis);
        assert_eq!(grabber.get_probe_for_port(12345), ProbeType::Generic);
    }

    #[test]
    fn test_banner_detection() {
        let ssh_banner = BannerResult {
            raw: b"SSH-2.0-OpenSSH_8.9".to_vec(),
            text: "SSH-2.0-OpenSSH_8.9".to_string(),
            probe_used: ProbeType::Null,
        };
        assert!(ssh_banner.is_ssh());
        assert!(!ssh_banner.is_http());

        let http_banner = BannerResult {
            raw: b"HTTP/1.1 200 OK".to_vec(),
            text: "HTTP/1.1 200 OK".to_string(),
            probe_used: ProbeType::Http,
        };
        assert!(http_banner.is_http());
        assert!(!http_banner.is_ssh());
    }
}
