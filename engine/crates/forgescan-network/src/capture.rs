//! Packet capture module for ForgeScan
//!
//! Provides three capture modes:
//! - **Scan-correlated capture**: Captures packets during an active scan to provide
//!   packet-level evidence for findings (e.g., SYN-ACK proving a port is open).
//! - **Targeted capture**: On-demand capture for a specific host, port, protocol,
//!   or BPF filter expression, triggered as a `"capture"` task type.
//! - **Passive monitoring** (future): Continuous background capture with real-time
//!   analysis for anomaly detection.
//!
//! # Architecture
//!
//! Capture runs within the `forgescan-scanner` binary, which already has `NET_RAW`
//! and `NET_ADMIN` capabilities. Raw packets are captured via `pnet::datalink`,
//! parsed into summaries, and optionally written to local PCAP files. Summaries
//! and statistics flow through the existing task results JSON pipeline, while
//! raw PCAPs are stored locally with optional upload to R2.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use pnet::datalink::{self, Channel::Ethernet, Config as PnetConfig, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Error Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Failed to open capture channel: {0}")]
    ChannelOpen(String),

    #[error("Invalid BPF filter: {0}")]
    InvalidFilter(String),

    #[error("Capture I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Capture exceeded size limit ({max_bytes} bytes)")]
    SizeLimitExceeded { max_bytes: u64 },

    #[error("Capture timed out after {seconds}s")]
    TimedOut { seconds: u64 },

    #[error("Capture cancelled")]
    Cancelled,
}

pub type CaptureResult<T> = std::result::Result<T, CaptureError>;

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for a single capture session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Network interface name (e.g., "eth0"). If None, auto-detect.
    pub interface: Option<String>,

    /// BPF filter expression (e.g., "host 192.168.1.1 and tcp").
    pub filter: Option<String>,

    /// Maximum number of packets to capture (0 = unlimited).
    #[serde(default)]
    pub max_packets: u64,

    /// Maximum bytes to capture (0 = unlimited, default 50MB).
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,

    /// Capture duration limit in seconds.
    #[serde(default = "default_duration_secs")]
    pub duration_secs: u64,

    /// Directory to write PCAP files to.
    #[serde(default = "default_capture_dir")]
    pub capture_dir: String,

    /// Enable promiscuous mode on the interface.
    #[serde(default)]
    pub promiscuous: bool,

    /// Maximum payload bytes to include in packet summaries.
    #[serde(default = "default_payload_preview_len")]
    pub payload_preview_len: usize,
}

fn default_max_bytes() -> u64 {
    50 * 1024 * 1024 // 50 MB
}

fn default_duration_secs() -> u64 {
    300 // 5 minutes
}

fn default_capture_dir() -> String {
    String::from("/var/lib/forgescan/captures")
}

fn default_payload_preview_len() -> usize {
    64
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            filter: None,
            max_packets: 0,
            max_bytes: default_max_bytes(),
            duration_secs: default_duration_secs(),
            capture_dir: default_capture_dir(),
            promiscuous: false,
            payload_preview_len: default_payload_preview_len(),
        }
    }
}

// ── Capture Statistics ───────────────────────────────────────────────────────

/// Aggregate statistics from a completed capture session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStats {
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub packets_dropped: u64,
    pub protocol_breakdown: HashMap<String, u64>,
    pub top_talkers: Vec<(String, u64)>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub pcap_path: Option<String>,
    pub capture_duration_ms: u64,
}

// ── Packet Summary ───────────────────────────────────────────────────────────

/// A parsed summary of a single captured packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: usize,
    pub timestamp: DateTime<Utc>,
    pub tcp_flags: Option<String>,
    pub payload_preview: Vec<u8>,
}

// ── Software BPF Filter ──────────────────────────────────────────────────────

/// A simple software-level packet filter.
/// Validates and applies filter expressions against parsed packets.
/// Supports: "host <ip>", "port <n>", "tcp", "udp", and combinations with "and"/"or".
#[derive(Debug, Clone)]
pub struct SoftwareFilter {
    rules: Vec<FilterRule>,
}

#[derive(Debug, Clone)]
enum FilterRule {
    Host(IpAddr),
    Port(u16),
    Tcp,
    Udp,
    And(Box<FilterRule>, Box<FilterRule>),
    Or(Box<FilterRule>, Box<FilterRule>),
    Any,
}

impl SoftwareFilter {
    /// Parse a BPF-like filter expression.
    pub fn parse(expr: &str) -> CaptureResult<Self> {
        let expr = expr.trim();
        if expr.is_empty() {
            return Ok(Self {
                rules: vec![FilterRule::Any],
            });
        }

        // Split on " or " first (lower precedence)
        if let Some(idx) = expr.find(" or ") {
            let left = Self::parse_single(&expr[..idx])?;
            let right = Self::parse_single(&expr[idx + 4..])?;
            return Ok(Self {
                rules: vec![FilterRule::Or(Box::new(left), Box::new(right))],
            });
        }

        // Split on " and " (higher precedence)
        if let Some(idx) = expr.find(" and ") {
            let left = Self::parse_single(&expr[..idx])?;
            let right = Self::parse_single(&expr[idx + 5..])?;
            return Ok(Self {
                rules: vec![FilterRule::And(Box::new(left), Box::new(right))],
            });
        }

        let rule = Self::parse_single(expr)?;
        Ok(Self { rules: vec![rule] })
    }

    fn parse_single(expr: &str) -> CaptureResult<FilterRule> {
        let expr = expr.trim();
        let parts: Vec<&str> = expr.split_whitespace().collect();

        match parts.as_slice() {
            ["host", ip] => {
                let addr: IpAddr = ip
                    .parse()
                    .map_err(|_| CaptureError::InvalidFilter(format!("Invalid IP: {}", ip)))?;
                Ok(FilterRule::Host(addr))
            }
            ["port", p] => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| CaptureError::InvalidFilter(format!("Invalid port: {}", p)))?;
                Ok(FilterRule::Port(port))
            }
            ["tcp"] => Ok(FilterRule::Tcp),
            ["udp"] => Ok(FilterRule::Udp),
            _ => Err(CaptureError::InvalidFilter(format!(
                "Unsupported filter expression: '{}'",
                expr
            ))),
        }
    }

    /// Test whether a parsed packet matches this filter.
    pub fn matches(&self, summary: &PacketSummary) -> bool {
        self.rules.iter().any(|r| Self::eval_rule(r, summary))
    }

    fn eval_rule(rule: &FilterRule, pkt: &PacketSummary) -> bool {
        match rule {
            FilterRule::Any => true,
            FilterRule::Host(ip) => pkt.src_ip == *ip || pkt.dst_ip == *ip,
            FilterRule::Port(p) => pkt.src_port == Some(*p) || pkt.dst_port == Some(*p),
            FilterRule::Tcp => pkt.protocol == "TCP",
            FilterRule::Udp => pkt.protocol == "UDP",
            FilterRule::And(a, b) => Self::eval_rule(a, pkt) && Self::eval_rule(b, pkt),
            FilterRule::Or(a, b) => Self::eval_rule(a, pkt) || Self::eval_rule(b, pkt),
        }
    }
}

/// Build a host-list filter expression for scan-correlated capture.
pub fn build_host_filter(targets: &[IpAddr]) -> Option<String> {
    if targets.is_empty() {
        return None;
    }
    let parts: Vec<String> = targets.iter().map(|ip| format!("host {}", ip)).collect();
    Some(parts.join(" or "))
}

// ── PCAP Writer ──────────────────────────────────────────────────────────────

/// Minimal PCAP file writer (libpcap format).
///
/// Produces standard pcap files readable by Wireshark and tcpdump.
/// Global header: 24 bytes, per-packet record header: 16 bytes.
struct PcapWriter<W: Write> {
    writer: W,
    bytes_written: u64,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new PCAP writer and write the global header.
    fn new(mut writer: W) -> std::io::Result<Self> {
        // Global header (24 bytes)
        let magic: u32 = 0xa1b2c3d4;
        let version_major: u16 = 2;
        let version_minor: u16 = 4;
        let thiszone: i32 = 0;
        let sigfigs: u32 = 0;
        let snaplen: u32 = 65535;
        let network: u32 = 1; // LINKTYPE_ETHERNET

        writer.write_all(&magic.to_le_bytes())?;
        writer.write_all(&version_major.to_le_bytes())?;
        writer.write_all(&version_minor.to_le_bytes())?;
        writer.write_all(&thiszone.to_le_bytes())?;
        writer.write_all(&sigfigs.to_le_bytes())?;
        writer.write_all(&snaplen.to_le_bytes())?;
        writer.write_all(&network.to_le_bytes())?;

        Ok(Self {
            writer,
            bytes_written: 24,
        })
    }

    /// Write a single packet record.
    fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> std::io::Result<()> {
        let incl_len = data.len() as u32;
        let orig_len = data.len() as u32;

        // Per-packet header (16 bytes)
        self.writer.write_all(&ts_sec.to_le_bytes())?;
        self.writer.write_all(&ts_usec.to_le_bytes())?;
        self.writer.write_all(&incl_len.to_le_bytes())?;
        self.writer.write_all(&orig_len.to_le_bytes())?;

        // Packet data
        self.writer.write_all(data)?;

        self.bytes_written += 16 + data.len() as u64;
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

// ── Capture Session ──────────────────────────────────────────────────────────

/// A single packet capture session.
///
/// Use [`CaptureSession::new`] to create, then call [`CaptureSession::run`]
/// to start capturing. Cancel via [`CaptureSession::cancel`].
pub struct CaptureSession {
    config: CaptureConfig,
    filter: SoftwareFilter,
    cancelled: Arc<AtomicBool>,
    packets_captured: Arc<AtomicU64>,
    bytes_captured: Arc<AtomicU64>,
}

impl CaptureSession {
    /// Create a new capture session with the given config.
    pub fn new(config: CaptureConfig) -> CaptureResult<Self> {
        let filter = match &config.filter {
            Some(expr) => SoftwareFilter::parse(expr)?,
            None => SoftwareFilter::parse("")?,
        };

        Ok(Self {
            config,
            filter,
            cancelled: Arc::new(AtomicBool::new(false)),
            packets_captured: Arc::new(AtomicU64::new(0)),
            bytes_captured: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Signal cancellation of an ongoing capture.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Get current capture statistics (safe to call while capture is running).
    pub fn current_stats(&self) -> (u64, u64) {
        (
            self.packets_captured.load(Ordering::Relaxed),
            self.bytes_captured.load(Ordering::Relaxed),
        )
    }

    /// Find the best network interface for capture.
    fn resolve_interface(&self) -> CaptureResult<NetworkInterface> {
        let interfaces = datalink::interfaces();

        if let Some(ref name) = self.config.interface {
            interfaces
                .into_iter()
                .find(|iface| &iface.name == name)
                .ok_or_else(|| CaptureError::InterfaceNotFound(name.clone()))
        } else {
            // Auto-detect: pick the first non-loopback interface that is up
            interfaces
                .into_iter()
                .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
                .ok_or_else(|| {
                    CaptureError::InterfaceNotFound("No suitable interface found".into())
                })
        }
    }

    /// Run the capture session. This blocks until duration expires, a limit is
    /// hit, or the session is cancelled.
    ///
    /// Returns aggregate statistics and all parsed packet summaries.
    pub fn run(&self) -> CaptureResult<(CaptureStats, Vec<PacketSummary>)> {
        let interface = self.resolve_interface()?;
        info!(
            "Starting packet capture on interface '{}' (duration: {:?})",
            interface.name, Duration::from_secs(self.config.duration_secs)
        );

        // Open datalink channel
        let mut pnet_config = PnetConfig::default();
        pnet_config.promiscuous = self.config.promiscuous;
        pnet_config.read_timeout = Some(Duration::from_millis(100));

        let (_tx, mut rx) = match datalink::channel(&interface, pnet_config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(CaptureError::ChannelOpen(
                    "Unsupported channel type".into(),
                ));
            }
            Err(e) => {
                return Err(CaptureError::ChannelOpen(e.to_string()));
            }
        };

        // Prepare PCAP file output
        let pcap_path = self.prepare_pcap_path()?;
        let pcap_file = std::fs::File::create(&pcap_path)?;
        let buf_writer = std::io::BufWriter::new(pcap_file);
        let mut pcap = PcapWriter::new(buf_writer)?;

        let started_at = Utc::now();
        let deadline = SystemTime::now() + Duration::from_secs(self.config.duration_secs);

        let mut summaries: Vec<PacketSummary> = Vec::new();
        let mut protocol_counts: HashMap<String, u64> = HashMap::new();
        let mut host_bytes: HashMap<String, u64> = HashMap::new();

        info!(
            "Capture started on {} — filter: {:?}, max_bytes: {}, duration: {:?}",
            interface.name,
            self.config.filter,
            self.config.max_bytes,
            Duration::from_secs(self.config.duration_secs)
        );

        loop {
            // Check cancellation
            if self.cancelled.load(Ordering::Relaxed) {
                info!("Capture cancelled by user");
                break;
            }

            // Check deadline
            if SystemTime::now() >= deadline {
                debug!("Capture duration limit reached");
                break;
            }

            // Check packet count limit
            if self.config.max_packets > 0
                && self.packets_captured.load(Ordering::Relaxed) >= self.config.max_packets
            {
                debug!("Capture packet limit reached");
                break;
            }

            // Check byte limit
            if self.config.max_bytes > 0
                && self.bytes_captured.load(Ordering::Relaxed) >= self.config.max_bytes
            {
                debug!("Capture byte limit reached");
                break;
            }

            // Read next packet
            match rx.next() {
                Ok(packet_data) => {
                    let now = Utc::now();
                    let ts_sec = now.timestamp() as u32;
                    let ts_usec = now.timestamp_subsec_micros();

                    // Parse the ethernet frame
                    if let Some(summary) =
                        self.parse_packet(packet_data, now)
                    {
                        // Apply software filter
                        if !self.filter.matches(&summary) {
                            continue;
                        }

                        // Write to PCAP
                        if let Err(e) = pcap.write_packet(ts_sec, ts_usec, packet_data) {
                            warn!("Failed to write PCAP packet: {}", e);
                        }

                        // Update counters
                        self.packets_captured.fetch_add(1, Ordering::Relaxed);
                        self.bytes_captured
                            .fetch_add(packet_data.len() as u64, Ordering::Relaxed);

                        // Update protocol breakdown
                        *protocol_counts.entry(summary.protocol.clone()).or_default() += 1;

                        // Update host bytes
                        *host_bytes
                            .entry(summary.src_ip.to_string())
                            .or_default() += summary.length as u64;
                        *host_bytes
                            .entry(summary.dst_ip.to_string())
                            .or_default() += summary.length as u64;

                        summaries.push(summary);
                    }
                }
                Err(e) => {
                    // Timeout on read is expected, not an error
                    let err_str = e.to_string();
                    if err_str.contains("timed out") || err_str.contains("Timed out") {
                        continue;
                    }
                    warn!("Packet read error: {}", e);
                }
            }
        }

        pcap.flush()?;
        let ended_at = Utc::now();

        // Build top talkers (sorted by byte count, top 10)
        let mut top_talkers: Vec<(String, u64)> = host_bytes.into_iter().collect();
        top_talkers.sort_by(|a, b| b.1.cmp(&a.1));
        top_talkers.truncate(10);

        let stats = CaptureStats {
            packets_captured: self.packets_captured.load(Ordering::Relaxed),
            bytes_captured: self.bytes_captured.load(Ordering::Relaxed),
            packets_dropped: 0,
            protocol_breakdown: protocol_counts,
            top_talkers,
            started_at: Some(started_at),
            ended_at: Some(ended_at),
            pcap_path: Some(pcap_path.to_string_lossy().to_string()),
            capture_duration_ms: (ended_at - started_at).num_milliseconds() as u64,
        };

        info!(
            "Capture complete: {} packets, {} bytes, PCAP at {:?}",
            stats.packets_captured,
            stats.bytes_captured,
            stats.pcap_path
        );

        Ok((stats, summaries))
    }

    /// Run capture correlated with a set of scan targets.
    /// Returns stats plus a map of target IP → relevant packet summaries.
    pub fn run_correlated(
        &self,
        targets: &[IpAddr],
    ) -> CaptureResult<(CaptureStats, HashMap<IpAddr, Vec<PacketSummary>>)> {
        let (stats, summaries) = self.run()?;

        // Group packets by target IP
        let mut by_target: HashMap<IpAddr, Vec<PacketSummary>> = HashMap::new();
        for target in targets {
            by_target.insert(*target, Vec::new());
        }

        for summary in summaries {
            for target in targets {
                if summary.src_ip == *target || summary.dst_ip == *target {
                    by_target.entry(*target).or_default().push(summary.clone());
                }
            }
        }

        Ok((stats, by_target))
    }

    // ── Packet Parsing ──────────────────────────────────────────────────

    fn parse_packet(&self, data: &[u8], timestamp: DateTime<Utc>) -> Option<PacketSummary> {
        let eth = EthernetPacket::new(data)?;

        match eth.get_ethertype() {
            EtherTypes::Ipv4 => self.parse_ipv4(eth.payload(), data.len(), timestamp),
            EtherTypes::Ipv6 => self.parse_ipv6(eth.payload(), data.len(), timestamp),
            _ => None,
        }
    }

    fn parse_ipv4(
        &self,
        data: &[u8],
        total_len: usize,
        timestamp: DateTime<Utc>,
    ) -> Option<PacketSummary> {
        let ipv4 = Ipv4Packet::new(data)?;
        let src_ip = IpAddr::V4(ipv4.get_source());
        let dst_ip = IpAddr::V4(ipv4.get_destination());

        let (src_port, dst_port, protocol, tcp_flags, payload) =
            self.parse_transport(ipv4.get_next_level_protocol(), ipv4.payload());

        Some(PacketSummary {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length: total_len,
            timestamp,
            tcp_flags,
            payload_preview: payload,
        })
    }

    fn parse_ipv6(
        &self,
        data: &[u8],
        total_len: usize,
        timestamp: DateTime<Utc>,
    ) -> Option<PacketSummary> {
        let ipv6 = Ipv6Packet::new(data)?;
        let src_ip = IpAddr::V6(ipv6.get_source());
        let dst_ip = IpAddr::V6(ipv6.get_destination());

        let (src_port, dst_port, protocol, tcp_flags, payload) =
            self.parse_transport(ipv6.get_next_header(), ipv6.payload());

        Some(PacketSummary {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length: total_len,
            timestamp,
            tcp_flags,
            payload_preview: payload,
        })
    }

    fn parse_transport(
        &self,
        proto: pnet::packet::ip::IpNextHeaderProtocol,
        payload: &[u8],
    ) -> (Option<u16>, Option<u16>, String, Option<String>, Vec<u8>) {
        match proto {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(payload) {
                    let flags = format_tcp_flags(&tcp);
                    let preview_len = self.config.payload_preview_len.min(tcp.payload().len());
                    let preview = tcp.payload()[..preview_len].to_vec();
                    (
                        Some(tcp.get_source()),
                        Some(tcp.get_destination()),
                        "TCP".into(),
                        Some(flags),
                        preview,
                    )
                } else {
                    (None, None, "TCP".into(), None, vec![])
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(payload) {
                    let preview_len = self.config.payload_preview_len.min(udp.payload().len());
                    let preview = udp.payload()[..preview_len].to_vec();
                    (
                        Some(udp.get_source()),
                        Some(udp.get_destination()),
                        "UDP".into(),
                        None,
                        preview,
                    )
                } else {
                    (None, None, "UDP".into(), None, vec![])
                }
            }
            IpNextHeaderProtocols::Icmp => (None, None, "ICMP".into(), None, vec![]),
            IpNextHeaderProtocols::Icmpv6 => (None, None, "ICMPv6".into(), None, vec![]),
            other => (None, None, format!("IP/{}", other.0), None, vec![]),
        }
    }

    /// Create the PCAP output path for this session.
    fn prepare_pcap_path(&self) -> CaptureResult<PathBuf> {
        let dir = Path::new(&self.config.capture_dir);
        std::fs::create_dir_all(dir)?;

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("capture_{}.pcap", timestamp);
        Ok(dir.join(filename))
    }
}

// ── TCP Flag Formatting ──────────────────────────────────────────────────────

fn format_tcp_flags(tcp: &TcpPacket) -> String {
    let mut flags = String::with_capacity(8);
    let raw = tcp.get_flags();
    if raw & 0x01 != 0 {
        flags.push('F');
    } // FIN
    if raw & 0x02 != 0 {
        flags.push('S');
    } // SYN
    if raw & 0x04 != 0 {
        flags.push('R');
    } // RST
    if raw & 0x08 != 0 {
        flags.push('P');
    } // PSH
    if raw & 0x10 != 0 {
        flags.push('A');
    } // ACK
    if raw & 0x20 != 0 {
        flags.push('U');
    } // URG
    if flags.is_empty() {
        flags.push_str("none");
    }
    flags
}

// ── Capture Evidence Helpers ─────────────────────────────────────────────────

/// Extract a small packet evidence blob suitable for `Finding.raw_evidence`.
/// Returns the first `max_bytes` of the most interesting packet (e.g., the
/// SYN-ACK for a port finding, or first data packet for a service finding).
pub fn extract_packet_evidence(
    summaries: &[PacketSummary],
    target: IpAddr,
    port: Option<u16>,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    // Prefer: SYN-ACK from target, then first data packet from target on the port
    let syn_ack = summaries.iter().find(|p| {
        p.src_ip == target
            && p.tcp_flags.as_deref() == Some("SA")
            && port.map_or(true, |pt| p.src_port == Some(pt))
    });

    if let Some(pkt) = syn_ack {
        return Some(build_evidence_blob(pkt, max_bytes));
    }

    // Fall back to first packet with payload from the target on the port
    let data_pkt = summaries.iter().find(|p| {
        p.src_ip == target
            && !p.payload_preview.is_empty()
            && port.map_or(true, |pt| p.src_port == Some(pt))
    });

    data_pkt.map(|pkt| build_evidence_blob(pkt, max_bytes))
}

fn build_evidence_blob(pkt: &PacketSummary, max_bytes: usize) -> Vec<u8> {
    // Compact representation: "proto:src_ip:src_port->dst_ip:dst_port|flags|payload"
    let header = format!(
        "{}:{}:{}->{}:{}|{}|",
        pkt.protocol,
        pkt.src_ip,
        pkt.src_port.unwrap_or(0),
        pkt.dst_ip,
        pkt.dst_port.unwrap_or(0),
        pkt.tcp_flags.as_deref().unwrap_or("-"),
    );

    let mut blob = header.into_bytes();
    let remaining = max_bytes.saturating_sub(blob.len());
    if remaining > 0 && !pkt.payload_preview.is_empty() {
        let take = remaining.min(pkt.payload_preview.len());
        blob.extend_from_slice(&pkt.payload_preview[..take]);
    }
    blob.truncate(max_bytes);
    blob
}

/// Build a human-readable evidence string from packet summaries for a target.
pub fn build_evidence_summary(summaries: &[PacketSummary], target: IpAddr) -> String {
    let relevant: Vec<&PacketSummary> = summaries
        .iter()
        .filter(|p| p.src_ip == target || p.dst_ip == target)
        .take(20)
        .collect();

    if relevant.is_empty() {
        return format!("No packets captured for {}", target);
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "Packet capture evidence for {} ({} packets shown):",
        target,
        relevant.len()
    ));

    for pkt in &relevant {
        let direction = if pkt.src_ip == target {
            "->"
        } else {
            "<-"
        };
        let flags = pkt.tcp_flags.as_deref().unwrap_or("");
        lines.push(format!(
            "  {} {}:{} {} {}:{} {} len={}{}",
            pkt.protocol,
            pkt.src_ip,
            pkt.src_port.unwrap_or(0),
            direction,
            pkt.dst_ip,
            pkt.dst_port.unwrap_or(0),
            flags,
            pkt.length,
            if !pkt.payload_preview.is_empty() {
                format!(" payload={}B", pkt.payload_preview.len())
            } else {
                String::new()
            },
        ));
    }

    lines.join("\n")
}

// ── Cleanup ──────────────────────────────────────────────────────────────────

/// Remove PCAP files older than `retention_days` from the capture directory.
pub fn cleanup_old_captures(capture_dir: &str, retention_days: u32) -> std::io::Result<u32> {
    let dir = Path::new(capture_dir);
    if !dir.exists() {
        return Ok(0);
    }

    let cutoff = SystemTime::now() - Duration::from_secs(retention_days as u64 * 86400);
    let mut removed = 0u32;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("pcap") {
            continue;
        }

        if let Ok(metadata) = entry.metadata() {
            if let Ok(modified) = metadata.modified() {
                if modified < cutoff {
                    if std::fs::remove_file(&path).is_ok() {
                        info!("Removed old capture: {:?}", path);
                        removed += 1;
                    }
                }
            }
        }
    }

    Ok(removed)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_software_filter_parse_host() {
        let filter = SoftwareFilter::parse("host 192.168.1.1").unwrap();
        let pkt = PacketSummary {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(80),
            dst_port: Some(12345),
            protocol: "TCP".into(),
            length: 100,
            timestamp: Utc::now(),
            tcp_flags: Some("SA".into()),
            payload_preview: vec![],
        };
        assert!(filter.matches(&pkt));

        let pkt2 = PacketSummary {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ..pkt.clone()
        };
        assert!(!filter.matches(&pkt2));
    }

    #[test]
    fn test_software_filter_parse_port() {
        let filter = SoftwareFilter::parse("port 443").unwrap();
        let pkt = PacketSummary {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: Some(12345),
            dst_port: Some(443),
            protocol: "TCP".into(),
            length: 100,
            timestamp: Utc::now(),
            tcp_flags: None,
            payload_preview: vec![],
        };
        assert!(filter.matches(&pkt));
    }

    #[test]
    fn test_software_filter_and() {
        let filter = SoftwareFilter::parse("host 10.0.0.1 and tcp").unwrap();
        let tcp_pkt = PacketSummary {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: Some(80),
            dst_port: Some(12345),
            protocol: "TCP".into(),
            length: 100,
            timestamp: Utc::now(),
            tcp_flags: None,
            payload_preview: vec![],
        };
        assert!(filter.matches(&tcp_pkt));

        let udp_pkt = PacketSummary {
            protocol: "UDP".into(),
            ..tcp_pkt.clone()
        };
        assert!(!filter.matches(&udp_pkt));
    }

    #[test]
    fn test_software_filter_empty() {
        let filter = SoftwareFilter::parse("").unwrap();
        let pkt = PacketSummary {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            src_port: None,
            dst_port: None,
            protocol: "ICMP".into(),
            length: 64,
            timestamp: Utc::now(),
            tcp_flags: None,
            payload_preview: vec![],
        };
        assert!(filter.matches(&pkt));
    }

    #[test]
    fn test_build_host_filter() {
        let targets = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        ];
        let filter = build_host_filter(&targets).unwrap();
        assert_eq!(filter, "host 192.168.1.1 or host 192.168.1.2");
    }

    #[test]
    fn test_build_host_filter_empty() {
        assert!(build_host_filter(&[]).is_none());
    }

    #[test]
    fn test_format_tcp_flags() {
        // We can't easily construct a TcpPacket in a unit test without raw bytes,
        // so we test the evidence helpers instead.
    }

    #[test]
    fn test_extract_packet_evidence() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let summaries = vec![
            PacketSummary {
                src_ip: target,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: Some(22),
                dst_port: Some(54321),
                protocol: "TCP".into(),
                length: 66,
                timestamp: Utc::now(),
                tcp_flags: Some("SA".into()),
                payload_preview: vec![],
            },
            PacketSummary {
                src_ip: target,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: Some(22),
                dst_port: Some(54321),
                protocol: "TCP".into(),
                length: 150,
                timestamp: Utc::now(),
                tcp_flags: Some("PA".into()),
                payload_preview: b"SSH-2.0-OpenSSH_9.6".to_vec(),
            },
        ];

        // Should find the SYN-ACK
        let evidence = extract_packet_evidence(&summaries, target, Some(22), 256).unwrap();
        let evidence_str = String::from_utf8_lossy(&evidence);
        assert!(evidence_str.contains("SA"));
        assert!(evidence_str.contains("192.168.1.1"));
    }

    #[test]
    fn test_pcap_writer() {
        let mut buf = Vec::new();
        {
            let mut writer = PcapWriter::new(&mut buf).unwrap();
            // Write a fake packet
            writer.write_packet(1000, 500000, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
            writer.flush().unwrap();
        }
        // Global header (24) + packet header (16) + packet data (4) = 44 bytes
        assert_eq!(buf.len(), 44);
        // Check magic number
        assert_eq!(&buf[0..4], &0xa1b2c3d4u32.to_le_bytes());
    }

    #[test]
    fn test_evidence_summary() {
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let summaries = vec![PacketSummary {
            src_ip: target,
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(80),
            dst_port: Some(54321),
            protocol: "TCP".into(),
            length: 100,
            timestamp: Utc::now(),
            tcp_flags: Some("SA".into()),
            payload_preview: vec![],
        }];

        let summary = build_evidence_summary(&summaries, target);
        assert!(summary.contains("10.0.0.5"));
        assert!(summary.contains("SA"));
    }
}
