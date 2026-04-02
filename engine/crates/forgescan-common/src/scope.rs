//! Scope guardrails for scanner target validation
//!
//! Provides allowlist/denylist CIDR filtering, hostname deny-lists,
//! an emergency kill switch, and per-scan target limits. All targets
//! are checked against these rules before scanning begins.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

/// Default CIDRs that are always denied unless explicitly overridden.
/// Includes loopback, link-local, multicast, reserved, and IPv6 equivalents.
const DEFAULT_DENIED_CIDRS: &[&str] = &[
    "127.0.0.0/8",     // IPv4 loopback
    "169.254.0.0/16",   // IPv4 link-local
    "224.0.0.0/4",      // IPv4 multicast
    "240.0.0.0/4",      // IPv4 reserved
    "::1/128",          // IPv6 loopback
    "fe80::/10",        // IPv6 link-local
    "ff00::/8",         // IPv6 multicast
];

/// Default hostnames that are always denied.
const DEFAULT_DENIED_HOSTNAMES: &[&str] = &[
    "localhost",
    "metadata.google.internal",        // GCP metadata
    "169.254.169.254",                 // AWS/Azure metadata (also caught by CIDR deny)
];

/// Scope configuration controlling what the scanner is allowed to target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    /// Positive allowlist of CIDRs. If non-empty, only targets whose IP
    /// falls within one of these ranges will be scanned. Empty means allow all
    /// (subject to denied_cidrs).
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,

    /// CIDRs that are always denied. Appended to the built-in deny list
    /// (loopback, link-local, multicast, reserved).
    #[serde(default)]
    pub denied_cidrs: Vec<String>,

    /// Hostnames (or hostname suffixes) that are always denied.
    /// The built-in list includes "localhost" and cloud metadata endpoints.
    #[serde(default)]
    pub denied_hostnames: Vec<String>,

    /// Emergency kill switch. When true, all scan targets are rejected.
    /// Can also be set via FORGESCAN_EMERGENCY_DISABLE=true env var.
    #[serde(default)]
    pub emergency_disable: bool,

    /// Maximum number of targets allowed per scan. Scans exceeding this
    /// limit are rejected entirely.
    #[serde(default = "default_max_targets_per_scan")]
    pub max_targets_per_scan: u32,
}

fn default_max_targets_per_scan() -> u32 {
    10000
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            allowed_cidrs: Vec::new(),
            denied_cidrs: Vec::new(),
            denied_hostnames: Vec::new(),
            emergency_disable: false,
            max_targets_per_scan: default_max_targets_per_scan(),
        }
    }
}

/// A parsed CIDR network for matching.
#[derive(Debug, Clone)]
struct CidrNet {
    addr: IpAddr,
    prefix: u8,
}

/// Validates scan targets against scope rules.
pub struct ScopeValidator {
    config: ScopeConfig,
    allowed: Vec<CidrNet>,
    denied: Vec<CidrNet>,
    denied_hosts: Vec<String>,
}

impl ScopeValidator {
    /// Create a new validator from scope configuration.
    /// Invalid CIDRs in the config are logged and skipped.
    pub fn new(config: &ScopeConfig) -> Self {
        let allowed: Vec<CidrNet> = config
            .allowed_cidrs
            .iter()
            .filter_map(|s| parse_cidr(s))
            .collect();

        // Combine built-in deny list with user-configured denied CIDRs
        let mut denied: Vec<CidrNet> = DEFAULT_DENIED_CIDRS
            .iter()
            .filter_map(|s| parse_cidr(s))
            .collect();
        for cidr_str in &config.denied_cidrs {
            if let Some(net) = parse_cidr(cidr_str) {
                denied.push(net);
            }
        }

        // Combine built-in hostname deny list with user config
        let mut denied_hosts: Vec<String> = DEFAULT_DENIED_HOSTNAMES
            .iter()
            .map(|s| s.to_lowercase())
            .collect();
        for h in &config.denied_hostnames {
            let lower = h.to_lowercase();
            if !denied_hosts.contains(&lower) {
                denied_hosts.push(lower);
            }
        }

        Self {
            config: config.clone(),
            allowed,
            denied,
            denied_hosts,
        }
    }

    /// Check if the emergency kill switch is active (config or env var).
    pub fn is_emergency_disabled(&self) -> bool {
        if self.config.emergency_disable {
            return true;
        }
        matches!(
            std::env::var("FORGESCAN_EMERGENCY_DISABLE").as_deref(),
            Ok("true") | Ok("1")
        )
    }

    /// Validate a single target string. Returns Ok(()) if allowed.
    pub fn check_target(&self, target: &str) -> Result<(), ScopeError> {
        if self.is_emergency_disabled() {
            return Err(ScopeError::EmergencyDisabled);
        }

        let target = target.trim();
        if target.is_empty() {
            return Err(ScopeError::InvalidTarget("empty target".into()));
        }

        // URL: extract hostname and check
        if target.starts_with("http://") || target.starts_with("https://") {
            let host = extract_url_host(target)
                .ok_or_else(|| ScopeError::InvalidTarget(target.into()))?;
            return self.check_hostname_or_ip(&host);
        }

        // CIDR: check network address
        if target.contains('/') {
            let parts: Vec<&str> = target.splitn(2, '/').collect();
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                return self.check_ip(ip);
            }
            return Err(ScopeError::InvalidTarget(target.into()));
        }

        // IP range: check start and end
        if target.contains('-') {
            let parts: Vec<&str> = target.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (
                    parts[0].trim().parse::<IpAddr>(),
                    parts[1].trim().parse::<IpAddr>(),
                ) {
                    self.check_ip(start)?;
                    return self.check_ip(end);
                }
            }
        }

        // Plain IP
        if let Ok(ip) = target.parse::<IpAddr>() {
            return self.check_ip(ip);
        }

        // Hostname
        self.check_hostname_or_ip(target)
    }

    /// Filter a batch of targets, returning (allowed, rejected) pairs.
    pub fn filter_targets(&self, targets: &[String]) -> (Vec<String>, Vec<ScopeRejection>) {
        if self.is_emergency_disabled() {
            let rejected = targets
                .iter()
                .map(|t| ScopeRejection {
                    target: t.clone(),
                    reason: ScopeError::EmergencyDisabled,
                })
                .collect();
            return (Vec::new(), rejected);
        }

        if targets.len() as u32 > self.config.max_targets_per_scan {
            let rejected = vec![ScopeRejection {
                target: format!("{} targets", targets.len()),
                reason: ScopeError::TargetLimitExceeded {
                    count: targets.len() as u32,
                    max: self.config.max_targets_per_scan,
                },
            }];
            return (Vec::new(), rejected);
        }

        let mut allowed = Vec::new();
        let mut rejected = Vec::new();

        for target in targets {
            match self.check_target(target) {
                Ok(()) => allowed.push(target.clone()),
                Err(reason) => rejected.push(ScopeRejection {
                    target: target.clone(),
                    reason,
                }),
            }
        }

        (allowed, rejected)
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), ScopeError> {
        // Check deny list first
        for net in &self.denied {
            if ip_in_cidr(ip, net.addr, net.prefix) {
                return Err(ScopeError::DeniedCidr(ip.to_string()));
            }
        }

        // If allowlist is non-empty, IP must match at least one entry
        if !self.allowed.is_empty() {
            let in_allowed = self
                .allowed
                .iter()
                .any(|net| ip_in_cidr(ip, net.addr, net.prefix));
            if !in_allowed {
                return Err(ScopeError::NotInAllowedCidrs(ip.to_string()));
            }
        }

        Ok(())
    }

    fn check_hostname_or_ip(&self, host: &str) -> Result<(), ScopeError> {
        let lower = host.to_lowercase();

        // Check against denied hostnames
        for denied in &self.denied_hosts {
            if lower == *denied || lower.ends_with(&format!(".{}", denied)) {
                return Err(ScopeError::DeniedHostname(host.into()));
            }
        }

        // If host parses as IP, also check IP rules
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.check_ip(ip);
        }

        // If allowlist is non-empty and host is not an IP, we can't verify
        // CIDR membership. Allow it — the DNS resolution step will produce
        // an IP that goes through check_ip before actual scanning.
        Ok(())
    }
}

/// Error when a target is rejected by scope validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// The emergency kill switch is active.
    EmergencyDisabled,
    /// The target IP falls within a denied CIDR range.
    DeniedCidr(String),
    /// The target hostname matches a denied hostname pattern.
    DeniedHostname(String),
    /// The target IP is not within any allowed CIDR range.
    NotInAllowedCidrs(String),
    /// The scan exceeds the maximum target count.
    TargetLimitExceeded { count: u32, max: u32 },
    /// The target string could not be parsed.
    InvalidTarget(String),
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeError::EmergencyDisabled => {
                write!(f, "Scanner emergency disable is active — all scans blocked")
            }
            ScopeError::DeniedCidr(ip) => {
                write!(f, "IP {} is in a denied CIDR range", ip)
            }
            ScopeError::DeniedHostname(host) => {
                write!(f, "Hostname '{}' is in the deny list", host)
            }
            ScopeError::NotInAllowedCidrs(ip) => {
                write!(f, "IP {} is not in any allowed CIDR range", ip)
            }
            ScopeError::TargetLimitExceeded { count, max } => {
                write!(
                    f,
                    "Scan has {} targets, exceeding the limit of {}",
                    count, max
                )
            }
            ScopeError::InvalidTarget(t) => {
                write!(f, "Invalid or unparseable target: '{}'", t)
            }
        }
    }
}

impl std::error::Error for ScopeError {}

/// A target that was rejected, with the reason.
#[derive(Debug, Clone)]
pub struct ScopeRejection {
    pub target: String,
    pub reason: ScopeError,
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn parse_cidr(s: &str) -> Option<CidrNet> {
    let parts: Vec<&str> = s.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let addr: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some(CidrNet { addr, prefix })
}

fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false, // mixed families never match
    }
}

fn extract_url_host(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Take everything before the first '/' or ':'
    let host = without_scheme
        .split('/')
        .next()?
        .split(':')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_validator() -> ScopeValidator {
        ScopeValidator::new(&ScopeConfig::default())
    }

    // ── Default deny list ──────────────────────────────────────────

    #[test]
    fn test_default_denies_loopback() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("127.0.0.1"),
            Err(ScopeError::DeniedCidr(_))
        ));
        assert!(matches!(
            v.check_target("127.0.0.53"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    #[test]
    fn test_default_denies_link_local() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("169.254.1.1"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    #[test]
    fn test_default_denies_multicast() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("224.0.0.1"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    #[test]
    fn test_default_denies_ipv6_loopback() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("::1"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    #[test]
    fn test_default_denies_ipv6_link_local() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("fe80::1"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    #[test]
    fn test_default_denies_localhost_hostname() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("localhost"),
            Err(ScopeError::DeniedHostname(_))
        ));
    }

    #[test]
    fn test_default_denies_metadata_hostname() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("metadata.google.internal"),
            Err(ScopeError::DeniedHostname(_))
        ));
    }

    // ── Default allow list (empty = allow all except denied) ───────

    #[test]
    fn test_default_allows_normal_ips() {
        let v = default_validator();
        assert!(v.check_target("10.0.0.1").is_ok());
        assert!(v.check_target("192.168.1.1").is_ok());
        assert!(v.check_target("8.8.8.8").is_ok());
    }

    #[test]
    fn test_default_allows_normal_hostnames() {
        let v = default_validator();
        assert!(v.check_target("server.example.com").is_ok());
    }

    #[test]
    fn test_default_allows_urls() {
        let v = default_validator();
        assert!(v.check_target("https://app.example.com").is_ok());
    }

    // ── Allowed CIDRs (positive allowlist) ────────────────────────

    #[test]
    fn test_allowed_cidrs_restricts_to_range() {
        let config = ScopeConfig {
            allowed_cidrs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        assert!(v.check_target("10.0.0.1").is_ok());
        assert!(v.check_target("10.255.255.255").is_ok());
        assert!(matches!(
            v.check_target("192.168.1.1"),
            Err(ScopeError::NotInAllowedCidrs(_))
        ));
        assert!(matches!(
            v.check_target("8.8.8.8"),
            Err(ScopeError::NotInAllowedCidrs(_))
        ));
    }

    #[test]
    fn test_denied_takes_precedence_over_allowed() {
        let config = ScopeConfig {
            allowed_cidrs: vec!["0.0.0.0/0".into()],
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        // 127.0.0.1 is in allowed (0.0.0.0/0) but denied by default deny list
        assert!(matches!(
            v.check_target("127.0.0.1"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    // ── Custom denied CIDRs ───────────────────────────────────────

    #[test]
    fn test_custom_denied_cidr() {
        let config = ScopeConfig {
            denied_cidrs: vec!["10.99.0.0/16".into()],
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        assert!(matches!(
            v.check_target("10.99.1.1"),
            Err(ScopeError::DeniedCidr(_))
        ));
        assert!(v.check_target("10.100.1.1").is_ok());
    }

    // ── Custom denied hostnames ───────────────────────────────────

    #[test]
    fn test_custom_denied_hostname() {
        let config = ScopeConfig {
            denied_hostnames: vec!["evil.example.com".into()],
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        assert!(matches!(
            v.check_target("evil.example.com"),
            Err(ScopeError::DeniedHostname(_))
        ));
        assert!(matches!(
            v.check_target("sub.evil.example.com"),
            Err(ScopeError::DeniedHostname(_))
        ));
        assert!(v.check_target("good.example.com").is_ok());
    }

    #[test]
    fn test_denied_hostname_in_url() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("https://localhost/admin"),
            Err(ScopeError::DeniedHostname(_))
        ));
        assert!(matches!(
            v.check_target("http://metadata.google.internal/computeMetadata"),
            Err(ScopeError::DeniedHostname(_))
        ));
    }

    // ── Emergency disable ─────────────────────────────────────────

    #[test]
    fn test_emergency_disable_config() {
        let config = ScopeConfig {
            emergency_disable: true,
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        assert!(v.is_emergency_disabled());
        assert!(matches!(
            v.check_target("10.0.0.1"),
            Err(ScopeError::EmergencyDisabled)
        ));
    }

    #[test]
    fn test_emergency_disable_env_var() {
        let v = default_validator();
        assert!(!v.is_emergency_disabled());

        std::env::set_var("FORGESCAN_EMERGENCY_DISABLE", "true");
        assert!(v.is_emergency_disabled());
        assert!(matches!(
            v.check_target("10.0.0.1"),
            Err(ScopeError::EmergencyDisabled)
        ));
        std::env::remove_var("FORGESCAN_EMERGENCY_DISABLE");
    }

    // ── Target limit ──────────────────────────────────────────────

    #[test]
    fn test_target_limit_exceeded() {
        let config = ScopeConfig {
            max_targets_per_scan: 3,
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        let targets: Vec<String> = (1..=4).map(|i| format!("10.0.0.{}", i)).collect();
        let (allowed, rejected) = v.filter_targets(&targets);

        assert!(allowed.is_empty());
        assert_eq!(rejected.len(), 1);
        assert!(matches!(
            rejected[0].reason,
            ScopeError::TargetLimitExceeded { count: 4, max: 3 }
        ));
    }

    #[test]
    fn test_target_limit_ok() {
        let config = ScopeConfig {
            max_targets_per_scan: 3,
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        let targets: Vec<String> = (1..=3).map(|i| format!("10.0.0.{}", i)).collect();
        let (allowed, rejected) = v.filter_targets(&targets);

        assert_eq!(allowed.len(), 3);
        assert!(rejected.is_empty());
    }

    // ── Filter targets batch ──────────────────────────────────────

    #[test]
    fn test_filter_targets_mixed() {
        let v = default_validator();
        let targets = vec![
            "10.0.0.1".into(),
            "127.0.0.1".into(),       // denied
            "192.168.1.1".into(),
            "localhost".into(),        // denied
        ];

        let (allowed, rejected) = v.filter_targets(&targets);
        assert_eq!(allowed.len(), 2);
        assert_eq!(rejected.len(), 2);
        assert_eq!(allowed[0], "10.0.0.1");
        assert_eq!(allowed[1], "192.168.1.1");
    }

    #[test]
    fn test_filter_targets_emergency_disable() {
        let config = ScopeConfig {
            emergency_disable: true,
            ..Default::default()
        };
        let v = ScopeValidator::new(&config);

        let targets = vec!["10.0.0.1".into()];
        let (allowed, rejected) = v.filter_targets(&targets);

        assert!(allowed.is_empty());
        assert_eq!(rejected.len(), 1);
    }

    // ── CIDR targets ──────────────────────────────────────────────

    #[test]
    fn test_cidr_target_checked() {
        let v = default_validator();
        assert!(v.check_target("10.0.0.0/24").is_ok());
        assert!(matches!(
            v.check_target("127.0.0.0/24"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    // ── IP range targets ──────────────────────────────────────────

    #[test]
    fn test_ip_range_target_checked() {
        let v = default_validator();
        assert!(v.check_target("10.0.0.1-10.0.0.5").is_ok());
        assert!(matches!(
            v.check_target("127.0.0.1-127.0.0.5"),
            Err(ScopeError::DeniedCidr(_))
        ));
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn test_empty_target_rejected() {
        let v = default_validator();
        assert!(matches!(
            v.check_target(""),
            Err(ScopeError::InvalidTarget(_))
        ));
        assert!(matches!(
            v.check_target("   "),
            Err(ScopeError::InvalidTarget(_))
        ));
    }

    #[test]
    fn test_hostname_case_insensitive() {
        let v = default_validator();
        assert!(matches!(
            v.check_target("LOCALHOST"),
            Err(ScopeError::DeniedHostname(_))
        ));
        assert!(matches!(
            v.check_target("Metadata.Google.Internal"),
            Err(ScopeError::DeniedHostname(_))
        ));
    }

    #[test]
    fn test_scope_error_display() {
        assert!(format!("{}", ScopeError::EmergencyDisabled).contains("emergency"));
        assert!(format!("{}", ScopeError::DeniedCidr("10.0.0.1".into())).contains("denied"));
        assert!(
            format!("{}", ScopeError::DeniedHostname("localhost".into())).contains("deny list")
        );
        assert!(
            format!("{}", ScopeError::NotInAllowedCidrs("8.8.8.8".into())).contains("allowed")
        );
        assert!(format!(
            "{}",
            ScopeError::TargetLimitExceeded {
                count: 100,
                max: 50
            }
        )
        .contains("100"));
        assert!(
            format!("{}", ScopeError::InvalidTarget("bad".into())).contains("Invalid")
        );
    }

    // ── ip_in_cidr unit tests ─────────────────────────────────────

    #[test]
    fn test_ip_in_cidr_v4() {
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        let ip_in: IpAddr = "10.0.0.42".parse().unwrap();
        let ip_out: IpAddr = "10.0.1.1".parse().unwrap();

        assert!(ip_in_cidr(ip_in, net, 24));
        assert!(!ip_in_cidr(ip_out, net, 24));
    }

    #[test]
    fn test_ip_in_cidr_v6() {
        let net: IpAddr = "fd00::".parse().unwrap();
        let ip_in: IpAddr = "fd00::42".parse().unwrap();
        let ip_out: IpAddr = "fe80::1".parse().unwrap();

        assert!(ip_in_cidr(ip_in, net, 16));
        assert!(!ip_in_cidr(ip_out, net, 16));
    }

    #[test]
    fn test_ip_in_cidr_mixed_families() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert!(!ip_in_cidr(v4, v6, 128));
    }

    #[test]
    fn test_default_config_values() {
        let config = ScopeConfig::default();
        assert!(config.allowed_cidrs.is_empty());
        assert!(config.denied_cidrs.is_empty());
        assert!(config.denied_hostnames.is_empty());
        assert!(!config.emergency_disable);
        assert_eq!(config.max_targets_per_scan, 10000);
    }

    #[test]
    fn test_url_host_extraction() {
        assert_eq!(
            extract_url_host("https://example.com/path"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_url_host("http://10.0.0.1:8080/api"),
            Some("10.0.0.1".into())
        );
        assert_eq!(extract_url_host("https://"), None);
        assert_eq!(extract_url_host("not-a-url"), None);
    }
}
