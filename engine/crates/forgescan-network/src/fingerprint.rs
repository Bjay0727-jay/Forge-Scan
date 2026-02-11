//! OS and Service Fingerprinting
//!
//! This module provides fingerprinting capabilities to identify:
//! - Operating system from TCP/IP stack behavior
//! - Service versions from response patterns

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tracing::debug;

use crate::banner::BannerResult;
use crate::service_detect::ServiceInfo;

/// OS fingerprint result
#[derive(Debug, Clone)]
pub struct OsFingerprint {
    /// Most likely OS name
    pub os_name: String,
    /// OS family (Linux, Windows, BSD, etc.)
    pub os_family: OsFamily,
    /// OS version if detected
    pub os_version: Option<String>,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// CPE identifier if available
    pub cpe: Option<String>,
    /// Additional OS hints
    pub hints: Vec<String>,
}

/// OS family categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFamily {
    Linux,
    Windows,
    Bsd,
    MacOs,
    Unix,
    Embedded,
    Unknown,
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsFamily::Linux => write!(f, "Linux"),
            OsFamily::Windows => write!(f, "Windows"),
            OsFamily::Bsd => write!(f, "BSD"),
            OsFamily::MacOs => write!(f, "macOS"),
            OsFamily::Unix => write!(f, "Unix"),
            OsFamily::Embedded => write!(f, "Embedded"),
            OsFamily::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Fingerprinter for OS and service detection
pub struct Fingerprinter {
    /// Known OS signatures from banners
    os_patterns: Vec<OsPattern>,
}

struct OsPattern {
    pattern: &'static str,
    os_name: &'static str,
    os_family: OsFamily,
    version_regex: Option<&'static str>,
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

impl Fingerprinter {
    pub fn new() -> Self {
        Self {
            os_patterns: Self::default_os_patterns(),
        }
    }

    /// Fingerprint OS from collected banners and service info
    pub fn fingerprint_os(
        &self,
        banners: &[BannerResult],
        services: &[ServiceInfo],
    ) -> Option<OsFingerprint> {
        let mut hints = Vec::new();
        let mut os_votes: HashMap<OsFamily, u32> = HashMap::new();
        let mut specific_os: Option<(&str, OsFamily, u8)> = None;

        // Analyze banners for OS hints
        for banner in banners {
            if let Some(os_info) = self.detect_os_from_banner(&banner.text) {
                *os_votes.entry(os_info.os_family).or_insert(0) += 1;
                hints.push(format!("Banner indicates {}", os_info.os_name));

                if os_info.confidence > specific_os.as_ref().map(|o| o.2).unwrap_or(0) {
                    specific_os = Some((os_info.os_name, os_info.os_family, os_info.confidence));
                }
            }
        }

        // Analyze services for OS hints
        for service in services {
            if let Some(product) = &service.product {
                if let Some(os_family) = self.infer_os_from_product(product) {
                    *os_votes.entry(os_family).or_insert(0) += 1;
                    hints.push(format!("Product {} suggests {}", product, os_family));
                }
            }

            if let Some(extra) = &service.extra_info {
                if let Some(os_family) = self.detect_os_from_extra_info(extra) {
                    *os_votes.entry(os_family).or_insert(0) += 1;
                    hints.push(format!("Service info indicates {}", os_family));
                }
            }
        }

        // Determine most likely OS
        if let Some((os_name, os_family, confidence)) = specific_os {
            Some(OsFingerprint {
                os_name: os_name.to_string(),
                os_family,
                os_version: None,
                confidence,
                cpe: self.generate_os_cpe(os_name, None),
                hints,
            })
        } else if let Some((&family, _)) = os_votes.iter().max_by_key(|(_, v)| *v) {
            Some(OsFingerprint {
                os_name: family.to_string(),
                os_family: family,
                os_version: None,
                confidence: 40,
                cpe: None,
                hints,
            })
        } else {
            None
        }
    }

    /// Detect OS from a banner string
    fn detect_os_from_banner(&self, banner: &str) -> Option<OsInfo> {
        let banner_lower = banner.to_lowercase();

        // Check for specific OS patterns
        for pattern in &self.os_patterns {
            if banner_lower.contains(pattern.pattern) {
                return Some(OsInfo {
                    os_name: pattern.os_name,
                    os_family: pattern.os_family,
                    confidence: 70,
                });
            }
        }

        // Generic OS detection
        if banner_lower.contains("ubuntu") {
            return Some(OsInfo {
                os_name: "Ubuntu Linux",
                os_family: OsFamily::Linux,
                confidence: 80,
            });
        }
        if banner_lower.contains("debian") {
            return Some(OsInfo {
                os_name: "Debian Linux",
                os_family: OsFamily::Linux,
                confidence: 80,
            });
        }
        if banner_lower.contains("centos") {
            return Some(OsInfo {
                os_name: "CentOS Linux",
                os_family: OsFamily::Linux,
                confidence: 80,
            });
        }
        if banner_lower.contains("red hat") || banner_lower.contains("rhel") {
            return Some(OsInfo {
                os_name: "Red Hat Enterprise Linux",
                os_family: OsFamily::Linux,
                confidence: 80,
            });
        }
        if banner_lower.contains("fedora") {
            return Some(OsInfo {
                os_name: "Fedora Linux",
                os_family: OsFamily::Linux,
                confidence: 80,
            });
        }
        if banner_lower.contains("freebsd") {
            return Some(OsInfo {
                os_name: "FreeBSD",
                os_family: OsFamily::Bsd,
                confidence: 80,
            });
        }
        if banner_lower.contains("openbsd") {
            return Some(OsInfo {
                os_name: "OpenBSD",
                os_family: OsFamily::Bsd,
                confidence: 80,
            });
        }
        if banner_lower.contains("windows") || banner_lower.contains("microsoft") {
            return Some(OsInfo {
                os_name: "Windows",
                os_family: OsFamily::Windows,
                confidence: 70,
            });
        }
        if banner_lower.contains("darwin") || banner_lower.contains("macos") {
            return Some(OsInfo {
                os_name: "macOS",
                os_family: OsFamily::MacOs,
                confidence: 80,
            });
        }

        None
    }

    /// Infer OS family from product name
    fn infer_os_from_product(&self, product: &str) -> Option<OsFamily> {
        let product_lower = product.to_lowercase();

        // Windows-specific products
        if product_lower.contains("iis")
            || product_lower.contains("microsoft")
            || product_lower.contains("exchange")
            || product_lower.contains("mssql")
        {
            return Some(OsFamily::Windows);
        }

        // Linux-specific or cross-platform leaning Linux
        if product_lower.contains("apache")
            || product_lower.contains("nginx")
            || product_lower.contains("openssh")
            || product_lower.contains("postfix")
            || product_lower.contains("exim")
        {
            // These run on Linux primarily but also other Unix-likes
            return Some(OsFamily::Linux);
        }

        None
    }

    /// Detect OS from extra service info
    fn detect_os_from_extra_info(&self, extra: &str) -> Option<OsFamily> {
        let extra_lower = extra.to_lowercase();

        if extra_lower.contains("ubuntu")
            || extra_lower.contains("debian")
            || extra_lower.contains("centos")
            || extra_lower.contains("fedora")
        {
            return Some(OsFamily::Linux);
        }
        if extra_lower.contains("windows") {
            return Some(OsFamily::Windows);
        }
        if extra_lower.contains("freebsd") || extra_lower.contains("openbsd") {
            return Some(OsFamily::Bsd);
        }

        None
    }

    /// Generate CPE string for OS
    fn generate_os_cpe(&self, os_name: &str, version: Option<&str>) -> Option<String> {
        let os_lower = os_name.to_lowercase();
        let ver = version.unwrap_or("*");

        if os_lower.contains("ubuntu") {
            return Some(format!("cpe:2.3:o:canonical:ubuntu_linux:{}:*:*:*:*:*:*:*", ver));
        }
        if os_lower.contains("debian") {
            return Some(format!("cpe:2.3:o:debian:debian_linux:{}:*:*:*:*:*:*:*", ver));
        }
        if os_lower.contains("centos") {
            return Some(format!("cpe:2.3:o:centos:centos:{}:*:*:*:*:*:*:*", ver));
        }
        if os_lower.contains("red hat") {
            return Some(format!(
                "cpe:2.3:o:redhat:enterprise_linux:{}:*:*:*:*:*:*:*",
                ver
            ));
        }
        if os_lower.contains("windows") {
            return Some(format!("cpe:2.3:o:microsoft:windows:{}:*:*:*:*:*:*:*", ver));
        }
        if os_lower.contains("freebsd") {
            return Some(format!("cpe:2.3:o:freebsd:freebsd:{}:*:*:*:*:*:*:*", ver));
        }

        None
    }

    /// Build default OS detection patterns
    fn default_os_patterns() -> Vec<OsPattern> {
        vec![
            OsPattern {
                pattern: "ubuntu",
                os_name: "Ubuntu Linux",
                os_family: OsFamily::Linux,
                version_regex: Some(r"Ubuntu[/ ](\d+\.\d+)"),
            },
            OsPattern {
                pattern: "debian",
                os_name: "Debian Linux",
                os_family: OsFamily::Linux,
                version_regex: Some(r"Debian[/ ](\d+)"),
            },
            OsPattern {
                pattern: "centos",
                os_name: "CentOS Linux",
                os_family: OsFamily::Linux,
                version_regex: Some(r"CentOS[/ ](\d+)"),
            },
            OsPattern {
                pattern: "red hat",
                os_name: "Red Hat Enterprise Linux",
                os_family: OsFamily::Linux,
                version_regex: None,
            },
            OsPattern {
                pattern: "fedora",
                os_name: "Fedora Linux",
                os_family: OsFamily::Linux,
                version_regex: Some(r"Fedora[/ ](\d+)"),
            },
            OsPattern {
                pattern: "alpine",
                os_name: "Alpine Linux",
                os_family: OsFamily::Linux,
                version_regex: None,
            },
            OsPattern {
                pattern: "arch linux",
                os_name: "Arch Linux",
                os_family: OsFamily::Linux,
                version_regex: None,
            },
            OsPattern {
                pattern: "freebsd",
                os_name: "FreeBSD",
                os_family: OsFamily::Bsd,
                version_regex: Some(r"FreeBSD[/ ](\d+\.\d+)"),
            },
            OsPattern {
                pattern: "openbsd",
                os_name: "OpenBSD",
                os_family: OsFamily::Bsd,
                version_regex: Some(r"OpenBSD[/ ](\d+\.\d+)"),
            },
            OsPattern {
                pattern: "netbsd",
                os_name: "NetBSD",
                os_family: OsFamily::Bsd,
                version_regex: None,
            },
            OsPattern {
                pattern: "microsoft-iis",
                os_name: "Windows Server",
                os_family: OsFamily::Windows,
                version_regex: None,
            },
            OsPattern {
                pattern: "win32",
                os_name: "Windows",
                os_family: OsFamily::Windows,
                version_regex: None,
            },
            OsPattern {
                pattern: "win64",
                os_name: "Windows",
                os_family: OsFamily::Windows,
                version_regex: None,
            },
        ]
    }
}

/// Internal struct for OS detection results
struct OsInfo {
    os_name: &'static str,
    os_family: OsFamily,
    confidence: u8,
}

/// Combined fingerprint result for a host
#[derive(Debug, Clone)]
pub struct HostFingerprint {
    /// Target IP address
    pub ip: IpAddr,
    /// OS fingerprint if detected
    pub os: Option<OsFingerprint>,
    /// Detected services by port
    pub services: HashMap<u16, ServiceInfo>,
    /// Raw banners by port
    pub banners: HashMap<u16, String>,
    /// Overall fingerprint confidence
    pub confidence: u8,
}

impl HostFingerprint {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            os: None,
            services: HashMap::new(),
            banners: HashMap::new(),
            confidence: 0,
        }
    }

    /// Add a service detection result
    pub fn add_service(&mut self, port: u16, service: ServiceInfo) {
        self.services.insert(port, service);
        self.update_confidence();
    }

    /// Add a banner
    pub fn add_banner(&mut self, port: u16, banner: String) {
        self.banners.insert(port, banner);
    }

    /// Set OS fingerprint
    pub fn set_os(&mut self, os: OsFingerprint) {
        self.os = Some(os);
        self.update_confidence();
    }

    /// Update overall confidence based on collected data
    fn update_confidence(&mut self) {
        let mut total_confidence = 0u32;
        let mut count = 0u32;

        if let Some(ref os) = self.os {
            total_confidence += os.confidence as u32;
            count += 1;
        }

        for service in self.services.values() {
            total_confidence += service.confidence as u32;
            count += 1;
        }

        self.confidence = if count > 0 {
            (total_confidence / count) as u8
        } else {
            0
        };
    }

    /// Get a summary of detected services
    pub fn service_summary(&self) -> String {
        let mut parts: Vec<String> = self
            .services
            .iter()
            .map(|(port, svc)| {
                if let Some(ref product) = svc.product {
                    format!("{}/{} ({})", port, svc.name, product)
                } else {
                    format!("{}/{}", port, svc.name)
                }
            })
            .collect();
        parts.sort();
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner::ProbeType;

    #[test]
    fn test_os_detection_from_banner() {
        let fingerprinter = Fingerprinter::new();

        let banners = vec![BannerResult {
            raw: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_vec(),
            text: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string(),
            probe_used: ProbeType::Null,
        }];

        let os = fingerprinter.fingerprint_os(&banners, &[]);
        assert!(os.is_some());
        let os = os.unwrap();
        assert_eq!(os.os_family, OsFamily::Linux);
        assert!(os.os_name.contains("Ubuntu"));
    }

    #[test]
    fn test_host_fingerprint() {
        let mut fp = HostFingerprint::new("192.168.1.1".parse().unwrap());

        fp.add_service(
            22,
            ServiceInfo::new("ssh")
                .with_product("OpenSSH")
                .with_version("8.9"),
        );
        fp.add_service(80, ServiceInfo::new("http").with_product("nginx"));

        assert_eq!(fp.services.len(), 2);
        assert!(fp.service_summary().contains("22/ssh"));
        assert!(fp.service_summary().contains("80/http"));
    }
}
