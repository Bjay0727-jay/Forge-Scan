//! Service detection - identify services from banners and protocol probing
//!
//! This module provides service identification based on:
//! - Banner pattern matching
//! - Protocol-specific probes
//! - Port-based defaults

use regex::Regex;
use std::collections::HashMap;
use tracing::debug;

/// Information about a detected service
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name (e.g., "ssh", "http", "mysql")
    pub name: String,
    /// Product name (e.g., "OpenSSH", "Apache", "nginx")
    pub product: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Extra info (e.g., protocol version, OS info)
    pub extra_info: Option<String>,
    /// CPE (Common Platform Enumeration) identifier
    pub cpe: Option<String>,
    /// Confidence level (0-100)
    pub confidence: u8,
}

impl ServiceInfo {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            product: None,
            version: None,
            extra_info: None,
            cpe: None,
            confidence: 50,
        }
    }

    pub fn with_product(mut self, product: &str) -> Self {
        self.product = Some(product.to_string());
        self
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    pub fn with_cpe(mut self, cpe: &str) -> Self {
        self.cpe = Some(cpe.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    /// Generate a CPE string from the service info
    pub fn generate_cpe(&self) -> Option<String> {
        if self.cpe.is_some() {
            return self.cpe.clone();
        }

        let product = self.product.as_ref()?;
        let version = self.version.as_ref().map(|v| v.as_str()).unwrap_or("*");

        // Normalize product name for CPE
        let product_normalized = product.to_lowercase().replace(' ', "_");

        Some(format!(
            "cpe:2.3:a:*:{}:{}:*:*:*:*:*:*:*",
            product_normalized, version
        ))
    }
}

/// Service detector using banner matching
pub struct ServiceDetector {
    /// Banner patterns for service detection
    patterns: Vec<ServicePattern>,
}

struct ServicePattern {
    regex: Regex,
    service: String,
    product_group: Option<usize>,
    version_group: Option<usize>,
    cpe_template: Option<String>,
}

impl ServiceDetector {
    /// Create a new service detector with default patterns
    pub fn new() -> Self {
        Self {
            patterns: Self::default_patterns(),
        }
    }

    /// Detect service from a banner string
    pub fn detect_from_banner(&self, banner: &str, port: u16) -> Option<ServiceInfo> {
        // Try pattern matching first
        for pattern in &self.patterns {
            if let Some(caps) = pattern.regex.captures(banner) {
                let mut info = ServiceInfo::new(&pattern.service);

                // Extract product name
                if let Some(group) = pattern.product_group {
                    if let Some(m) = caps.get(group) {
                        info.product = Some(m.as_str().to_string());
                    }
                }

                // Extract version
                if let Some(group) = pattern.version_group {
                    if let Some(m) = caps.get(group) {
                        info.version = Some(m.as_str().to_string());
                    }
                }

                // Generate CPE
                if let Some(ref template) = pattern.cpe_template {
                    let cpe = template
                        .replace("{product}", info.product.as_deref().unwrap_or("*"))
                        .replace("{version}", info.version.as_deref().unwrap_or("*"));
                    info.cpe = Some(cpe);
                }

                info.confidence = 90;
                debug!(
                    "Detected service {} ({:?} {:?}) from banner",
                    info.name, info.product, info.version
                );
                return Some(info);
            }
        }

        // Fall back to port-based detection
        self.detect_from_port(port)
    }

    /// Detect service based on port number (low confidence)
    pub fn detect_from_port(&self, port: u16) -> Option<ServiceInfo> {
        let service = match port {
            20 => "ftp-data",
            21 => "ftp",
            22 => "ssh",
            23 => "telnet",
            25 => "smtp",
            53 => "dns",
            67 | 68 => "dhcp",
            69 => "tftp",
            80 => "http",
            88 => "kerberos",
            110 => "pop3",
            111 => "rpcbind",
            119 => "nntp",
            123 => "ntp",
            135 => "msrpc",
            137 | 138 | 139 => "netbios",
            143 => "imap",
            161 | 162 => "snmp",
            389 => "ldap",
            443 => "https",
            445 => "microsoft-ds",
            465 => "smtps",
            514 => "syslog",
            515 => "printer",
            587 => "submission",
            636 => "ldaps",
            993 => "imaps",
            995 => "pop3s",
            1080 => "socks",
            1433 => "mssql",
            1434 => "mssql-udp",
            1521 => "oracle",
            1723 => "pptp",
            2049 => "nfs",
            2082 | 2083 => "cpanel",
            2222 => "ssh-alt",
            3306 => "mysql",
            3389 => "rdp",
            5432 => "postgresql",
            5672 => "amqp",
            5900..=5999 => "vnc",
            6379 => "redis",
            6667 => "irc",
            8000 | 8080 | 8443 | 8888 => "http-alt",
            9000 => "php-fpm",
            9200 | 9300 => "elasticsearch",
            11211 => "memcached",
            27017 => "mongodb",
            _ => return None,
        };

        Some(ServiceInfo::new(service).with_confidence(30))
    }

    /// Build default service detection patterns
    fn default_patterns() -> Vec<ServicePattern> {
        let mut patterns = Vec::new();

        // OpenSSH specific (must be before generic SSH pattern)
        if let Ok(re) = Regex::new(r"SSH-[\d.]+-OpenSSH[_-](\d+\.\d+(?:\.\d+)?[p\d]*)") {
            patterns.push(ServicePattern {
                regex: re,
                service: "ssh".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some("cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*".to_string()),
            });
        }

        // SSH (generic)
        if let Ok(re) = Regex::new(r"SSH-[\d.]+-(\S+?)(?:_(\d+[\d.]*\S*))?") {
            patterns.push(ServicePattern {
                regex: re,
                service: "ssh".to_string(),
                product_group: Some(1),
                version_group: Some(2),
                cpe_template: Some("cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*".to_string()),
            });
        }

        // Apache (specific, before generic Server header)
        if let Ok(re) = Regex::new(r"Apache(?:/(\d+\.\d+(?:\.\d+)?))?") {
            patterns.push(ServicePattern {
                regex: re,
                service: "http".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some(
                    "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*".to_string(),
                ),
            });
        }

        // nginx (specific, before generic Server header)
        if let Ok(re) = Regex::new(r"nginx(?:/(\d+\.\d+(?:\.\d+)?))?") {
            patterns.push(ServicePattern {
                regex: re,
                service: "http".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some("cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*".to_string()),
            });
        }

        // Microsoft IIS (specific, before generic Server header)
        if let Ok(re) = Regex::new(r"Microsoft-IIS(?:/(\d+\.\d+))?") {
            patterns.push(ServicePattern {
                regex: re,
                service: "http".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some(
                    "cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*"
                        .to_string(),
                ),
            });
        }

        // HTTP Server headers (generic, after specific patterns)
        if let Ok(re) = Regex::new(r"Server:\s*([^\r\n/]+)(?:/(\d+[\d.]*\S*))?") {
            patterns.push(ServicePattern {
                regex: re,
                service: "http".to_string(),
                product_group: Some(1),
                version_group: Some(2),
                cpe_template: None,
            });
        }

        // FTP banners
        if let Ok(re) =
            Regex::new(r"220[- ].*\b(vsftpd|ProFTPD|Pure-FTPd|FileZilla)\s*(\d+[\d.]*)?")
        {
            patterns.push(ServicePattern {
                regex: re,
                service: "ftp".to_string(),
                product_group: Some(1),
                version_group: Some(2),
                cpe_template: None,
            });
        }

        // MySQL
        if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+(?:-\S+)?)-.*MySQL") {
            patterns.push(ServicePattern {
                regex: re,
                service: "mysql".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some("cpe:2.3:a:mysql:mysql:{version}:*:*:*:*:*:*:*".to_string()),
            });
        }

        // MariaDB
        if let Ok(re) = Regex::new(r"(\d+\.\d+\.\d+)-MariaDB") {
            patterns.push(ServicePattern {
                regex: re,
                service: "mysql".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some("cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*".to_string()),
            });
        }

        // PostgreSQL
        if let Ok(re) = Regex::new(r"PostgreSQL\s*(\d+(?:\.\d+)*)") {
            patterns.push(ServicePattern {
                regex: re,
                service: "postgresql".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some(
                    "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*".to_string(),
                ),
            });
        }

        // SMTP
        if let Ok(re) = Regex::new(r"220[- ].*\b(Postfix|Sendmail|Exim|Exchange)\b.*?(\d+[\d.]*)?")
        {
            patterns.push(ServicePattern {
                regex: re,
                service: "smtp".to_string(),
                product_group: Some(1),
                version_group: Some(2),
                cpe_template: None,
            });
        }

        // Redis
        if let Ok(re) = Regex::new(r"\+PONG|redis_version:(\d+\.\d+\.\d+)") {
            patterns.push(ServicePattern {
                regex: re,
                service: "redis".to_string(),
                product_group: None,
                version_group: Some(1),
                cpe_template: Some("cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*".to_string()),
            });
        }

        // MongoDB
        if let Ok(re) = Regex::new(r"MongoDB|mongod") {
            patterns.push(ServicePattern {
                regex: re,
                service: "mongodb".to_string(),
                product_group: None,
                version_group: None,
                cpe_template: None,
            });
        }

        // Microsoft RDP
        if let Ok(re) = Regex::new(r"\x03\x00.{2}\x02\xf0\x80") {
            patterns.push(ServicePattern {
                regex: re,
                service: "rdp".to_string(),
                product_group: None,
                version_group: None,
                cpe_template: None,
            });
        }

        patterns
    }
}

impl Default for ServiceDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Well-known service to port mappings
pub fn get_default_port(service: &str) -> Option<u16> {
    match service.to_lowercase().as_str() {
        "ftp" => Some(21),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "dns" => Some(53),
        "http" => Some(80),
        "pop3" => Some(110),
        "imap" => Some(143),
        "https" => Some(443),
        "smtps" => Some(465),
        "imaps" => Some(993),
        "pop3s" => Some(995),
        "mssql" => Some(1433),
        "mysql" => Some(3306),
        "rdp" => Some(3389),
        "postgresql" | "postgres" => Some(5432),
        "redis" => Some(6379),
        "mongodb" => Some(27017),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_openssh() {
        let detector = ServiceDetector::new();
        let banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
        let info = detector.detect_from_banner(banner, 22).unwrap();

        assert_eq!(info.name, "ssh");
        assert!(info.version.is_some());
    }

    #[test]
    fn test_detect_apache() {
        let detector = ServiceDetector::new();
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)";
        let info = detector.detect_from_banner(banner, 80).unwrap();

        assert_eq!(info.name, "http");
    }

    #[test]
    fn test_detect_nginx() {
        let detector = ServiceDetector::new();
        let banner = "Server: nginx/1.18.0";
        let info = detector.detect_from_banner(banner, 80).unwrap();

        assert_eq!(info.name, "http");
        assert!(info.cpe.as_ref().unwrap().contains("nginx"));
    }

    #[test]
    fn test_port_fallback() {
        let detector = ServiceDetector::new();
        let info = detector.detect_from_port(3306).unwrap();

        assert_eq!(info.name, "mysql");
        assert_eq!(info.confidence, 30);
    }

    #[test]
    fn test_generate_cpe() {
        let info = ServiceInfo::new("http")
            .with_product("Apache HTTP Server")
            .with_version("2.4.52");

        let cpe = info.generate_cpe().unwrap();
        assert!(cpe.contains("apache_http_server"));
        assert!(cpe.contains("2.4.52"));
    }
}
