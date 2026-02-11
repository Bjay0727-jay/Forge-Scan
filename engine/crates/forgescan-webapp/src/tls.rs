//! TLS/SSL configuration analyzer

use forgescan_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, warn};
use url::Url;

/// TLS connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// TLS protocol version
    pub protocol_version: String,
    /// Cipher suite
    pub cipher_suite: Option<String>,
    /// Certificate information
    pub certificate: Option<CertificateInfo>,
    /// Supported protocols
    pub supported_protocols: Vec<String>,
    /// Issues found
    pub issues: Vec<TlsIssue>,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject common name
    pub subject_cn: String,
    /// Issuer common name
    pub issuer_cn: String,
    /// Subject alternative names
    pub san: Vec<String>,
    /// Not valid before
    pub not_before: String,
    /// Not valid after
    pub not_after: String,
    /// Days until expiry
    pub days_until_expiry: i64,
    /// Is self-signed
    pub is_self_signed: bool,
    /// Certificate chain length
    pub chain_length: usize,
    /// Key type and size
    pub key_info: String,
    /// Signature algorithm
    pub signature_algorithm: String,
}

/// TLS issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsIssue {
    /// Issue title
    pub title: String,
    /// Issue description
    pub description: String,
    /// Severity
    pub severity: Severity,
    /// Remediation
    pub remediation: String,
}

/// TLS analyzer
pub struct TlsAnalyzer;

impl TlsAnalyzer {
    /// Analyze TLS configuration of a target
    pub async fn analyze(url: &Url) -> anyhow::Result<TlsInfo> {
        let host = url.host_str().ok_or_else(|| anyhow::anyhow!("No host in URL"))?;
        let port = url.port().unwrap_or(443);

        debug!("Analyzing TLS for {}:{}", host, port);

        let mut issues = Vec::new();
        let mut supported_protocols = Vec::new();

        // Check for deprecated protocols
        let deprecated_protocols = [
            ("SSLv2", false), // Almost never supported anymore
            ("SSLv3", false),
            ("TLSv1.0", true),
            ("TLSv1.1", true),
        ];

        // In a real implementation, we'd test each protocol
        // For now, we'll use the native TLS connection to get info

        // Try to connect and get TLS info
        let tls_info = Self::probe_tls(host, port).await?;

        // Check protocol version
        if tls_info.protocol_version.contains("1.0") {
            issues.push(TlsIssue {
                title: "TLS 1.0 in use".into(),
                description: "TLS 1.0 is deprecated and has known vulnerabilities".into(),
                severity: Severity::High,
                remediation: "Disable TLS 1.0 and use TLS 1.2 or 1.3".into(),
            });
        }

        if tls_info.protocol_version.contains("1.1") {
            issues.push(TlsIssue {
                title: "TLS 1.1 in use".into(),
                description: "TLS 1.1 is deprecated".into(),
                severity: Severity::Medium,
                remediation: "Disable TLS 1.1 and use TLS 1.2 or 1.3".into(),
            });
        }

        // Check certificate
        if let Some(ref cert) = tls_info.certificate {
            // Check expiry
            if cert.days_until_expiry <= 0 {
                issues.push(TlsIssue {
                    title: "Certificate has expired".into(),
                    description: format!("Certificate expired {} days ago", -cert.days_until_expiry),
                    severity: Severity::Critical,
                    remediation: "Renew the SSL/TLS certificate immediately".into(),
                });
            } else if cert.days_until_expiry <= 30 {
                issues.push(TlsIssue {
                    title: "Certificate expires soon".into(),
                    description: format!("Certificate expires in {} days", cert.days_until_expiry),
                    severity: Severity::Medium,
                    remediation: "Renew the SSL/TLS certificate before expiration".into(),
                });
            }

            // Check self-signed
            if cert.is_self_signed {
                issues.push(TlsIssue {
                    title: "Self-signed certificate".into(),
                    description: "Certificate is self-signed and not trusted by browsers".into(),
                    severity: Severity::Medium,
                    remediation: "Use a certificate from a trusted Certificate Authority".into(),
                });
            }

            // Check weak key
            if cert.key_info.contains("RSA") {
                if let Some(size) = extract_key_size(&cert.key_info) {
                    if size < 2048 {
                        issues.push(TlsIssue {
                            title: "Weak RSA key".into(),
                            description: format!("RSA key size is {} bits, minimum recommended is 2048", size),
                            severity: Severity::High,
                            remediation: "Use RSA 2048+ or switch to ECDSA".into(),
                        });
                    }
                }
            }

            // Check weak signature algorithm
            let weak_algorithms = ["SHA1", "MD5", "MD2"];
            for alg in weak_algorithms {
                if cert.signature_algorithm.to_uppercase().contains(alg) {
                    issues.push(TlsIssue {
                        title: format!("Weak signature algorithm: {}", alg),
                        description: format!("{} is cryptographically weak", alg),
                        severity: Severity::High,
                        remediation: "Use SHA-256 or stronger signature algorithm".into(),
                    });
                }
            }
        }

        // Check cipher suite
        if let Some(ref cipher) = tls_info.cipher_suite {
            // Check for weak ciphers
            let weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"];
            for weak in weak_ciphers {
                if cipher.to_uppercase().contains(weak) {
                    issues.push(TlsIssue {
                        title: format!("Weak cipher: {}", weak),
                        description: format!("Cipher suite contains weak algorithm: {}", cipher),
                        severity: Severity::High,
                        remediation: "Disable weak cipher suites and use modern ciphers".into(),
                    });
                }
            }

            // Check for lack of forward secrecy
            if !cipher.contains("DHE") && !cipher.contains("ECDHE") {
                issues.push(TlsIssue {
                    title: "No forward secrecy".into(),
                    description: "Cipher suite doesn't provide perfect forward secrecy".into(),
                    severity: Severity::Medium,
                    remediation: "Use ECDHE or DHE key exchange for forward secrecy".into(),
                });
            }
        }

        Ok(TlsInfo {
            protocol_version: tls_info.protocol_version,
            cipher_suite: tls_info.cipher_suite,
            certificate: tls_info.certificate,
            supported_protocols,
            issues,
        })
    }

    /// Probe TLS connection
    async fn probe_tls(host: &str, port: u16) -> anyhow::Result<TlsInfo> {
        use tokio_native_tls::TlsConnector;

        let connector = native_tls::TlsConnector::builder()
            // Accept invalid certs for analysis purposes
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;

        let connector = TlsConnector::from(connector);

        let addr = format!("{}:{}", host, port);
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(&addr),
        )
        .await??;

        let tls_stream = connector.connect(host, stream).await?;

        // Get connection info
        let session = tls_stream.get_ref();

        // Extract TLS version
        let protocol_version = session
            .tls_server_end_point()
            .map(|_| "TLS 1.2/1.3") // native-tls doesn't expose version directly
            .unwrap_or("Unknown")
            .to_string();

        // Get peer certificate
        let certificate = session.peer_certificate().ok().flatten().map(|cert| {
            let der = cert.to_der().unwrap_or_default();

            // Parse certificate details using x509-parser would be ideal here
            // For now, provide basic info
            CertificateInfo {
                subject_cn: extract_cn_from_subject(&cert),
                issuer_cn: extract_cn_from_issuer(&cert),
                san: Vec::new(), // Would need x509 parsing
                not_before: "Unknown".into(),
                not_after: "Unknown".into(),
                days_until_expiry: 365, // Placeholder
                is_self_signed: extract_cn_from_subject(&cert) == extract_cn_from_issuer(&cert),
                chain_length: 1,
                key_info: "Unknown".into(),
                signature_algorithm: "Unknown".into(),
            }
        });

        Ok(TlsInfo {
            protocol_version,
            cipher_suite: None, // native-tls doesn't expose this directly
            certificate,
            supported_protocols: vec!["TLSv1.2".into(), "TLSv1.3".into()],
            issues: Vec::new(),
        })
    }

    /// Quick check if HTTPS is available
    pub async fn check_https_available(host: &str) -> bool {
        use tokio_native_tls::TlsConnector;

        let connector = native_tls::TlsConnector::new().ok();
        if connector.is_none() {
            return false;
        }

        let connector = TlsConnector::from(connector.unwrap());
        let addr = format!("{}:443", host);

        match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => connector.connect(host, stream).await.is_ok(),
            _ => false,
        }
    }
}

impl TlsInfo {
    /// Convert TLS info to security findings
    pub fn to_findings(&self, url: &Url) -> Vec<Finding> {
        self.issues
            .iter()
            .map(|issue| {
                Finding::new(&issue.title, issue.severity)
                    .with_description(&issue.description)
                    .with_affected_asset(url.as_str())
                    .with_remediation(&issue.remediation)
            })
            .collect()
    }

    /// Get overall TLS grade (A-F)
    pub fn grade(&self) -> char {
        let critical_issues = self.issues.iter().filter(|i| i.severity == Severity::Critical).count();
        let high_issues = self.issues.iter().filter(|i| i.severity == Severity::High).count();
        let medium_issues = self.issues.iter().filter(|i| i.severity == Severity::Medium).count();

        if critical_issues > 0 {
            'F'
        } else if high_issues > 1 {
            'D'
        } else if high_issues > 0 {
            'C'
        } else if medium_issues > 1 {
            'B'
        } else if medium_issues > 0 || !self.protocol_version.contains("1.3") {
            'B'
        } else {
            'A'
        }
    }
}

// Helper functions
fn extract_key_size(key_info: &str) -> Option<u32> {
    key_info
        .split_whitespace()
        .find(|s| s.parse::<u32>().is_ok())
        .and_then(|s| s.parse().ok())
}

fn extract_cn_from_subject(cert: &native_tls::Certificate) -> String {
    // Would need actual x509 parsing
    "Unknown".to_string()
}

fn extract_cn_from_issuer(cert: &native_tls::Certificate) -> String {
    // Would need actual x509 parsing
    "Unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grade_calculation() {
        let info = TlsInfo {
            protocol_version: "TLSv1.3".into(),
            cipher_suite: None,
            certificate: None,
            supported_protocols: vec!["TLSv1.3".into()],
            issues: vec![],
        };

        assert_eq!(info.grade(), 'A');

        let info_with_issues = TlsInfo {
            protocol_version: "TLSv1.2".into(),
            cipher_suite: None,
            certificate: None,
            supported_protocols: vec![],
            issues: vec![TlsIssue {
                title: "Test".into(),
                description: "Test".into(),
                severity: Severity::High,
                remediation: "Test".into(),
            }],
        };

        assert_eq!(info_with_issues.grade(), 'C');
    }
}
