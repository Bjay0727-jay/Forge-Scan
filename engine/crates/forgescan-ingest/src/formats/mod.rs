//! File format parsers for vulnerability data import

pub mod csv;
pub mod json;
pub mod nessus;
pub mod qualys_xml;

pub use csv::{detect_csv_format, parse_csv, parse_csv_file};
pub use json::{parse_json, parse_json_file};
pub use nessus::{parse_nessus_file, parse_nessus_xml};
pub use qualys_xml::{parse_qualys_file, parse_qualys_xml};

/// CSV column mapping configuration
/// Each field contains possible column names (case-insensitive)
#[derive(Debug, Clone)]
pub struct CsvMapping {
    /// Columns for vulnerability ID
    pub vuln_id: Vec<String>,
    /// Columns for vulnerability title
    pub title: Vec<String>,
    /// Columns for severity
    pub severity: Vec<String>,
    /// Columns for CVE IDs
    pub cve: Vec<String>,
    /// Columns for CVSS score
    pub cvss_score: Vec<String>,
    /// Columns for CVSS vector
    pub cvss_vector: Vec<String>,
    /// Columns for IP address
    pub asset_ip: Vec<String>,
    /// Columns for hostname
    pub asset_hostname: Vec<String>,
    /// Columns for port
    pub port: Vec<String>,
    /// Columns for protocol
    pub protocol: Vec<String>,
    /// Columns for description
    pub description: Vec<String>,
    /// Columns for solution
    pub solution: Vec<String>,
    /// Columns for evidence/output
    pub evidence: Vec<String>,
    /// Columns for family/category
    pub family: Vec<String>,
}

impl Default for CsvMapping {
    fn default() -> Self {
        Self {
            vuln_id: vec![
                "id".to_string(),
                "vuln_id".to_string(),
                "vulnerability_id".to_string(),
            ],
            title: vec![
                "title".to_string(),
                "name".to_string(),
                "summary".to_string(),
            ],
            severity: vec![
                "severity".to_string(),
                "risk".to_string(),
                "level".to_string(),
            ],
            cve: vec!["cve".to_string(), "cve_id".to_string(), "cves".to_string()],
            cvss_score: vec![
                "cvss".to_string(),
                "cvss_score".to_string(),
                "cvss3_score".to_string(),
            ],
            cvss_vector: vec![
                "cvss_vector".to_string(),
                "cvss3_vector".to_string(),
                "vector".to_string(),
            ],
            asset_ip: vec![
                "ip".to_string(),
                "host_ip".to_string(),
                "target".to_string(),
            ],
            asset_hostname: vec![
                "hostname".to_string(),
                "host".to_string(),
                "dns".to_string(),
                "fqdn".to_string(),
            ],
            port: vec!["port".to_string()],
            protocol: vec!["protocol".to_string(), "proto".to_string()],
            description: vec![
                "description".to_string(),
                "details".to_string(),
                "synopsis".to_string(),
            ],
            solution: vec![
                "solution".to_string(),
                "remediation".to_string(),
                "fix".to_string(),
            ],
            evidence: vec![
                "evidence".to_string(),
                "output".to_string(),
                "result".to_string(),
            ],
            family: vec![
                "family".to_string(),
                "category".to_string(),
                "type".to_string(),
            ],
        }
    }
}

impl CsvMapping {
    /// Create mapping for Tenable.io CSV export format
    pub fn tenable_csv() -> Self {
        Self {
            vuln_id: vec!["Plugin ID".to_string(), "plugin".to_string()],
            title: vec![
                "Plugin Name".to_string(),
                "Name".to_string(),
                "Title".to_string(),
            ],
            severity: vec!["Severity".to_string(), "Risk".to_string()],
            cve: vec!["CVE".to_string(), "CVEs".to_string()],
            cvss_score: vec![
                "CVSS v3.0 Base Score".to_string(),
                "CVSS V3 Base Score".to_string(),
                "CVSS v2.0 Base Score".to_string(),
                "CVSS".to_string(),
            ],
            cvss_vector: vec![
                "CVSS v3.0 Vector".to_string(),
                "CVSS V3 Vector".to_string(),
                "CVSS v2.0 Vector".to_string(),
            ],
            asset_ip: vec![
                "Host".to_string(),
                "IP Address".to_string(),
                "IP".to_string(),
            ],
            asset_hostname: vec![
                "DNS Name".to_string(),
                "NetBIOS Name".to_string(),
                "Hostname".to_string(),
            ],
            port: vec!["Port".to_string()],
            protocol: vec!["Protocol".to_string()],
            description: vec!["Synopsis".to_string(), "Description".to_string()],
            solution: vec!["Solution".to_string()],
            evidence: vec!["Plugin Output".to_string(), "Output".to_string()],
            family: vec!["Plugin Family".to_string(), "Family".to_string()],
        }
    }

    /// Create mapping for Qualys CSV export format
    pub fn qualys_csv() -> Self {
        Self {
            vuln_id: vec!["QID".to_string()],
            title: vec!["Title".to_string(), "Vulnerability".to_string()],
            severity: vec!["Severity".to_string()],
            cve: vec![
                "CVE ID".to_string(),
                "CVE".to_string(),
                "Associated CVEs".to_string(),
            ],
            cvss_score: vec![
                "CVSS Base".to_string(),
                "CVSS3 Base".to_string(),
                "CVSS Score".to_string(),
            ],
            cvss_vector: vec!["CVSS Vector".to_string(), "CVSS3 Vector".to_string()],
            asset_ip: vec!["IP".to_string(), "IP Address".to_string()],
            asset_hostname: vec![
                "DNS".to_string(),
                "DNS Name".to_string(),
                "Hostname".to_string(),
            ],
            port: vec!["Port".to_string()],
            protocol: vec!["Protocol".to_string()],
            description: vec!["Threat".to_string(), "Description".to_string()],
            solution: vec!["Solution".to_string()],
            evidence: vec!["Results".to_string(), "Result".to_string()],
            family: vec!["Category".to_string(), "Type".to_string()],
        }
    }

    /// Create mapping for Nessus CSV export format
    pub fn nessus_csv() -> Self {
        Self {
            vuln_id: vec!["Plugin ID".to_string()],
            title: vec!["Name".to_string(), "Plugin Name".to_string()],
            severity: vec!["Risk".to_string(), "Severity".to_string()],
            cve: vec!["CVE".to_string()],
            cvss_score: vec![
                "CVSS v3.0 Base Score".to_string(),
                "CVSS v2.0 Base Score".to_string(),
            ],
            cvss_vector: vec![
                "CVSS v3.0 Vector".to_string(),
                "CVSS v2.0 Vector".to_string(),
            ],
            asset_ip: vec!["Host".to_string(), "IP".to_string()],
            asset_hostname: vec!["DNS Name".to_string(), "FQDN".to_string()],
            port: vec!["Port".to_string()],
            protocol: vec!["Protocol".to_string()],
            description: vec!["Synopsis".to_string(), "Description".to_string()],
            solution: vec!["Solution".to_string()],
            evidence: vec!["Plugin Output".to_string()],
            family: vec!["Plugin Family".to_string()],
        }
    }

    /// Create mapping for Rapid7 InsightVM CSV export format
    pub fn rapid7_csv() -> Self {
        Self {
            vuln_id: vec![
                "Vulnerability ID".to_string(),
                "Nexpose ID".to_string(),
                "Vuln ID".to_string(),
            ],
            title: vec![
                "Vulnerability Title".to_string(),
                "Title".to_string(),
                "Name".to_string(),
            ],
            severity: vec!["Severity".to_string(), "Risk Score".to_string()],
            cve: vec!["CVE".to_string(), "CVEs".to_string(), "CVE IDs".to_string()],
            cvss_score: vec![
                "CVSS Score".to_string(),
                "CVSSv3 Score".to_string(),
                "CVSS v3 Score".to_string(),
            ],
            cvss_vector: vec!["CVSS Vector".to_string(), "CVSSv3 Vector".to_string()],
            asset_ip: vec![
                "Asset IP Address".to_string(),
                "IP Address".to_string(),
                "IP".to_string(),
            ],
            asset_hostname: vec![
                "Asset Name".to_string(),
                "Hostname".to_string(),
                "Host Name".to_string(),
            ],
            port: vec!["Service Port".to_string(), "Port".to_string()],
            protocol: vec!["Service Protocol".to_string(), "Protocol".to_string()],
            description: vec!["Description".to_string(), "Synopsis".to_string()],
            solution: vec!["Solution".to_string(), "Remediation".to_string()],
            evidence: vec![
                "Proof".to_string(),
                "Evidence".to_string(),
                "Output".to_string(),
            ],
            family: vec!["Category".to_string(), "Vulnerability Category".to_string()],
        }
    }

    /// Create mapping for CrowdStrike Spotlight CSV export format
    pub fn crowdstrike_csv() -> Self {
        Self {
            vuln_id: vec!["CVE ID".to_string(), "Vulnerability ID".to_string()],
            title: vec!["Vulnerability Name".to_string(), "Name".to_string()],
            severity: vec!["Severity".to_string(), "ExPRT Rating".to_string()],
            cve: vec!["CVE ID".to_string(), "CVE".to_string()],
            cvss_score: vec!["Base Score".to_string(), "CVSS Score".to_string()],
            cvss_vector: vec!["Vector String".to_string()],
            asset_ip: vec!["Local IP".to_string(), "IP Address".to_string()],
            asset_hostname: vec![
                "Hostname".to_string(),
                "Host Name".to_string(),
                "ComputerName".to_string(),
            ],
            port: vec![],
            protocol: vec![],
            description: vec!["Description".to_string()],
            solution: vec!["Remediation".to_string()],
            evidence: vec![],
            family: vec!["Product".to_string(), "Vendor".to_string()],
        }
    }

    /// Create mapping for AWS Inspector CSV export format
    pub fn aws_inspector_csv() -> Self {
        Self {
            vuln_id: vec!["Finding ARN".to_string(), "Finding ID".to_string()],
            title: vec!["Title".to_string(), "Finding Title".to_string()],
            severity: vec!["Severity".to_string()],
            cve: vec!["Vulnerability ID".to_string(), "CVE".to_string()],
            cvss_score: vec!["Inspector Score".to_string(), "CVSS Score".to_string()],
            cvss_vector: vec![],
            asset_ip: vec!["Network Reachability".to_string()],
            asset_hostname: vec![
                "Resource ID".to_string(),
                "Instance ID".to_string(),
                "EC2 Instance".to_string(),
            ],
            port: vec!["Port".to_string()],
            protocol: vec!["Protocol".to_string()],
            description: vec!["Description".to_string()],
            solution: vec!["Remediation".to_string(), "Recommendation".to_string()],
            evidence: vec![],
            family: vec!["Finding Type".to_string(), "Type".to_string()],
        }
    }
}
