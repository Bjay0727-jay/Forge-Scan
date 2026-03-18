//! Accuracy validation framework
//!
//! Compares ForgeScan results against Nessus/OpenVAS baseline exports to measure:
//! - Finding overlap (true positives vs. baseline)
//! - False positive rate
//! - Missing detections (false negatives)
//!
//! Usage: import Nessus CSV or OpenVAS XML, run ForgeScan against same target,
//! then call `compare()` to generate accuracy metrics.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// A normalized finding from any scanner for comparison
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedFinding {
    /// Target host (IP or hostname)
    pub host: String,
    /// Port (0 if not applicable)
    pub port: u16,
    /// CVE IDs associated with this finding
    pub cve_ids: Vec<String>,
    /// Severity level (normalized to 1-4 scale: 1=Low, 2=Medium, 3=High, 4=Critical)
    pub severity: u8,
    /// Short title / plugin name
    pub title: String,
}

impl NormalizedFinding {
    /// Generate a comparison key: host:port + sorted CVE IDs
    fn match_key(&self) -> String {
        let mut cves = self.cve_ids.clone();
        cves.sort();
        format!("{}:{}:{}", self.host, self.port, cves.join(","))
    }
}

/// Accuracy comparison results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyReport {
    /// Total findings in ForgeScan results
    pub forgescan_total: usize,
    /// Total findings in baseline (Nessus/OpenVAS)
    pub baseline_total: usize,
    /// Findings present in both scanners (matched by host:port + CVE)
    pub true_positives: usize,
    /// Findings in ForgeScan but NOT in baseline (potential false positives)
    pub false_positives: usize,
    /// Findings in baseline but NOT in ForgeScan (missed detections)
    pub false_negatives: usize,
    /// Finding overlap percentage: true_positives / baseline_total * 100
    pub overlap_percent: f64,
    /// False positive rate: false_positives / forgescan_total * 100
    pub false_positive_rate: f64,
    /// Details of missed findings (from baseline)
    pub missed_findings: Vec<String>,
    /// Details of extra findings (ForgeScan-only)
    pub extra_findings: Vec<String>,
}

/// Compare ForgeScan results against a baseline scanner
pub fn compare(
    forgescan_findings: &[NormalizedFinding],
    baseline_findings: &[NormalizedFinding],
) -> AccuracyReport {
    let fs_keys: HashSet<String> = forgescan_findings.iter().map(|f| f.match_key()).collect();
    let bl_keys: HashSet<String> = baseline_findings.iter().map(|f| f.match_key()).collect();

    let true_positives = fs_keys.intersection(&bl_keys).count();
    let false_positives = fs_keys.difference(&bl_keys).count();
    let false_negatives = bl_keys.difference(&fs_keys).count();

    let overlap_percent = if baseline_findings.is_empty() {
        100.0
    } else {
        (true_positives as f64 / baseline_findings.len() as f64) * 100.0
    };

    let false_positive_rate = if forgescan_findings.is_empty() {
        0.0
    } else {
        (false_positives as f64 / forgescan_findings.len() as f64) * 100.0
    };

    let missed_findings: Vec<String> = baseline_findings
        .iter()
        .filter(|f| !fs_keys.contains(&f.match_key()))
        .map(|f| format!("{}:{} - {} {:?}", f.host, f.port, f.title, f.cve_ids))
        .collect();

    let extra_findings: Vec<String> = forgescan_findings
        .iter()
        .filter(|f| !bl_keys.contains(&f.match_key()))
        .map(|f| format!("{}:{} - {} {:?}", f.host, f.port, f.title, f.cve_ids))
        .collect();

    AccuracyReport {
        forgescan_total: forgescan_findings.len(),
        baseline_total: baseline_findings.len(),
        true_positives,
        false_positives,
        false_negatives,
        overlap_percent,
        false_positive_rate,
        missed_findings,
        extra_findings,
    }
}

/// Parse a Nessus CSV export into normalized findings.
///
/// Expected columns: "Host", "Port", "CVE", "Risk", "Name"
pub fn parse_nessus_csv(path: &Path) -> Result<Vec<NormalizedFinding>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read Nessus CSV: {}", e))?;

    let mut findings = Vec::new();
    let mut lines = content.lines();

    // Parse header to find column indices
    let header = lines.next().ok_or("Empty CSV file")?;
    let headers: Vec<&str> = header
        .split(',')
        .map(|h| h.trim().trim_matches('"'))
        .collect();

    let host_idx = headers.iter().position(|h| h.eq_ignore_ascii_case("Host"));
    let port_idx = headers.iter().position(|h| h.eq_ignore_ascii_case("Port"));
    let cve_idx = headers.iter().position(|h| h.eq_ignore_ascii_case("CVE"));
    let risk_idx = headers.iter().position(|h| h.eq_ignore_ascii_case("Risk"));
    let name_idx = headers.iter().position(|h| h.eq_ignore_ascii_case("Name"));

    for line in lines {
        let cols: Vec<&str> = line
            .split(',')
            .map(|c| c.trim().trim_matches('"'))
            .collect();

        let host = host_idx
            .and_then(|i| cols.get(i))
            .unwrap_or(&"")
            .to_string();
        let port: u16 = port_idx
            .and_then(|i| cols.get(i))
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let cve_str = cve_idx.and_then(|i| cols.get(i)).unwrap_or(&"");
        let risk = risk_idx.and_then(|i| cols.get(i)).unwrap_or(&"");
        let title = name_idx
            .and_then(|i| cols.get(i))
            .unwrap_or(&"")
            .to_string();

        if host.is_empty() {
            continue;
        }

        let cve_ids: Vec<String> = cve_str
            .split(';')
            .map(|s| s.trim().to_string())
            .filter(|s| s.starts_with("CVE-"))
            .collect();

        let severity = match risk.to_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };

        if severity > 0 {
            findings.push(NormalizedFinding {
                host,
                port,
                cve_ids,
                severity,
                title,
            });
        }
    }

    Ok(findings)
}

/// Convert ForgeScan core findings to normalized findings for comparison
pub fn normalize_forgescan_findings(
    findings: &[forgescan_core::Finding],
) -> Vec<NormalizedFinding> {
    findings
        .iter()
        .map(|f| {
            let severity = match f.severity {
                forgescan_core::Severity::Critical => 4,
                forgescan_core::Severity::High => 3,
                forgescan_core::Severity::Medium => 2,
                forgescan_core::Severity::Low => 1,
                _ => 0,
            };
            NormalizedFinding {
                host: f.target.clone(),
                port: f.port.unwrap_or(0),
                cve_ids: f.cve_ids.clone(),
                severity,
                title: f.title.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_findings() -> (Vec<NormalizedFinding>, Vec<NormalizedFinding>) {
        let forgescan = vec![
            NormalizedFinding {
                host: "192.168.1.1".into(),
                port: 443,
                cve_ids: vec!["CVE-2021-44228".into()],
                severity: 4,
                title: "Log4Shell RCE".into(),
            },
            NormalizedFinding {
                host: "192.168.1.1".into(),
                port: 22,
                cve_ids: vec!["CVE-2023-48795".into()],
                severity: 3,
                title: "SSH Terrapin".into(),
            },
            NormalizedFinding {
                host: "192.168.1.2".into(),
                port: 80,
                cve_ids: vec![],
                severity: 2,
                title: "HTTP header missing".into(),
            },
        ];
        let baseline = vec![
            NormalizedFinding {
                host: "192.168.1.1".into(),
                port: 443,
                cve_ids: vec!["CVE-2021-44228".into()],
                severity: 4,
                title: "Apache Log4j RCE".into(),
            },
            NormalizedFinding {
                host: "192.168.1.1".into(),
                port: 8080,
                cve_ids: vec!["CVE-2024-0001".into()],
                severity: 3,
                title: "Something ForgeScan missed".into(),
            },
        ];
        (forgescan, baseline)
    }

    #[test]
    fn test_comparison_metrics() {
        let (fs, bl) = sample_findings();
        let report = compare(&fs, &bl);

        assert_eq!(report.forgescan_total, 3);
        assert_eq!(report.baseline_total, 2);
        assert_eq!(report.true_positives, 1); // Log4Shell matched
        assert_eq!(report.false_positives, 2); // SSH Terrapin + HTTP header
        assert_eq!(report.false_negatives, 1); // CVE-2024-0001 missed
        assert_eq!(report.overlap_percent, 50.0);
        assert!(report.false_positive_rate > 60.0);
    }

    #[test]
    fn test_perfect_overlap() {
        let findings = vec![NormalizedFinding {
            host: "10.0.0.1".into(),
            port: 443,
            cve_ids: vec!["CVE-2021-44228".into()],
            severity: 4,
            title: "Log4Shell".into(),
        }];
        let report = compare(&findings, &findings);
        assert_eq!(report.overlap_percent, 100.0);
        assert_eq!(report.false_positive_rate, 0.0);
    }

    #[test]
    fn test_empty_baseline() {
        let fs = vec![NormalizedFinding {
            host: "10.0.0.1".into(),
            port: 80,
            cve_ids: vec![],
            severity: 2,
            title: "Test".into(),
        }];
        let report = compare(&fs, &[]);
        assert_eq!(report.overlap_percent, 100.0); // nothing to miss
    }
}
