//! JSON file format parser for vulnerability data
//!
//! Supports multiple JSON formats:
//! - Generic vulnerability JSON
//! - SARIF (Static Analysis Results Interchange Format)
//! - Custom vendor exports

use crate::normalize::{NormalizedAsset, NormalizedFindingBuilder, Normalizer};
use crate::{IngestResult, IngestStats, Vendor};
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tracing::info;

/// Parse a JSON vulnerability export file
pub async fn parse_json_file(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
    let start = Instant::now();
    let path = path.as_ref();

    info!("Parsing JSON file: {}", path.display());

    let content = tokio::fs::read_to_string(path).await?;
    parse_json(&content, start)
}

/// Parse JSON content and auto-detect format
pub fn parse_json(json_content: &str, start: Instant) -> anyhow::Result<IngestResult> {
    let value: Value = serde_json::from_str(json_content)?;

    // Try to detect format
    if is_sarif(&value) {
        return parse_sarif(value, start);
    }

    if is_generic_vuln_array(&value) {
        return parse_generic_array(value, start);
    }

    // Try as object with findings array
    if let Some(findings) = value.get("findings").or(value.get("vulnerabilities")) {
        if findings.is_array() {
            return parse_findings_object(value, start);
        }
    }

    anyhow::bail!("Unrecognized JSON format. Expected SARIF, findings array, or generic vulnerability format.")
}

/// Check if JSON is SARIF format
fn is_sarif(value: &Value) -> bool {
    value
        .get("$schema")
        .and_then(|s| s.as_str())
        .map(|s| s.contains("sarif"))
        .unwrap_or(false)
        || value
            .get("version")
            .and_then(|v| v.as_str())
            .map(|v| v.starts_with("2."))
            .unwrap_or(false)
            && value.get("runs").is_some()
}

/// Check if JSON is a generic vulnerability array
fn is_generic_vuln_array(value: &Value) -> bool {
    if let Some(arr) = value.as_array() {
        if let Some(first) = arr.first() {
            return first.get("id").is_some()
                || first.get("vuln_id").is_some()
                || first.get("vulnerability_id").is_some()
                || first.get("cve").is_some();
        }
    }
    false
}

/// Parse SARIF format
fn parse_sarif(value: Value, start: Instant) -> anyhow::Result<IngestResult> {
    let mut findings = Vec::new();
    let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
    let mut stats = IngestStats::default();

    let runs = value
        .get("runs")
        .and_then(|r| r.as_array())
        .unwrap_or(&Vec::new())
        .clone();

    for run in runs {
        let tool_name = run
            .get("tool")
            .and_then(|t| t.get("driver"))
            .and_then(|d| d.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        // Get rule definitions for enrichment
        let rules: HashMap<String, &Value> = run
            .get("tool")
            .and_then(|t| t.get("driver"))
            .and_then(|d| d.get("rules"))
            .and_then(|r| r.as_array())
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|r| {
                        r.get("id")
                            .and_then(|id| id.as_str())
                            .map(|id| (id.to_string(), r))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let results = run.get("results").and_then(|r| r.as_array());

        for result in results.unwrap_or(&Vec::new()) {
            stats.records_processed += 1;

            let rule_id = result.get("ruleId").and_then(|r| r.as_str()).unwrap_or("");
            if rule_id.is_empty() {
                stats.records_skipped += 1;
                continue;
            }

            // Get rule details
            let rule = rules.get(rule_id);

            let title = result
                .get("message")
                .and_then(|m| m.get("text"))
                .and_then(|t| t.as_str())
                .or_else(|| {
                    rule.and_then(|r| {
                        r.get("shortDescription")
                            .and_then(|d| d.get("text"))
                            .and_then(|t| t.as_str())
                    })
                })
                .unwrap_or(rule_id);

            // Map SARIF level to severity
            let level = result
                .get("level")
                .and_then(|l| l.as_str())
                .unwrap_or("warning");
            let severity = match level {
                "error" => forgescan_core::Severity::High,
                "warning" => forgescan_core::Severity::Medium,
                "note" => forgescan_core::Severity::Low,
                _ => forgescan_core::Severity::Info,
            };

            let mut builder =
                NormalizedFindingBuilder::new(tool_name, rule_id, title).severity(severity);

            // Description from rule
            if let Some(desc) = rule.and_then(|r| {
                r.get("fullDescription")
                    .and_then(|d| d.get("text"))
                    .and_then(|t| t.as_str())
            }) {
                builder = builder.description(desc);
            }

            // Extract location info
            if let Some(locations) = result.get("locations").and_then(|l| l.as_array()) {
                if let Some(loc) = locations.first() {
                    if let Some(physical) = loc.get("physicalLocation") {
                        if let Some(uri) = physical
                            .get("artifactLocation")
                            .and_then(|a| a.get("uri"))
                            .and_then(|u| u.as_str())
                        {
                            builder = builder.asset_hostname(uri);
                        }
                    }
                }
            }

            // Extract CWE from rule tags
            if let Some(tags) = rule.and_then(|r| {
                r.get("properties")
                    .and_then(|p| p.get("tags"))
                    .and_then(|t| t.as_array())
            }) {
                let cwes: Vec<String> = tags
                    .iter()
                    .filter_map(|t| t.as_str())
                    .filter(|t| t.starts_with("CWE-"))
                    .map(|t| t.to_string())
                    .collect();

                if !cwes.is_empty() {
                    builder = builder.cwes(cwes);
                }
            }

            // Solution/help from rule
            if let Some(help) = rule.and_then(|r| {
                r.get("help")
                    .and_then(|h| h.get("text"))
                    .and_then(|t| t.as_str())
            }) {
                builder = builder.solution(help);
            }

            let finding = builder.build();

            if !assets.contains_key(&finding.asset.id) {
                assets.insert(finding.asset.id.clone(), finding.asset.clone());
            }

            findings.push(finding);
            stats.records_imported += 1;
        }
    }

    stats.unique_assets = assets.len() as u32;
    stats.unique_vulns = findings
        .iter()
        .map(|f| &f.vendor_id)
        .collect::<std::collections::HashSet<_>>()
        .len() as u32;
    stats.duration_ms = start.elapsed().as_millis() as u64;

    info!(
        "SARIF parse complete: {} findings, {} assets in {}ms",
        findings.len(),
        assets.len(),
        stats.duration_ms
    );

    Ok(IngestResult {
        vendor: Vendor::Sarif,
        imported_at: Utc::now(),
        findings,
        assets: assets.into_values().collect(),
        stats,
        errors: Vec::new(),
    })
}

/// Parse generic vulnerability array format
fn parse_generic_array(value: Value, start: Instant) -> anyhow::Result<IngestResult> {
    let mut findings = Vec::new();
    let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
    let mut stats = IngestStats::default();

    let arr = value.as_array().unwrap();

    for item in arr {
        stats.records_processed += 1;

        let vuln_id = get_string_field(
            item,
            &["id", "vuln_id", "vulnerability_id", "plugin_id", "qid"],
        );
        let title = get_string_field(item, &["title", "name", "summary", "description"]);

        if vuln_id.is_empty() || title.is_empty() {
            stats.records_skipped += 1;
            continue;
        }

        let severity_str = get_string_field(item, &["severity", "risk", "level", "priority"]);
        let cvss_str = get_string_field(
            item,
            &["cvss", "cvss_score", "cvss3_score", "cvss_base_score"],
        );
        let cvss_score: Option<f32> = cvss_str
            .parse()
            .ok()
            .or_else(|| item.get("cvss").and_then(|v| v.as_f64()).map(|f| f as f32))
            .or_else(|| {
                item.get("cvss_score")
                    .and_then(|v| v.as_f64())
                    .map(|f| f as f32)
            });

        let severity = Normalizer::normalize_severity("generic", &severity_str, cvss_score);

        let mut builder =
            NormalizedFindingBuilder::new("generic", &vuln_id, &title).severity(severity);

        // Description
        let description = get_string_field(item, &["description", "details", "synopsis"]);
        if !description.is_empty() && description != title {
            builder = builder.description(&description);
        }

        // CVSS
        if let Some(score) = cvss_score {
            let vector = get_string_field(item, &["cvss_vector", "cvss3_vector", "vector"]);
            builder = builder.cvss(
                score,
                if vector.is_empty() {
                    None
                } else {
                    Some(&vector)
                },
            );
        }

        // CVEs
        let cve_str = get_string_field(item, &["cve", "cves", "cve_id"]);
        if !cve_str.is_empty() {
            let cves = Normalizer::extract_cves(&cve_str);
            if !cves.is_empty() {
                builder = builder.cves(cves);
            }
        }

        // Also check for CVE array
        if let Some(cve_arr) = item
            .get("cves")
            .or(item.get("cve"))
            .and_then(|c| c.as_array())
        {
            let cves: Vec<String> = cve_arr
                .iter()
                .filter_map(|c| c.as_str())
                .filter(|c| c.starts_with("CVE-"))
                .map(|c| c.to_string())
                .collect();
            if !cves.is_empty() {
                builder = builder.cves(cves);
            }
        }

        // Asset info
        let ip = get_string_field(item, &["ip", "host_ip", "asset_ip", "target"]);
        if !ip.is_empty() {
            builder = builder.asset_ip(&ip);
        }

        let hostname =
            get_string_field(item, &["hostname", "host", "dns", "fqdn", "asset_hostname"]);
        if !hostname.is_empty() {
            builder = builder.asset_hostname(&hostname);
        }

        // Port
        let port_str = get_string_field(item, &["port"]);
        let port: Option<u16> = port_str
            .parse()
            .ok()
            .or_else(|| item.get("port").and_then(|p| p.as_u64()).map(|p| p as u16));

        if let Some(port) = port {
            let protocol = get_string_field(item, &["protocol", "proto"]);
            builder = builder.port(
                port,
                if protocol.is_empty() {
                    None
                } else {
                    Some(&protocol)
                },
            );
        }

        // Solution
        let solution =
            get_string_field(item, &["solution", "remediation", "fix", "recommendation"]);
        if !solution.is_empty() {
            builder = builder.solution(&solution);
        }

        // Evidence
        let evidence = get_string_field(item, &["evidence", "output", "result", "proof"]);
        if !evidence.is_empty() {
            builder = builder.evidence(&evidence);
        }

        // Family
        let family = get_string_field(item, &["family", "category", "type", "plugin_family"]);
        if !family.is_empty() {
            builder = builder.family(&family);
        }

        let finding = builder.build();

        if !assets.contains_key(&finding.asset.id) {
            assets.insert(finding.asset.id.clone(), finding.asset.clone());
        }

        findings.push(finding);
        stats.records_imported += 1;
    }

    stats.unique_assets = assets.len() as u32;
    stats.unique_vulns = findings
        .iter()
        .map(|f| &f.vendor_id)
        .collect::<std::collections::HashSet<_>>()
        .len() as u32;
    stats.duration_ms = start.elapsed().as_millis() as u64;

    info!(
        "Generic JSON parse complete: {} findings, {} assets in {}ms",
        findings.len(),
        assets.len(),
        stats.duration_ms
    );

    Ok(IngestResult {
        vendor: Vendor::Generic,
        imported_at: Utc::now(),
        findings,
        assets: assets.into_values().collect(),
        stats,
        errors: Vec::new(),
    })
}

/// Parse object with findings array
fn parse_findings_object(value: Value, start: Instant) -> anyhow::Result<IngestResult> {
    let findings_arr = value
        .get("findings")
        .or(value.get("vulnerabilities"))
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();

    // Convert to generic array format
    let arr_value = Value::Array(findings_arr);
    parse_generic_array(arr_value, start)
}

/// Get string field from JSON value trying multiple field names
fn get_string_field(value: &Value, field_names: &[&str]) -> String {
    for name in field_names {
        if let Some(v) = value.get(*name) {
            if let Some(s) = v.as_str() {
                if !s.trim().is_empty() {
                    return s.trim().to_string();
                }
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_generic_array() {
        let json = r#"[
            {
                "id": "VULN-001",
                "title": "SQL Injection",
                "severity": "high",
                "cvss": 9.8,
                "cve": "CVE-2023-1234",
                "ip": "10.0.0.1",
                "port": 443
            },
            {
                "id": "VULN-002",
                "title": "XSS Vulnerability",
                "severity": "medium",
                "hostname": "web.example.com"
            }
        ]"#;

        let result = parse_json(json, Instant::now()).unwrap();

        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].vendor_id, "VULN-001");
        assert_eq!(result.findings[0].title, "SQL Injection");
    }

    #[test]
    fn test_parse_sarif() {
        let sarif = r#"{
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner",
                            "rules": [
                                {
                                    "id": "RULE-001",
                                    "shortDescription": { "text": "Test Rule" }
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "RULE-001",
                            "level": "error",
                            "message": { "text": "Found vulnerability" }
                        }
                    ]
                }
            ]
        }"#;

        let result = parse_json(sarif, Instant::now()).unwrap();

        assert_eq!(result.vendor, Vendor::Sarif);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].vendor_id, "RULE-001");
    }

    #[test]
    fn test_parse_findings_object() {
        let json = r#"{
            "scan_id": "12345",
            "findings": [
                {
                    "id": "F001",
                    "title": "Test Finding",
                    "severity": "high"
                }
            ]
        }"#;

        let result = parse_json(json, Instant::now()).unwrap();

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].vendor_id, "F001");
    }
}
