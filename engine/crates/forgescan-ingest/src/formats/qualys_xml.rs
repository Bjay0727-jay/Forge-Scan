//! Qualys XML file format parser

use crate::normalize::{NormalizedAsset, NormalizedFinding, NormalizedFindingBuilder, Normalizer};
use crate::{IngestResult, IngestStats, Vendor};
use chrono::Utc;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// Parse a Qualys XML export file
pub async fn parse_qualys_file(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
    let start = Instant::now();
    let path = path.as_ref();

    info!("Parsing Qualys XML file: {}", path.display());

    let content = tokio::fs::read_to_string(path).await?;
    parse_qualys_xml(&content, start)
}

/// Parse Qualys XML content
pub fn parse_qualys_xml(xml: &str, start: Instant) -> anyhow::Result<IngestResult> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut findings = Vec::new();
    let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
    let mut stats = IngestStats::default();

    let mut current_host: Option<QualysHost> = None;
    let mut current_vuln: Option<QualysVuln> = None;
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match current_element.as_str() {
                    "HOST" => {
                        current_host = Some(QualysHost::default());
                    }
                    "VULN" | "CAT" | "DETECTION" => {
                        current_vuln = Some(QualysVuln::default());
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                if name == "VULN" || name == "CAT" || name == "DETECTION" {
                    if let (Some(ref host), Some(vuln)) = (&current_host, current_vuln.take()) {
                        stats.records_processed += 1;

                        // Skip informational (severity 0 or 1)
                        if vuln.severity <= 1 {
                            stats.records_skipped += 1;
                        } else {
                            let finding = build_finding(host, &vuln);

                            // Track assets
                            if !assets.contains_key(&finding.asset.id) {
                                assets.insert(finding.asset.id.clone(), finding.asset.clone());
                            }

                            findings.push(finding);
                            stats.records_imported += 1;
                        }
                    }
                } else if name == "HOST" {
                    current_host = None;
                }

                current_element.clear();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();

                if let Some(ref mut host) = current_host {
                    match current_element.as_str() {
                        "IP" => host.ip = Some(text.clone()),
                        "DNS" => host.dns = Some(text.clone()),
                        "NETBIOS" => host.netbios = Some(text.clone()),
                        "OS" => host.os = Some(text.clone()),
                        _ => {}
                    }
                }

                if let Some(ref mut vuln) = current_vuln {
                    match current_element.as_str() {
                        "QID" => vuln.qid = text.clone(),
                        "TITLE" => vuln.title = text.clone(),
                        "SEVERITY" => vuln.severity = text.parse().unwrap_or(1),
                        "CATEGORY" => vuln.category = Some(text.clone()),
                        "CONSEQUENCE" | "IMPACT" => vuln.consequence = Some(text.clone()),
                        "SOLUTION" => vuln.solution = Some(text.clone()),
                        "RESULT" | "RESULTS" => vuln.results = Some(text.clone()),
                        "CVE_ID" | "CVE" => {
                            for cve in text.split(',') {
                                let cve = cve.trim();
                                if cve.starts_with("CVE-") {
                                    vuln.cves.push(cve.to_string());
                                }
                            }
                        }
                        "CVSS_BASE" | "CVSS3_BASE" => {
                            vuln.cvss_score = text.parse().ok();
                        }
                        "CVSS3_VECTOR" | "CVSS_VECTOR" => {
                            vuln.cvss_vector = Some(text);
                        }
                        "PORT" => vuln.port = text.parse().ok(),
                        "PROTOCOL" => vuln.protocol = Some(text),
                        "SSL" => vuln.ssl = text == "1" || text.to_lowercase() == "true",
                        "FIRST_FOUND" | "FIRST_FOUND_DATETIME" => {
                            vuln.first_found = Some(text);
                        }
                        "LAST_FOUND" | "LAST_FOUND_DATETIME" => {
                            vuln.last_found = Some(text);
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                warn!("Error parsing Qualys XML: {}", e);
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    stats.unique_assets = assets.len() as u32;
    stats.unique_vulns = findings
        .iter()
        .map(|f| &f.vendor_id)
        .collect::<std::collections::HashSet<_>>()
        .len() as u32;
    stats.duration_ms = start.elapsed().as_millis() as u64;

    info!(
        "Qualys XML parse complete: {} findings, {} assets in {}ms",
        findings.len(),
        assets.len(),
        stats.duration_ms
    );

    Ok(IngestResult {
        vendor: Vendor::Qualys,
        imported_at: Utc::now(),
        findings,
        assets: assets.into_values().collect(),
        stats,
        errors: Vec::new(),
    })
}

fn build_finding(host: &QualysHost, vuln: &QualysVuln) -> NormalizedFinding {
    let severity =
        Normalizer::normalize_severity("qualys", &vuln.severity.to_string(), vuln.cvss_score);

    let mut builder =
        NormalizedFindingBuilder::new("qualys", &vuln.qid, &vuln.title).severity(severity);

    // Description
    if let Some(ref consequence) = vuln.consequence {
        builder = builder.description(consequence);
    }

    // CVSS
    if let Some(score) = vuln.cvss_score {
        builder = builder.cvss(score, vuln.cvss_vector.as_deref());
    }

    // CVEs
    if !vuln.cves.is_empty() {
        builder = builder.cves(vuln.cves.clone());
    }

    // Asset info
    if let Some(ref ip) = host.ip {
        builder = builder.asset_ip(ip);
    }
    if let Some(ref dns) = host.dns {
        builder = builder.asset_hostname(dns);
    }

    // Port
    if let Some(port) = vuln.port {
        builder = builder.port(port, vuln.protocol.as_deref());
    }

    // Solution
    if let Some(ref solution) = vuln.solution {
        builder = builder.solution(solution);
    }

    // Evidence
    if let Some(ref results) = vuln.results {
        builder = builder.evidence(results);
    }

    // Family
    if let Some(ref category) = vuln.category {
        builder = builder.family(category);
    }

    builder.build()
}

#[derive(Debug, Default)]
struct QualysHost {
    ip: Option<String>,
    dns: Option<String>,
    netbios: Option<String>,
    os: Option<String>,
}

#[derive(Debug, Default)]
struct QualysVuln {
    qid: String,
    title: String,
    severity: u8,
    category: Option<String>,
    consequence: Option<String>,
    solution: Option<String>,
    results: Option<String>,
    cves: Vec<String>,
    cvss_score: Option<f32>,
    cvss_vector: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    ssl: bool,
    first_found: Option<String>,
    last_found: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_qualys() {
        let xml = r#"<?xml version="1.0"?>
<HOST_LIST>
  <HOST>
    <IP>10.0.0.1</IP>
    <DNS>server.example.com</DNS>
    <VULN>
      <QID>12345</QID>
      <TITLE>Test Vulnerability</TITLE>
      <SEVERITY>4</SEVERITY>
      <CVE_ID>CVE-2023-1234</CVE_ID>
      <PORT>443</PORT>
      <PROTOCOL>tcp</PROTOCOL>
    </VULN>
  </HOST>
</HOST_LIST>"#;

        let result = parse_qualys_xml(xml, Instant::now()).unwrap();

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].vendor_id, "12345");
    }
}
