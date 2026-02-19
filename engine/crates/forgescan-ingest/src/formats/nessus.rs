//! Nessus file format parser (.nessus XML)

use crate::normalize::{NormalizedAsset, NormalizedFinding, NormalizedFindingBuilder};
use crate::{IngestResult, IngestStats, Vendor};
use chrono::Utc;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// Parse a Nessus XML file
pub async fn parse_nessus_file(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
    let start = Instant::now();
    let path = path.as_ref();

    info!("Parsing Nessus file: {}", path.display());

    let content = tokio::fs::read_to_string(path).await?;
    parse_nessus_xml(&content, start)
}

/// Parse Nessus XML content
pub fn parse_nessus_xml(xml: &str, start: Instant) -> anyhow::Result<IngestResult> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut findings = Vec::new();
    let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
    let mut stats = IngestStats::default();

    let mut current_host: Option<NessusHost> = None;
    let mut current_item: Option<NessusReportItem> = None;
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match current_element.as_str() {
                    "ReportHost" => {
                        current_host = Some(NessusHost::default());

                        // Get host name from attribute
                        for attr in e.attributes().filter_map(|a| a.ok()) {
                            if attr.key.as_ref() == b"name" {
                                if let Ok(name) = attr.unescape_value() {
                                    current_host.as_mut().unwrap().name = name.to_string();
                                }
                            }
                        }
                    }
                    "ReportItem" => {
                        current_item = Some(NessusReportItem::default());

                        // Get attributes
                        for attr in e.attributes().filter_map(|a| a.ok()) {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            if let Ok(value) = attr.unescape_value() {
                                let item = current_item.as_mut().unwrap();
                                match key.as_str() {
                                    "port" => item.port = value.parse().ok(),
                                    "svc_name" => item.service = Some(value.to_string()),
                                    "protocol" => item.protocol = Some(value.to_string()),
                                    "severity" => item.severity = value.parse().unwrap_or(0),
                                    "pluginID" => item.plugin_id = value.to_string(),
                                    "pluginName" => item.plugin_name = value.to_string(),
                                    "pluginFamily" => item.plugin_family = Some(value.to_string()),
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                if name == "ReportItem" {
                    if let (Some(ref host), Some(item)) = (&current_host, current_item.take()) {
                        stats.records_processed += 1;

                        // Skip informational
                        if item.severity == 0 {
                            stats.records_skipped += 1;
                        } else {
                            let finding = build_finding(host, &item);

                            // Track assets
                            if !assets.contains_key(&finding.asset.id) {
                                assets.insert(finding.asset.id.clone(), finding.asset.clone());
                            }

                            findings.push(finding);
                            stats.records_imported += 1;
                        }
                    }
                } else if name == "ReportHost" {
                    current_host = None;
                }

                current_element.clear();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();

                if let Some(ref mut host) = current_host {
                    if current_element.as_str() == "tag" {
                        // Handle host properties in tag elements
                    }
                }

                if let Some(ref mut item) = current_item {
                    match current_element.as_str() {
                        "description" => item.description = Some(text),
                        "synopsis" => item.synopsis = Some(text),
                        "solution" => item.solution = Some(text),
                        "plugin_output" => item.plugin_output = Some(text),
                        "cve" => item.cves.push(text),
                        "cwe" => item.cwes.push(text),
                        "cvss3_base_score" => item.cvss3_score = text.parse().ok(),
                        "cvss3_vector" => item.cvss3_vector = Some(text),
                        "cvss_base_score" => item.cvss2_score = text.parse().ok(),
                        "cvss_vector" => item.cvss2_vector = Some(text),
                        "exploit_available" => {
                            item.exploit_available = text == "true" || text == "1";
                        }
                        "xref" => item.xrefs.push(text),
                        "see_also" => item.see_also.push(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                warn!("Error parsing Nessus XML: {}", e);
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
        "Nessus parse complete: {} findings, {} assets in {}ms",
        findings.len(),
        assets.len(),
        stats.duration_ms
    );

    Ok(IngestResult {
        vendor: Vendor::Nessus,
        imported_at: Utc::now(),
        findings,
        assets: assets.into_values().collect(),
        stats,
        errors: Vec::new(),
    })
}

fn build_finding(host: &NessusHost, item: &NessusReportItem) -> NormalizedFinding {
    let severity = match item.severity {
        4 => forgescan_core::Severity::Critical,
        3 => forgescan_core::Severity::High,
        2 => forgescan_core::Severity::Medium,
        1 => forgescan_core::Severity::Low,
        _ => forgescan_core::Severity::Info,
    };

    let mut builder = NormalizedFindingBuilder::new("nessus", &item.plugin_id, &item.plugin_name)
        .severity(severity);

    // Description
    if let Some(ref desc) = item.description {
        builder = builder.description(desc);
    } else if let Some(ref synopsis) = item.synopsis {
        builder = builder.description(synopsis);
    }

    // CVSS
    if let Some(score) = item.cvss3_score {
        builder = builder.cvss(score, item.cvss3_vector.as_deref());
    } else if let Some(score) = item.cvss2_score {
        builder = builder.cvss(score, item.cvss2_vector.as_deref());
    }

    // CVEs
    if !item.cves.is_empty() {
        builder = builder.cves(item.cves.clone());
    }

    // Asset info
    if host.name.contains('.') && !host.name.chars().all(|c| c.is_numeric() || c == '.') {
        // Looks like a hostname
        builder = builder.asset_hostname(&host.name);
    } else {
        // Looks like an IP
        builder = builder.asset_ip(&host.name);
    }

    // Port
    if let Some(port) = item.port {
        if port > 0 {
            builder = builder.port(port, item.protocol.as_deref());
        }
    }

    // Service
    if let Some(ref service) = item.service {
        builder = builder.service(service);
    }

    // Solution
    if let Some(ref solution) = item.solution {
        builder = builder.solution(solution);
    }

    // Evidence
    if let Some(ref output) = item.plugin_output {
        builder = builder.evidence(output);
    }

    // Exploit
    builder = builder.exploit_available(item.exploit_available);

    // Family
    if let Some(ref family) = item.plugin_family {
        builder = builder.family(family);
    }

    // References
    for xref in &item.xrefs {
        builder = builder.reference(xref);
    }
    for url in &item.see_also {
        builder = builder.reference(url);
    }

    builder.build()
}

#[derive(Debug, Default)]
struct NessusHost {
    name: String,
    ip: Option<String>,
    fqdn: Option<String>,
    os: Option<String>,
    mac: Option<String>,
}

#[derive(Debug, Default)]
struct NessusReportItem {
    plugin_id: String,
    plugin_name: String,
    plugin_family: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    service: Option<String>,
    severity: u8,
    description: Option<String>,
    synopsis: Option<String>,
    solution: Option<String>,
    plugin_output: Option<String>,
    cves: Vec<String>,
    cwes: Vec<String>,
    cvss3_score: Option<f32>,
    cvss3_vector: Option<String>,
    cvss2_score: Option<f32>,
    cvss2_vector: Option<String>,
    exploit_available: bool,
    xrefs: Vec<String>,
    see_also: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_nessus() {
        let xml = r#"<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="192.168.1.1">
      <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="12345" pluginName="Test Plugin" pluginFamily="General">
        <description>Test description</description>
        <solution>Update software</solution>
        <cve>CVE-2023-1234</cve>
        <cvss3_base_score>6.5</cvss3_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"#;

        let result = parse_nessus_xml(xml, Instant::now()).unwrap();

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].vendor_id, "12345");
        assert_eq!(result.findings[0].cve_ids.len(), 1);
    }
}
