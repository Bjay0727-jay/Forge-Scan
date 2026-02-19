//! CSV file format parser for vulnerability data

//! CSV file format parser for vulnerability data

use crate::formats::CsvMapping;
use crate::normalize::{NormalizedAsset, NormalizedFinding, NormalizedFindingBuilder, Normalizer};
use crate::{IngestResult, IngestStats, Vendor};
use chrono::Utc;
use csv::ReaderBuilder;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn};

/// Parse a CSV vulnerability export file
pub async fn parse_csv_file(
    path: impl AsRef<Path>,
    mapping: &CsvMapping,
    vendor: Vendor,
) -> anyhow::Result<IngestResult> {
    let start = Instant::now();
    let path = path.as_ref();

    info!("Parsing CSV file: {}", path.display());

    let content = tokio::fs::read_to_string(path).await?;
    parse_csv(&content, mapping, vendor, start)
}

/// Parse CSV content with field mapping
pub fn parse_csv(
    csv_content: &str,
    mapping: &CsvMapping,
    vendor: Vendor,
    start: Instant,
) -> anyhow::Result<IngestResult> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(csv_content.as_bytes());

    let headers = reader.headers()?.clone();
    let header_map: HashMap<String, usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| (h.to_lowercase(), i))
        .collect();

    let mut findings = Vec::new();
    let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
    let mut stats = IngestStats::default();

    for result in reader.records() {
        stats.records_processed += 1;

        let record = match result {
            Ok(r) => r,
            Err(e) => {
                warn!("Error parsing CSV row {}: {}", stats.records_processed, e);
                stats.records_skipped += 1;
                continue;
            }
        };

        // Extract fields using mapping
        let vuln_id = get_field(&record, &header_map, &mapping.vuln_id);
        let title = get_field(&record, &header_map, &mapping.title);

        // Skip if missing required fields
        if vuln_id.is_empty() || title.is_empty() {
            stats.records_skipped += 1;
            continue;
        }

        let severity_str = get_field(&record, &header_map, &mapping.severity);
        let cvss_str = get_field(&record, &header_map, &mapping.cvss_score);
        let cvss_score: Option<f32> = cvss_str.parse().ok();

        let severity = Normalizer::normalize_severity(vendor.as_str(), &severity_str, cvss_score);

        // Build finding
        let mut builder =
            NormalizedFindingBuilder::new(vendor.as_str(), &vuln_id, &title).severity(severity);

        // Description
        let description = get_field(&record, &header_map, &mapping.description);
        if !description.is_empty() {
            builder = builder.description(&description);
        }

        // CVSS
        if let Some(score) = cvss_score {
            let vector = get_field(&record, &header_map, &mapping.cvss_vector);
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
        let cve_str = get_field(&record, &header_map, &mapping.cve);
        if !cve_str.is_empty() {
            let cves = Normalizer::extract_cves(&cve_str);
            if !cves.is_empty() {
                builder = builder.cves(cves);
            }
        }

        // Asset IP
        let ip = get_field(&record, &header_map, &mapping.asset_ip);
        if !ip.is_empty() {
            builder = builder.asset_ip(&ip);
        }

        // Asset hostname
        let hostname = get_field(&record, &header_map, &mapping.asset_hostname);
        if !hostname.is_empty() {
            builder = builder.asset_hostname(&hostname);
        }

        // Port
        let port_str = get_field(&record, &header_map, &mapping.port);
        if let Ok(port) = port_str.parse::<u16>() {
            let protocol = get_field(&record, &header_map, &mapping.protocol);
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
        let solution = get_field(&record, &header_map, &mapping.solution);
        if !solution.is_empty() {
            builder = builder.solution(&solution);
        }

        // Evidence/output
        let evidence = get_field(&record, &header_map, &mapping.evidence);
        if !evidence.is_empty() {
            builder = builder.evidence(&evidence);
        }

        // Family/category
        let family = get_field(&record, &header_map, &mapping.family);
        if !family.is_empty() {
            builder = builder.family(&family);
        }

        let finding = builder.build();

        // Track assets
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
        "CSV parse complete: {} findings, {} assets in {}ms",
        findings.len(),
        assets.len(),
        stats.duration_ms
    );

    Ok(IngestResult {
        vendor,
        imported_at: Utc::now(),
        findings,
        assets: assets.into_values().collect(),
        stats,
        errors: Vec::new(),
    })
}

/// Get field value from CSV record using column mapping
fn get_field(
    record: &csv::StringRecord,
    header_map: &HashMap<String, usize>,
    column_names: &[String],
) -> String {
    for name in column_names {
        let lowercase = name.to_lowercase();
        if let Some(&idx) = header_map.get(&lowercase) {
            if let Some(value) = record.get(idx) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    String::new()
}

/// Auto-detect CSV format based on headers
pub fn detect_csv_format(csv_content: &str) -> Option<(CsvMapping, Vendor)> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());

    let headers = reader.headers().ok()?;
    let header_set: std::collections::HashSet<String> =
        headers.iter().map(|h| h.to_lowercase()).collect();

    // Check for Tenable CSV format
    if header_set.contains("plugin id") || header_set.contains("plugin") {
        return Some((CsvMapping::tenable_csv(), Vendor::Tenable));
    }

    // Check for Qualys CSV format
    if header_set.contains("qid") {
        return Some((CsvMapping::qualys_csv(), Vendor::Qualys));
    }

    // Check for Nessus CSV format
    if header_set.contains("plugin id") && header_set.contains("cve") {
        return Some((CsvMapping::nessus_csv(), Vendor::Tenable));
    }

    // Check for Rapid7 CSV format
    if header_set.contains("vulnerability id") || header_set.contains("nexpose id") {
        return Some((CsvMapping::rapid7_csv(), Vendor::Rapid7));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_csv() {
        let csv = r#"Plugin ID,Title,Severity,IP,Port,CVE
12345,Test Vulnerability,High,10.0.0.1,443,CVE-2023-1234
67890,Another Vuln,Medium,10.0.0.2,80,CVE-2023-5678"#;

        let mapping = CsvMapping::tenable_csv();
        let result = parse_csv(csv, &mapping, Vendor::Tenable, Instant::now()).unwrap();

        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].vendor_id, "12345");
        assert_eq!(result.findings[1].vendor_id, "67890");
    }

    #[test]
    fn test_auto_detect_tenable() {
        let csv = "Plugin ID,Title,Severity,Host IP\n12345,Test,High,10.0.0.1";
        let detected = detect_csv_format(csv);
        assert!(detected.is_some());
        let (_, vendor) = detected.unwrap();
        assert_eq!(vendor, Vendor::Tenable);
    }

    #[test]
    fn test_auto_detect_qualys() {
        let csv = "QID,Title,Severity,IP\n12345,Test,4,10.0.0.1";
        let detected = detect_csv_format(csv);
        assert!(detected.is_some());
        let (_, vendor) = detected.unwrap();
        assert_eq!(vendor, Vendor::Qualys);
    }
}
