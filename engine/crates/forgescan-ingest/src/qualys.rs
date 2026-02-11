//! Qualys VMDR data ingestion

use crate::normalize::{
    NormalizedAsset, NormalizedFinding, NormalizedFindingBuilder, Normalizer,
};
use crate::{IngestConfig, IngestError, IngestResult, IngestStats, Vendor, VendorIngester};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Qualys VMDR configuration
#[derive(Debug, Clone)]
pub struct QualysConfig {
    /// API URL (varies by platform, e.g., https://qualysapi.qualys.com)
    pub api_url: String,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

impl QualysConfig {
    /// Create from environment variables
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            api_url: std::env::var("QUALYS_API_URL")
                .map_err(|_| anyhow::anyhow!("QUALYS_API_URL not set"))?,
            username: std::env::var("QUALYS_USERNAME")
                .map_err(|_| anyhow::anyhow!("QUALYS_USERNAME not set"))?,
            password: std::env::var("QUALYS_PASSWORD")
                .map_err(|_| anyhow::anyhow!("QUALYS_PASSWORD not set"))?,
        })
    }

    /// Create with explicit credentials
    pub fn new(api_url: &str, username: &str, password: &str) -> Self {
        Self {
            api_url: api_url.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}

/// Qualys VMDR ingester
pub struct QualysIngester {
    config: QualysConfig,
    client: Client,
}

impl QualysIngester {
    /// Create a new Qualys ingester
    pub fn new(config: QualysConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Make authenticated API request
    async fn api_post(&self, endpoint: &str, params: &[(&str, &str)]) -> anyhow::Result<String> {
        let url = format!("{}{}", self.config.api_url, endpoint);

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .header("X-Requested-With", "ForgeScan")
            .form(params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Qualys API error ({}): {}", status, body);
        }

        Ok(response.text().await?)
    }

    /// Get host detection list
    async fn get_detections(&self, config: &IngestConfig) -> anyhow::Result<Vec<QualysDetection>> {
        let mut params = vec![
            ("action", "list"),
            ("show_results", "1"),
            ("show_igs", "1"),
            ("output_format", "XML"),
        ];

        // Add severity filter
        if !config.include_info {
            params.push(("severities", "1,2,3,4,5"));
        }

        let xml = self.api_post("/api/2.0/fo/asset/host/vm/detection/", &params).await?;

        // Parse XML response
        let detections = self.parse_detection_xml(&xml)?;
        Ok(detections)
    }

    /// Parse detection XML
    fn parse_detection_xml(&self, xml: &str) -> anyhow::Result<Vec<QualysDetection>> {
        // Using quick-xml for parsing
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut detections = Vec::new();
        let mut current_host: Option<QualysHost> = None;
        let mut current_detection: Option<QualysDetectionBuilder> = None;
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
                        "DETECTION" => {
                            current_detection = Some(QualysDetectionBuilder::default());
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    if name == "DETECTION" {
                        if let (Some(host), Some(det)) = (&current_host, current_detection.take()) {
                            detections.push(QualysDetection {
                                host: host.clone(),
                                qid: det.qid.unwrap_or_default(),
                                severity: det.severity.unwrap_or(1),
                                status: det.status.unwrap_or_default(),
                                results: det.results,
                                first_found: det.first_found,
                                last_found: det.last_found,
                                port: det.port,
                                protocol: det.protocol,
                                ssl: det.ssl.unwrap_or(false),
                            });
                        }
                    }

                    current_element.clear();
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape().unwrap_or_default().to_string();

                    if let Some(ref mut host) = current_host {
                        match current_element.as_str() {
                            "IP" => host.ip = Some(text),
                            "DNS" => host.dns = Some(text),
                            "NETBIOS" => host.netbios = Some(text),
                            "OS" => host.os = Some(text),
                            _ => {}
                        }
                    }

                    if let Some(ref mut det) = current_detection {
                        match current_element.as_str() {
                            "QID" => det.qid = text.parse().ok(),
                            "SEVERITY" => det.severity = text.parse().ok(),
                            "STATUS" => det.status = Some(text),
                            "RESULTS" => det.results = Some(text),
                            "FIRST_FOUND_DATETIME" => det.first_found = Some(text),
                            "LAST_FOUND_DATETIME" => det.last_found = Some(text),
                            "PORT" => det.port = text.parse().ok(),
                            "PROTOCOL" => det.protocol = Some(text),
                            "SSL" => det.ssl = Some(text == "1" || text.to_lowercase() == "true"),
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

        Ok(detections)
    }

    /// Get vulnerability details (knowledge base)
    async fn get_vuln_details(&self, qids: &[u64]) -> anyhow::Result<HashMap<u64, QualysVuln>> {
        if qids.is_empty() {
            return Ok(HashMap::new());
        }

        let qid_list: String = qids.iter().map(|q| q.to_string()).collect::<Vec<_>>().join(",");

        let params = vec![
            ("action", "list"),
            ("ids", &qid_list),
        ];

        let xml = self.api_post("/api/2.0/fo/knowledge_base/vuln/", &params).await?;

        let vulns = self.parse_kb_xml(&xml)?;
        Ok(vulns)
    }

    /// Parse knowledge base XML
    fn parse_kb_xml(&self, xml: &str) -> anyhow::Result<HashMap<u64, QualysVuln>> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut vulns = HashMap::new();
        let mut current_vuln: Option<QualysVuln> = None;
        let mut current_element = String::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    if current_element == "VULN" {
                        current_vuln = Some(QualysVuln::default());
                    }
                }
                Ok(Event::End(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    if name == "VULN" {
                        if let Some(vuln) = current_vuln.take() {
                            vulns.insert(vuln.qid, vuln);
                        }
                    }

                    current_element.clear();
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape().unwrap_or_default().to_string();

                    if let Some(ref mut vuln) = current_vuln {
                        match current_element.as_str() {
                            "QID" => vuln.qid = text.parse().unwrap_or_default(),
                            "TITLE" => vuln.title = text,
                            "SEVERITY" => vuln.severity = text.parse().unwrap_or(1),
                            "CATEGORY" => vuln.category = Some(text),
                            "CONSEQUENCE" => vuln.consequence = Some(text),
                            "SOLUTION" => vuln.solution = Some(text),
                            "CVE_LIST" => vuln.cves.push(text),
                            "CVSS_BASE" | "CVSS3_BASE" => {
                                vuln.cvss_base = text.parse().ok();
                            }
                            "CVSS3_VECTOR" => vuln.cvss_vector = Some(text),
                            _ => {}
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    warn!("Error parsing Qualys KB XML: {}", e);
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(vulns)
    }

    /// Convert Qualys detection to normalized finding
    fn normalize_detection(
        &self,
        detection: &QualysDetection,
        vuln: Option<&QualysVuln>,
    ) -> NormalizedFinding {
        let title = vuln
            .map(|v| v.title.clone())
            .unwrap_or_else(|| format!("QID {}", detection.qid));

        let severity = Normalizer::normalize_severity(
            "qualys",
            &detection.severity.to_string(),
            vuln.and_then(|v| v.cvss_base),
        );

        let mut builder = NormalizedFindingBuilder::new(
            "qualys",
            &detection.qid.to_string(),
            &title,
        )
        .severity(severity);

        // Description from consequence
        if let Some(v) = vuln {
            if let Some(ref consequence) = v.consequence {
                builder = builder.description(consequence);
            }

            // CVSS
            if let Some(score) = v.cvss_base {
                builder = builder.cvss(score, v.cvss_vector.as_deref());
            }

            // CVEs
            if !v.cves.is_empty() {
                builder = builder.cves(v.cves.clone());
            }

            // Solution
            if let Some(ref solution) = v.solution {
                builder = builder.solution(solution);
            }

            // Category as family
            if let Some(ref category) = v.category {
                builder = builder.family(category);
            }
        }

        // Asset info
        if let Some(ref ip) = detection.host.ip {
            builder = builder.asset_ip(ip);
        }
        if let Some(ref dns) = detection.host.dns {
            builder = builder.asset_hostname(dns);
        }

        // Port
        if let Some(port) = detection.port {
            builder = builder.port(port, detection.protocol.as_deref());
        }

        // Evidence
        if let Some(ref results) = detection.results {
            builder = builder.evidence(results);
        }

        // Timestamps
        if let Some(ref first) = detection.first_found {
            if let Ok(dt) = DateTime::parse_from_rfc3339(first) {
                builder = builder.first_seen(dt.with_timezone(&Utc));
            }
        }
        if let Some(ref last) = detection.last_found {
            if let Ok(dt) = DateTime::parse_from_rfc3339(last) {
                builder = builder.last_seen(dt.with_timezone(&Utc));
            }
        }

        builder.build()
    }
}

#[async_trait::async_trait]
impl VendorIngester for QualysIngester {
    fn vendor(&self) -> Vendor {
        Vendor::Qualys
    }

    async fn test_connection(&self) -> anyhow::Result<bool> {
        let params = [("action", "list")];
        self.api_post("/api/2.0/fo/scan/", &params).await?;
        Ok(true)
    }

    async fn sync(&self, config: &IngestConfig) -> anyhow::Result<IngestResult> {
        let start = Instant::now();
        info!("Starting Qualys VMDR sync");

        // Get all detections
        let detections = self.get_detections(config).await?;
        debug!("Retrieved {} detections", detections.len());

        // Get unique QIDs
        let qids: Vec<u64> = detections.iter().map(|d| d.qid).collect();
        let unique_qids: Vec<u64> = qids.clone().into_iter().collect::<std::collections::HashSet<_>>().into_iter().collect();

        // Get vulnerability details from knowledge base
        let vulns = self.get_vuln_details(&unique_qids).await?;
        debug!("Retrieved {} vulnerability details", vulns.len());

        let mut findings = Vec::new();
        let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
        let mut stats = IngestStats::default();

        for detection in &detections {
            stats.records_processed += 1;

            let vuln = vulns.get(&detection.qid);
            let finding = self.normalize_detection(detection, vuln);

            // Track unique assets
            if !assets.contains_key(&finding.asset.id) {
                assets.insert(finding.asset.id.clone(), finding.asset.clone());
            }

            findings.push(finding);
            stats.records_imported += 1;
        }

        stats.unique_assets = assets.len() as u32;
        stats.unique_vulns = unique_qids.len() as u32;
        stats.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "Qualys sync complete: {} findings, {} assets in {}ms",
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

    async fn sync_since(
        &self,
        since: DateTime<Utc>,
        config: &IngestConfig,
    ) -> anyhow::Result<IngestResult> {
        self.sync(config).await
    }
}

// Qualys data structures

#[derive(Debug, Clone, Default)]
struct QualysHost {
    ip: Option<String>,
    dns: Option<String>,
    netbios: Option<String>,
    os: Option<String>,
}

#[derive(Debug, Clone)]
struct QualysDetection {
    host: QualysHost,
    qid: u64,
    severity: u8,
    status: String,
    results: Option<String>,
    first_found: Option<String>,
    last_found: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    ssl: bool,
}

#[derive(Debug, Default)]
struct QualysDetectionBuilder {
    qid: Option<u64>,
    severity: Option<u8>,
    status: Option<String>,
    results: Option<String>,
    first_found: Option<String>,
    last_found: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    ssl: Option<bool>,
}

#[derive(Debug, Clone, Default)]
struct QualysVuln {
    qid: u64,
    title: String,
    severity: u8,
    category: Option<String>,
    consequence: Option<String>,
    solution: Option<String>,
    cves: Vec<String>,
    cvss_base: Option<f32>,
    cvss_vector: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = QualysConfig::new(
            "https://qualysapi.qualys.com",
            "user",
            "pass",
        );
        assert!(!config.api_url.is_empty());
    }
}
