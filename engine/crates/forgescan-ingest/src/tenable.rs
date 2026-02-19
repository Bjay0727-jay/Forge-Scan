//! Tenable.io and Nessus data ingestion

use crate::normalize::{
    NormalizedAsset, NormalizedFinding, NormalizedFindingBuilder, Normalizer,
};
use crate::{IngestConfig, IngestResult, IngestStats, Vendor, VendorIngester};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, info};

/// Tenable.io configuration
#[derive(Debug, Clone)]
pub struct TenableConfig {
    /// API URL (default: https://cloud.tenable.com)
    pub api_url: String,
    /// Access key
    pub access_key: String,
    /// Secret key
    pub secret_key: String,
}

impl TenableConfig {
    /// Create from environment variables
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            api_url: std::env::var("TENABLE_API_URL")
                .unwrap_or_else(|_| "https://cloud.tenable.com".to_string()),
            access_key: std::env::var("TENABLE_ACCESS_KEY")
                .map_err(|_| anyhow::anyhow!("TENABLE_ACCESS_KEY not set"))?,
            secret_key: std::env::var("TENABLE_SECRET_KEY")
                .map_err(|_| anyhow::anyhow!("TENABLE_SECRET_KEY not set"))?,
        })
    }

    /// Create with explicit credentials
    pub fn new(access_key: &str, secret_key: &str) -> Self {
        Self {
            api_url: "https://cloud.tenable.com".to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        }
    }
}

/// Tenable.io ingester
pub struct TenableIngester {
    config: TenableConfig,
    client: Client,
}

impl TenableIngester {
    /// Create a new Tenable ingester
    pub fn new(config: TenableConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Make authenticated API request
    async fn api_get<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> anyhow::Result<T> {
        let url = format!("{}{}", self.config.api_url, endpoint);

        let response = self
            .client
            .get(&url)
            .header(
                "X-ApiKeys",
                format!(
                    "accessKey={}; secretKey={}",
                    self.config.access_key, self.config.secret_key
                ),
            )
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Tenable API error ({}): {}", status, body);
        }

        let data = response.json().await?;
        Ok(data)
    }

    /// Export vulnerabilities
    async fn export_vulns(&self, config: &IngestConfig) -> anyhow::Result<Vec<TenableVuln>> {
        // Start export
        let export_request = VulnExportRequest {
            num_assets: config.batch_size,
            filters: VulnExportFilters {
                severity: if config.include_info {
                    vec!["info", "low", "medium", "high", "critical"]
                } else {
                    vec!["low", "medium", "high", "critical"]
                },
                state: vec!["open", "reopened"],
            },
        };

        let start_response: VulnExportStartResponse = self
            .client
            .post(format!("{}/vulns/export", self.config.api_url))
            .header(
                "X-ApiKeys",
                format!(
                    "accessKey={}; secretKey={}",
                    self.config.access_key, self.config.secret_key
                ),
            )
            .json(&export_request)
            .send()
            .await?
            .json()
            .await?;

        let export_uuid = start_response.export_uuid;
        debug!("Started Tenable export: {}", export_uuid);

        // Poll for completion
        loop {
            let status: VulnExportStatusResponse = self
                .api_get(&format!("/vulns/export/{}/status", export_uuid))
                .await?;

            match status.status.as_str() {
                "FINISHED" => break,
                "ERROR" => anyhow::bail!("Tenable export failed"),
                "CANCELLED" => anyhow::bail!("Tenable export was cancelled"),
                _ => {
                    debug!(
                        "Export status: {} ({} chunks)",
                        status.status,
                        status.chunks_available.len()
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }

        // Download chunks
        let status: VulnExportStatusResponse = self
            .api_get(&format!("/vulns/export/{}/status", export_uuid))
            .await?;

        let mut all_vulns = Vec::new();

        for chunk_id in &status.chunks_available {
            let vulns: Vec<TenableVuln> = self
                .api_get(&format!(
                    "/vulns/export/{}/chunks/{}",
                    export_uuid, chunk_id
                ))
                .await?;

            all_vulns.extend(vulns);
        }

        Ok(all_vulns)
    }

    /// Convert Tenable vuln to normalized finding
    fn normalize_vuln(&self, vuln: &TenableVuln) -> NormalizedFinding {
        let severity =
            Normalizer::normalize_severity("tenable", &vuln.severity, vuln.plugin.cvss3_base_score);

        let mut builder = NormalizedFindingBuilder::new(
            "tenable",
            &vuln.plugin.id.to_string(),
            &vuln.plugin.name,
        )
        .description(&vuln.plugin.description)
        .severity(severity);

        // CVSS
        if let Some(score) = vuln.plugin.cvss3_base_score {
            builder = builder.cvss(score, vuln.plugin.cvss3_vector.as_deref());
        }

        // CVEs
        if !vuln.plugin.cve.is_empty() {
            builder = builder.cves(vuln.plugin.cve.clone());
        }

        // Asset info
        if let Some(ref ip) = vuln.asset.ipv4 {
            builder = builder.asset_ip(ip);
        }
        if let Some(ref hostname) = vuln.asset.hostname {
            builder = builder.asset_hostname(hostname);
        }

        // Port
        if let Some(port) = vuln.port.port {
            builder = builder.port(port, vuln.port.protocol.as_deref());
        }

        // Service
        if let Some(ref service) = vuln.port.service {
            builder = builder.service(service);
        }

        // Solution
        if let Some(ref solution) = vuln.plugin.solution {
            builder = builder.solution(solution);
        }

        // Evidence
        if let Some(ref output) = vuln.output {
            builder = builder.evidence(output);
        }

        // Exploit
        builder = builder.exploit_available(vuln.plugin.exploit_available.unwrap_or(false));

        // Family
        builder = builder.family(&vuln.plugin.family);

        // References
        for xref in &vuln.plugin.xrefs {
            builder = builder.reference(&format!("{}: {}", xref.r#type, xref.id));
        }

        // Timestamps
        if let Some(ref first) = vuln.first_found {
            if let Ok(dt) = DateTime::parse_from_rfc3339(first) {
                builder = builder.first_seen(dt.with_timezone(&Utc));
            }
        }
        if let Some(ref last) = vuln.last_found {
            if let Ok(dt) = DateTime::parse_from_rfc3339(last) {
                builder = builder.last_seen(dt.with_timezone(&Utc));
            }
        }

        builder.build()
    }
}

#[async_trait::async_trait]
impl VendorIngester for TenableIngester {
    fn vendor(&self) -> Vendor {
        Vendor::Tenable
    }

    async fn test_connection(&self) -> anyhow::Result<bool> {
        let _: serde_json::Value = self.api_get("/server/status").await?;
        Ok(true)
    }

    async fn sync(&self, config: &IngestConfig) -> anyhow::Result<IngestResult> {
        let start = Instant::now();
        info!("Starting Tenable.io sync");

        let vulns = self.export_vulns(config).await?;

        let mut findings = Vec::new();
        let mut assets: HashMap<String, NormalizedAsset> = HashMap::new();
        let mut errors = Vec::new();
        let mut stats = IngestStats::default();

        for vuln in &vulns {
            stats.records_processed += 1;

            let finding = self.normalize_vuln(vuln);

            // Track unique assets
            if !assets.contains_key(&finding.asset.id) {
                assets.insert(finding.asset.id.clone(), finding.asset.clone());
            }

            findings.push(finding);
            stats.records_imported += 1;
        }

        stats.unique_assets = assets.len() as u32;
        stats.unique_vulns = findings.len() as u32;
        stats.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "Tenable sync complete: {} findings, {} assets in {}ms",
            findings.len(),
            assets.len(),
            stats.duration_ms
        );

        Ok(IngestResult {
            vendor: Vendor::Tenable,
            imported_at: Utc::now(),
            findings,
            assets: assets.into_values().collect(),
            stats,
            errors,
        })
    }

    async fn sync_since(
        &self,
        since: DateTime<Utc>,
        config: &IngestConfig,
    ) -> anyhow::Result<IngestResult> {
        // For now, just do a full sync and filter
        // Tenable API supports date filtering in the export request
        self.sync(config).await
    }
}

// Tenable API response structures

#[derive(Debug, Deserialize)]
struct VulnExportStartResponse {
    export_uuid: String,
}

#[derive(Debug, Serialize)]
struct VulnExportRequest {
    num_assets: u32,
    filters: VulnExportFilters,
}

#[derive(Debug, Serialize)]
struct VulnExportFilters {
    severity: Vec<&'static str>,
    state: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct VulnExportStatusResponse {
    status: String,
    chunks_available: Vec<u32>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TenableVuln {
    asset: TenableAsset,
    plugin: TenablePlugin,
    port: TenablePort,
    severity: String,
    output: Option<String>,
    first_found: Option<String>,
    last_found: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TenableAsset {
    uuid: Option<String>,
    hostname: Option<String>,
    ipv4: Option<String>,
    ipv6: Option<String>,
    operating_system: Option<Vec<String>>,
    fqdn: Option<Vec<String>>,
    mac_address: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct TenablePlugin {
    id: u64,
    name: String,
    family: String,
    description: String,
    solution: Option<String>,
    #[serde(default)]
    cve: Vec<String>,
    cvss3_base_score: Option<f32>,
    cvss3_vector: Option<String>,
    exploit_available: Option<bool>,
    #[serde(default)]
    xrefs: Vec<TenableXref>,
}

#[derive(Debug, Deserialize)]
struct TenablePort {
    port: Option<u16>,
    protocol: Option<String>,
    service: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TenableXref {
    r#type: String,
    id: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_config_from_env() {
        // Would require env vars to be set
    }
}
