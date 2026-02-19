//! Rapid7 InsightVM data ingestion

use crate::normalize::{NormalizedAsset, NormalizedFinding, NormalizedFindingBuilder, Normalizer};
use crate::{IngestConfig, IngestResult, IngestStats, Vendor, VendorIngester};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Rapid7 InsightVM configuration
#[derive(Debug, Clone)]
pub struct Rapid7Config {
    /// Console URL (e.g., https://insightvm.example.com:3780)
    pub console_url: String,
    /// API key or username
    pub api_key: String,
    /// API secret or password
    pub api_secret: Option<String>,
    /// Use API key auth (vs basic auth)
    pub use_api_key: bool,
}

impl Rapid7Config {
    /// Create from environment variables
    pub fn from_env() -> anyhow::Result<Self> {
        let api_key = std::env::var("RAPID7_API_KEY")
            .or_else(|_| std::env::var("RAPID7_USERNAME"))
            .map_err(|_| anyhow::anyhow!("RAPID7_API_KEY or RAPID7_USERNAME not set"))?;

        let api_secret = std::env::var("RAPID7_API_SECRET")
            .or_else(|_| std::env::var("RAPID7_PASSWORD"))
            .ok();

        Ok(Self {
            console_url: std::env::var("RAPID7_CONSOLE_URL")
                .map_err(|_| anyhow::anyhow!("RAPID7_CONSOLE_URL not set"))?,
            api_key,
            api_secret,
            use_api_key: std::env::var("RAPID7_USE_API_KEY")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
        })
    }

    /// Create with API key auth
    pub fn with_api_key(console_url: &str, api_key: &str) -> Self {
        Self {
            console_url: console_url.to_string(),
            api_key: api_key.to_string(),
            api_secret: None,
            use_api_key: true,
        }
    }

    /// Create with basic auth
    pub fn with_credentials(console_url: &str, username: &str, password: &str) -> Self {
        Self {
            console_url: console_url.to_string(),
            api_key: username.to_string(),
            api_secret: Some(password.to_string()),
            use_api_key: false,
        }
    }
}

/// Rapid7 InsightVM ingester
pub struct Rapid7Ingester {
    config: Rapid7Config,
    client: Client,
}

impl Rapid7Ingester {
    /// Create a new Rapid7 ingester
    pub fn new(config: Rapid7Config) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            // InsightVM often uses self-signed certs
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Make authenticated API request
    async fn api_get<T: for<'de> Deserialize<'de>>(&self, endpoint: &str) -> anyhow::Result<T> {
        let url = format!("{}/api/3{}", self.config.console_url, endpoint);

        let mut request = self.client.get(&url);

        if self.config.use_api_key {
            // API key header auth
            request = request.header("X-Api-Key", &self.config.api_key);
        } else {
            // Basic auth
            request = request.basic_auth(&self.config.api_key, self.config.api_secret.as_deref());
        }

        let response = request.header("Accept", "application/json").send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Rapid7 API error ({}): {}", status, body);
        }

        let data = response.json().await?;
        Ok(data)
    }

    /// Get paginated results
    async fn api_get_all<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        page_size: u32,
    ) -> anyhow::Result<Vec<T>> {
        let mut all_results = Vec::new();
        let mut page = 0;

        loop {
            let paginated_endpoint = format!("{}?page={}&size={}", endpoint, page, page_size);
            let response: Rapid7PagedResponse<T> = self.api_get(&paginated_endpoint).await?;

            all_results.extend(response.resources);

            if response.page.number >= response.page.total_pages.saturating_sub(1) {
                break;
            }

            page += 1;
        }

        Ok(all_results)
    }

    /// Get all assets
    async fn get_assets(&self) -> anyhow::Result<Vec<Rapid7Asset>> {
        debug!("Fetching assets from Rapid7");
        self.api_get_all("/assets", 500).await
    }

    /// Get vulnerabilities for an asset
    async fn get_asset_vulns(&self, asset_id: i64) -> anyhow::Result<Vec<Rapid7AssetVuln>> {
        let endpoint = format!("/assets/{}/vulnerabilities", asset_id);
        self.api_get_all(&endpoint, 500).await
    }

    /// Get vulnerability details
    async fn get_vuln_details(&self, vuln_id: &str) -> anyhow::Result<Rapid7Vulnerability> {
        let endpoint = format!("/vulnerabilities/{}", vuln_id);
        self.api_get(&endpoint).await
    }

    /// Convert Rapid7 data to normalized finding
    fn normalize_finding(
        &self,
        asset: &Rapid7Asset,
        asset_vuln: &Rapid7AssetVuln,
        vuln_details: Option<&Rapid7Vulnerability>,
    ) -> NormalizedFinding {
        let title = vuln_details
            .map(|v| v.title.clone())
            .unwrap_or_else(|| asset_vuln.id.clone());

        let severity = Normalizer::normalize_severity(
            "rapid7",
            &asset_vuln.severity.to_lowercase(),
            vuln_details.and_then(|v| {
                v.cvss
                    .as_ref()
                    .and_then(|c| c.v3.as_ref().map(|s| s.score))
            }),
        );

        let mut builder =
            NormalizedFindingBuilder::new("rapid7", &asset_vuln.id, &title).severity(severity);

        // Description
        if let Some(v) = vuln_details {
            builder = builder.description(&v.description.text);

            // CVSS
            if let Some(ref cvss) = v.cvss {
                if let Some(ref v3) = cvss.v3 {
                    builder = builder.cvss(v3.score, Some(&v3.vector));
                } else if let Some(ref v2) = cvss.v2 {
                    builder = builder.cvss(v2.score, Some(&v2.vector));
                }
            }

            // CVEs
            if !v.cves.is_empty() {
                builder = builder.cves(v.cves.clone());
            }

            // Solution
            if let Some(ref solution) = v.solution {
                builder = builder.solution(&solution.steps.join("\n"));
            }

            // Exploitability
            if let Some(ref exploits) = v.exploits {
                builder = builder.exploit_available(!exploits.is_empty());
            }

            // References
            for reference in &v.references {
                builder = builder.reference(&reference.url);
            }

            // Categories as family
            if !v.categories.is_empty() {
                builder = builder.family(&v.categories.join(", "));
            }
        }

        // Asset info
        if let Some(ref ip) = asset.ip {
            builder = builder.asset_ip(ip);
        }
        if let Some(ref hostname) = asset.host_name {
            builder = builder.asset_hostname(hostname);
        }

        // Port
        if let Some(port) = asset_vuln.port {
            builder = builder.port(port, asset_vuln.protocol.as_deref());
        }

        // Service
        if let Some(ref service) = asset_vuln.service {
            builder = builder.service(service);
        }

        // Evidence
        if let Some(ref proof) = asset_vuln.proof {
            builder = builder.evidence(proof);
        }

        // Timestamps
        if let Some(ref found) = asset_vuln.since {
            if let Ok(dt) = DateTime::parse_from_rfc3339(found) {
                builder = builder.first_seen(dt.with_timezone(&Utc));
            }
        }

        builder.build()
    }
}

#[async_trait::async_trait]
impl VendorIngester for Rapid7Ingester {
    fn vendor(&self) -> Vendor {
        Vendor::Rapid7
    }

    async fn test_connection(&self) -> anyhow::Result<bool> {
        let _: Rapid7SystemInfo = self.api_get("/administration/info").await?;
        Ok(true)
    }

    async fn sync(&self, config: &IngestConfig) -> anyhow::Result<IngestResult> {
        let start = Instant::now();
        info!("Starting Rapid7 InsightVM sync");

        // Get all assets
        let assets = self.get_assets().await?;
        debug!("Retrieved {} assets", assets.len());

        let mut findings = Vec::new();
        let mut normalized_assets: HashMap<String, NormalizedAsset> = HashMap::new();
        let mut vuln_cache: HashMap<String, Rapid7Vulnerability> = HashMap::new();
        let mut stats = IngestStats::default();

        for asset in &assets {
            // Get vulnerabilities for this asset
            let asset_vulns = match self.get_asset_vulns(asset.id).await {
                Ok(vulns) => vulns,
                Err(e) => {
                    warn!("Failed to get vulns for asset {}: {}", asset.id, e);
                    continue;
                }
            };

            for asset_vuln in &asset_vulns {
                stats.records_processed += 1;

                // Get vuln details (with caching)
                let vuln_details = if let Some(cached) = vuln_cache.get(&asset_vuln.id) {
                    Some(cached)
                } else {
                    match self.get_vuln_details(&asset_vuln.id).await {
                        Ok(details) => {
                            vuln_cache.insert(asset_vuln.id.clone(), details);
                            vuln_cache.get(&asset_vuln.id)
                        }
                        Err(e) => {
                            debug!("Failed to get vuln details for {}: {}", asset_vuln.id, e);
                            None
                        }
                    }
                };

                let finding = self.normalize_finding(asset, asset_vuln, vuln_details);

                // Filter by severity
                if let Some(min_sev) = config.min_severity {
                    if finding.severity < min_sev {
                        stats.records_skipped += 1;
                        continue;
                    }
                }

                // Track unique assets
                if !normalized_assets.contains_key(&finding.asset.id) {
                    normalized_assets.insert(finding.asset.id.clone(), finding.asset.clone());
                }

                findings.push(finding);
                stats.records_imported += 1;
            }
        }

        stats.unique_assets = normalized_assets.len() as u32;
        stats.unique_vulns = vuln_cache.len() as u32;
        stats.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "Rapid7 sync complete: {} findings, {} assets in {}ms",
            findings.len(),
            normalized_assets.len(),
            stats.duration_ms
        );

        Ok(IngestResult {
            vendor: Vendor::Rapid7,
            imported_at: Utc::now(),
            findings,
            assets: normalized_assets.into_values().collect(),
            stats,
            errors: Vec::new(),
        })
    }

    async fn sync_since(
        &self,
        _since: DateTime<Utc>,
        config: &IngestConfig,
    ) -> anyhow::Result<IngestResult> {
        self.sync(config).await
    }
}

// Rapid7 API response structures

#[derive(Debug, Deserialize)]
struct Rapid7PagedResponse<T> {
    resources: Vec<T>,
    page: Rapid7Page,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Rapid7Page {
    number: u32,
    size: u32,
    #[serde(rename = "totalPages")]
    total_pages: u32,
    #[serde(rename = "totalResources")]
    total_resources: u32,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Rapid7Asset {
    id: i64,
    ip: Option<String>,
    #[serde(rename = "hostName")]
    host_name: Option<String>,
    #[serde(rename = "hostNames")]
    host_names: Option<Vec<Rapid7HostName>>,
    mac: Option<String>,
    os: Option<String>,
    #[serde(rename = "osFingerprint")]
    os_fingerprint: Option<Rapid7OsFingerprint>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Rapid7HostName {
    name: String,
    source: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Rapid7OsFingerprint {
    description: Option<String>,
    family: Option<String>,
    product: Option<String>,
    vendor: Option<String>,
    version: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Rapid7AssetVuln {
    id: String,
    severity: String,
    status: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
    service: Option<String>,
    since: Option<String>,
    proof: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct Rapid7Vulnerability {
    id: String,
    title: String,
    description: Rapid7Description,
    severity: String,
    cvss: Option<Rapid7Cvss>,
    #[serde(default)]
    cves: Vec<String>,
    solution: Option<Rapid7Solution>,
    exploits: Option<Vec<Rapid7Exploit>>,
    #[serde(default)]
    references: Vec<Rapid7Reference>,
    #[serde(default)]
    categories: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct Rapid7Description {
    text: String,
    html: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Rapid7Cvss {
    v2: Option<Rapid7CvssScore>,
    v3: Option<Rapid7CvssScore>,
}

#[derive(Debug, Clone, Deserialize)]
struct Rapid7CvssScore {
    score: f32,
    vector: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct Rapid7Solution {
    #[serde(rename = "type")]
    solution_type: Option<String>,
    #[serde(default)]
    steps: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct Rapid7Exploit {
    id: i64,
    title: String,
    source: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
struct Rapid7Reference {
    url: String,
    source: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Rapid7SystemInfo {
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_with_api_key() {
        let config = Rapid7Config::with_api_key("https://console.example.com:3780", "api_key");
        assert!(config.use_api_key);
    }

    #[test]
    fn test_config_with_credentials() {
        let config =
            Rapid7Config::with_credentials("https://console.example.com:3780", "user", "pass");
        assert!(!config.use_api_key);
    }
}
