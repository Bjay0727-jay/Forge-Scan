//! NVD sync - download and update CVE data from NVD API
//!
//! Implements NVD API 2.0 client for downloading CVE data and CISA KEV catalog.

use crate::database::NvdDb;
use forgescan_core::{CveInfo, Error, Result};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, info, warn};

/// NVD API synchronizer
pub struct NvdSync {
    client: Client,
    api_url: String,
    api_key: Option<String>,
    db: NvdDb,
    /// Delay between requests (NVD rate limiting)
    request_delay: Duration,
}

impl NvdSync {
    /// Create a new NVD synchronizer
    pub fn new(db: NvdDb, api_key: Option<String>) -> Self {
        let request_delay = if api_key.is_some() {
            Duration::from_millis(600) // With API key: 50 requests/30s
        } else {
            Duration::from_secs(6) // Without API key: 5 requests/30s
        };

        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            api_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            api_key,
            db,
            request_delay,
        }
    }

    /// Sync all CVEs from NVD (full sync)
    pub async fn full_sync(&self) -> Result<SyncStats> {
        info!("Starting full NVD sync...");
        let mut stats = SyncStats::default();
        let mut start_index = 0;
        let results_per_page = 2000;

        loop {
            let response = self.fetch_cves(start_index, results_per_page, None).await?;

            for vuln in &response.vulnerabilities {
                if let Err(e) = self.process_vulnerability(vuln) {
                    warn!("Failed to process {}: {}", vuln.cve.id, e);
                    stats.errors += 1;
                } else {
                    stats.cves_processed += 1;
                }
            }

            stats.total_results = response.total_results;
            start_index += response.results_per_page;

            info!(
                "Processed {}/{} CVEs",
                start_index.min(response.total_results),
                response.total_results
            );

            if start_index >= response.total_results {
                break;
            }

            tokio::time::sleep(self.request_delay).await;
        }

        info!("NVD sync complete: {} CVEs processed", stats.cves_processed);
        Ok(stats)
    }

    /// Incremental sync since last modification date
    pub async fn incremental_sync(&self, since: &str) -> Result<SyncStats> {
        info!("Starting incremental NVD sync since {}...", since);
        let mut stats = SyncStats::default();
        let mut start_index = 0;
        let results_per_page = 2000;

        loop {
            let response = self
                .fetch_cves(start_index, results_per_page, Some(since))
                .await?;

            for vuln in &response.vulnerabilities {
                if let Err(e) = self.process_vulnerability(vuln) {
                    warn!("Failed to process {}: {}", vuln.cve.id, e);
                    stats.errors += 1;
                } else {
                    stats.cves_processed += 1;
                }
            }

            stats.total_results = response.total_results;
            start_index += response.results_per_page;

            if start_index >= response.total_results {
                break;
            }

            tokio::time::sleep(self.request_delay).await;
        }

        info!(
            "Incremental sync complete: {} CVEs updated",
            stats.cves_processed
        );
        Ok(stats)
    }

    /// Fetch CVEs from NVD API
    async fn fetch_cves(
        &self,
        start_index: u32,
        results_per_page: u32,
        last_mod_start: Option<&str>,
    ) -> Result<NvdResponse> {
        let mut url = format!(
            "{}?startIndex={}&resultsPerPage={}",
            self.api_url, start_index, results_per_page
        );

        if let Some(date) = last_mod_start {
            url.push_str(&format!("&lastModStartDate={}", date));
        }

        debug!("Fetching CVEs: {}", url);

        let mut request = self.client.get(&url);

        if let Some(ref key) = self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::NvdSyncFailed(format!("Failed to fetch NVD data: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::NvdSyncFailed(format!(
                "NVD API returned status {}",
                response.status()
            )));
        }

        let data: NvdResponse = response
            .json()
            .await
            .map_err(|e| Error::Parse(format!("Failed to parse NVD response: {}", e)))?;

        Ok(data)
    }

    /// Process a vulnerability from NVD response
    fn process_vulnerability(&self, vuln: &NvdVulnerability) -> Result<()> {
        let cve = &vuln.cve;

        // Extract CVSS v3 score
        let (cvss_score, cvss_vector) = cve
            .metrics
            .as_ref()
            .and_then(|m| m.cvss_metric_v31.as_ref())
            .and_then(|v| v.first())
            .map(|m| {
                (
                    Some(m.cvss_data.base_score),
                    Some(m.cvss_data.vector_string.clone()),
                )
            })
            .unwrap_or((None, None));

        // Extract CWE IDs
        let cwe_ids: Vec<String> = cve
            .weaknesses
            .as_ref()
            .map(|w| {
                w.iter()
                    .flat_map(|weakness| {
                        weakness.description.iter().filter_map(|d| {
                            if d.value.starts_with("CWE-") {
                                Some(d.value.clone())
                            } else {
                                None
                            }
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Extract references
        let references: Vec<String> = cve
            .references
            .as_ref()
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default();

        // Get description
        let description = cve
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.clone())
            .unwrap_or_default();

        let cve_info = CveInfo {
            cve_id: cve.id.clone(),
            description,
            cvss_v3_score: cvss_score.map(|s| s as f32),
            cvss_v3_vector: cvss_vector,
            cwe_ids,
            references,
            published_date: cve.published.clone().unwrap_or_default(),
        };

        self.db.upsert_cve(&cve_info)?;

        // Process CPE matches
        if let Some(ref configs) = cve.configurations {
            for config in configs {
                for node in &config.nodes {
                    self.process_cpe_matches(&cve.id, node)?;
                }
            }
        }

        Ok(())
    }

    /// Process CPE match nodes
    fn process_cpe_matches(&self, cve_id: &str, node: &NvdNode) -> Result<()> {
        if let Some(ref matches) = node.cpe_match {
            for cpe_match in matches {
                if cpe_match.vulnerable {
                    self.db.add_cpe_match(
                        cve_id,
                        &cpe_match.criteria,
                        cpe_match.version_start_including.as_deref(),
                        cpe_match.version_start_excluding.as_deref(),
                        cpe_match.version_end_including.as_deref(),
                        cpe_match.version_end_excluding.as_deref(),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Sync CISA Known Exploited Vulnerabilities catalog
    pub async fn sync_kev(&self) -> Result<u32> {
        info!("Syncing CISA KEV catalog...");

        let url =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::NvdSyncFailed(format!("Failed to fetch KEV catalog: {}", e)))?;

        let kev: KevCatalog = response
            .json()
            .await
            .map_err(|e| Error::Parse(format!("Failed to parse KEV catalog: {}", e)))?;

        let mut count = 0;
        for vuln in &kev.vulnerabilities {
            self.db.add_kev(
                &vuln.cve_id,
                &vuln.vendor_project,
                &vuln.product,
                &vuln.date_added,
            )?;
            count += 1;
        }

        info!("KEV sync complete: {} vulnerabilities", count);
        Ok(count)
    }
}

/// Sync statistics
#[derive(Debug, Default)]
pub struct SyncStats {
    pub total_results: u32,
    pub cves_processed: u32,
    pub cpe_matches_added: u32,
    pub errors: u32,
}

// NVD API Response structures
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    results_per_page: u32,
    start_index: u32,
    total_results: u32,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    published: Option<String>,
    last_modified: Option<String>,
    descriptions: Vec<NvdDescription>,
    metrics: Option<NvdMetrics>,
    weaknesses: Option<Vec<NvdWeakness>>,
    configurations: Option<Vec<NvdConfiguration>>,
    references: Option<Vec<NvdReference>>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v31: Option<Vec<CvssMetricV31>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetricV31 {
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    base_score: f64,
    vector_string: String,
}

#[derive(Debug, Deserialize)]
struct NvdWeakness {
    description: Vec<NvdDescription>,
}

#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdNode {
    operator: Option<String>,
    negate: Option<bool>,
    cpe_match: Option<Vec<NvdCpeMatch>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCpeMatch {
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

// CISA KEV structures
#[derive(Debug, Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevVulnerability {
    cve_id: String,
    vendor_project: String,
    product: String,
    date_added: String,
}
