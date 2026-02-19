//! ForgeScan Ingest - Vendor data ingestion
//!
//! This crate provides import capabilities for third-party vulnerability scanners:
//! - Tenable.io and Nessus
//! - Qualys VMDR
//! - Rapid7 InsightVM
//! - Generic CSV/JSON formats
//!
//! # Example
//!
//! ```no_run
//! use forgescan_ingest::{Ingester, TenableConfig, IngestResult};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Import from Tenable.io API
//!     let config = TenableConfig::from_env().unwrap();
//!     let ingester = Ingester::tenable(config);
//!     let result = ingester.sync().await.unwrap();
//!
//!     println!("Imported {} findings", result.findings.len());
//!
//!     // Or import from Nessus file
//!     let result = Ingester::from_nessus_file("scan.nessus").await.unwrap();
//! }
//! ```

pub mod formats;
pub mod normalize;
pub mod qualys;
pub mod rapid7;
pub mod tenable;

pub use normalize::{NormalizedAsset, NormalizedFinding, Normalizer};
pub use qualys::{QualysConfig, QualysIngester};
pub use rapid7::{Rapid7Config, Rapid7Ingester};
pub use tenable::{TenableConfig, TenableIngester};

use chrono::{DateTime, Utc};
use forgescan_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Vendor type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Vendor {
    Tenable,
    Qualys,
    Rapid7,
    Nessus,
    OpenVAS,
    Nexpose,
    CrowdStrike,
    AwsInspector,
    Sarif,
    Generic,
}

impl Vendor {
    pub fn as_str(&self) -> &'static str {
        match self {
            Vendor::Tenable => "Tenable.io",
            Vendor::Qualys => "Qualys VMDR",
            Vendor::Rapid7 => "Rapid7 InsightVM",
            Vendor::Nessus => "Nessus",
            Vendor::OpenVAS => "OpenVAS",
            Vendor::Nexpose => "Nexpose",
            Vendor::CrowdStrike => "CrowdStrike Spotlight",
            Vendor::AwsInspector => "AWS Inspector",
            Vendor::Sarif => "SARIF",
            Vendor::Generic => "Generic",
        }
    }
}

/// Result of an ingestion operation
#[derive(Debug, Clone)]
pub struct IngestResult {
    /// Source vendor
    pub vendor: Vendor,
    /// Import timestamp
    pub imported_at: DateTime<Utc>,
    /// Normalized findings
    pub findings: Vec<NormalizedFinding>,
    /// Discovered assets
    pub assets: Vec<NormalizedAsset>,
    /// Import statistics
    pub stats: IngestStats,
    /// Errors encountered during import
    pub errors: Vec<IngestError>,
}

/// Import statistics
#[derive(Debug, Clone, Default)]
pub struct IngestStats {
    /// Total records processed
    pub records_processed: u32,
    /// Records successfully imported
    pub records_imported: u32,
    /// Records skipped (duplicates, filtered)
    pub records_skipped: u32,
    /// Records with errors
    pub records_errored: u32,
    /// Unique hosts/assets
    pub unique_assets: u32,
    /// Unique vulnerabilities
    pub unique_vulns: u32,
    /// Import duration in milliseconds
    pub duration_ms: u64,
}

/// Import error
#[derive(Debug, Clone)]
pub struct IngestError {
    /// Record identifier
    pub record_id: Option<String>,
    /// Error message
    pub message: String,
    /// Error context
    pub context: HashMap<String, String>,
}

/// Ingest configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConfig {
    /// Vendor type
    pub vendor: Vendor,
    /// Minimum severity to import
    pub min_severity: Option<Severity>,
    /// Maximum age of findings (days)
    pub max_age_days: Option<u32>,
    /// Filter by asset tags
    pub asset_tags: Vec<String>,
    /// Filter by plugin/check families
    pub families: Vec<String>,
    /// Deduplicate findings
    pub deduplicate: bool,
    /// Include informational findings
    pub include_info: bool,
    /// Batch size for API calls
    pub batch_size: u32,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            vendor: Vendor::Generic,
            min_severity: None,
            max_age_days: Some(90),
            asset_tags: Vec::new(),
            families: Vec::new(),
            deduplicate: true,
            include_info: false,
            batch_size: 1000,
        }
    }
}

/// Main ingester facade
pub struct Ingester {
    vendor: Vendor,
    config: IngestConfig,
    tenable: Option<TenableIngester>,
    qualys: Option<QualysIngester>,
    rapid7: Option<Rapid7Ingester>,
}

impl Ingester {
    /// Create Tenable ingester
    pub fn tenable(config: TenableConfig) -> Self {
        Self {
            vendor: Vendor::Tenable,
            config: IngestConfig {
                vendor: Vendor::Tenable,
                ..Default::default()
            },
            tenable: Some(TenableIngester::new(config)),
            qualys: None,
            rapid7: None,
        }
    }

    /// Create Qualys ingester
    pub fn qualys(config: QualysConfig) -> Self {
        Self {
            vendor: Vendor::Qualys,
            config: IngestConfig {
                vendor: Vendor::Qualys,
                ..Default::default()
            },
            tenable: None,
            qualys: Some(QualysIngester::new(config)),
            rapid7: None,
        }
    }

    /// Create Rapid7 ingester
    pub fn rapid7(config: Rapid7Config) -> Self {
        Self {
            vendor: Vendor::Rapid7,
            config: IngestConfig {
                vendor: Vendor::Rapid7,
                ..Default::default()
            },
            tenable: None,
            qualys: None,
            rapid7: Some(Rapid7Ingester::new(config)),
        }
    }

    /// Set ingest configuration
    pub fn with_config(mut self, config: IngestConfig) -> Self {
        self.config = config;
        self
    }

    /// Sync all findings from the vendor
    pub async fn sync(&self) -> anyhow::Result<IngestResult> {
        match self.vendor {
            Vendor::Tenable => {
                let ingester = self.tenable.as_ref().unwrap();
                ingester.sync(&self.config).await
            }
            Vendor::Qualys => {
                let ingester = self.qualys.as_ref().unwrap();
                ingester.sync(&self.config).await
            }
            Vendor::Rapid7 => {
                let ingester = self.rapid7.as_ref().unwrap();
                ingester.sync(&self.config).await
            }
            _ => anyhow::bail!("Vendor sync not implemented"),
        }
    }

    /// Import from a Nessus file
    pub async fn from_nessus_file(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
        formats::nessus::parse_nessus_file(path).await
    }

    /// Import from a Qualys XML file
    pub async fn from_qualys_file(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
        formats::qualys_xml::parse_qualys_file(path).await
    }

    /// Import from CSV file with custom mapping
    pub async fn from_csv(
        path: impl AsRef<Path>,
        mapping: &formats::CsvMapping,
        vendor: Vendor,
    ) -> anyhow::Result<IngestResult> {
        formats::csv::parse_csv_file(path, mapping, vendor).await
    }

    /// Import from CSV file with auto-detected format
    pub async fn from_csv_auto(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path).await?;

        let (mapping, vendor) = formats::csv::detect_csv_format(&content)
            .ok_or_else(|| anyhow::anyhow!("Could not auto-detect CSV format"))?;

        formats::csv::parse_csv_file(path, &mapping, vendor).await
    }

    /// Import from JSON file
    pub async fn from_json(path: impl AsRef<Path>) -> anyhow::Result<IngestResult> {
        formats::json::parse_json_file(path).await
    }
}

/// Trait for vendor-specific ingesters
#[async_trait::async_trait]
pub trait VendorIngester: Send + Sync {
    /// Get vendor type
    fn vendor(&self) -> Vendor;

    /// Test connectivity
    async fn test_connection(&self) -> anyhow::Result<bool>;

    /// Sync all findings
    async fn sync(&self, config: &IngestConfig) -> anyhow::Result<IngestResult>;

    /// Get findings since a specific time
    async fn sync_since(
        &self,
        since: DateTime<Utc>,
        config: &IngestConfig,
    ) -> anyhow::Result<IngestResult>;
}
