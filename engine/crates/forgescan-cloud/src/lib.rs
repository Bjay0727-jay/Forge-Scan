//! ForgeScan Cloud - Cloud misconfiguration checks (AWS, Azure, GCP)
//!
//! This crate provides cloud security posture management capabilities:
//! - AWS security checks (S3, IAM, EC2, RDS, Lambda, etc.)
//! - Azure security checks (planned)
//! - GCP security checks (planned)
//! - Multi-cloud aggregation
//!
//! # Example
//!
//! ```no_run
//! use forgescan_cloud::{CloudScanner, AwsConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let scanner = CloudScanner::aws(AwsConfig::from_env()).await.unwrap();
//!     let results = scanner.scan_all().await.unwrap();
//!
//!     for finding in results.findings {
//!         println!("{}: {}", finding.severity, finding.title);
//!     }
//! }
//! ```

pub mod aws;
pub mod checks;

// Azure and GCP modules will be added in future phases
// pub mod azure;
// pub mod gcp;

pub use aws::{AwsConfig, AwsScanner};
pub use checks::{CloudCheck, CloudCheckResult, CloudResource};

use forgescan_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cloud provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "AWS",
            CloudProvider::Azure => "Azure",
            CloudProvider::Gcp => "GCP",
        }
    }
}

/// Result of a cloud scan
#[derive(Debug, Clone)]
pub struct CloudScanResult {
    /// Cloud provider
    pub provider: CloudProvider,
    /// Account/subscription/project ID
    pub account_id: String,
    /// Region(s) scanned
    pub regions: Vec<String>,
    /// Discovered resources
    pub resources: Vec<CloudResource>,
    /// Security findings
    pub findings: Vec<Finding>,
    /// Statistics
    pub stats: CloudScanStats,
}

/// Cloud scan statistics
#[derive(Debug, Clone, Default)]
pub struct CloudScanStats {
    /// Resources scanned
    pub resources_scanned: u32,
    /// Checks performed
    pub checks_performed: u32,
    /// Checks passed
    pub checks_passed: u32,
    /// Checks failed
    pub checks_failed: u32,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Cloud scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScanConfig {
    /// Regions to scan (empty = all available)
    pub regions: Vec<String>,
    /// Resource types to scan (empty = all)
    pub resource_types: Vec<String>,
    /// Check categories to run
    pub check_categories: Vec<CloudCheckCategory>,
    /// Skip specific checks by ID
    pub skip_checks: Vec<String>,
    /// Maximum concurrent API calls
    pub concurrency: u32,
    /// Include compliant resources in results
    pub include_compliant: bool,
}

impl Default for CloudScanConfig {
    fn default() -> Self {
        Self {
            regions: Vec::new(),
            resource_types: Vec::new(),
            check_categories: vec![
                CloudCheckCategory::Identity,
                CloudCheckCategory::Storage,
                CloudCheckCategory::Network,
                CloudCheckCategory::Compute,
                CloudCheckCategory::Database,
                CloudCheckCategory::Logging,
                CloudCheckCategory::Encryption,
            ],
            skip_checks: Vec::new(),
            concurrency: 10,
            include_compliant: false,
        }
    }
}

/// Cloud check categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudCheckCategory {
    /// Identity and access management
    Identity,
    /// Storage security
    Storage,
    /// Network security
    Network,
    /// Compute security
    Compute,
    /// Database security
    Database,
    /// Logging and monitoring
    Logging,
    /// Encryption
    Encryption,
    /// Compliance
    Compliance,
}

impl CloudCheckCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "Identity & Access",
            Self::Storage => "Storage",
            Self::Network => "Network",
            Self::Compute => "Compute",
            Self::Database => "Database",
            Self::Logging => "Logging & Monitoring",
            Self::Encryption => "Encryption",
            Self::Compliance => "Compliance",
        }
    }
}

/// Multi-cloud scanner
pub struct CloudScanner {
    provider: CloudProvider,
    config: CloudScanConfig,
    aws: Option<AwsScanner>,
    // azure: Option<AzureScanner>,
    // gcp: Option<GcpScanner>,
}

impl CloudScanner {
    /// Create AWS scanner
    pub async fn aws(aws_config: AwsConfig) -> anyhow::Result<Self> {
        let aws_scanner = AwsScanner::new(aws_config).await?;

        Ok(Self {
            provider: CloudProvider::Aws,
            config: CloudScanConfig::default(),
            aws: Some(aws_scanner),
        })
    }

    /// Set scan configuration
    pub fn with_config(mut self, config: CloudScanConfig) -> Self {
        self.config = config;
        self
    }

    /// Scan all enabled resource types
    pub async fn scan_all(&self) -> anyhow::Result<CloudScanResult> {
        match self.provider {
            CloudProvider::Aws => {
                let scanner = self.aws.as_ref().unwrap();
                scanner.scan_all(&self.config).await
            }
            CloudProvider::Azure => {
                anyhow::bail!("Azure scanning not yet implemented")
            }
            CloudProvider::Gcp => {
                anyhow::bail!("GCP scanning not yet implemented")
            }
        }
    }

    /// Scan specific resource types
    pub async fn scan_resources(&self, resource_types: &[&str]) -> anyhow::Result<CloudScanResult> {
        let mut config = self.config.clone();
        config.resource_types = resource_types.iter().map(|s| s.to_string()).collect();

        match self.provider {
            CloudProvider::Aws => {
                let scanner = self.aws.as_ref().unwrap();
                scanner.scan_all(&config).await
            }
            _ => anyhow::bail!("Cloud provider not yet implemented"),
        }
    }
}

/// CIS Benchmark mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CisBenchmark {
    /// Benchmark name (e.g., "CIS AWS Foundations")
    pub name: String,
    /// Version
    pub version: String,
    /// Control ID
    pub control_id: String,
    /// Control title
    pub control_title: String,
    /// Profile level (1 or 2)
    pub level: u8,
}

/// Compliance framework reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// CIS Benchmark
    Cis(CisBenchmark),
    /// SOC 2 Type II
    Soc2 { control: String },
    /// PCI DSS
    PciDss { requirement: String },
    /// HIPAA
    Hipaa { section: String },
    /// NIST 800-53
    Nist800_53 { control: String },
    /// AWS Well-Architected
    AwsWellArchitected { pillar: String, practice: String },
}
