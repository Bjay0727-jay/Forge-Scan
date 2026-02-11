//! ForgeScan Vuln - Vulnerability detection and CVE version matching
//!
//! This crate provides the vulnerability detection engine that:
//! - Correlates detected services with CVE database
//! - Performs version-based vulnerability matching
//! - Calculates Forge Risk Score (FRS)

pub mod detector;
pub mod frs;
pub mod matcher;

pub use detector::{VulnDetector, DetectionResult};
pub use frs::{FrsCalculator, FrsScore, RiskFactors};
pub use matcher::{VersionMatcher, MatchResult};
