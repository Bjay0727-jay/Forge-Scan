//! ForgeScan NVD - NVD/CISA KEV database management and CPE matching
//!
//! This crate provides:
//! - SQLite-based local CVE database
//! - NVD API 2.0 sync client
//! - CISA KEV catalog integration
//! - CPE 2.3 parsing and matching
//! - Version comparison for vulnerability detection

pub mod cpe;
pub mod database;
pub mod sync;

pub use cpe::{compare_versions, Cpe, CpeMatch, CpeParseError, CpePart, VersionBoundType};
pub use database::NvdDb;
pub use sync::{NvdSync, SyncStats};
