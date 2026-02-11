//! ForgeScan NVD - NVD/CISA KEV database management and CPE matching
//!
//! This crate provides:
//! - SQLite-based local CVE database
//! - NVD JSON feed sync
//! - CISA KEV catalog integration
//! - CPE matching for vulnerability detection

pub mod database;
pub mod sync;
pub mod cpe;

pub use database::NvdDb;
