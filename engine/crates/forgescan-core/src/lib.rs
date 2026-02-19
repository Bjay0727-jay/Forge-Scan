//! ForgeScan Core - Foundation types, traits, and error handling
//!
//! This crate provides the core abstractions used throughout the ForgeScan Engine:
//! - `ScanTarget`: Specification of what to scan (IP, CIDR, hostname, URL)
//! - `Finding`: A vulnerability or misconfiguration discovered during scanning
//! - `Check`: The trait that all vulnerability checks implement
//! - `Severity`, `CheckCategory`, etc.: Core enums

pub mod check;
pub mod error;
pub mod finding;
pub mod severity;
pub mod target;

// Re-export commonly used types at crate root
pub use check::{
    Check, CheckContext, CheckMetadata, CheckResult, CredentialProvider, CveInfo, NvdDatabase,
};
pub use error::{Error, Result};
pub use finding::{ComplianceRef, ExploitMaturity, Finding, PortInfo};
pub use severity::{CheckCategory, Severity};
pub use target::{IpRange, ScanMode, ScanTarget};
