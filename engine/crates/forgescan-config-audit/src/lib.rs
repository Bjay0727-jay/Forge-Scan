//! ForgeScan Config Audit - CIS/STIG configuration auditing (agent mode)
//!
//! This crate provides local configuration auditing capabilities:
//! - CIS Benchmark checks for Linux and Windows
//! - DISA STIG compliance checks
//! - File permission auditing
//! - Registry checks (Windows)
//! - Service configuration checks
//!
//! # Example
//!
//! ```no_run
//! use forgescan_config_audit::{ConfigAuditor, AuditResult};
//!
//! // Create auditor with default checks for current platform
//! let mut auditor = ConfigAuditor::new();
//!
//! // Run all checks
//! let result = auditor.run_audit();
//!
//! println!("Passed: {}", result.summary.passed);
//! println!("Failed: {}", result.summary.failed);
//!
//! // Get all failures
//! for failure in auditor.get_failures() {
//!     println!("{}: {} (expected: {})", failure.check_name, failure.actual, failure.expected);
//! }
//! ```

pub mod auditor;
pub mod checks;
pub mod collectors;

#[cfg(unix)]
pub mod linux;

#[cfg(windows)]
pub mod windows;

pub use auditor::{AuditResult, AuditSummary, ComplianceCoverage, ConfigAuditor, Platform};
pub use checks::{
    CheckResult, CheckType, ComplianceMapping, ConfigCheck, RegistryValue, ServiceState,
    UserAccountCheck,
};
pub use collectors::{
    HardwareInfo, NetworkInfo, OsInfo, PackageInfo, ServiceInfo, SystemCollector, SystemInfo,
    UserInfo,
};
