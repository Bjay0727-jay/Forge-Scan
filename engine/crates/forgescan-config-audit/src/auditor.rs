//! Configuration auditor - orchestrates check execution

use crate::checks::{CheckResult, CheckType, ConfigCheck};
use forgescan_core::Severity;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Configuration auditor that runs checks against the local system
pub struct ConfigAuditor {
    /// Available checks
    checks: Vec<ConfigCheck>,
    /// Check results cache
    results: Vec<CheckResult>,
    /// Platform filter
    platform: Platform,
}

/// Current platform
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    Windows,
    MacOS,
    Unknown,
}

impl Platform {
    /// Detect current platform
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        return Platform::Linux;

        #[cfg(target_os = "windows")]
        return Platform::Windows;

        #[cfg(target_os = "macos")]
        return Platform::MacOS;

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        return Platform::Unknown;
    }

    /// Get platform string for filtering
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::MacOS => "macos",
            Platform::Unknown => "unknown",
        }
    }
}

/// Result of a full audit run
#[derive(Debug, Clone)]
pub struct AuditResult {
    /// All check results
    pub results: Vec<CheckResult>,
    /// Summary statistics
    pub summary: AuditSummary,
}

/// Summary of audit results
#[derive(Debug, Clone, Default)]
pub struct AuditSummary {
    /// Total checks run
    pub total_checks: usize,
    /// Checks that passed
    pub passed: usize,
    /// Checks that failed
    pub failed: usize,
    /// Checks that errored
    pub errors: usize,
    /// Checks skipped (wrong platform, disabled)
    pub skipped: usize,
    /// Failures by severity
    pub by_severity: HashMap<Severity, usize>,
    /// Compliance framework coverage
    pub compliance_coverage: HashMap<String, ComplianceCoverage>,
}

/// Coverage for a compliance framework
#[derive(Debug, Clone, Default)]
pub struct ComplianceCoverage {
    /// Framework name
    pub framework: String,
    /// Total controls checked
    pub total: usize,
    /// Controls passing
    pub passing: usize,
    /// Controls failing
    pub failing: usize,
    /// Pass percentage
    pub pass_rate: f64,
}

impl ConfigAuditor {
    /// Create a new auditor with default checks for current platform
    pub fn new() -> Self {
        let platform = Platform::current();
        let checks = Self::load_default_checks(&platform);

        Self {
            checks,
            results: Vec::new(),
            platform,
        }
    }

    /// Create auditor with custom checks
    pub fn with_checks(checks: Vec<ConfigCheck>) -> Self {
        Self {
            checks,
            results: Vec::new(),
            platform: Platform::current(),
        }
    }

    /// Load default checks for platform
    fn load_default_checks(platform: &Platform) -> Vec<ConfigCheck> {
        match platform {
            Platform::Linux => crate::checks::cis_linux_checks(),
            Platform::Windows => crate::checks::cis_windows_checks(),
            _ => Vec::new(),
        }
    }

    /// Add a check to the auditor
    pub fn add_check(&mut self, check: ConfigCheck) {
        self.checks.push(check);
    }

    /// Run all enabled checks
    pub fn run_audit(&mut self) -> AuditResult {
        info!("Starting configuration audit on {:?}", self.platform);

        self.results.clear();
        let mut summary = AuditSummary::default();

        for check in &self.checks {
            // Skip disabled checks
            if !check.enabled {
                debug!("Skipping disabled check: {}", check.id);
                summary.skipped += 1;
                continue;
            }

            // Skip checks for other platforms
            if check.platform != "all" && check.platform != self.platform.as_str() {
                debug!(
                    "Skipping check {} (platform {} != {})",
                    check.id,
                    check.platform,
                    self.platform.as_str()
                );
                summary.skipped += 1;
                continue;
            }

            summary.total_checks += 1;

            let result = self.execute_check(check);

            if result.passed {
                summary.passed += 1;
            } else if result.actual.starts_with("Error:") {
                summary.errors += 1;
            } else {
                summary.failed += 1;
                *summary.by_severity.entry(result.severity).or_insert(0) += 1;
            }

            // Update compliance coverage
            for mapping in &result.compliance {
                let coverage = summary
                    .compliance_coverage
                    .entry(mapping.framework.clone())
                    .or_insert_with(|| ComplianceCoverage {
                        framework: mapping.framework.clone(),
                        ..Default::default()
                    });

                coverage.total += 1;
                if result.passed {
                    coverage.passing += 1;
                } else {
                    coverage.failing += 1;
                }
            }

            self.results.push(result);
        }

        // Calculate pass rates
        for coverage in summary.compliance_coverage.values_mut() {
            if coverage.total > 0 {
                coverage.pass_rate = (coverage.passing as f64 / coverage.total as f64) * 100.0;
            }
        }

        info!(
            "Audit complete: {} passed, {} failed, {} errors, {} skipped",
            summary.passed, summary.failed, summary.errors, summary.skipped
        );

        AuditResult {
            results: self.results.clone(),
            summary,
        }
    }

    /// Execute a single check
    fn execute_check(&self, check: &ConfigCheck) -> CheckResult {
        debug!("Executing check: {} - {}", check.id, check.name);

        match &check.check_type {
            CheckType::FilePermission {
                path,
                expected_mode,
                max_mode,
                owner,
                group,
            } => self.check_file_permission(check, path, *expected_mode, *max_mode, owner, group),

            CheckType::FileContent {
                path,
                pattern,
                expected,
                should_exist,
            } => self.check_file_content(check, path, pattern, expected.as_deref(), *should_exist),

            CheckType::ConfigValue {
                file,
                key,
                expected,
                delimiter,
            } => self.check_config_value(check, file, key, expected, delimiter.as_deref()),

            CheckType::ServiceState {
                service,
                expected_state,
            } => self.check_service_state(check, service, *expected_state),

            CheckType::PackageInstalled {
                package,
                should_be_installed,
            } => self.check_package_installed(check, package, *should_be_installed),

            CheckType::Sysctl { key, expected } => self.check_sysctl(check, key, expected),

            CheckType::Registry {
                path,
                value_name,
                expected,
            } => self.check_registry(check, path, value_name, expected),

            CheckType::UserAccount { check: user_check } => {
                self.check_user_account(check, user_check)
            }

            CheckType::Command {
                command,
                args,
                expected_output,
                expected_exit_code,
            } => self.check_command(
                check,
                command,
                args,
                expected_output.as_deref(),
                *expected_exit_code,
            ),
        }
    }

    // Platform-specific implementations are in linux.rs and windows.rs
    // These are stub implementations that delegate to platform modules

    #[cfg(unix)]
    fn check_file_permission(
        &self,
        check: &ConfigCheck,
        path: &str,
        expected_mode: Option<u32>,
        max_mode: Option<u32>,
        owner: &Option<String>,
        group: &Option<String>,
    ) -> CheckResult {
        crate::linux::check_file_permission(check, path, expected_mode, max_mode, owner, group)
    }

    #[cfg(windows)]
    fn check_file_permission(
        &self,
        check: &ConfigCheck,
        path: &str,
        _expected_mode: Option<u32>,
        _max_mode: Option<u32>,
        _owner: &Option<String>,
        _group: &Option<String>,
    ) -> CheckResult {
        // Windows doesn't use Unix-style permissions
        CheckResult::error(check, "File permission checks not applicable on Windows")
    }

    #[cfg(not(any(unix, windows)))]
    fn check_file_permission(
        &self,
        check: &ConfigCheck,
        _path: &str,
        _expected_mode: Option<u32>,
        _max_mode: Option<u32>,
        _owner: &Option<String>,
        _group: &Option<String>,
    ) -> CheckResult {
        CheckResult::error(
            check,
            "File permission checks not supported on this platform",
        )
    }

    fn check_file_content(
        &self,
        check: &ConfigCheck,
        path: &str,
        pattern: &str,
        expected: Option<&str>,
        should_exist: bool,
    ) -> CheckResult {
        use std::fs;

        match fs::read_to_string(path) {
            Ok(content) => {
                let re = match regex::Regex::new(pattern) {
                    Ok(r) => r,
                    Err(e) => return CheckResult::error(check, &format!("Invalid regex: {}", e)),
                };

                if let Some(caps) = re.captures(&content) {
                    let found = caps
                        .get(1)
                        .map(|m| m.as_str())
                        .unwrap_or(caps.get(0).unwrap().as_str());

                    if let Some(exp) = expected {
                        if found == exp {
                            CheckResult::pass(check, found)
                        } else {
                            CheckResult::fail(check, found, exp)
                        }
                    } else if should_exist {
                        CheckResult::pass(check, found)
                    } else {
                        CheckResult::fail(check, found, "pattern should not exist")
                    }
                } else if should_exist {
                    CheckResult::fail(check, "not found", "pattern should exist")
                } else {
                    CheckResult::pass(check, "pattern not found (expected)")
                }
            }
            Err(e) => CheckResult::error(check, &format!("Cannot read file {}: {}", path, e)),
        }
    }

    fn check_config_value(
        &self,
        check: &ConfigCheck,
        file: &str,
        key: &str,
        expected: &str,
        delimiter: Option<&str>,
    ) -> CheckResult {
        use std::fs;

        match fs::read_to_string(file) {
            Ok(content) => {
                let delim = delimiter.unwrap_or(" ");

                for line in content.lines() {
                    let line = line.trim();

                    // Skip comments
                    if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                        continue;
                    }

                    if let Some((k, v)) = line.split_once(delim) {
                        if k.trim() == key {
                            let value = v.trim();
                            if value == expected {
                                return CheckResult::pass(check, value);
                            } else {
                                return CheckResult::fail(check, value, expected);
                            }
                        }
                    }
                }

                CheckResult::fail(check, "key not found", expected)
                    .with_details(&format!("Key '{}' not found in {}", key, file))
            }
            Err(e) => CheckResult::error(check, &format!("Cannot read file {}: {}", file, e)),
        }
    }

    #[cfg(unix)]
    fn check_service_state(
        &self,
        check: &ConfigCheck,
        service: &str,
        expected: crate::checks::ServiceState,
    ) -> CheckResult {
        crate::linux::check_service_state(check, service, expected)
    }

    #[cfg(windows)]
    fn check_service_state(
        &self,
        check: &ConfigCheck,
        service: &str,
        expected: crate::checks::ServiceState,
    ) -> CheckResult {
        crate::windows::check_service_state(check, service, expected)
    }

    #[cfg(not(any(unix, windows)))]
    fn check_service_state(
        &self,
        check: &ConfigCheck,
        _service: &str,
        _expected: crate::checks::ServiceState,
    ) -> CheckResult {
        CheckResult::error(check, "Service checks not supported on this platform")
    }

    #[cfg(unix)]
    fn check_package_installed(
        &self,
        check: &ConfigCheck,
        package: &str,
        should_be_installed: bool,
    ) -> CheckResult {
        crate::linux::check_package_installed(check, package, should_be_installed)
    }

    #[cfg(windows)]
    fn check_package_installed(
        &self,
        check: &ConfigCheck,
        _package: &str,
        _should_be_installed: bool,
    ) -> CheckResult {
        CheckResult::error(check, "Package checks not implemented for Windows")
    }

    #[cfg(not(any(unix, windows)))]
    fn check_package_installed(
        &self,
        check: &ConfigCheck,
        _package: &str,
        _should_be_installed: bool,
    ) -> CheckResult {
        CheckResult::error(check, "Package checks not supported on this platform")
    }

    #[cfg(unix)]
    fn check_sysctl(&self, check: &ConfigCheck, key: &str, expected: &str) -> CheckResult {
        crate::linux::check_sysctl(check, key, expected)
    }

    #[cfg(windows)]
    fn check_sysctl(&self, check: &ConfigCheck, _key: &str, _expected: &str) -> CheckResult {
        CheckResult::error(check, "Sysctl checks not applicable on Windows")
    }

    #[cfg(not(any(unix, windows)))]
    fn check_sysctl(&self, check: &ConfigCheck, _key: &str, _expected: &str) -> CheckResult {
        CheckResult::error(check, "Sysctl checks not supported on this platform")
    }

    #[cfg(windows)]
    fn check_registry(
        &self,
        check: &ConfigCheck,
        path: &str,
        value_name: &str,
        expected: &crate::checks::RegistryValue,
    ) -> CheckResult {
        crate::windows::check_registry(check, path, value_name, expected)
    }

    #[cfg(not(windows))]
    fn check_registry(
        &self,
        check: &ConfigCheck,
        _path: &str,
        _value_name: &str,
        _expected: &crate::checks::RegistryValue,
    ) -> CheckResult {
        CheckResult::error(check, "Registry checks only applicable on Windows")
    }

    #[cfg(unix)]
    fn check_user_account(
        &self,
        check: &ConfigCheck,
        user_check: &crate::checks::UserAccountCheck,
    ) -> CheckResult {
        crate::linux::check_user_account(check, user_check)
    }

    #[cfg(windows)]
    fn check_user_account(
        &self,
        check: &ConfigCheck,
        user_check: &crate::checks::UserAccountCheck,
    ) -> CheckResult {
        crate::windows::check_user_account(check, user_check)
    }

    #[cfg(not(any(unix, windows)))]
    fn check_user_account(
        &self,
        check: &ConfigCheck,
        _user_check: &crate::checks::UserAccountCheck,
    ) -> CheckResult {
        CheckResult::error(check, "User account checks not supported on this platform")
    }

    fn check_command(
        &self,
        check: &ConfigCheck,
        command: &str,
        args: &[String],
        expected_output: Option<&str>,
        expected_exit_code: Option<i32>,
    ) -> CheckResult {
        use std::process::Command;

        match Command::new(command).args(args).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let exit_code = output.status.code().unwrap_or(-1);

                // Check exit code if specified
                if let Some(expected_code) = expected_exit_code {
                    if exit_code != expected_code {
                        return CheckResult::fail(
                            check,
                            &format!("exit code {}", exit_code),
                            &format!("exit code {}", expected_code),
                        );
                    }
                }

                // Check output if specified
                if let Some(expected) = expected_output {
                    if stdout.contains(expected) {
                        CheckResult::pass(check, stdout.trim())
                    } else {
                        CheckResult::fail(check, stdout.trim(), expected)
                    }
                } else {
                    // Just check exit code was 0
                    if exit_code == 0 {
                        CheckResult::pass(check, &format!("exit code {}", exit_code))
                    } else {
                        CheckResult::fail(check, &format!("exit code {}", exit_code), "exit code 0")
                    }
                }
            }
            Err(e) => CheckResult::error(check, &format!("Failed to run command: {}", e)),
        }
    }

    /// Get results for a specific compliance framework
    pub fn get_compliance_results(&self, framework: &str) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|r| r.compliance.iter().any(|c| c.framework == framework))
            .collect()
    }

    /// Get all failed checks
    pub fn get_failures(&self) -> Vec<&CheckResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    /// Get failures by severity
    pub fn get_failures_by_severity(&self, severity: Severity) -> Vec<&CheckResult> {
        self.results
            .iter()
            .filter(|r| !r.passed && r.severity == severity)
            .collect()
    }
}

impl Default for ConfigAuditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::current();

        #[cfg(target_os = "linux")]
        assert_eq!(platform, Platform::Linux);

        #[cfg(target_os = "windows")]
        assert_eq!(platform, Platform::Windows);

        #[cfg(target_os = "macos")]
        assert_eq!(platform, Platform::MacOS);
    }

    #[test]
    fn test_empty_auditor() {
        let mut auditor = ConfigAuditor::with_checks(vec![]);
        let result = auditor.run_audit();

        assert_eq!(result.summary.total_checks, 0);
        assert_eq!(result.summary.passed, 0);
        assert_eq!(result.summary.failed, 0);
    }
}
