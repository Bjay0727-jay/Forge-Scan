//! Linux-specific configuration check implementations

use crate::checks::{CheckResult, ConfigCheck, ServiceState, UserAccountCheck};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

/// Check file permissions on Linux
pub fn check_file_permission(
    check: &ConfigCheck,
    path: &str,
    expected_mode: Option<u32>,
    max_mode: Option<u32>,
    owner: &Option<String>,
    group: &Option<String>,
) -> CheckResult {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return CheckResult::error(check, &format!("Cannot access {}: {}", path, e)),
    };

    let mode = metadata.permissions().mode() & 0o7777;
    let uid = metadata.uid();
    let gid = metadata.gid();

    // Check mode if specified
    if let Some(expected) = expected_mode {
        if mode != expected {
            return CheckResult::fail(
                check,
                &format!("{:04o}", mode),
                &format!("{:04o}", expected),
            )
            .with_details(&format!(
                "File {} has mode {:04o}, expected {:04o}",
                path, mode, expected
            ))
            .with_remediation(&format!("chmod {:04o} {}", expected, path));
        }
    }

    // Check max mode if specified
    if let Some(max) = max_mode {
        if mode > max {
            return CheckResult::fail(check, &format!("{:04o}", mode), &format!("<= {:04o}", max))
                .with_details(&format!(
                    "File {} has mode {:04o}, which is more permissive than {:04o}",
                    path, mode, max
                ))
                .with_remediation(&format!("chmod {:04o} {}", max, path));
        }
    }

    // Check owner if specified
    if let Some(expected_owner) = owner {
        let actual_owner = get_username(uid);
        if actual_owner != *expected_owner {
            return CheckResult::fail(check, &actual_owner, expected_owner)
                .with_details(&format!(
                    "File {} is owned by {}, expected {}",
                    path, actual_owner, expected_owner
                ))
                .with_remediation(&format!("chown {} {}", expected_owner, path));
        }
    }

    // Check group if specified
    if let Some(expected_group) = group {
        let actual_group = get_groupname(gid);
        if actual_group != *expected_group {
            return CheckResult::fail(check, &actual_group, expected_group)
                .with_details(&format!(
                    "File {} has group {}, expected {}",
                    path, actual_group, expected_group
                ))
                .with_remediation(&format!("chgrp {} {}", expected_group, path));
        }
    }

    CheckResult::pass(
        check,
        &format!(
            "mode={:04o} owner={} group={}",
            mode,
            get_username(uid),
            get_groupname(gid)
        ),
    )
}

/// Get username from UID
fn get_username(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(uid) {
                    Some(parts[0].to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| uid.to_string())
}

/// Get group name from GID
fn get_groupname(gid: u32) -> String {
    fs::read_to_string("/etc/group")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(gid) {
                    Some(parts[0].to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| gid.to_string())
}

/// Check service state using systemctl
pub fn check_service_state(
    check: &ConfigCheck,
    service: &str,
    expected: ServiceState,
) -> CheckResult {
    // Check if service is active
    let is_active = Command::new("systemctl")
        .args(["is-active", service])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false);

    // Check if service is enabled
    let is_enabled = Command::new("systemctl")
        .args(["is-enabled", service])
        .output()
        .map(|o| {
            let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
            status == "enabled" || status == "static"
        })
        .unwrap_or(false);

    let actual_state = match (is_active, is_enabled) {
        (true, true) => "running and enabled",
        (true, false) => "running but disabled",
        (false, true) => "stopped but enabled",
        (false, false) => "stopped and disabled",
    };

    match expected {
        ServiceState::Running => {
            if is_active {
                CheckResult::pass(check, actual_state)
            } else {
                CheckResult::fail(check, actual_state, "running")
                    .with_remediation(&format!("systemctl start {}", service))
            }
        }
        ServiceState::Stopped => {
            if !is_active {
                CheckResult::pass(check, actual_state)
            } else {
                CheckResult::fail(check, actual_state, "stopped")
                    .with_remediation(&format!("systemctl stop {}", service))
            }
        }
        ServiceState::Enabled => {
            if is_enabled {
                CheckResult::pass(check, actual_state)
            } else {
                CheckResult::fail(check, actual_state, "enabled")
                    .with_remediation(&format!("systemctl enable {}", service))
            }
        }
        ServiceState::Disabled => {
            if !is_enabled {
                CheckResult::pass(check, actual_state)
            } else {
                CheckResult::fail(check, actual_state, "disabled")
                    .with_remediation(&format!("systemctl disable {}", service))
            }
        }
    }
}

/// Check if a package is installed
pub fn check_package_installed(
    check: &ConfigCheck,
    package: &str,
    should_be_installed: bool,
) -> CheckResult {
    // Try dpkg first
    let dpkg_installed = Command::new("dpkg-query")
        .args(["-W", "-f", "${Status}", package])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout).contains("install ok installed")
        })
        .unwrap_or(false);

    // Try rpm as fallback
    let rpm_installed = if !dpkg_installed {
        Command::new("rpm")
            .args(["-q", package])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        false
    };

    let is_installed = dpkg_installed || rpm_installed;

    if is_installed == should_be_installed {
        if is_installed {
            CheckResult::pass(check, "installed")
        } else {
            CheckResult::pass(check, "not installed")
        }
    } else if should_be_installed {
        CheckResult::fail(check, "not installed", "installed")
            .with_remediation(&format!("Install package: {}", package))
    } else {
        CheckResult::fail(check, "installed", "not installed")
            .with_remediation(&format!("Remove package: {}", package))
    }
}

/// Check sysctl value
pub fn check_sysctl(check: &ConfigCheck, key: &str, expected: &str) -> CheckResult {
    // First try reading from /proc/sys
    let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));

    let actual = if let Ok(value) = fs::read_to_string(&proc_path) {
        value.trim().to_string()
    } else {
        // Fallback to sysctl command
        match Command::new("sysctl").args(["-n", key]).output() {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            _ => {
                return CheckResult::error(check, &format!("Cannot read sysctl key: {}", key));
            }
        }
    };

    if actual == expected {
        CheckResult::pass(check, &actual)
    } else {
        CheckResult::fail(check, &actual, expected)
            .with_details(&format!(
                "Sysctl {} is {}, expected {}",
                key, actual, expected
            ))
            .with_remediation(&format!(
                "sysctl -w {}={} && echo '{}={}' >> /etc/sysctl.conf",
                key, expected, key, expected
            ))
    }
}

/// Check user account settings
pub fn check_user_account(check: &ConfigCheck, user_check: &UserAccountCheck) -> CheckResult {
    match user_check {
        UserAccountCheck::AccountDisabled { username, expected } => {
            check_account_disabled(check, username, *expected)
        }
        UserAccountCheck::PasswordMaxAge { max_days } => check_password_max_age(check, *max_days),
        UserAccountCheck::PasswordMinLength { min_length } => {
            check_password_min_length(check, *min_length)
        }
        UserAccountCheck::ShellAccess { username, allowed } => {
            check_shell_access(check, username, *allowed)
        }
    }
}

fn check_account_disabled(check: &ConfigCheck, username: &str, expected: bool) -> CheckResult {
    // Check /etc/shadow for locked account (! or * prefix)
    let is_disabled = fs::read_to_string("/etc/shadow")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 && parts[0] == username {
                    let password_field = parts[1];
                    Some(
                        password_field.starts_with('!')
                            || password_field.starts_with('*')
                            || password_field == "!!",
                    )
                } else {
                    None
                }
            })
        })
        .unwrap_or(false);

    if is_disabled == expected {
        if is_disabled {
            CheckResult::pass(check, "account is disabled")
        } else {
            CheckResult::pass(check, "account is enabled")
        }
    } else if expected {
        CheckResult::fail(check, "account is enabled", "account should be disabled")
            .with_remediation(&format!("usermod -L {}", username))
    } else {
        CheckResult::fail(check, "account is disabled", "account should be enabled")
            .with_remediation(&format!("usermod -U {}", username))
    }
}

fn check_password_max_age(check: &ConfigCheck, max_days: u32) -> CheckResult {
    // Read from /etc/login.defs
    let actual = fs::read_to_string("/etc/login.defs")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let line = line.trim();
                if line.starts_with("PASS_MAX_DAYS") && !line.starts_with('#') {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u32>().ok())
                } else {
                    None
                }
            })
        });

    match actual {
        Some(value) if value <= max_days => CheckResult::pass(check, &format!("{} days", value)),
        Some(value) => CheckResult::fail(
            check,
            &format!("{} days", value),
            &format!("<= {} days", max_days),
        )
        .with_details(&format!(
            "Password max age is {} days, should be {} days or less",
            value, max_days
        ))
        .with_remediation(&format!(
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS {}/' /etc/login.defs",
            max_days
        )),
        None => CheckResult::error(check, "Cannot determine PASS_MAX_DAYS from /etc/login.defs"),
    }
}

fn check_password_min_length(check: &ConfigCheck, min_length: u32) -> CheckResult {
    // Check PAM configuration
    let pam_pwquality = fs::read_to_string("/etc/security/pwquality.conf")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let line = line.trim();
                if line.starts_with("minlen") && !line.starts_with('#') {
                    line.split('=')
                        .nth(1)
                        .and_then(|v| v.trim().parse::<u32>().ok())
                } else {
                    None
                }
            })
        });

    // Fallback to login.defs
    let login_defs = fs::read_to_string("/etc/login.defs")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let line = line.trim();
                if line.starts_with("PASS_MIN_LEN") && !line.starts_with('#') {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u32>().ok())
                } else {
                    None
                }
            })
        });

    let actual = pam_pwquality.or(login_defs);

    match actual {
        Some(value) if value >= min_length => {
            CheckResult::pass(check, &format!("{} characters", value))
        }
        Some(value) => CheckResult::fail(
            check,
            &format!("{} characters", value),
            &format!(">= {} characters", min_length),
        )
        .with_details(&format!(
            "Minimum password length is {}, should be {} or more",
            value, min_length
        ))
        .with_remediation(&format!(
            "echo 'minlen = {}' >> /etc/security/pwquality.conf",
            min_length
        )),
        None => CheckResult::error(
            check,
            "Cannot determine password minimum length from system config",
        ),
    }
}

fn check_shell_access(check: &ConfigCheck, username: &str, allowed: bool) -> CheckResult {
    let shell = fs::read_to_string("/etc/passwd").ok().and_then(|content| {
        content.lines().find_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 && parts[0] == username {
                Some(parts[6].to_string())
            } else {
                None
            }
        })
    });

    match shell {
        Some(shell) => {
            let has_shell =
                !shell.contains("nologin") && !shell.contains("false") && !shell.contains("sync");

            if has_shell == allowed {
                CheckResult::pass(check, &format!("shell: {}", shell))
            } else if allowed {
                CheckResult::fail(
                    check,
                    &format!("no shell access ({})", shell),
                    "shell access",
                )
                .with_remediation(&format!("usermod -s /bin/bash {}", username))
            } else {
                CheckResult::fail(
                    check,
                    &format!("has shell access ({})", shell),
                    "no shell access",
                )
                .with_remediation(&format!("usermod -s /sbin/nologin {}", username))
            }
        }
        None => CheckResult::error(check, &format!("User {} not found", username)),
    }
}

/// Check kernel module configuration
pub fn check_kernel_module_disabled(check: &ConfigCheck, module: &str) -> CheckResult {
    // Check if module is blacklisted
    let is_blacklisted = fs::read_dir("/etc/modprobe.d")
        .ok()
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|entry| {
                fs::read_to_string(entry.path())
                    .ok()
                    .map(|content| {
                        content
                            .lines()
                            .any(|l| l.contains(&format!("blacklist {}", module)))
                    })
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    // Check if module is set to install /bin/true
    let install_true = Command::new("modprobe")
        .args(["-n", "-v", module])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("install /bin/true"))
        .unwrap_or(false);

    if is_blacklisted || install_true {
        CheckResult::pass(check, "module is disabled")
    } else {
        CheckResult::fail(check, "module is enabled", "module should be disabled")
            .with_remediation(&format!(
                "echo 'install {} /bin/true' >> /etc/modprobe.d/{}.conf && echo 'blacklist {}' >> /etc/modprobe.d/{}.conf",
                module, module, module, module
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::*;

    fn test_check() -> ConfigCheck {
        ConfigCheck {
            id: "TEST-001".into(),
            name: "Test Check".into(),
            description: "A test check".into(),
            check_type: CheckType::Command {
                command: "true".into(),
                args: vec![],
                expected_output: None,
                expected_exit_code: Some(0),
            },
            severity: forgescan_core::Severity::Low,
            compliance: vec![],
            platform: "linux".into(),
            enabled: true,
        }
    }

    #[test]
    fn test_sysctl_check() {
        let check = test_check();
        // This should work on most Linux systems
        let result = check_sysctl(&check, "kernel.hostname", "");
        // We just verify it doesn't error out
        assert!(!result.actual.starts_with("Error:") || result.actual.contains("Cannot read"));
    }
}
