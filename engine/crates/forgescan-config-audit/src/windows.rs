//! Windows-specific configuration check implementations

use crate::checks::{CheckResult, ConfigCheck, RegistryValue, ServiceState, UserAccountCheck};
use std::process::Command;
use tracing::debug;

/// Check registry value
pub fn check_registry(
    check: &ConfigCheck,
    path: &str,
    value_name: &str,
    expected: &RegistryValue,
) -> CheckResult {
    // Parse the registry path
    let (hive, subkey) = match parse_registry_path(path) {
        Some((h, s)) => (h, s),
        None => return CheckResult::error(check, &format!("Invalid registry path: {}", path)),
    };

    // Use reg.exe to query the value
    let output = match Command::new("reg")
        .args(["query", path, "/v", value_name])
        .output()
    {
        Ok(o) => o,
        Err(e) => return CheckResult::error(check, &format!("Failed to query registry: {}", e)),
    };

    if !output.status.success() {
        return CheckResult::fail(check, "value not found", &format!("{:?}", expected))
            .with_details(&format!(
                "Registry value {}\\{} does not exist",
                path, value_name
            ));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse the output to get the value
    let actual_value = parse_reg_query_output(&output_str, value_name);

    match (actual_value, expected) {
        (Some(RegValue::Dword(actual)), RegistryValue::Dword(exp)) => {
            if actual == *exp {
                CheckResult::pass(check, &format!("0x{:08x} ({})", actual, actual))
            } else {
                CheckResult::fail(
                    check,
                    &format!("0x{:08x} ({})", actual, actual),
                    &format!("0x{:08x} ({})", exp, exp),
                )
                .with_remediation(&format!(
                    "reg add \"{}\" /v {} /t REG_DWORD /d {} /f",
                    path, value_name, exp
                ))
            }
        }
        (Some(RegValue::String(actual)), RegistryValue::String(exp)) => {
            if actual == *exp {
                CheckResult::pass(check, &actual)
            } else {
                CheckResult::fail(check, &actual, exp).with_remediation(&format!(
                    "reg add \"{}\" /v {} /t REG_SZ /d \"{}\" /f",
                    path, value_name, exp
                ))
            }
        }
        (Some(RegValue::MultiString(actual)), RegistryValue::MultiString(exp)) => {
            if actual == *exp {
                CheckResult::pass(check, &actual.join(", "))
            } else {
                CheckResult::fail(check, &actual.join(", "), &exp.join(", "))
            }
        }
        (None, _) => {
            CheckResult::fail(check, "value not found", &format!("{:?}", expected)).with_details(
                &format!("Registry value {}\\{} does not exist", path, value_name),
            )
        }
        (Some(actual), expected) => {
            CheckResult::fail(check, &format!("{:?}", actual), &format!("{:?}", expected))
                .with_details("Registry value type mismatch")
        }
    }
}

/// Parsed registry value
#[derive(Debug)]
enum RegValue {
    Dword(u32),
    String(String),
    MultiString(Vec<String>),
    Binary(Vec<u8>),
}

/// Parse registry path into hive and subkey
fn parse_registry_path(path: &str) -> Option<(&str, &str)> {
    let path = path.trim_start_matches('\\');

    if let Some(pos) = path.find('\\') {
        let hive = &path[..pos];
        let subkey = &path[pos + 1..];
        Some((hive, subkey))
    } else {
        None
    }
}

/// Parse reg query output
fn parse_reg_query_output(output: &str, value_name: &str) -> Option<RegValue> {
    for line in output.lines() {
        let line = line.trim();

        // Look for the line containing our value
        if line.starts_with(value_name) || line.contains(value_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() >= 3 {
                let reg_type = parts.iter().find(|&&p| p.starts_with("REG_"))?;
                let value_start = parts.iter().position(|&p| p.starts_with("REG_"))? + 1;
                let value = parts[value_start..].join(" ");

                return match *reg_type {
                    "REG_DWORD" => {
                        // Parse hex value like 0x1
                        let value = value.trim_start_matches("0x");
                        u32::from_str_radix(value, 16).ok().map(RegValue::Dword)
                    }
                    "REG_SZ" | "REG_EXPAND_SZ" => Some(RegValue::String(value)),
                    "REG_MULTI_SZ" => Some(RegValue::MultiString(
                        value.split("\\0").map(String::from).collect(),
                    )),
                    "REG_BINARY" => {
                        let bytes = value
                            .split_whitespace()
                            .filter_map(|s| u8::from_str_radix(s, 16).ok())
                            .collect();
                        Some(RegValue::Binary(bytes))
                    }
                    _ => None,
                };
            }
        }
    }
    None
}

/// Check Windows service state
pub fn check_service_state(
    check: &ConfigCheck,
    service: &str,
    expected: ServiceState,
) -> CheckResult {
    // Query service state using sc.exe
    let output = match Command::new("sc").args(["query", service]).output() {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::error(check, &format!("Failed to query service: {}", e));
        }
    };

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse the state from output
    let is_running = output_str.contains("RUNNING");
    let is_stopped = output_str.contains("STOPPED");

    // Query startup type
    let startup_output = Command::new("sc")
        .args(["qc", service])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let is_disabled = startup_output.contains("DISABLED");
    let is_auto = startup_output.contains("AUTO_START");

    let actual_state = if is_running {
        "running"
    } else if is_stopped {
        "stopped"
    } else {
        "unknown"
    };

    let startup_type = if is_disabled {
        "disabled"
    } else if is_auto {
        "automatic"
    } else {
        "manual"
    };

    match expected {
        ServiceState::Running => {
            if is_running {
                CheckResult::pass(check, &format!("{} ({})", actual_state, startup_type))
            } else {
                CheckResult::fail(check, actual_state, "running")
                    .with_remediation(&format!("net start {}", service))
            }
        }
        ServiceState::Stopped => {
            if is_stopped {
                CheckResult::pass(check, &format!("{} ({})", actual_state, startup_type))
            } else {
                CheckResult::fail(check, actual_state, "stopped")
                    .with_remediation(&format!("net stop {}", service))
            }
        }
        ServiceState::Enabled => {
            if !is_disabled {
                CheckResult::pass(check, &format!("{} ({})", actual_state, startup_type))
            } else {
                CheckResult::fail(check, startup_type, "enabled")
                    .with_remediation(&format!("sc config {} start= auto", service))
            }
        }
        ServiceState::Disabled => {
            if is_disabled {
                CheckResult::pass(check, &format!("{} ({})", actual_state, startup_type))
            } else {
                CheckResult::fail(check, startup_type, "disabled")
                    .with_remediation(&format!("sc config {} start= disabled", service))
            }
        }
    }
}

/// Check Windows user account settings
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
            // Windows doesn't have shell concept like Unix
            CheckResult::pass(check, "N/A on Windows")
        }
    }
}

fn check_account_disabled(check: &ConfigCheck, username: &str, expected: bool) -> CheckResult {
    let output = match Command::new("net").args(["user", username]).output() {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::error(check, &format!("Failed to query user: {}", e));
        }
    };

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Look for "Account active" line
    let is_active = output_str
        .lines()
        .find(|l| l.contains("Account active"))
        .map(|l| l.contains("Yes"))
        .unwrap_or(false);

    let is_disabled = !is_active;

    if is_disabled == expected {
        if is_disabled {
            CheckResult::pass(check, "account is disabled")
        } else {
            CheckResult::pass(check, "account is active")
        }
    } else if expected {
        CheckResult::fail(check, "account is active", "account should be disabled")
            .with_remediation(&format!("net user {} /active:no", username))
    } else {
        CheckResult::fail(check, "account is disabled", "account should be active")
            .with_remediation(&format!("net user {} /active:yes", username))
    }
}

fn check_password_max_age(check: &ConfigCheck, max_days: u32) -> CheckResult {
    // Use net accounts to check password policy
    let output = match Command::new("net").args(["accounts"]).output() {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::error(check, &format!("Failed to query password policy: {}", e));
        }
    };

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Look for "Maximum password age" line
    let actual_max = output_str
        .lines()
        .find(|l| l.contains("Maximum password age"))
        .and_then(|l| {
            l.split(':')
                .nth(1)
                .and_then(|v| v.trim().split_whitespace().next())
                .and_then(|v| {
                    if v == "Unlimited" {
                        Some(u32::MAX)
                    } else {
                        v.parse::<u32>().ok()
                    }
                })
        });

    match actual_max {
        Some(value) if value <= max_days => CheckResult::pass(check, &format!("{} days", value)),
        Some(value) if value == u32::MAX => {
            CheckResult::fail(check, "Unlimited", &format!("<= {} days", max_days))
                .with_remediation(&format!("net accounts /maxpwage:{}", max_days))
        }
        Some(value) => CheckResult::fail(
            check,
            &format!("{} days", value),
            &format!("<= {} days", max_days),
        )
        .with_remediation(&format!("net accounts /maxpwage:{}", max_days)),
        None => CheckResult::error(check, "Cannot determine maximum password age"),
    }
}

fn check_password_min_length(check: &ConfigCheck, min_length: u32) -> CheckResult {
    let output = match Command::new("net").args(["accounts"]).output() {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::error(check, &format!("Failed to query password policy: {}", e));
        }
    };

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Look for "Minimum password length" line
    let actual_min = output_str
        .lines()
        .find(|l| l.contains("Minimum password length"))
        .and_then(|l| {
            l.split(':')
                .nth(1)
                .and_then(|v| v.trim().parse::<u32>().ok())
        });

    match actual_min {
        Some(value) if value >= min_length => {
            CheckResult::pass(check, &format!("{} characters", value))
        }
        Some(value) => CheckResult::fail(
            check,
            &format!("{} characters", value),
            &format!(">= {} characters", min_length),
        )
        .with_remediation(&format!("net accounts /minpwlen:{}", min_length)),
        None => CheckResult::error(check, "Cannot determine minimum password length"),
    }
}

/// Check Windows Firewall state
pub fn check_firewall_enabled(check: &ConfigCheck, profile: &str) -> CheckResult {
    let output = match Command::new("netsh")
        .args(["advfirewall", "show", profile])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::error(check, &format!("Failed to query firewall: {}", e));
        }
    };

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Look for "State" line
    let is_enabled = output_str
        .lines()
        .find(|l| l.contains("State"))
        .map(|l| l.contains("ON"))
        .unwrap_or(false);

    if is_enabled {
        CheckResult::pass(check, "firewall is enabled")
    } else {
        CheckResult::fail(check, "firewall is disabled", "firewall should be enabled")
            .with_remediation(&format!("netsh advfirewall set {} state on", profile))
    }
}

/// Check if Windows audit policy is configured
pub fn check_audit_policy(check: &ConfigCheck, subcategory: &str, expected: &str) -> CheckResult {
    let output = match Command::new("auditpol")
        .args(["/get", "/subcategory:", subcategory])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return CheckResult::error(check, &format!("Failed to query audit policy: {}", e));
        }
    };

    let output_str = String::from_utf8_lossy(&output.stdout);

    // Parse the policy setting
    let actual = output_str
        .lines()
        .find(|l| l.contains(subcategory))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("unknown");

    if actual.to_lowercase() == expected.to_lowercase() {
        CheckResult::pass(check, actual)
    } else {
        CheckResult::fail(check, actual, expected).with_remediation(&format!(
            "auditpol /set /subcategory:\"{}\" /success:enable /failure:enable",
            subcategory
        ))
    }
}

/// Check if a Windows feature is installed
pub fn check_feature_installed(
    check: &ConfigCheck,
    feature: &str,
    should_be_installed: bool,
) -> CheckResult {
    // Use DISM or Get-WindowsFeature depending on server/desktop
    let output = Command::new("dism")
        .args([
            "/online",
            "/get-featureinfo",
            &format!("/featurename:{}", feature),
        ])
        .output();

    match output {
        Ok(o) => {
            let output_str = String::from_utf8_lossy(&o.stdout);
            let is_enabled = output_str.contains("State : Enabled");

            if is_enabled == should_be_installed {
                if is_enabled {
                    CheckResult::pass(check, "feature is installed")
                } else {
                    CheckResult::pass(check, "feature is not installed")
                }
            } else if should_be_installed {
                CheckResult::fail(check, "not installed", "installed").with_remediation(&format!(
                    "dism /online /enable-feature /featurename:{}",
                    feature
                ))
            } else {
                CheckResult::fail(check, "installed", "not installed").with_remediation(&format!(
                    "dism /online /disable-feature /featurename:{}",
                    feature
                ))
            }
        }
        Err(e) => CheckResult::error(check, &format!("Failed to check feature: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_registry_path() {
        let (hive, subkey) = parse_registry_path(r"HKLM\SOFTWARE\Microsoft\Windows").unwrap();
        assert_eq!(hive, "HKLM");
        assert_eq!(subkey, r"SOFTWARE\Microsoft\Windows");
    }

    #[test]
    fn test_parse_reg_query_output() {
        let output = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Test
    TestValue    REG_DWORD    0x1
"#;
        let value = parse_reg_query_output(output, "TestValue");
        assert!(matches!(value, Some(RegValue::Dword(1))));
    }
}
