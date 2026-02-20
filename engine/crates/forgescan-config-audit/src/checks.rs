//! Configuration check types and results

use forgescan_core::Severity;
use serde::{Deserialize, Serialize};

/// A configuration check definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigCheck {
    /// Unique check ID
    pub id: String,
    /// Check name
    pub name: String,
    /// Description
    pub description: String,
    /// Check type
    pub check_type: CheckType,
    /// Severity if check fails
    pub severity: Severity,
    /// Compliance framework mappings
    pub compliance: Vec<ComplianceMapping>,
    /// Platform (linux, windows, all)
    pub platform: String,
    /// Is check enabled by default
    pub enabled: bool,
}

/// Types of configuration checks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CheckType {
    /// Check file permissions
    FilePermission {
        path: String,
        expected_mode: Option<u32>,
        max_mode: Option<u32>,
        owner: Option<String>,
        group: Option<String>,
    },
    /// Check file content
    FileContent {
        path: String,
        pattern: String,
        expected: Option<String>,
        should_exist: bool,
    },
    /// Check configuration value
    ConfigValue {
        file: String,
        key: String,
        expected: String,
        delimiter: Option<String>,
    },
    /// Check if service is running/stopped
    ServiceState {
        service: String,
        expected_state: ServiceState,
    },
    /// Check if package is installed
    PackageInstalled {
        package: String,
        should_be_installed: bool,
    },
    /// Check sysctl value (Linux)
    Sysctl { key: String, expected: String },
    /// Check registry value (Windows)
    Registry {
        path: String,
        value_name: String,
        expected: RegistryValue,
    },
    /// Check user account settings
    UserAccount { check: UserAccountCheck },
    /// Run a command and check output
    Command {
        command: String,
        args: Vec<String>,
        expected_output: Option<String>,
        expected_exit_code: Option<i32>,
    },
}

/// Service states
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    Disabled,
    Enabled,
}

/// Registry value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum RegistryValue {
    Dword(u32),
    String(String),
    MultiString(Vec<String>),
    Binary(Vec<u8>),
}

/// User account checks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "check")]
pub enum UserAccountCheck {
    /// Check if account is disabled
    AccountDisabled { username: String, expected: bool },
    /// Check password expiry settings
    PasswordMaxAge { max_days: u32 },
    /// Check minimum password length
    PasswordMinLength { min_length: u32 },
    /// Check if account has shell access
    ShellAccess { username: String, allowed: bool },
}

/// Compliance framework mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapping {
    pub framework: String,
    pub control: String,
    pub benchmark: Option<String>,
}

/// Result of a configuration check
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Check ID
    pub check_id: String,
    /// Check name
    pub check_name: String,
    /// Whether check passed
    pub passed: bool,
    /// Actual value found
    pub actual: String,
    /// Expected value
    pub expected: String,
    /// Severity if failed
    pub severity: Severity,
    /// Additional details
    pub details: Option<String>,
    /// Remediation steps
    pub remediation: Option<String>,
    /// Compliance mappings
    pub compliance: Vec<ComplianceMapping>,
}

impl CheckResult {
    pub fn pass(check: &ConfigCheck, actual: &str) -> Self {
        Self {
            check_id: check.id.clone(),
            check_name: check.name.clone(),
            passed: true,
            actual: actual.to_string(),
            expected: String::new(),
            severity: check.severity,
            details: None,
            remediation: None,
            compliance: check.compliance.clone(),
        }
    }

    pub fn fail(check: &ConfigCheck, actual: &str, expected: &str) -> Self {
        Self {
            check_id: check.id.clone(),
            check_name: check.name.clone(),
            passed: false,
            actual: actual.to_string(),
            expected: expected.to_string(),
            severity: check.severity,
            details: None,
            remediation: None,
            compliance: check.compliance.clone(),
        }
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    pub fn error(check: &ConfigCheck, error: &str) -> Self {
        Self {
            check_id: check.id.clone(),
            check_name: check.name.clone(),
            passed: false,
            actual: format!("Error: {}", error),
            expected: String::new(),
            severity: Severity::Info,
            details: Some(error.to_string()),
            remediation: None,
            compliance: check.compliance.clone(),
        }
    }
}

/// Built-in CIS checks for Linux
pub fn cis_linux_checks() -> Vec<ConfigCheck> {
    vec![
        ConfigCheck {
            id: "CIS-LIN-1.1.1".into(),
            name: "Ensure mounting of cramfs is disabled".into(),
            description: "The cramfs filesystem type is a compressed read-only Linux filesystem".into(),
            check_type: CheckType::Command {
                command: "modprobe".into(),
                args: vec!["-n".into(), "-v".into(), "cramfs".into()],
                expected_output: Some("install /bin/true".into()),
                expected_exit_code: None,
            },
            severity: Severity::Low,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "1.1.1".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-LIN-1.4.1".into(),
            name: "Ensure permissions on bootloader config are configured".into(),
            description: "The grub configuration file contains information on boot settings".into(),
            check_type: CheckType::FilePermission {
                path: "/boot/grub/grub.cfg".into(),
                expected_mode: Some(0o400),
                max_mode: Some(0o600),
                owner: Some("root".into()),
                group: Some("root".into()),
            },
            severity: Severity::High,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "1.4.1".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-LIN-5.2.1".into(),
            name: "Ensure permissions on /etc/ssh/sshd_config are configured".into(),
            description: "The /etc/ssh/sshd_config file contains configuration specifications for sshd".into(),
            check_type: CheckType::FilePermission {
                path: "/etc/ssh/sshd_config".into(),
                expected_mode: Some(0o600),
                max_mode: Some(0o600),
                owner: Some("root".into()),
                group: Some("root".into()),
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "5.2.1".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-LIN-5.2.4".into(),
            name: "Ensure SSH Protocol is set to 2".into(),
            description: "SSH supports two different and incompatible protocols: SSH1 and SSH2".into(),
            check_type: CheckType::ConfigValue {
                file: "/etc/ssh/sshd_config".into(),
                key: "Protocol".into(),
                expected: "2".into(),
                delimiter: Some(" ".into()),
            },
            severity: Severity::High,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "5.2.4".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-LIN-5.2.10".into(),
            name: "Ensure SSH root login is disabled".into(),
            description: "The PermitRootLogin parameter specifies if root can log in using ssh".into(),
            check_type: CheckType::ConfigValue {
                file: "/etc/ssh/sshd_config".into(),
                key: "PermitRootLogin".into(),
                expected: "no".into(),
                delimiter: Some(" ".into()),
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "5.2.10".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-LIN-5.4.1.1".into(),
            name: "Ensure password expiration is 365 days or less".into(),
            description: "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force passwords to expire".into(),
            check_type: CheckType::ConfigValue {
                file: "/etc/login.defs".into(),
                key: "PASS_MAX_DAYS".into(),
                expected: "365".into(),
                delimiter: None,
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "5.4.1.1".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-LIN-3.1.1".into(),
            name: "Ensure IP forwarding is disabled".into(),
            description: "The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets".into(),
            check_type: CheckType::Sysctl {
                key: "net.ipv4.ip_forward".into(),
                expected: "0".into(),
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "3.1.1".into(),
                benchmark: Some("CIS Ubuntu Linux 22.04 LTS".into()),
            }],
            platform: "linux".into(),
            enabled: true,
        },
    ]
}

/// Built-in CIS checks for Windows
pub fn cis_windows_checks() -> Vec<ConfigCheck> {
    vec![
        ConfigCheck {
            id: "CIS-WIN-1.1.1".into(),
            name: "Ensure 'Enforce password history' is set to '24 or more password(s)'".into(),
            description: "This policy setting determines the number of renewed, unique passwords"
                .into(),
            check_type: CheckType::Registry {
                path: r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters".into(),
                value_name: "PasswordHistorySize".into(),
                expected: RegistryValue::Dword(24),
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "1.1.1".into(),
                benchmark: Some("CIS Microsoft Windows Server 2022".into()),
            }],
            platform: "windows".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-WIN-1.1.2".into(),
            name: "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'".into(),
            description: "This policy setting defines how long a user can use their password"
                .into(),
            check_type: CheckType::Registry {
                path: r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters".into(),
                value_name: "MaximumPasswordAge".into(),
                expected: RegistryValue::Dword(365),
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "1.1.2".into(),
                benchmark: Some("CIS Microsoft Windows Server 2022".into()),
            }],
            platform: "windows".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-WIN-2.3.1.1".into(),
            name: "Ensure 'Accounts: Administrator account status' is set to 'Disabled'".into(),
            description: "This policy setting enables or disables the Administrator account".into(),
            check_type: CheckType::UserAccount {
                check: UserAccountCheck::AccountDisabled {
                    username: "Administrator".into(),
                    expected: true,
                },
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "2.3.1.1".into(),
                benchmark: Some("CIS Microsoft Windows Server 2022".into()),
            }],
            platform: "windows".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-WIN-2.3.1.2".into(),
            name: "Ensure 'Accounts: Guest account status' is set to 'Disabled'".into(),
            description:
                "This policy setting determines whether the Guest account is enabled or disabled"
                    .into(),
            check_type: CheckType::UserAccount {
                check: UserAccountCheck::AccountDisabled {
                    username: "Guest".into(),
                    expected: true,
                },
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "2.3.1.2".into(),
                benchmark: Some("CIS Microsoft Windows Server 2022".into()),
            }],
            platform: "windows".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-WIN-18.9.5.1".into(),
            name: "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'".into(),
            description: "Autoplay starts to read from a drive as soon as media is inserted".into(),
            check_type: CheckType::Registry {
                path: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer".into(),
                value_name: "NoDriveTypeAutoRun".into(),
                expected: RegistryValue::Dword(255),
            },
            severity: Severity::Medium,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "18.9.5.1".into(),
                benchmark: Some("CIS Microsoft Windows Server 2022".into()),
            }],
            platform: "windows".into(),
            enabled: true,
        },
        ConfigCheck {
            id: "CIS-WIN-18.9.102.1".into(),
            name: "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'".into(),
            description:
                "Select On to have Windows Firewall with Advanced Security use the settings".into(),
            check_type: CheckType::Registry {
                path: r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile".into(),
                value_name: "EnableFirewall".into(),
                expected: RegistryValue::Dword(1),
            },
            severity: Severity::High,
            compliance: vec![ComplianceMapping {
                framework: "CIS".into(),
                control: "18.9.102.1".into(),
                benchmark: Some("CIS Microsoft Windows Server 2022".into()),
            }],
            platform: "windows".into(),
            enabled: true,
        },
    ]
}
