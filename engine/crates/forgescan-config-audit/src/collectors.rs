//! System information collectors for configuration auditing

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Collected system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system info
    pub os: OsInfo,
    /// Hardware info
    pub hardware: HardwareInfo,
    /// Network info
    pub network: NetworkInfo,
    /// Installed packages
    pub packages: Vec<PackageInfo>,
    /// Running services
    pub services: Vec<ServiceInfo>,
    /// User accounts
    pub users: Vec<UserInfo>,
    /// Environment variables (filtered for security)
    pub environment: HashMap<String, String>,
}

/// Operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    /// OS name (e.g., "Ubuntu", "Windows Server")
    pub name: String,
    /// OS version
    pub version: String,
    /// Kernel version
    pub kernel: String,
    /// Architecture
    pub arch: String,
    /// Hostname
    pub hostname: String,
}

/// Hardware information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    /// CPU model
    pub cpu_model: String,
    /// Number of CPU cores
    pub cpu_cores: u32,
    /// Total RAM in bytes
    pub total_memory: u64,
    /// Is virtual machine
    pub is_virtual: bool,
    /// Hypervisor type if virtual
    pub hypervisor: Option<String>,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Network interfaces
    pub interfaces: Vec<NetworkInterface>,
    /// Listening ports
    pub listening_ports: Vec<ListeningPort>,
}

/// Network interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,
    /// MAC address
    pub mac: Option<String>,
    /// IPv4 addresses
    pub ipv4: Vec<String>,
    /// IPv6 addresses
    pub ipv6: Vec<String>,
    /// Is interface up
    pub is_up: bool,
}

/// Listening port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Local address
    pub address: String,
    /// Port number
    pub port: u16,
    /// Process ID
    pub pid: Option<u32>,
    /// Process name
    pub process: Option<String>,
}

/// Installed package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package manager (apt, yum, msi, etc.)
    pub manager: String,
    /// Install date if available
    pub install_date: Option<String>,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
    /// Current state
    pub state: String,
    /// Start type (auto, manual, disabled)
    pub start_type: String,
    /// User account running the service
    pub user: Option<String>,
}

/// User account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Username
    pub username: String,
    /// User ID
    pub uid: u32,
    /// Primary group ID
    pub gid: u32,
    /// Home directory
    pub home: String,
    /// Login shell
    pub shell: String,
    /// Is account disabled
    pub disabled: bool,
    /// Is account locked
    pub locked: bool,
    /// Last login time
    pub last_login: Option<String>,
    /// Password expiry info
    pub password_expiry: Option<PasswordInfo>,
}

/// Password policy information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordInfo {
    /// Days until password expires
    pub days_until_expiry: Option<i32>,
    /// Minimum password age in days
    pub min_age: Option<u32>,
    /// Maximum password age in days
    pub max_age: Option<u32>,
    /// Warning days before expiry
    pub warn_days: Option<u32>,
}

/// System information collector
pub struct SystemCollector;

impl SystemCollector {
    /// Collect all system information
    pub fn collect() -> SystemInfo {
        SystemInfo {
            os: Self::collect_os_info(),
            hardware: Self::collect_hardware_info(),
            network: Self::collect_network_info(),
            packages: Self::collect_packages(),
            services: Self::collect_services(),
            users: Self::collect_users(),
            environment: Self::collect_environment(),
        }
    }

    /// Collect OS information
    #[cfg(unix)]
    pub fn collect_os_info() -> OsInfo {
        use std::process::Command;

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into());

        let kernel = Command::new("uname")
            .arg("-r")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());

        let arch = std::env::consts::ARCH.to_string();

        // Try to read os-release
        let (name, version) = std::fs::read_to_string("/etc/os-release")
            .map(|content| {
                let mut name = String::new();
                let mut version = String::new();

                for line in content.lines() {
                    if let Some(n) = line.strip_prefix("NAME=") {
                        name = n.trim_matches('"').to_string();
                    } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
                        version = v.trim_matches('"').to_string();
                    }
                }

                (name, version)
            })
            .unwrap_or_else(|_| ("Linux".into(), "unknown".into()));

        OsInfo {
            name,
            version,
            kernel,
            arch,
            hostname,
        }
    }

    #[cfg(windows)]
    pub fn collect_os_info() -> OsInfo {
        use std::process::Command;

        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into());

        let arch = std::env::consts::ARCH.to_string();

        // Use systeminfo or wmic
        let (name, version, kernel) = Command::new("wmic")
            .args(["os", "get", "Caption,Version", "/value"])
            .output()
            .map(|o| {
                let output = String::from_utf8_lossy(&o.stdout);
                let mut name = "Windows".to_string();
                let mut version = "unknown".to_string();

                for line in output.lines() {
                    if let Some(n) = line.strip_prefix("Caption=") {
                        name = n.trim().to_string();
                    } else if let Some(v) = line.strip_prefix("Version=") {
                        version = v.trim().to_string();
                    }
                }

                (name, version.clone(), version)
            })
            .unwrap_or_else(|_| ("Windows".into(), "unknown".into(), "unknown".into()));

        OsInfo {
            name,
            version,
            kernel,
            arch,
            hostname,
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn collect_os_info() -> OsInfo {
        OsInfo {
            name: std::env::consts::OS.to_string(),
            version: "unknown".into(),
            kernel: "unknown".into(),
            arch: std::env::consts::ARCH.to_string(),
            hostname: "unknown".into(),
        }
    }

    /// Collect hardware information
    pub fn collect_hardware_info() -> HardwareInfo {
        HardwareInfo {
            cpu_model: Self::get_cpu_model(),
            cpu_cores: num_cpus::get() as u32,
            total_memory: Self::get_total_memory(),
            is_virtual: Self::detect_virtualization().is_some(),
            hypervisor: Self::detect_virtualization(),
        }
    }

    #[cfg(unix)]
    fn get_cpu_model() -> String {
        std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "Unknown CPU".into())
    }

    #[cfg(windows)]
    fn get_cpu_model() -> String {
        use std::process::Command;

        Command::new("wmic")
            .args(["cpu", "get", "Name", "/value"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.starts_with("Name="))
                    .and_then(|l| l.strip_prefix("Name="))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "Unknown CPU".into())
            })
            .unwrap_or_else(|_| "Unknown CPU".into())
    }

    #[cfg(not(any(unix, windows)))]
    fn get_cpu_model() -> String {
        "Unknown CPU".into()
    }

    #[cfg(unix)]
    fn get_total_memory() -> u64 {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u64>().ok())
                    })
            })
            .map(|kb| kb * 1024)
            .unwrap_or(0)
    }

    #[cfg(windows)]
    fn get_total_memory() -> u64 {
        use std::process::Command;

        Command::new("wmic")
            .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .find(|l| l.starts_with("TotalPhysicalMemory="))
                    .and_then(|l| l.strip_prefix("TotalPhysicalMemory="))
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    #[cfg(not(any(unix, windows)))]
    fn get_total_memory() -> u64 {
        0
    }

    /// Detect virtualization
    #[cfg(unix)]
    fn detect_virtualization() -> Option<String> {
        use std::process::Command;

        // Check systemd-detect-virt
        Command::new("systemd-detect-virt")
            .output()
            .ok()
            .and_then(|o| {
                let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if result != "none" && !result.is_empty() {
                    Some(result)
                } else {
                    None
                }
            })
            .or_else(|| {
                // Fallback: check DMI
                std::fs::read_to_string("/sys/class/dmi/id/product_name")
                    .ok()
                    .and_then(|s| {
                        let lower = s.to_lowercase();
                        if lower.contains("virtualbox") {
                            Some("virtualbox".into())
                        } else if lower.contains("vmware") {
                            Some("vmware".into())
                        } else if lower.contains("qemu") || lower.contains("kvm") {
                            Some("kvm".into())
                        } else if lower.contains("hyper-v") {
                            Some("hyperv".into())
                        } else {
                            None
                        }
                    })
            })
    }

    #[cfg(windows)]
    fn detect_virtualization() -> Option<String> {
        use std::process::Command;

        Command::new("wmic")
            .args(["computersystem", "get", "Model", "/value"])
            .output()
            .ok()
            .and_then(|o| {
                let output = String::from_utf8_lossy(&o.stdout).to_lowercase();
                if output.contains("virtual") {
                    Some("hyperv".into())
                } else if output.contains("vmware") {
                    Some("vmware".into())
                } else if output.contains("virtualbox") {
                    Some("virtualbox".into())
                } else {
                    None
                }
            })
    }

    #[cfg(not(any(unix, windows)))]
    fn detect_virtualization() -> Option<String> {
        None
    }

    /// Collect network information
    pub fn collect_network_info() -> NetworkInfo {
        NetworkInfo {
            interfaces: Self::collect_interfaces(),
            listening_ports: Self::collect_listening_ports(),
        }
    }

    fn collect_interfaces() -> Vec<NetworkInterface> {
        // Simplified - in production would use pnet or similar
        Vec::new()
    }

    fn collect_listening_ports() -> Vec<ListeningPort> {
        // Simplified - in production would parse netstat/ss output
        Vec::new()
    }

    /// Collect installed packages
    #[cfg(unix)]
    pub fn collect_packages() -> Vec<PackageInfo> {
        use std::process::Command;

        // Try dpkg first (Debian/Ubuntu)
        if let Ok(output) = Command::new("dpkg-query")
            .args(["-W", "-f", "${Package} ${Version}\n"])
            .output()
        {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            Some(PackageInfo {
                                name: parts[0].to_string(),
                                version: parts[1].to_string(),
                                manager: "dpkg".into(),
                                install_date: None,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }

        // Try rpm (RHEL/CentOS)
        if let Ok(output) = Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME} %{VERSION}\n"])
            .output()
        {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            Some(PackageInfo {
                                name: parts[0].to_string(),
                                version: parts[1].to_string(),
                                manager: "rpm".into(),
                                install_date: None,
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }

        Vec::new()
    }

    #[cfg(windows)]
    pub fn collect_packages() -> Vec<PackageInfo> {
        // Windows package collection would use WMI or registry
        Vec::new()
    }

    #[cfg(not(any(unix, windows)))]
    pub fn collect_packages() -> Vec<PackageInfo> {
        Vec::new()
    }

    /// Collect running services
    #[cfg(unix)]
    pub fn collect_services() -> Vec<ServiceInfo> {
        use std::process::Command;

        Command::new("systemctl")
            .args(["list-units", "--type=service", "--no-legend", "--no-pager"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            Some(ServiceInfo {
                                name: parts[0].trim_end_matches(".service").to_string(),
                                display_name: None,
                                state: parts[3].to_string(),
                                start_type: "unknown".into(),
                                user: None,
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(windows)]
    pub fn collect_services() -> Vec<ServiceInfo> {
        use std::process::Command;

        Command::new("sc")
            .args(["query", "state=", "all"])
            .output()
            .map(|o| {
                let output = String::from_utf8_lossy(&o.stdout);
                let mut services = Vec::new();
                let mut current_name = String::new();
                let mut current_state = String::new();

                for line in output.lines() {
                    if let Some(name) = line.strip_prefix("SERVICE_NAME: ") {
                        current_name = name.trim().to_string();
                    } else if line.contains("STATE") {
                        if let Some(state) = line.split_whitespace().last() {
                            current_state = state.to_string();
                        }

                        if !current_name.is_empty() {
                            services.push(ServiceInfo {
                                name: current_name.clone(),
                                display_name: None,
                                state: current_state.clone(),
                                start_type: "unknown".into(),
                                user: None,
                            });
                        }
                    }
                }

                services
            })
            .unwrap_or_default()
    }

    #[cfg(not(any(unix, windows)))]
    pub fn collect_services() -> Vec<ServiceInfo> {
        Vec::new()
    }

    /// Collect user accounts
    #[cfg(unix)]
    pub fn collect_users() -> Vec<UserInfo> {
        std::fs::read_to_string("/etc/passwd")
            .map(|content| {
                content
                    .lines()
                    .filter_map(|line| {
                        let parts: Vec<&str> = line.split(':').collect();
                        if parts.len() >= 7 {
                            Some(UserInfo {
                                username: parts[0].to_string(),
                                uid: parts[2].parse().unwrap_or(0),
                                gid: parts[3].parse().unwrap_or(0),
                                home: parts[5].to_string(),
                                shell: parts[6].to_string(),
                                disabled: parts[6].contains("nologin") || parts[6].contains("false"),
                                locked: false,
                                last_login: None,
                                password_expiry: None,
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(windows)]
    pub fn collect_users() -> Vec<UserInfo> {
        use std::process::Command;

        Command::new("net")
            .args(["user"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .skip(4) // Skip header lines
                    .take_while(|l| !l.starts_with("The command"))
                    .flat_map(|line| line.split_whitespace())
                    .filter(|s| !s.is_empty())
                    .map(|username| UserInfo {
                        username: username.to_string(),
                        uid: 0,
                        gid: 0,
                        home: String::new(),
                        shell: String::new(),
                        disabled: false,
                        locked: false,
                        last_login: None,
                        password_expiry: None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(not(any(unix, windows)))]
    pub fn collect_users() -> Vec<UserInfo> {
        Vec::new()
    }

    /// Collect environment variables (filtered for security)
    pub fn collect_environment() -> HashMap<String, String> {
        let safe_vars = [
            "PATH",
            "HOME",
            "USER",
            "SHELL",
            "TERM",
            "LANG",
            "LC_ALL",
            "TZ",
            "HOSTNAME",
            "LOGNAME",
        ];

        std::env::vars()
            .filter(|(k, _)| safe_vars.contains(&k.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_info_collection() {
        let os = SystemCollector::collect_os_info();
        assert!(!os.hostname.is_empty());
        assert!(!os.arch.is_empty());
    }

    #[test]
    fn test_hardware_info() {
        let hw = SystemCollector::collect_hardware_info();
        assert!(hw.cpu_cores > 0);
    }
}
