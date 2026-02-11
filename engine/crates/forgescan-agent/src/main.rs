//! ForgeScan Agent - Lightweight endpoint agent
//!
//! This is the main entry point for the agent binary deployed on endpoints.
//! The agent runs locally on hosts and performs:
//! - Configuration auditing (CIS/STIG checks)
//! - Patch detection
//! - File integrity monitoring
//! - Heartbeat/health reporting

use anyhow::Result;
use clap::Parser;
use forgescan_config_audit::{ConfigAuditor, SystemCollector};
use forgescan_core::Severity;
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info, warn};

/// ForgeScan Endpoint Agent
#[derive(Parser, Debug)]
#[command(name = "forgescan-agent")]
#[command(author = "Forge Cyber Defense")]
#[command(version)]
#[command(about = "Lightweight endpoint security agent", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Platform endpoint for registration
    #[arg(long)]
    platform: Option<String>,

    /// Run registration and exit
    #[arg(long)]
    register: bool,

    /// Run a single scan and exit (for testing)
    #[arg(long)]
    scan_now: bool,

    /// Output format for scan results (json, text, table)
    #[arg(long, default_value = "text")]
    format: String,

    /// Only show failed checks
    #[arg(long)]
    failures_only: bool,

    /// Filter by minimum severity (low, medium, high, critical)
    #[arg(long)]
    min_severity: Option<String>,

    /// Collect and display system information
    #[arg(long)]
    system_info: bool,
}

fn default_config_path() -> String {
    #[cfg(target_os = "windows")]
    {
        String::from("C:\\ProgramData\\ForgeScan\\agent.toml")
    }
    #[cfg(not(target_os = "windows"))]
    {
        String::from("/etc/forgescan/agent.toml")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_config = forgescan_common::logging::LogConfig::new().level(&args.log_level);
    forgescan_common::logging::init_logging_with_config(log_config);

    info!("ForgeScan Agent v{}", env!("CARGO_PKG_VERSION"));
    info!("Platform: {} ({})", std::env::consts::OS, std::env::consts::ARCH);

    // Handle system info request
    if args.system_info {
        return print_system_info(&args);
    }

    // Determine config path
    let config_path = args.config.unwrap_or_else(default_config_path);

    // Load configuration
    let config = if std::path::Path::new(&config_path).exists() {
        info!("Loading config from: {}", config_path);
        forgescan_common::Config::from_file(&config_path)?
    } else {
        debug!("Config file not found, using defaults");
        forgescan_common::Config::default()
    };

    let config = config.merge_env();

    // Override platform endpoint if provided
    let platform_endpoint = args
        .platform
        .unwrap_or_else(|| config.platform.endpoint.clone());

    if args.register {
        return run_registration(&platform_endpoint).await;
    }

    if args.scan_now {
        return run_immediate_scan(&args);
    }

    // Check if agent is registered for daemon mode
    if config.agent.agent_id.is_none() {
        error!("Agent not registered. Run with --register first, or use --scan-now for local testing.");
        anyhow::bail!("Agent not registered");
    }

    let agent_id = config.agent.agent_id.as_ref().unwrap();
    run_daemon(agent_id, &config, &platform_endpoint).await
}

/// Print system information
fn print_system_info(args: &Args) -> Result<()> {
    let info = SystemCollector::collect();

    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        _ => {
            println!("=== System Information ===\n");

            println!("Operating System:");
            println!("  Name:     {}", info.os.name);
            println!("  Version:  {}", info.os.version);
            println!("  Kernel:   {}", info.os.kernel);
            println!("  Arch:     {}", info.os.arch);
            println!("  Hostname: {}", info.os.hostname);

            println!("\nHardware:");
            println!("  CPU:      {}", info.hardware.cpu_model);
            println!("  Cores:    {}", info.hardware.cpu_cores);
            println!(
                "  Memory:   {} MB",
                info.hardware.total_memory / 1024 / 1024
            );
            if info.hardware.is_virtual {
                println!(
                    "  Virtual:  {} ({})",
                    info.hardware.is_virtual,
                    info.hardware.hypervisor.as_deref().unwrap_or("unknown")
                );
            }

            println!("\nUsers:      {} accounts", info.users.len());
            println!("Packages:   {} installed", info.packages.len());
            println!("Services:   {} running", info.services.len());
        }
    }

    Ok(())
}

/// Run agent registration
async fn run_registration(platform_endpoint: &str) -> Result<()> {
    info!("Registering agent with platform: {}", platform_endpoint);

    // Collect system info for registration
    let sys_info = SystemCollector::collect();

    info!("Hostname: {}", sys_info.os.hostname);
    info!("OS: {} {}", sys_info.os.name, sys_info.os.version);

    // TODO: Generate CSR using crypto utils
    // TODO: Send registration request via gRPC
    // TODO: Receive and save certificate
    // TODO: Save agent ID to config

    warn!("Agent registration requires platform connectivity (not yet implemented)");
    info!("For local testing, use --scan-now instead");

    Ok(())
}

/// Run immediate configuration scan
fn run_immediate_scan(args: &Args) -> Result<()> {
    info!("Running configuration audit...");

    let mut auditor = ConfigAuditor::new();
    let result = auditor.run_audit();

    // Parse minimum severity filter
    let min_severity = args.min_severity.as_ref().and_then(|s| match s.to_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    });

    match args.format.as_str() {
        "json" => {
            print_results_json(&result, args.failures_only, min_severity)?;
        }
        "table" => {
            print_results_table(&result, args.failures_only, min_severity);
        }
        _ => {
            print_results_text(&result, args.failures_only, min_severity);
        }
    }

    // Exit with non-zero status if there are high/critical failures
    let critical_failures = result
        .results
        .iter()
        .filter(|r| !r.passed && matches!(r.severity, Severity::High | Severity::Critical))
        .count();

    if critical_failures > 0 {
        warn!("{} high/critical severity issues found", critical_failures);
        std::process::exit(1);
    }

    Ok(())
}

/// Print results as JSON
fn print_results_json(
    result: &forgescan_config_audit::AuditResult,
    failures_only: bool,
    min_severity: Option<Severity>,
) -> Result<()> {
    let results: Vec<_> = result
        .results
        .iter()
        .filter(|r| !failures_only || !r.passed)
        .filter(|r| min_severity.is_none() || r.severity >= min_severity.unwrap())
        .collect();

    let output = serde_json::json!({
        "summary": {
            "total": result.summary.total_checks,
            "passed": result.summary.passed,
            "failed": result.summary.failed,
            "errors": result.summary.errors,
            "skipped": result.summary.skipped,
        },
        "results": results.iter().map(|r| {
            serde_json::json!({
                "check_id": r.check_id,
                "check_name": r.check_name,
                "passed": r.passed,
                "actual": r.actual,
                "expected": r.expected,
                "severity": format!("{:?}", r.severity),
                "details": r.details,
                "remediation": r.remediation,
            })
        }).collect::<Vec<_>>(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Print results as table
fn print_results_table(
    result: &forgescan_config_audit::AuditResult,
    failures_only: bool,
    min_severity: Option<Severity>,
) {
    println!("\n{:<15} {:<50} {:<10} {:<10}", "CHECK ID", "NAME", "STATUS", "SEVERITY");
    println!("{}", "-".repeat(90));

    for r in &result.results {
        if failures_only && r.passed {
            continue;
        }
        if let Some(min) = min_severity {
            if r.severity < min {
                continue;
            }
        }

        let status = if r.passed { "PASS" } else { "FAIL" };
        let status_color = if r.passed { "\x1b[32m" } else { "\x1b[31m" };
        let severity = format!("{:?}", r.severity);

        println!(
            "{:<15} {:<50} {}{:<10}\x1b[0m {:<10}",
            r.check_id,
            truncate(&r.check_name, 48),
            status_color,
            status,
            severity
        );
    }

    println!("\n{}", "-".repeat(90));
    print_summary(&result.summary);
}

/// Print results as text
fn print_results_text(
    result: &forgescan_config_audit::AuditResult,
    failures_only: bool,
    min_severity: Option<Severity>,
) {
    println!("\n=== Configuration Audit Results ===\n");

    for r in &result.results {
        if failures_only && r.passed {
            continue;
        }
        if let Some(min) = min_severity {
            if r.severity < min {
                continue;
            }
        }

        let status = if r.passed { "PASS" } else { "FAIL" };
        let status_icon = if r.passed { "✓" } else { "✗" };

        println!("[{}] {} - {}", status, r.check_id, r.check_name);
        println!("    Status:   {} {}", status_icon, status);
        println!("    Severity: {:?}", r.severity);
        println!("    Actual:   {}", r.actual);

        if !r.passed {
            println!("    Expected: {}", r.expected);
        }

        if let Some(ref details) = r.details {
            println!("    Details:  {}", details);
        }

        if !r.passed {
            if let Some(ref remediation) = r.remediation {
                println!("    Fix:      {}", remediation);
            }
        }

        println!();
    }

    print_summary(&result.summary);
}

fn print_summary(summary: &forgescan_config_audit::AuditSummary) {
    println!("Summary:");
    println!("  Total:   {}", summary.total_checks);
    println!("  Passed:  {} ({:.1}%)", summary.passed,
        if summary.total_checks > 0 { summary.passed as f64 / summary.total_checks as f64 * 100.0 } else { 0.0 });
    println!("  Failed:  {}", summary.failed);
    println!("  Errors:  {}", summary.errors);
    println!("  Skipped: {}", summary.skipped);

    if !summary.compliance_coverage.is_empty() {
        println!("\nCompliance Coverage:");
        for (framework, coverage) in &summary.compliance_coverage {
            println!(
                "  {}: {}/{} ({:.1}%)",
                framework, coverage.passing, coverage.total, coverage.pass_rate
            );
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

/// Run agent in daemon mode
async fn run_daemon(
    agent_id: &str,
    config: &forgescan_common::Config,
    platform_endpoint: &str,
) -> Result<()> {
    info!("Starting agent daemon...");
    info!("Agent ID: {}", agent_id);
    info!("Platform endpoint: {}", platform_endpoint);
    info!("Heartbeat interval: {}s", config.agent.heartbeat_interval_seconds);
    info!("CPU limit: {}%", config.agent.scan_cpu_limit_percent);
    info!("Memory limit: {}MB", config.agent.scan_memory_limit_mb);

    let heartbeat_interval = Duration::from_secs(config.agent.heartbeat_interval_seconds);
    let mut heartbeat_timer = time::interval(heartbeat_interval);

    // TODO: Establish gRPC connection to platform
    // TODO: Subscribe to scan commands

    info!("Agent daemon running. Press Ctrl+C to exit.");

    loop {
        tokio::select! {
            _ = heartbeat_timer.tick() => {
                debug!("Sending heartbeat...");
                // TODO: Send heartbeat via gRPC
                // Include: agent health, system metrics, last scan time
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
        }
    }

    info!("Agent shutdown complete");
    Ok(())
}
