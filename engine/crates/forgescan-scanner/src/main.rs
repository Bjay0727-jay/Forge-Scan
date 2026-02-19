//! ForgeScan Scanner - Agentless vulnerability scanner
//!
//! This is the main entry point for the agentless scanner binary.
//! It connects to the ForgeScan 360 platform via REST API, polls for
//! scan tasks, executes them using the scanning engine crates, and
//! submits results back to the platform.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use forgescan_network::discovery::{self, HostDiscovery};
use forgescan_network::port_scan::{
    self, PortResult, PortScanConfig, PortScanner, PortState, ScanSummary,
};
use forgescan_transport::{
    AssetPayload, FindingPayload, PortPayload, RestApiClient, RestClientConfig, TaskResultsPayload,
};
use forgescan_vuln::{DetectedService, VulnDetector};
use forgescan_webapp::{ScanConfig as WebScanConfig, WebScanner};

/// ForgeScan Agentless Scanner
#[derive(Parser, Debug)]
#[command(name = "forgescan-scanner")]
#[command(author = "Forge Cyber Defense")]
#[command(version)]
#[command(about = "Enterprise vulnerability scanner", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/forgescan/scanner.toml")]
    config: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log format (pretty, json, compact)
    #[arg(long, default_value = "pretty")]
    log_format: String,

    /// Platform API base URL (overrides config)
    #[arg(long)]
    platform: Option<String>,

    /// Scanner API key (overrides config / env FORGESCAN_SCANNER_API_KEY)
    #[arg(long, env = "FORGESCAN_SCANNER_API_KEY")]
    api_key: Option<String>,

    /// Scanner ID (overrides config / env FORGESCAN_SCANNER_ID)
    #[arg(long, env = "FORGESCAN_SCANNER_ID")]
    scanner_id: Option<String>,

    /// Run a single scan and exit (for testing)
    #[arg(long)]
    one_shot: bool,

    /// Target for one-shot scan (IP, CIDR, or URL)
    #[arg(long)]
    target: Option<String>,

    /// Scan type for one-shot (network, webapp, vulnerability, discovery)
    #[arg(long, default_value = "network")]
    scan_type: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_config = forgescan_common::logging::LogConfig::new()
        .level(&args.log_level)
        .format(match args.log_format.as_str() {
            "json" => forgescan_common::logging::LogFormat::Json,
            "compact" => forgescan_common::logging::LogFormat::Compact,
            _ => forgescan_common::logging::LogFormat::Pretty,
        });
    forgescan_common::logging::init_logging_with_config(log_config);

    info!("ForgeScan Scanner starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Load configuration (file → env → CLI args)
    let config = if std::path::Path::new(&args.config).exists() {
        forgescan_common::Config::from_file(&args.config)?
    } else {
        info!("Config file not found at {}, using defaults", args.config);
        forgescan_common::Config::default()
    };
    let config = config.merge_env();

    // Resolve platform endpoint (CLI > env > config > default)
    let api_base_url = args
        .platform
        .clone()
        .unwrap_or_else(|| config.platform.endpoint.clone());

    // Resolve API key
    let api_key = args
        .api_key
        .clone()
        .or_else(|| std::env::var("FORGESCAN_SCANNER_API_KEY").ok())
        .or_else(|| config.platform.api_key.clone())
        .unwrap_or_default();

    // Resolve scanner ID
    let scanner_id = args
        .scanner_id
        .clone()
        .or_else(|| std::env::var("FORGESCAN_SCANNER_ID").ok())
        .or_else(|| config.scanner.scanner_id.clone())
        .unwrap_or_default();

    if args.one_shot {
        run_one_shot_scan(&args, &api_base_url).await
    } else {
        run_daemon_mode(&config, &api_base_url, &api_key, &scanner_id).await
    }
}

// ── Daemon Mode ─────────────────────────────────────────────────────────────

async fn run_daemon_mode(
    config: &forgescan_common::Config,
    api_base_url: &str,
    api_key: &str,
    scanner_id: &str,
) -> Result<()> {
    info!("Starting scanner daemon...");
    info!("Platform: {}", api_base_url);
    info!("Scanner ID: {}", scanner_id);
    info!(
        "Max concurrent scans: {}",
        config.scanner.max_concurrent_scans
    );

    if api_key.is_empty() {
        anyhow::bail!(
            "API key required for daemon mode. Set via --api-key, \
             FORGESCAN_SCANNER_API_KEY env, or config file."
        );
    }
    if scanner_id.is_empty() {
        anyhow::bail!(
            "Scanner ID required for daemon mode. Set via --scanner-id, \
             FORGESCAN_SCANNER_ID env, or config file."
        );
    }

    // Build REST client
    let rest_config = RestClientConfig {
        api_base_url: api_base_url.to_string(),
        api_key: api_key.to_string(),
        scanner_id: scanner_id.to_string(),
        capabilities: vec![
            "network".into(),
            "vulnerability".into(),
            "webapp".into(),
            "discovery".into(),
        ],
        ..Default::default()
    };

    let client = RestApiClient::new(rest_config).context("Failed to create REST API client")?;

    // Send initial heartbeat
    info!("Sending initial heartbeat...");
    match client.heartbeat().await {
        Ok(()) => info!("Connected to platform successfully"),
        Err(e) => {
            error!("Initial heartbeat failed: {}. Continuing anyway...", e);
        }
    }

    // Start background heartbeat loop
    let _heartbeat_handle = client.start_heartbeat_loop();

    // Concurrency limiter for scan tasks
    let semaphore = Arc::new(Semaphore::new(config.scanner.max_concurrent_scans as usize));
    let poll_interval = client.poll_interval();

    info!("Scanner daemon ready — polling for tasks");

    // Main polling loop
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                // Try to acquire a permit (non-blocking check if we have capacity)
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        debug!("All scan slots busy, skipping poll");
                        continue;
                    }
                };

                // Poll for a task
                match client.poll_task().await {
                    Ok(Some(task)) => {
                        let task_id = task.id.clone();
                        let task_type = task.task_type.clone();
                        info!("Received task {} (type: {})", task_id, task_type);

                        // Execute task in background
                        let api_base = api_base_url.to_string();
                        let key = api_key.to_string();
                        let sid = scanner_id.to_string();

                        tokio::spawn(async move {
                            let _permit = permit; // held until task completes
                            if let Err(e) = execute_task_wrapper(
                                &api_base, &key, &sid, &task_id, &task_type, task.task_payload,
                            )
                            .await
                            {
                                error!("Task {} failed: {:#}", task_id, e);
                            }
                        });
                    }
                    Ok(None) => {
                        debug!("No tasks available");
                        drop(permit);
                    }
                    Err(e) => {
                        warn!("Task poll error: {}", e);
                        drop(permit);
                    }
                }
            }
        }
    }

    info!("Scanner daemon shutting down gracefully");
    Ok(())
}

/// Wrapper that creates its own REST client for background task execution.
/// This avoids lifetime issues with the spawned task.
async fn execute_task_wrapper(
    api_base_url: &str,
    api_key: &str,
    scanner_id: &str,
    task_id: &str,
    task_type: &str,
    payload: Option<serde_json::Value>,
) -> Result<()> {
    let rest_config = RestClientConfig {
        api_base_url: api_base_url.to_string(),
        api_key: api_key.to_string(),
        scanner_id: scanner_id.to_string(),
        ..Default::default()
    };
    let client = RestApiClient::new(rest_config)?;

    // Mark task as started
    client
        .start_task(task_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to mark task as started: {}", e))?;

    // Execute the scan
    let result = execute_task(task_type, payload).await;

    match result {
        Ok(results_payload) => {
            client
                .submit_results(task_id, results_payload)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to submit results: {}", e))?;
            info!("Task {} completed successfully", task_id);
        }
        Err(e) => {
            error!("Task {} execution failed: {:#}", task_id, e);
            let _ = client.submit_failure(task_id, &format!("{:#}", e)).await;
        }
    }

    Ok(())
}

/// Execute a scan task based on its type, returning results payload.
async fn execute_task(
    task_type: &str,
    payload: Option<serde_json::Value>,
) -> Result<TaskResultsPayload> {
    let targets = extract_targets(&payload)?;

    match task_type {
        "network" | "network_scan" => execute_network_scan(&targets, &payload).await,
        "vulnerability" | "vuln_scan" => execute_vulnerability_scan(&targets, &payload).await,
        "webapp" | "webapp_scan" | "web" => execute_webapp_scan(&targets, &payload).await,
        "discovery" | "host_discovery" => execute_discovery_scan(&targets, &payload).await,
        "full" | "full_scan" => execute_full_scan(&targets, &payload).await,
        other => {
            warn!("Unknown scan type '{}', attempting network scan", other);
            execute_network_scan(&targets, &payload).await
        }
    }
}

/// Extract target list from task payload
fn extract_targets(payload: &Option<serde_json::Value>) -> Result<Vec<String>> {
    if let Some(p) = payload {
        // Try "targets" array
        if let Some(targets) = p.get("targets").and_then(|v| v.as_array()) {
            return Ok(targets
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect());
        }
        // Try single "target" string
        if let Some(target) = p.get("target").and_then(|v| v.as_str()) {
            return Ok(vec![target.to_string()]);
        }
        // Try "hosts" array
        if let Some(hosts) = p.get("hosts").and_then(|v| v.as_array()) {
            return Ok(hosts
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect());
        }
    }
    anyhow::bail!("No targets found in task payload")
}

// ── Scan Executors ──────────────────────────────────────────────────────────

/// Network scan: host discovery + port scanning + service detection
async fn execute_network_scan(
    targets: &[String],
    payload: &Option<serde_json::Value>,
) -> Result<TaskResultsPayload> {
    let start = Instant::now();
    info!("Starting network scan of {} target(s)", targets.len());

    // Determine port list from payload or default
    let ports = extract_ports(payload);
    let port_config = PortScanConfig::default();
    let scanner = PortScanner::with_config(port_config);

    let mut summary = ScanSummary::default();
    let mut all_findings: Vec<FindingPayload> = Vec::new();
    let mut all_assets: Vec<AssetPayload> = Vec::new();

    for target_str in targets {
        // Resolve target to IP(s)
        let ips = resolve_target(target_str).await?;

        for ip in ips {
            info!("Scanning host {}", ip);

            // Port scan
            let port_results = scanner.scan_ports(ip, &ports).await;
            let open_ports: Vec<&PortResult> = port_results
                .iter()
                .filter(|r| r.state == PortState::Open)
                .collect();

            info!(
                "Host {}: scanned {} ports, {} open",
                ip,
                port_results.len(),
                open_ports.len()
            );

            // Build asset
            let asset = AssetPayload {
                hostname: None,
                ip_addresses: ip.to_string(),
                os: None,
                os_version: None,
                asset_type: "host".into(),
                mac_addresses: None,
                open_ports: open_ports
                    .iter()
                    .map(|p| PortPayload {
                        port: p.port,
                        protocol: p.protocol.clone(),
                        state: p.state.as_str().to_string(),
                        service: p.service.clone(),
                        version: p.version.clone(),
                        banner: p.banner.clone(),
                    })
                    .collect(),
            };
            all_assets.push(asset);

            // Create informational findings for interesting open ports
            for port_result in &open_ports {
                let finding = FindingPayload {
                    title: format!(
                        "Open port {}/{} on {}",
                        port_result.port, port_result.protocol, ip
                    ),
                    description: format!(
                        "Port {}/{} is open{}",
                        port_result.port,
                        port_result.protocol,
                        port_result
                            .service
                            .as_deref()
                            .map(|s| format!(" (service: {})", s))
                            .unwrap_or_default()
                    ),
                    severity: "info".into(),
                    state: "open".into(),
                    vendor: "forgescan".into(),
                    vendor_id: format!(
                        "FSC-NET-PORT-{}-{}",
                        port_result.port, port_result.protocol
                    ),
                    port: Some(port_result.port),
                    protocol: Some(port_result.protocol.clone()),
                    service: port_result.service.clone(),
                    evidence: port_result.banner.clone(),
                    solution: None,
                    cve_ids: vec![],
                    cvss_score: None,
                    frs_score: None,
                    metadata: None,
                };
                all_findings.push(finding);
            }

            summary.add_host_results(ip, port_results);
        }
    }

    let elapsed = start.elapsed();
    let result_summary = format!(
        "Network scan complete: {} hosts scanned, {} up, {} open ports, {} findings in {:.1}s",
        summary.hosts_scanned,
        summary.hosts_up,
        summary.open_ports,
        all_findings.len(),
        elapsed.as_secs_f64()
    );

    info!("{}", result_summary);

    Ok(TaskResultsPayload {
        status: "completed".into(),
        result_summary,
        findings: all_findings,
        assets_discovered: all_assets,
    })
}

/// Vulnerability scan: port scan → service detection → CVE matching
async fn execute_vulnerability_scan(
    targets: &[String],
    payload: &Option<serde_json::Value>,
) -> Result<TaskResultsPayload> {
    let start = Instant::now();
    info!("Starting vulnerability scan of {} target(s)", targets.len());

    let ports = extract_ports(payload);
    let scanner = PortScanner::new();

    // Try to open NVD database for CVE matching
    let nvd_db = match forgescan_nvd::NvdDb::open("/var/lib/forgescan/nvd.db") {
        Ok(db) => {
            info!("Loaded NVD database for CVE matching");
            Some(db)
        }
        Err(e) => {
            warn!("NVD database not available ({}), CVE matching disabled", e);
            None
        }
    };

    let detector = nvd_db.map(VulnDetector::new);

    let mut all_findings: Vec<FindingPayload> = Vec::new();
    let mut all_assets: Vec<AssetPayload> = Vec::new();

    for target_str in targets {
        let ips = resolve_target(target_str).await?;

        for ip in ips {
            // Scan ports (only open)
            let open_ports = scanner.scan_ports_open_only(ip, &ports).await;

            if open_ports.is_empty() {
                debug!("No open ports on {}, skipping vuln detection", ip);
                continue;
            }

            // Build detected services for CVE matching
            let services: Vec<DetectedService> = open_ports
                .iter()
                .map(|p| DetectedService {
                    target: ip.to_string(),
                    port: p.port,
                    service: p.service.clone().unwrap_or_else(|| "unknown".into()),
                    product: p.service.clone(), // Use service name as product hint
                    version: p.version.clone(),
                    cpe: None,
                    extra_info: p.banner.clone(),
                })
                .collect();

            // Run vulnerability detection if NVD is available
            if let Some(ref det) = detector {
                let result = det.detect(&services);
                info!(
                    "Host {}: {} vulnerabilities detected (max FRS: {:.1})",
                    ip,
                    result.vulnerabilities.len(),
                    result.max_frs
                );

                for vuln in &result.vulnerabilities {
                    let finding = det.to_finding(vuln);
                    all_findings.push(FindingPayload::from(&finding));
                }
            }

            // Build asset payload
            let asset = AssetPayload {
                hostname: None,
                ip_addresses: ip.to_string(),
                os: None,
                os_version: None,
                asset_type: "host".into(),
                mac_addresses: None,
                open_ports: open_ports
                    .iter()
                    .map(|p| PortPayload {
                        port: p.port,
                        protocol: p.protocol.clone(),
                        state: p.state.as_str().to_string(),
                        service: p.service.clone(),
                        version: p.version.clone(),
                        banner: p.banner.clone(),
                    })
                    .collect(),
            };
            all_assets.push(asset);
        }
    }

    let elapsed = start.elapsed();
    let result_summary = format!(
        "Vulnerability scan complete: {} findings, {} assets in {:.1}s",
        all_findings.len(),
        all_assets.len(),
        elapsed.as_secs_f64()
    );
    info!("{}", result_summary);

    Ok(TaskResultsPayload {
        status: "completed".into(),
        result_summary,
        findings: all_findings,
        assets_discovered: all_assets,
    })
}

/// Web application scan: crawl + OWASP checks + header/TLS analysis
async fn execute_webapp_scan(
    targets: &[String],
    _payload: &Option<serde_json::Value>,
) -> Result<TaskResultsPayload> {
    let start = Instant::now();
    info!("Starting webapp scan of {} target(s)", targets.len());

    let web_config = WebScanConfig::default()
        .with_max_depth(3)
        .with_timeout_seconds(30)
        .with_concurrency(5);
    let scanner = WebScanner::new(web_config);

    let mut all_findings: Vec<FindingPayload> = Vec::new();
    let mut all_assets: Vec<AssetPayload> = Vec::new();

    for target in targets {
        // Ensure target looks like a URL
        let url = if target.starts_with("http://") || target.starts_with("https://") {
            target.clone()
        } else {
            format!("https://{}", target)
        };

        info!("Scanning web application: {}", url);
        match scanner.scan(&url).await {
            Ok(result) => {
                info!(
                    "Web scan of {}: {} findings, {} pages crawled",
                    url,
                    result.findings.len(),
                    result.stats.pages_crawled
                );

                // Convert findings
                for finding in &result.findings {
                    all_findings.push(FindingPayload::from(finding));
                }

                // Build web asset
                let asset = AssetPayload {
                    hostname: Some(
                        url::Url::parse(&url)
                            .ok()
                            .and_then(|u| u.host_str().map(String::from))
                            .unwrap_or_else(|| target.clone()),
                    ),
                    ip_addresses: String::new(),
                    os: None,
                    os_version: None,
                    asset_type: "webapp".into(),
                    mac_addresses: None,
                    open_ports: vec![PortPayload {
                        port: if url.starts_with("https") { 443 } else { 80 },
                        protocol: "tcp".into(),
                        state: "open".into(),
                        service: Some("http".into()),
                        version: None,
                        banner: None,
                    }],
                };
                all_assets.push(asset);
            }
            Err(e) => {
                error!("Web scan of {} failed: {}", url, e);
                all_findings.push(FindingPayload {
                    title: format!("Web scan error for {}", url),
                    description: format!("Web scan failed: {}", e),
                    severity: "info".into(),
                    state: "error".into(),
                    vendor: "forgescan".into(),
                    vendor_id: "FSC-WEB-ERROR".into(),
                    port: None,
                    protocol: None,
                    service: None,
                    evidence: None,
                    solution: None,
                    cve_ids: vec![],
                    cvss_score: None,
                    frs_score: None,
                    metadata: None,
                });
            }
        }
    }

    let elapsed = start.elapsed();
    let result_summary = format!(
        "Webapp scan complete: {} findings, {} assets in {:.1}s",
        all_findings.len(),
        all_assets.len(),
        elapsed.as_secs_f64()
    );
    info!("{}", result_summary);

    Ok(TaskResultsPayload {
        status: "completed".into(),
        result_summary,
        findings: all_findings,
        assets_discovered: all_assets,
    })
}

/// Host discovery scan: find live hosts on a network
async fn execute_discovery_scan(
    targets: &[String],
    _payload: &Option<serde_json::Value>,
) -> Result<TaskResultsPayload> {
    let start = Instant::now();
    info!("Starting discovery scan of {} target(s)", targets.len());

    let discovery = HostDiscovery::new();
    let mut all_assets: Vec<AssetPayload> = Vec::new();
    let mut live_hosts = 0u32;

    for target_str in targets {
        // Expand CIDR / ranges
        let ips = resolve_target(target_str).await?;
        info!("Discovering {} hosts in {}", ips.len(), target_str);

        let results = discovery.discover_hosts(ips).await;

        for result in results {
            if result.is_up {
                live_hosts += 1;
                all_assets.push(AssetPayload {
                    hostname: result.hostname.clone(),
                    ip_addresses: result.ip.to_string(),
                    os: None,
                    os_version: None,
                    asset_type: "host".into(),
                    mac_addresses: result.mac_address.clone(),
                    open_ports: vec![],
                });
            }
        }
    }

    let elapsed = start.elapsed();
    let result_summary = format!(
        "Discovery complete: {} live hosts found in {:.1}s",
        live_hosts,
        elapsed.as_secs_f64()
    );
    info!("{}", result_summary);

    Ok(TaskResultsPayload {
        status: "completed".into(),
        result_summary,
        findings: vec![],
        assets_discovered: all_assets,
    })
}

/// Full scan: discovery → network → vulnerability (combined)
async fn execute_full_scan(
    targets: &[String],
    payload: &Option<serde_json::Value>,
) -> Result<TaskResultsPayload> {
    let start = Instant::now();
    info!("Starting full scan of {} target(s)", targets.len());

    // Phase 1: Discovery
    let discovery_results = execute_discovery_scan(targets, payload).await?;
    let live_hosts: Vec<String> = discovery_results
        .assets_discovered
        .iter()
        .map(|a| a.ip_addresses.clone())
        .collect();

    if live_hosts.is_empty() {
        return Ok(TaskResultsPayload {
            status: "completed".into(),
            result_summary: "Full scan complete: no live hosts found".into(),
            findings: vec![],
            assets_discovered: vec![],
        });
    }

    // Phase 2: Network + Vulnerability scan on live hosts
    let vuln_results = execute_vulnerability_scan(&live_hosts, payload).await?;

    let elapsed = start.elapsed();
    let result_summary = format!(
        "Full scan complete: {} hosts discovered, {} findings, {} assets in {:.1}s",
        live_hosts.len(),
        vuln_results.findings.len(),
        vuln_results.assets_discovered.len(),
        elapsed.as_secs_f64()
    );
    info!("{}", result_summary);

    Ok(TaskResultsPayload {
        status: "completed".into(),
        result_summary,
        findings: vuln_results.findings,
        assets_discovered: vuln_results.assets_discovered,
    })
}

// ── One-Shot Mode ───────────────────────────────────────────────────────────

async fn run_one_shot_scan(args: &Args, _api_base_url: &str) -> Result<()> {
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--target required for one-shot mode"))?;

    info!(
        "Running one-shot {} scan against: {}",
        args.scan_type, target
    );

    let targets = vec![target.to_string()];
    let payload = Some(serde_json::json!({ "targets": targets }));

    let result = execute_task(&args.scan_type, payload).await?;

    // Print results
    println!("\n{}", "=".repeat(60));
    println!("  ForgeScan One-Shot Scan Results");
    println!("{}", "=".repeat(60));
    println!("Status: {}", result.status);
    println!("Summary: {}", result.result_summary);
    println!("\nFindings ({}):", result.findings.len());
    for (i, f) in result.findings.iter().enumerate() {
        println!(
            "  {}. [{}] {} ({})",
            i + 1,
            f.severity.to_uppercase(),
            f.title,
            f.vendor_id
        );
        if !f.cve_ids.is_empty() {
            println!("     CVEs: {}", f.cve_ids.join(", "));
        }
    }
    println!("\nAssets Discovered ({}):", result.assets_discovered.len());
    for asset in &result.assets_discovered {
        println!(
            "  - {} ({}) — {} open ports",
            asset.ip_addresses,
            asset.asset_type,
            asset.open_ports.len()
        );
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Resolve a target string to IP addresses.
/// Handles single IPs, CIDR notation, IP ranges, and hostnames.
async fn resolve_target(target: &str) -> Result<Vec<IpAddr>> {
    // Try parsing as single IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    // Try CIDR
    if target.contains('/') {
        return discovery::parse_cidr(target)
            .map_err(|e| anyhow::anyhow!("Invalid CIDR {}: {}", target, e));
    }

    // Try IP range
    if target.contains('-') && !target.contains("://") {
        return discovery::parse_ip_range(target)
            .map_err(|e| anyhow::anyhow!("Invalid IP range {}: {}", target, e));
    }

    // Try DNS resolution
    let stripped = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target);

    match tokio::net::lookup_host(format!("{}:80", stripped)).await {
        Ok(addrs) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                anyhow::bail!("DNS resolution for '{}' returned no addresses", target);
            }
            // Deduplicate
            let mut unique: Vec<IpAddr> = ips;
            unique.sort_by_key(|a| a.to_string());
            unique.dedup();
            Ok(unique)
        }
        Err(e) => {
            anyhow::bail!("Failed to resolve '{}': {}", target, e);
        }
    }
}

/// Extract port list from task payload, falling back to top-100
fn extract_ports(payload: &Option<serde_json::Value>) -> Vec<u16> {
    if let Some(p) = payload {
        // "ports" as a spec string like "22,80,443,8000-9000"
        if let Some(spec) = p.get("ports").and_then(|v| v.as_str()) {
            if let Ok(ports) = port_scan::ports::parse_port_spec(spec) {
                return ports;
            }
        }
        // "port_range" as a string
        if let Some(spec) = p.get("port_range").and_then(|v| v.as_str()) {
            if let Ok(ports) = port_scan::ports::parse_port_spec(spec) {
                return ports;
            }
        }
        // "top_ports" number
        if let Some(n) = p.get("top_ports").and_then(|v| v.as_u64()) {
            return match n {
                0..=20 => port_scan::ports::TOP_20.to_vec(),
                21..=100 => port_scan::ports::TOP_100.to_vec(),
                _ => port_scan::ports::well_known(),
            };
        }
    }

    // Default: top 100
    port_scan::ports::TOP_100.to_vec()
}
