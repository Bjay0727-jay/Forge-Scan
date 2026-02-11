//! ForgeScan Scanner - Agentless vulnerability scanner
//!
//! This is the main entry point for the agentless scanner binary.

use anyhow::Result;
use clap::Parser;
use tracing::info;

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

    /// Platform endpoint (overrides config)
    #[arg(long)]
    platform: Option<String>,

    /// Run a single scan and exit (for testing)
    #[arg(long)]
    one_shot: bool,

    /// Target for one-shot scan
    #[arg(long)]
    target: Option<String>,
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

    // Load configuration
    let config = if std::path::Path::new(&args.config).exists() {
        forgescan_common::Config::from_file(&args.config)?
    } else {
        info!("Config file not found, using defaults");
        forgescan_common::Config::default()
    };

    let config = config.merge_env();

    // Override platform endpoint if provided
    let platform_endpoint = args
        .platform
        .unwrap_or_else(|| config.platform.endpoint.clone());

    info!("Platform endpoint: {}", platform_endpoint);

    if args.one_shot {
        // One-shot mode for testing
        if let Some(target) = args.target {
            info!("Running one-shot scan against: {}", target);
            // TODO: Implement one-shot scan
            info!("One-shot scan not yet implemented");
        } else {
            anyhow::bail!("--target required for one-shot mode");
        }
    } else {
        // Normal daemon mode
        info!("Starting scanner daemon...");
        info!("Max concurrent scans: {}", config.scanner.max_concurrent_scans);
        info!("Max concurrent targets: {}", config.scanner.max_concurrent_targets);

        // TODO: Connect to platform via gRPC
        // TODO: Start heartbeat loop
        // TODO: Wait for scan tasks

        info!("Scanner daemon not yet fully implemented");
        info!("Press Ctrl+C to exit");

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
    }

    Ok(())
}
