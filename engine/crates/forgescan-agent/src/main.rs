//! ForgeScan Agent - Lightweight endpoint agent
//!
//! This is the main entry point for the agent binary deployed on endpoints.

use anyhow::Result;
use clap::Parser;
use tracing::info;

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

    info!("ForgeScan Agent starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Platform: {}", std::env::consts::OS);
    info!("Architecture: {}", std::env::consts::ARCH);

    // Determine config path
    let config_path = args.config.unwrap_or_else(default_config_path);

    // Load configuration
    let config = if std::path::Path::new(&config_path).exists() {
        info!("Loading config from: {}", config_path);
        forgescan_common::Config::from_file(&config_path)?
    } else {
        info!("Config file not found, using defaults");
        forgescan_common::Config::default()
    };

    let config = config.merge_env();

    // Override platform endpoint if provided
    let platform_endpoint = args
        .platform
        .unwrap_or_else(|| config.platform.endpoint.clone());

    if args.register {
        // Registration mode
        info!("Registering agent with platform: {}", platform_endpoint);
        // TODO: Generate CSR, send registration request, save certificate
        info!("Agent registration not yet implemented");
        return Ok(());
    }

    // Check if agent is registered
    if config.agent.agent_id.is_none() {
        anyhow::bail!("Agent not registered. Run with --register first.");
    }

    let agent_id = config.agent.agent_id.as_ref().unwrap();
    info!("Agent ID: {}", agent_id);

    if args.scan_now {
        // One-shot scan mode
        info!("Running immediate scan...");
        // TODO: Run local configuration audit
        info!("Immediate scan not yet implemented");
        return Ok(());
    }

    // Normal daemon mode
    info!("Starting agent daemon...");
    info!("Heartbeat interval: {}s", config.agent.heartbeat_interval_seconds);
    info!("CPU limit: {}%", config.agent.scan_cpu_limit_percent);
    info!("Memory limit: {}MB", config.agent.scan_memory_limit_mb);

    // TODO: Connect to platform
    // TODO: Start heartbeat loop
    // TODO: Wait for scan commands

    info!("Agent daemon not yet fully implemented");
    info!("Press Ctrl+C to exit");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
