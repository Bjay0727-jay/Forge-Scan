//! gRPC server for receiving scan tasks
//!
//! This module provides the server-side implementation for the platform
//! to receive scan results from scanners. It handles:
//! - Accepting connections from scanners
//! - Receiving streamed scan events
//! - Heartbeat management
//! - Scanner registration

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::types::*;

/// Configuration for the scan service server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address to bind to
    pub bind_addr: SocketAddr,
    /// TLS configuration
    pub tls: Option<ServerTlsConfig>,
    /// Maximum concurrent connections
    pub max_connections: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8443".parse().unwrap(),
            tls: None,
            max_connections: 100,
        }
    }
}

/// TLS configuration for the server
#[derive(Debug, Clone)]
pub struct ServerTlsConfig {
    /// Server certificate path
    pub cert_path: String,
    /// Server key path
    pub key_path: String,
    /// CA certificate for client verification (mTLS)
    pub ca_cert_path: Option<String>,
}

/// Handler for scan service events
#[async_trait::async_trait]
pub trait ScanServiceHandler: Send + Sync {
    /// Handle a new finding
    async fn on_finding(&self, scanner_id: &str, task_id: &str, finding: forgescan_core::Finding);

    /// Handle progress update
    async fn on_progress(&self, scanner_id: &str, progress: ScanProgress);

    /// Handle scan completion
    async fn on_complete(&self, scanner_id: &str, complete: ScanComplete);

    /// Handle scanner heartbeat
    async fn on_heartbeat(&self, request: HeartbeatRequest) -> HeartbeatResponse;

    /// Get next task for scanner
    async fn get_task(&self, scanner_id: &str) -> Option<ScanTask>;
}

/// Scan service gRPC server
pub struct ScanServiceServer {
    config: ServerConfig,
    handler: Arc<dyn ScanServiceHandler>,
    /// Connected scanners
    scanners: Arc<RwLock<HashMap<String, ScannerInfo>>>,
}

/// Information about a connected scanner
#[derive(Debug, Clone)]
pub struct ScannerInfo {
    pub scanner_id: String,
    pub hostname: String,
    pub version: String,
    pub status: ScannerStatus,
    pub last_heartbeat: std::time::Instant,
    pub active_tasks: Vec<String>,
}

impl ScanServiceServer {
    /// Create a new scan service server
    pub fn new(config: ServerConfig, handler: Arc<dyn ScanServiceHandler>) -> Self {
        Self {
            config,
            handler,
            scanners: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start the gRPC server
    ///
    /// Note: This is a placeholder. Full implementation requires tonic server.
    pub async fn serve(&self) -> Result<(), ServerError> {
        info!("Starting scan service server on {}", self.config.bind_addr);

        // TODO: Implement actual gRPC server with tonic
        // let svc = ScanServiceServer::new(self.clone());
        //
        // let mut builder = Server::builder();
        //
        // if let Some(tls) = &self.config.tls {
        //     let cert = std::fs::read(&tls.cert_path)?;
        //     let key = std::fs::read(&tls.key_path)?;
        //     let identity = Identity::from_pem(cert, key);
        //
        //     let tls_config = if let Some(ca_path) = &tls.ca_cert_path {
        //         let ca = std::fs::read(ca_path)?;
        //         ServerTlsConfig::new()
        //             .identity(identity)
        //             .client_ca_root(Certificate::from_pem(ca))
        //     } else {
        //         ServerTlsConfig::new().identity(identity)
        //     };
        //
        //     builder = builder.tls_config(tls_config)?;
        // }
        //
        // builder
        //     .add_service(svc)
        //     .serve(self.config.bind_addr)
        //     .await?;

        info!("Scan service server started");
        Ok(())
    }

    /// Get list of connected scanners
    pub async fn get_scanners(&self) -> Vec<ScannerInfo> {
        self.scanners.read().await.values().cloned().collect()
    }

    /// Check if a scanner is connected
    pub async fn is_scanner_connected(&self, scanner_id: &str) -> bool {
        self.scanners.read().await.contains_key(scanner_id)
    }

    /// Disconnect a scanner
    pub async fn disconnect_scanner(&self, scanner_id: &str) {
        let mut scanners = self.scanners.write().await;
        if scanners.remove(scanner_id).is_some() {
            info!("Scanner {} disconnected", scanner_id);
        }
    }

    /// Process a heartbeat and update scanner info
    async fn process_heartbeat(&self, request: HeartbeatRequest) -> HeartbeatResponse {
        let mut scanners = self.scanners.write().await;

        let info = ScannerInfo {
            scanner_id: request.scanner_id.clone(),
            hostname: request.hostname.clone(),
            version: request.version.clone(),
            status: request.status.clone(),
            last_heartbeat: std::time::Instant::now(),
            active_tasks: request.active_task_ids.clone(),
        };

        scanners.insert(request.scanner_id.clone(), info);

        self.handler.on_heartbeat(request).await
    }

    /// Clean up stale scanners (no heartbeat for too long)
    pub async fn cleanup_stale_scanners(&self, max_age: std::time::Duration) {
        let mut scanners = self.scanners.write().await;
        let now = std::time::Instant::now();

        let stale: Vec<String> = scanners
            .iter()
            .filter(|(_, info)| now.duration_since(info.last_heartbeat) > max_age)
            .map(|(id, _)| id.clone())
            .collect();

        for id in stale {
            warn!("Removing stale scanner: {}", id);
            scanners.remove(&id);
        }
    }
}

/// Server errors
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Bind failed: {0}")]
    BindFailed(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Server error: {0}")]
    ServerError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Default implementation of scan service handler for testing
pub struct DefaultHandler {
    findings_tx: mpsc::Sender<(String, forgescan_core::Finding)>,
}

impl DefaultHandler {
    pub fn new(findings_tx: mpsc::Sender<(String, forgescan_core::Finding)>) -> Self {
        Self { findings_tx }
    }
}

#[async_trait::async_trait]
impl ScanServiceHandler for DefaultHandler {
    async fn on_finding(&self, scanner_id: &str, task_id: &str, finding: forgescan_core::Finding) {
        debug!("Received finding from {} for task {}", scanner_id, task_id);
        let _ = self.findings_tx.send((task_id.to_string(), finding)).await;
    }

    async fn on_progress(&self, scanner_id: &str, progress: ScanProgress) {
        debug!(
            "Progress from {}: {:.1}% complete",
            scanner_id, progress.percent_complete
        );
    }

    async fn on_complete(&self, scanner_id: &str, complete: ScanComplete) {
        info!(
            "Scan {} completed by {}: {} findings",
            complete.task_id, scanner_id, complete.stats.findings_total
        );
    }

    async fn on_heartbeat(&self, request: HeartbeatRequest) -> HeartbeatResponse {
        debug!("Heartbeat from {}", request.scanner_id);
        HeartbeatResponse {
            acknowledged: true,
            server_time: std::time::SystemTime::now(),
            cancel_task_ids: Vec::new(),
            update_available: false,
            update_version: None,
        }
    }

    async fn get_task(&self, _scanner_id: &str) -> Option<ScanTask> {
        None
    }
}
