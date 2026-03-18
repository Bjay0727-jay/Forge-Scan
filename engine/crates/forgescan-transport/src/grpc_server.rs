//! gRPC streaming server for real-time scan event delivery
//!
//! Implements the `ScanService` gRPC service, allowing clients to subscribe
//! to scan events as they are discovered during execution.
//!
//! Supports optional mTLS: when TLS cert/key/CA paths are provided, the server
//! requires clients to present valid certificates signed by the trusted CA.

use crate::proto::scan::scan_service_server::ScanService;
use crate::proto::scan::{
    ConfigRequest, HeartbeatRequest, HeartbeatResponse, ScanEvent, ScannerConfig, UploadResponse,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Identity, ServerTlsConfig as TonicTlsConfig};
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, warn};

/// TLS configuration for gRPC mTLS
#[derive(Debug, Clone)]
pub struct GrpcTlsConfig {
    /// PEM-encoded server certificate
    pub server_cert_path: String,
    /// PEM-encoded server private key
    pub server_key_path: String,
    /// PEM-encoded CA certificate for client verification (mTLS)
    pub client_ca_cert_path: String,
}

/// ForgeScan gRPC streaming server
///
/// Provides real-time finding delivery during scans via server-streaming RPC.
/// Clients call `ExecuteScan` and receive a stream of `ScanEvent` messages
/// including progress updates, findings, and completion notifications.
pub struct ForgeScanGrpcServer {
    /// Scanner ID
    scanner_id: String,
    /// Active scan counter
    active_scans: Arc<AtomicU32>,
    /// Channel sender for injecting scan events from scan executors
    event_tx: mpsc::Sender<ScanEvent>,
    /// Channel receiver (wrapped in Option for take-once pattern)
    event_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<ScanEvent>>>>,
}

impl ForgeScanGrpcServer {
    /// Create a new gRPC server instance
    pub fn new(scanner_id: impl Into<String>) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        Self {
            scanner_id: scanner_id.into(),
            active_scans: Arc::new(AtomicU32::new(0)),
            event_tx: tx,
            event_rx: Arc::new(tokio::sync::Mutex::new(Some(rx))),
        }
    }

    /// Get the scanner ID this server is associated with
    pub fn scanner_id(&self) -> &str {
        &self.scanner_id
    }

    /// Get a sender handle for pushing scan events from scan executors
    pub fn event_sender(&self) -> mpsc::Sender<ScanEvent> {
        self.event_tx.clone()
    }

    /// Start the gRPC server on the given port (plaintext, no TLS)
    pub async fn serve(self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", port).parse()?;
        info!("Starting gRPC streaming server on {} (plaintext)", addr);

        tonic::transport::Server::builder()
            .add_service(crate::proto::scan::scan_service_server::ScanServiceServer::new(self))
            .serve(addr)
            .await?;

        Ok(())
    }

    /// Start the gRPC server with mTLS on the given port.
    ///
    /// Requires clients to present a valid certificate signed by the trusted CA.
    pub async fn serve_mtls(
        self,
        port: u16,
        tls: &GrpcTlsConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("0.0.0.0:{}", port).parse()?;

        let server_cert = std::fs::read(&tls.server_cert_path)?;
        let server_key = std::fs::read(&tls.server_key_path)?;
        let client_ca = std::fs::read(&tls.client_ca_cert_path)?;

        let identity = Identity::from_pem(server_cert, server_key);
        let client_ca_cert = tonic::transport::Certificate::from_pem(client_ca);

        let tls_config = TonicTlsConfig::new()
            .identity(identity)
            .client_ca_root(client_ca_cert);

        info!("Starting gRPC streaming server on {} (mTLS enabled)", addr);

        tonic::transport::Server::builder()
            .tls_config(tls_config)?
            .add_service(crate::proto::scan::scan_service_server::ScanServiceServer::new(self))
            .serve(addr)
            .await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl ScanService for ForgeScanGrpcServer {
    type ExecuteScanStream = ReceiverStream<Result<ScanEvent, Status>>;

    /// Execute a scan and stream events back to the client in real-time.
    async fn execute_scan(
        &self,
        request: Request<crate::proto::scan::ScanTask>,
    ) -> Result<Response<Self::ExecuteScanStream>, Status> {
        let task = request.into_inner();
        let task_id = task.task_id.clone();
        let job_id = task.job_id.clone();
        info!(
            "gRPC ExecuteScan: job={}, task={}, targets={}",
            job_id,
            task_id,
            task.targets.len()
        );

        self.active_scans.fetch_add(1, Ordering::Relaxed);

        // Create a per-stream channel for this scan execution
        let (tx, rx) = mpsc::channel::<Result<ScanEvent, Status>>(256);

        // Forward events from the shared event channel to this stream
        let event_rx = self.event_rx.clone();
        let active_scans = self.active_scans.clone();

        tokio::spawn(async move {
            // Take ownership of the receiver if available
            let mut receiver = {
                let mut guard = event_rx.lock().await;
                guard.take()
            };

            if let Some(ref mut rx) = receiver {
                while let Some(event) = rx.recv().await {
                    if tx.send(Ok(event)).await.is_err() {
                        // Client disconnected
                        warn!("gRPC client disconnected during scan {}", task_id);
                        break;
                    }
                }
            }

            active_scans.fetch_sub(1, Ordering::Relaxed);

            // Return the receiver back
            if let Some(rx) = receiver {
                let mut guard = event_rx.lock().await;
                *guard = Some(rx);
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(stream))
    }

    /// Receive batch result uploads (streaming client -> server)
    async fn upload_results(
        &self,
        request: Request<Streaming<crate::proto::results::ScanResult>>,
    ) -> Result<Response<UploadResponse>, Status> {
        let mut stream = request.into_inner();
        let mut findings_count = 0u32;

        while let Some(result) = stream.message().await? {
            for target_result in &result.target_results {
                findings_count += target_result.findings.len() as u32;
            }
            info!(
                "Received batch results for task {}: {} target results",
                result.task_id,
                result.target_results.len()
            );
        }

        Ok(Response::new(UploadResponse {
            success: true,
            findings_accepted: findings_count,
            errors: vec![],
        }))
    }

    /// Scanner heartbeat -- returns acknowledgment and any pending commands
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        info!(
            "gRPC Heartbeat from scanner {} (v{}), {} active tasks",
            req.scanner_id,
            req.version,
            req.active_task_ids.len()
        );

        let now = chrono::Utc::now();
        Ok(Response::new(HeartbeatResponse {
            acknowledged: true,
            server_time: Some(crate::proto::common::Timestamp {
                seconds: now.timestamp(),
                nanos: now.timestamp_subsec_nanos() as i32,
            }),
            cancel_task_ids: vec![],
            update_available: false,
            update_version: String::new(),
        }))
    }

    /// Return scanner configuration from platform
    async fn get_configuration(
        &self,
        request: Request<ConfigRequest>,
    ) -> Result<Response<ScannerConfig>, Status> {
        let req = request.into_inner();
        info!(
            "Config request from scanner {}, current version: {}",
            req.scanner_id, req.current_config_version
        );

        Ok(Response::new(ScannerConfig {
            version: "1.0".into(),
            max_concurrent_scans: 4,
            max_concurrent_targets: 50,
            default_timeout_seconds: 300,
            enabled_check_categories: vec![
                "network".into(),
                "vulnerability".into(),
                "webapp".into(),
                "cloud".into(),
            ],
            custom_settings: std::collections::HashMap::new(),
        }))
    }
}
