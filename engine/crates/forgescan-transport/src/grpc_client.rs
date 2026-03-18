//! gRPC client for connecting to the ForgeScan platform streaming service
//!
//! Wraps the generated tonic client with convenient methods for scan execution,
//! heartbeat management, and configuration retrieval.
//!
//! Supports optional mTLS: when TLS config is provided, the client presents its
//! certificate and validates the server certificate against the trusted CA.

use crate::grpc_server::GrpcTlsConfig;
use crate::proto::scan::scan_service_client::ScanServiceClient;
use crate::proto::scan::{
    ConfigRequest, HeartbeatRequest, HeartbeatResponse, ScanEvent, ScanTask, ScannerConfig,
    ScannerStatus,
};
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::{debug, info};

/// gRPC client for streaming scan events from the platform
pub struct GrpcScannerClient {
    inner: ScanServiceClient<Channel>,
    scanner_id: String,
}

impl GrpcScannerClient {
    /// Connect to the gRPC server at the given address (plaintext)
    pub async fn connect(
        addr: &str,
        scanner_id: impl Into<String>,
    ) -> Result<Self, tonic::transport::Error> {
        let endpoint = if addr.starts_with("http") {
            addr.to_string()
        } else {
            format!("http://{}", addr)
        };
        info!("Connecting to gRPC server at {} (plaintext)", endpoint);
        let inner = ScanServiceClient::connect(endpoint).await?;
        Ok(Self {
            inner,
            scanner_id: scanner_id.into(),
        })
    }

    /// Connect to the gRPC server with mTLS
    pub async fn connect_mtls(
        addr: &str,
        scanner_id: impl Into<String>,
        tls: &GrpcTlsConfig,
    ) -> Result<Self, tonic::transport::Error> {
        let endpoint = if addr.starts_with("https") {
            addr.to_string()
        } else {
            format!("https://{}", addr)
        };
        info!("Connecting to gRPC server at {} (mTLS)", endpoint);

        let ca_cert = std::fs::read(&tls.client_ca_cert_path)
            .expect("Failed to read CA certificate for mTLS client");
        let client_cert = std::fs::read(&tls.server_cert_path)
            .expect("Failed to read client certificate for mTLS");
        let client_key =
            std::fs::read(&tls.server_key_path).expect("Failed to read client key for mTLS");

        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert))
            .identity(tonic::transport::Identity::from_pem(
                client_cert,
                client_key,
            ));

        let channel = Channel::from_shared(endpoint)
            .expect("Invalid endpoint URI")
            .tls_config(tls_config)?
            .connect()
            .await?;

        let inner = ScanServiceClient::new(channel);
        Ok(Self {
            inner,
            scanner_id: scanner_id.into(),
        })
    }

    /// Execute a scan and return a stream of events
    pub async fn execute_scan(
        &mut self,
        task: ScanTask,
    ) -> Result<impl tokio_stream::Stream<Item = Result<ScanEvent, tonic::Status>>, tonic::Status>
    {
        let response = self.inner.execute_scan(task).await?;
        Ok(response.into_inner())
    }

    /// Send a heartbeat to the platform
    pub async fn heartbeat(
        &mut self,
        active_task_ids: Vec<String>,
    ) -> Result<HeartbeatResponse, tonic::Status> {
        let hostname = get_hostname();
        let request = HeartbeatRequest {
            scanner_id: self.scanner_id.clone(),
            hostname,
            version: env!("CARGO_PKG_VERSION").to_string(),
            status: Some(ScannerStatus {
                state: 1, // IDLE
                queue_depth: 0,
                active_scans: active_task_ids.len() as u32,
            }),
            active_task_ids,
            resources: None,
        };

        let response = self.inner.heartbeat(request).await?;
        Ok(response.into_inner())
    }

    /// Get scanner configuration from the platform
    pub async fn get_configuration(
        &mut self,
        current_version: &str,
    ) -> Result<ScannerConfig, tonic::Status> {
        let request = ConfigRequest {
            scanner_id: self.scanner_id.clone(),
            current_config_version: current_version.to_string(),
        };

        let response = self.inner.get_configuration(request).await?;
        Ok(response.into_inner())
    }

    /// Subscribe to scan events, calling the handler for each event
    pub async fn subscribe_scan_events<F>(
        &mut self,
        task: ScanTask,
        mut handler: F,
    ) -> Result<(), tonic::Status>
    where
        F: FnMut(ScanEvent),
    {
        let mut stream = self.execute_scan(task).await?;
        while let Some(event) = stream.next().await {
            match event {
                Ok(scan_event) => {
                    debug!("Received scan event");
                    handler(scan_event);
                }
                Err(status) => {
                    return Err(status);
                }
            }
        }
        Ok(())
    }
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        let mut buf = [0u8; 256];
        unsafe {
            if libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) == 0 {
                if let Ok(s) = CStr::from_ptr(buf.as_ptr() as *const _).to_str() {
                    return s.to_string();
                }
            }
        }
    }
    "unknown".to_string()
}
