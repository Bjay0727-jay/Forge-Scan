//! REST API client for connecting to the ForgeScan 360 platform
//!
//! This module provides an HTTP/JSON bridge for the scanner to communicate
//! with the Cloudflare Workers API backend. It replaces the gRPC transport
//! with a REST-based approach using the Scanner Bridge API.
//!
//! API endpoints used:
//! - POST   /api/v1/scanner/heartbeat       - Send heartbeat
//! - GET    /api/v1/scanner/tasks/next       - Poll for next task
//! - POST   /api/v1/scanner/tasks/:id/start  - Mark task as started
//! - POST   /api/v1/scanner/tasks/:id/results - Submit task results
//!

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use forgescan_core::Finding;

// ── Configuration ────────────────────────────────────────────────────────────

/// Configuration for the REST API client
#[derive(Debug, Clone)]
pub struct RestClientConfig {
    /// Platform API base URL (e.g., "https://forgescan-api.example.workers.dev")
    pub api_base_url: String,
    /// Scanner API key (issued during registration via admin dashboard)
    pub api_key: String,
    /// Scanner ID (assigned during registration)
    pub scanner_id: String,
    /// Scanner hostname
    pub hostname: String,
    /// Scanner version
    pub version: String,
    /// Scanner capabilities (e.g., ["network", "webapp", "cloud"])
    pub capabilities: Vec<String>,
    /// HTTP request timeout
    pub request_timeout: Duration,
    /// Task polling interval
    pub poll_interval: Duration,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
}

impl Default for RestClientConfig {
    fn default() -> Self {
        Self {
            api_base_url: String::from("https://forgescan-api.stanley-riley.workers.dev"),
            api_key: String::new(),
            scanner_id: String::new(),
            hostname: get_hostname(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: vec!["network".into(), "webapp".into(), "vulnerability".into()],
            request_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(120),
        }
    }
}

// ── API Response/Request Types ───────────────────────────────────────────────

/// Task received from the platform API
#[derive(Debug, Clone, Deserialize)]
pub struct ApiTask {
    pub id: String,
    pub scan_id: String,
    pub task_type: String,
    pub task_payload: Option<serde_json::Value>,
    pub priority: i32,
    pub max_retries: i32,
}

/// Response from GET /tasks/next
#[derive(Debug, Deserialize)]
pub struct NextTaskResponse {
    pub task: Option<ApiTask>,
    pub message: Option<String>,
}

/// Request body for POST /tasks/:id/results
#[derive(Debug, Serialize)]
pub struct TaskResultsPayload {
    pub status: String,
    pub result_summary: String,
    pub findings: Vec<FindingPayload>,
    pub assets_discovered: Vec<AssetPayload>,
}

/// A finding to submit to the platform
#[derive(Debug, Clone, Serialize)]
pub struct FindingPayload {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub state: String,
    pub vendor: String,
    pub vendor_id: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub evidence: Option<String>,
    pub solution: Option<String>,
    pub cve_ids: Vec<String>,
    pub cvss_score: Option<f32>,
    pub frs_score: Option<f32>,
    pub metadata: Option<serde_json::Value>,
}

/// An asset discovered during scanning
#[derive(Debug, Clone, Serialize)]
pub struct AssetPayload {
    pub hostname: Option<String>,
    pub ip_addresses: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub asset_type: String,
    pub mac_addresses: Option<String>,
    pub open_ports: Vec<PortPayload>,
}

/// Port information for discovered assets
#[derive(Debug, Clone, Serialize)]
pub struct PortPayload {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
}

/// Heartbeat request body
#[derive(Debug, Serialize)]
struct HeartbeatBody {
    scanner_id: String,
    hostname: String,
    version: String,
    capabilities: Vec<String>,
    active_task_ids: Vec<String>,
}

// ── Client Errors ────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RestClientError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Not configured: {0}")]
    NotConfigured(String),

    #[error("Task not found: {0}")]
    TaskNotFound(String),
}

// ── REST API Client ──────────────────────────────────────────────────────────

/// REST API client for scanner-platform communication
pub struct RestApiClient {
    config: RestClientConfig,
    http: Client,
    active_tasks: Arc<Mutex<Vec<String>>>,
    tasks_completed: Arc<AtomicU32>,
    tasks_failed: Arc<AtomicU32>,
}

impl RestApiClient {
    /// Create a new REST API client
    pub fn new(config: RestClientConfig) -> Result<Self, RestClientError> {
        if config.api_key.is_empty() {
            return Err(RestClientError::NotConfigured("api_key is required".into()));
        }
        if config.scanner_id.is_empty() {
            return Err(RestClientError::NotConfigured(
                "scanner_id is required".into(),
            ));
        }

        let http = Client::builder()
            .timeout(config.request_timeout)
            .user_agent(format!("ForgeScan-Scanner/{}", config.version))
            .build()?;

        Ok(Self {
            config,
            http,
            active_tasks: Arc::new(Mutex::new(Vec::new())),
            tasks_completed: Arc::new(AtomicU32::new(0)),
            tasks_failed: Arc::new(AtomicU32::new(0)),
        })
    }

    /// Get the API base URL with prefix
    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/api/v1/scanner{}",
            self.config.api_base_url.trim_end_matches('/'),
            path
        )
    }

    // ── Heartbeat ────────────────────────────────────────────────────────

    /// Send a heartbeat to the platform
    pub async fn heartbeat(&self) -> Result<(), RestClientError> {
        let active = self.active_tasks.lock().await;
        let body = HeartbeatBody {
            scanner_id: self.config.scanner_id.clone(),
            hostname: self.config.hostname.clone(),
            version: self.config.version.clone(),
            capabilities: self.config.capabilities.clone(),
            active_task_ids: active.clone(),
        };
        drop(active);

        let res = self
            .http
            .post(self.api_url("/heartbeat"))
            .header("X-Scanner-Key", &self.config.api_key)
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(RestClientError::Api {
                status,
                message: text,
            });
        }

        debug!("Heartbeat sent successfully");
        Ok(())
    }

    /// Start the heartbeat loop (runs until the returned handle is dropped)
    pub fn start_heartbeat_loop(&self) -> tokio::task::JoinHandle<()> {
        let interval = self.config.heartbeat_interval;
        let api_url = self.config.api_base_url.clone();
        let api_key = self.config.api_key.clone();
        let scanner_id = self.config.scanner_id.clone();
        let hostname = self.config.hostname.clone();
        let version = self.config.version.clone();
        let capabilities = self.config.capabilities.clone();
        let active_tasks = Arc::clone(&self.active_tasks);
        let timeout = self.config.request_timeout;

        tokio::spawn(async move {
            let http = Client::builder()
                .timeout(timeout)
                .user_agent(format!("ForgeScan-Scanner/{}", version))
                .build()
                .expect("Failed to build HTTP client for heartbeat");

            let mut tick = tokio::time::interval(interval);

            loop {
                tick.tick().await;

                let active = active_tasks.lock().await.clone();
                let body = HeartbeatBody {
                    scanner_id: scanner_id.clone(),
                    hostname: hostname.clone(),
                    version: version.clone(),
                    capabilities: capabilities.clone(),
                    active_task_ids: active,
                };

                let url = format!("{}/api/v1/scanner/heartbeat", api_url.trim_end_matches('/'));

                match http
                    .post(&url)
                    .header("X-Scanner-Key", &api_key)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(res) if res.status().is_success() => {
                        debug!("Heartbeat OK");
                    }
                    Ok(res) => {
                        warn!("Heartbeat returned {}", res.status());
                    }
                    Err(e) => {
                        warn!("Heartbeat failed: {}", e);
                    }
                }
            }
        })
    }

    // ── Task Polling ─────────────────────────────────────────────────────

    /// Poll for the next available task
    pub async fn poll_task(&self) -> Result<Option<ApiTask>, RestClientError> {
        let caps = self.config.capabilities.join(",");
        let url = format!("{}?capabilities={}", self.api_url("/tasks/next"), caps);

        let res = self
            .http
            .get(&url)
            .header("X-Scanner-Key", &self.config.api_key)
            .send()
            .await?;

        if res.status().as_u16() == 204 {
            return Ok(None); // No tasks available
        }

        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(RestClientError::Api {
                status,
                message: text,
            });
        }

        let body: NextTaskResponse = res.json().await?;
        if let Some(task) = body.task {
            info!("Received task {} (type: {})", task.id, task.task_type);
            // Track active task
            self.active_tasks.lock().await.push(task.id.clone());
            Ok(Some(task))
        } else {
            Ok(None)
        }
    }

    // ── Task Lifecycle ───────────────────────────────────────────────────

    /// Mark a task as started
    pub async fn start_task(&self, task_id: &str) -> Result<(), RestClientError> {
        let url = self.api_url(&format!("/tasks/{}/start", task_id));

        let res = self
            .http
            .post(&url)
            .header("X-Scanner-Key", &self.config.api_key)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(RestClientError::Api {
                status,
                message: text,
            });
        }

        info!("Task {} marked as started", task_id);
        Ok(())
    }

    /// Submit task results (findings + assets)
    pub async fn submit_results(
        &self,
        task_id: &str,
        results: TaskResultsPayload,
    ) -> Result<(), RestClientError> {
        let url = self.api_url(&format!("/tasks/{}/results", task_id));

        let findings_count = results.findings.len();
        let assets_count = results.assets_discovered.len();

        let res = self
            .http
            .post(&url)
            .header("X-Scanner-Key", &self.config.api_key)
            .json(&results)
            .send()
            .await?;

        // Remove from active tasks
        {
            let mut active = self.active_tasks.lock().await;
            active.retain(|id| id != task_id);
        }

        if !res.status().is_success() {
            self.tasks_failed.fetch_add(1, Ordering::Relaxed);
            let status = res.status().as_u16();
            let text = res.text().await.unwrap_or_default();
            return Err(RestClientError::Api {
                status,
                message: text,
            });
        }

        self.tasks_completed.fetch_add(1, Ordering::Relaxed);
        info!(
            "Task {} results submitted: {} findings, {} assets",
            task_id, findings_count, assets_count
        );
        Ok(())
    }

    /// Submit a failed task
    pub async fn submit_failure(
        &self,
        task_id: &str,
        error_message: &str,
    ) -> Result<(), RestClientError> {
        let payload = TaskResultsPayload {
            status: "failed".into(),
            result_summary: error_message.into(),
            findings: vec![],
            assets_discovered: vec![],
        };
        self.submit_results(task_id, payload).await
    }

    // ── Statistics ───────────────────────────────────────────────────────

    /// Get tasks completed count
    pub fn tasks_completed(&self) -> u32 {
        self.tasks_completed.load(Ordering::Relaxed)
    }

    /// Get tasks failed count
    pub fn tasks_failed(&self) -> u32 {
        self.tasks_failed.load(Ordering::Relaxed)
    }

    /// Get poll interval
    pub fn poll_interval(&self) -> Duration {
        self.config.poll_interval
    }

    /// Get scanner ID
    pub fn scanner_id(&self) -> &str {
        &self.config.scanner_id
    }
}

// ── Conversion helpers ───────────────────────────────────────────────────────

impl From<&Finding> for FindingPayload {
    fn from(f: &Finding) -> Self {
        FindingPayload {
            title: f.title.clone(),
            description: f.description.clone(),
            severity: f.severity.as_str().to_lowercase(),
            state: "open".into(),
            vendor: "forgescan".into(),
            vendor_id: f.check_id.clone(),
            port: f.port,
            protocol: f.protocol.clone(),
            service: f.service.clone(),
            evidence: Some(f.evidence.clone()),
            solution: f.remediation.clone(),
            cve_ids: f.cve_ids.clone(),
            cvss_score: f.cvss_v3_score,
            frs_score: None, // Will be calculated by platform
            metadata: Some(serde_json::json!({
                "check_name": f.check_name,
                "category": f.category.as_str(),
                "detection_method": f.detection_method,
                "exploit_maturity": f.exploit_maturity.as_str(),
                "cisa_kev": f.cisa_kev,
                "cwe_ids": f.cwe_ids,
                "compliance_mappings": f.compliance_mappings,
                "detected_at": f.detected_at.to_rfc3339(),
            })),
        }
    }
}

// ── Utility ──────────────────────────────────────────────────────────────────

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        use std::ffi::{c_char, CStr};
        let mut buf = [0 as c_char; 256];
        unsafe {
            libc::gethostname(buf.as_mut_ptr(), buf.len());
            CStr::from_ptr(buf.as_ptr()).to_string_lossy().to_string()
        }
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unknown".into()
    }
}
