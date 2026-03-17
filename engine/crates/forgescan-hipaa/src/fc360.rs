//! Bidirectional integration with ForgeComply 360
//!
//! Provides continuous compliance evidence collection and status synchronization
//! between ForgeScan's HIPAA compliance engine and the ForgeComply 360 platform.

use crate::hccra::{ComplianceStatus, HccraControl};
use crate::mapper::HipaaComplianceResult;
use crate::report::HipaaReport;
use crate::safeguards::TechnicalSafeguard;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Errors from ForgeComply 360 integration
#[derive(Debug, Error)]
pub enum Fc360Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API returned error status {status}: {message}")]
    Api { status: u16, message: String },
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Fc360Error>;

/// ForgeComply 360 API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fc360Config {
    /// Base URL for the ForgeComply 360 API
    pub base_url: String,
    /// API key for authentication
    pub api_key: String,
    /// Organization ID in ForgeComply 360
    pub org_id: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Fc360Config {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        org_id: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            org_id: org_id.into(),
            timeout_secs: 30,
        }
    }
}

/// Evidence item for compliance evidence collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvidence {
    /// Unique evidence ID
    pub id: Uuid,
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Which HIPAA safeguard this evidence relates to
    pub safeguard: TechnicalSafeguard,
    /// Related HCCRA control (if applicable)
    pub hccra_control: Option<HccraControl>,
    /// Compliance status this evidence supports
    pub status: ComplianceStatus,
    /// Evidence title
    pub title: String,
    /// Evidence description/details
    pub description: String,
    /// When the evidence was collected
    pub collected_at: DateTime<Utc>,
    /// Source of the evidence
    pub source: String,
    /// Raw evidence data (scan finding JSON, config snapshot, etc.)
    pub data: Option<serde_json::Value>,
}

/// Type of compliance evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Vulnerability scan result
    ScanResult,
    /// Configuration audit finding
    ConfigAudit,
    /// Compliance assessment report
    ComplianceReport,
    /// Remediation verification
    RemediationVerification,
    /// Policy validation
    PolicyValidation,
}

/// Status update to push to ForgeComply 360
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fc360StatusUpdate {
    /// Assessment ID (ties back to an FC360 assessment cycle)
    pub assessment_id: Option<String>,
    /// Overall HIPAA compliance score
    pub overall_score: f64,
    /// Per-safeguard scores
    pub safeguard_scores: Vec<Fc360SafeguardScore>,
    /// Per-HCCRA control statuses
    pub hccra_statuses: Vec<Fc360HccraStatus>,
    /// Timestamp of the assessment
    pub assessed_at: DateTime<Utc>,
    /// ForgeScan report ID
    pub forgescan_report_id: Uuid,
}

/// Safeguard score for FC360
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fc360SafeguardScore {
    pub safeguard_name: String,
    pub cfr_citation: String,
    pub score: f64,
    pub status: String,
    pub finding_count: u32,
}

/// HCCRA control status for FC360
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fc360HccraStatus {
    pub control_id: String,
    pub control_name: String,
    pub status: String,
    pub finding_count: u32,
    pub recommendations: Vec<String>,
}

/// Response from ForgeComply 360 when pushing evidence
#[derive(Debug, Clone, Deserialize)]
pub struct Fc360PushResponse {
    /// Whether the push was accepted
    pub accepted: bool,
    /// FC360 evidence record ID
    pub record_id: Option<String>,
    /// Any warnings
    pub warnings: Vec<String>,
}

/// Compliance requirements pulled from ForgeComply 360
#[derive(Debug, Clone, Deserialize)]
pub struct Fc360ComplianceRequirements {
    /// Active assessment cycle ID
    pub assessment_id: String,
    /// Required safeguard checks
    pub required_checks: Vec<Fc360RequiredCheck>,
    /// Due date for next evidence submission
    pub next_due_date: Option<DateTime<Utc>>,
    /// Custom compliance thresholds
    pub thresholds: Fc360Thresholds,
}

/// A specific check required by ForgeComply 360
#[derive(Debug, Clone, Deserialize)]
pub struct Fc360RequiredCheck {
    pub check_id: String,
    pub safeguard: String,
    pub hccra_control: Option<String>,
    pub description: String,
    pub last_evidence_date: Option<DateTime<Utc>>,
    pub status: String,
}

/// Custom compliance thresholds from ForgeComply 360
#[derive(Debug, Clone, Deserialize)]
pub struct Fc360Thresholds {
    /// Minimum overall score to be considered compliant
    pub min_overall_score: f64,
    /// Maximum allowed critical findings
    pub max_critical_findings: u32,
    /// Maximum days between vulnerability scans
    pub max_scan_interval_days: u32,
    /// Maximum days to remediate critical findings
    pub critical_sla_days: u32,
}

/// Bidirectional ForgeComply 360 integration client
pub struct Fc360Client {
    config: Fc360Config,
    http: reqwest::Client,
}

impl Fc360Client {
    /// Create a new ForgeComply 360 client
    pub fn new(config: Fc360Config) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(Fc360Error::Http)?;

        Ok(Self { config, http })
    }

    // ─── OUTBOUND (ForgeScan → FC360) ────────────────────────────────

    /// Push compliance evidence to ForgeComply 360
    pub async fn push_evidence(&self, evidence: &ComplianceEvidence) -> Result<Fc360PushResponse> {
        let url = format!(
            "{}/api/v1/orgs/{}/evidence",
            self.config.base_url, self.config.org_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(evidence)
            .send()
            .await
            .map_err(Fc360Error::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Fc360Error::Api { status, message });
        }

        resp.json().await.map_err(Fc360Error::Http)
    }

    /// Push bulk evidence items
    pub async fn push_evidence_batch(
        &self,
        evidence: &[ComplianceEvidence],
    ) -> Result<Vec<Fc360PushResponse>> {
        let url = format!(
            "{}/api/v1/orgs/{}/evidence/batch",
            self.config.base_url, self.config.org_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(evidence)
            .send()
            .await
            .map_err(Fc360Error::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Fc360Error::Api { status, message });
        }

        resp.json().await.map_err(Fc360Error::Http)
    }

    /// Push a compliance status update (overall scores + per-safeguard)
    pub async fn push_status_update(
        &self,
        update: &Fc360StatusUpdate,
    ) -> Result<Fc360PushResponse> {
        let url = format!(
            "{}/api/v1/orgs/{}/compliance/hipaa/status",
            self.config.base_url, self.config.org_id
        );

        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(update)
            .send()
            .await
            .map_err(Fc360Error::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Fc360Error::Api { status, message });
        }

        resp.json().await.map_err(Fc360Error::Http)
    }

    /// Push a full HIPAA report to ForgeComply 360
    pub async fn push_report(&self, report: &HipaaReport) -> Result<Fc360PushResponse> {
        let url = format!(
            "{}/api/v1/orgs/{}/compliance/hipaa/reports",
            self.config.base_url, self.config.org_id
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(report)
            .send()
            .await
            .map_err(Fc360Error::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Fc360Error::Api { status, message });
        }

        resp.json().await.map_err(Fc360Error::Http)
    }

    // ─── INBOUND (FC360 → ForgeScan) ─────────────────────────────────

    /// Pull compliance requirements from ForgeComply 360
    /// (what checks/evidence FC360 needs from ForgeScan)
    pub async fn pull_requirements(&self) -> Result<Fc360ComplianceRequirements> {
        let url = format!(
            "{}/api/v1/orgs/{}/compliance/hipaa/requirements",
            self.config.base_url, self.config.org_id
        );

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await
            .map_err(Fc360Error::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Fc360Error::Api { status, message });
        }

        resp.json().await.map_err(Fc360Error::Http)
    }

    /// Pull current compliance status from ForgeComply 360
    /// (to show FC360's view of compliance alongside ForgeScan's assessment)
    pub async fn pull_compliance_status(&self) -> Result<Fc360StatusUpdate> {
        let url = format!(
            "{}/api/v1/orgs/{}/compliance/hipaa/status",
            self.config.base_url, self.config.org_id
        );

        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await
            .map_err(Fc360Error::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(Fc360Error::Api { status, message });
        }

        resp.json().await.map_err(Fc360Error::Http)
    }

    // ─── CONVENIENCE ─────────────────────────────────────────────────

    /// Build a status update from a HIPAA compliance result and report
    pub fn build_status_update(
        result: &HipaaComplianceResult,
        report: &HipaaReport,
    ) -> Fc360StatusUpdate {
        let safeguard_scores = result
            .safeguard_summary
            .values()
            .map(|s| Fc360SafeguardScore {
                safeguard_name: s.safeguard.name().to_string(),
                cfr_citation: s.safeguard.cfr_citation().to_string(),
                score: s.score,
                status: s.status.as_str().to_string(),
                finding_count: s.total_findings,
            })
            .collect();

        let hccra_statuses = result
            .hccra_statuses
            .iter()
            .map(|s| Fc360HccraStatus {
                control_id: s.control.control_id().to_string(),
                control_name: s.control.name().to_string(),
                status: s.status.as_str().to_string(),
                finding_count: s.finding_count,
                recommendations: s.recommendations.clone(),
            })
            .collect();

        Fc360StatusUpdate {
            assessment_id: None,
            overall_score: result.overall_score,
            safeguard_scores,
            hccra_statuses,
            assessed_at: result.assessed_at,
            forgescan_report_id: report.metadata.report_id,
        }
    }

    /// Build compliance evidence items from a HIPAA compliance result
    pub fn build_evidence(result: &HipaaComplianceResult) -> Vec<ComplianceEvidence> {
        let mut evidence = Vec::new();

        // One evidence item per safeguard assessment
        for (name, status) in &result.safeguard_summary {
            evidence.push(ComplianceEvidence {
                id: Uuid::new_v4(),
                evidence_type: EvidenceType::ScanResult,
                safeguard: status.safeguard,
                hccra_control: None,
                status: status.status,
                title: format!("{} Assessment", name),
                description: format!(
                    "Automated vulnerability scan assessed {} ({}) — score: {:.0}/100, \
                     {} findings ({} critical, {} high)",
                    name,
                    status.safeguard.cfr_citation(),
                    status.score,
                    status.total_findings,
                    status.critical_count,
                    status.high_count,
                ),
                collected_at: result.assessed_at,
                source: "ForgeScan HIPAA Compliance Engine".into(),
                data: None,
            });
        }

        // One evidence item per HCCRA control
        for ctrl_status in &result.hccra_statuses {
            evidence.push(ComplianceEvidence {
                id: Uuid::new_v4(),
                evidence_type: EvidenceType::ComplianceReport,
                safeguard: ctrl_status
                    .control
                    .mapped_safeguards()
                    .first()
                    .copied()
                    .unwrap_or(TechnicalSafeguard::Integrity),
                hccra_control: Some(ctrl_status.control),
                status: ctrl_status.status,
                title: format!("{} Compliance Evidence", ctrl_status.control),
                description: format!(
                    "HCCRA {} assessment — status: {}, {} findings ({} critical/high)",
                    ctrl_status.control,
                    ctrl_status.status,
                    ctrl_status.finding_count,
                    ctrl_status.critical_high_count,
                ),
                collected_at: result.assessed_at,
                source: "ForgeScan HIPAA Compliance Engine".into(),
                data: None,
            });
        }

        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapper::HipaaMapper;
    use crate::report::HipaaReportGenerator;
    use forgescan_core::{Finding, Severity};

    fn sample_result() -> (HipaaComplianceResult, HipaaReport) {
        let mapper = HipaaMapper::new();
        let findings = vec![
            Finding::new("Weak TLS", Severity::High)
                .with_description("TLS 1.0 in use on ePHI server"),
            Finding::new("Missing Patches", Severity::Critical)
                .with_description("Unpatched critical vulnerability"),
        ];
        let result = mapper.map_findings(&findings);
        let generator = HipaaReportGenerator::new("Test Hospital");
        let now = Utc::now();
        let report = generator.generate(&result, now, now);
        (result, report)
    }

    #[test]
    fn test_build_status_update() {
        let (result, report) = sample_result();
        let update = Fc360Client::build_status_update(&result, &report);

        assert!(!update.safeguard_scores.is_empty());
        assert!(!update.hccra_statuses.is_empty());
        assert_eq!(update.hccra_statuses.len(), 7);
    }

    #[test]
    fn test_build_evidence() {
        let (result, _) = sample_result();
        let evidence = Fc360Client::build_evidence(&result);

        // 4 safeguard evidence + 7 HCCRA evidence = 11
        assert_eq!(evidence.len(), 11);
        assert!(evidence
            .iter()
            .any(|e| e.evidence_type == EvidenceType::ScanResult));
        assert!(evidence
            .iter()
            .any(|e| e.evidence_type == EvidenceType::ComplianceReport));
    }

    #[test]
    fn test_evidence_has_descriptions() {
        let (result, _) = sample_result();
        let evidence = Fc360Client::build_evidence(&result);

        for e in &evidence {
            assert!(!e.title.is_empty());
            assert!(!e.description.is_empty());
            assert!(!e.source.is_empty());
        }
    }

    #[test]
    fn test_config() {
        let config = Fc360Config::new("https://fc360.forgecyber.com", "test-api-key", "org-12345");
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.org_id, "org-12345");
    }

    #[test]
    fn test_status_update_serialization() {
        let (result, report) = sample_result();
        let update = Fc360Client::build_status_update(&result, &report);
        let json = serde_json::to_string(&update);
        assert!(json.is_ok());
    }
}
