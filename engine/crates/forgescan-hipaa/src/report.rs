//! HIPAA-formatted report generator
//!
//! Generates compliance reports mapped to HIPAA Security Rule requirements
//! and the 7 mandatory HCCRA controls, including board-ready executive summaries
//! with compliance scorecards.

use crate::hccra::{ComplianceStatus, HccraControl};
use crate::mapper::{HipaaComplianceResult, HipaaMapping};
use crate::safeguards::TechnicalSafeguard;
use chrono::{DateTime, Utc};
use forgescan_core::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A complete HIPAA compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaReport {
    /// Report metadata
    pub metadata: ReportMetadata,
    /// Executive summary (board-ready)
    pub executive_summary: ExecutiveSummary,
    /// HIPAA compliance scorecard
    pub scorecard: ComplianceScorecard,
    /// Detailed safeguard findings
    pub safeguard_details: Vec<SafeguardDetail>,
    /// HCCRA control compliance details
    pub hccra_details: Vec<HccraDetail>,
    /// Prioritized remediation plan
    pub remediation_plan: RemediationPlan,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report title
    pub title: String,
    /// Organization name
    pub organization: String,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Assessment period start
    pub assessment_start: DateTime<Utc>,
    /// Assessment period end
    pub assessment_end: DateTime<Utc>,
    /// Report version
    pub version: String,
    /// Prepared by
    pub prepared_by: String,
    /// Classification level
    pub classification: String,
    /// Unique report ID
    pub report_id: uuid::Uuid,
}

/// Board-ready executive summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// Overall HIPAA compliance posture
    pub compliance_posture: CompliancePosture,
    /// Overall compliance score (0-100)
    pub overall_score: f64,
    /// Previous assessment score (for trend)
    pub previous_score: Option<f64>,
    /// Total findings count
    pub total_findings: u32,
    /// Critical findings requiring immediate action
    pub critical_findings: u32,
    /// High-priority findings
    pub high_findings: u32,
    /// Key risk areas
    pub key_risks: Vec<String>,
    /// Positive compliance highlights
    pub highlights: Vec<String>,
    /// Board-level recommendations
    pub recommendations: Vec<String>,
    /// Estimated cost of non-compliance
    pub risk_exposure: RiskExposure,
}

/// Overall compliance posture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompliancePosture {
    /// All safeguards compliant, score >= 95
    Strong,
    /// Most safeguards compliant, score >= 75
    Adequate,
    /// Some safeguards non-compliant, score >= 50
    NeedsImprovement,
    /// Multiple safeguards non-compliant, score < 50
    AtRisk,
}

impl CompliancePosture {
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 95.0 => Self::Strong,
            s if s >= 75.0 => Self::Adequate,
            s if s >= 50.0 => Self::NeedsImprovement,
            _ => Self::AtRisk,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Strong => "Strong",
            Self::Adequate => "Adequate",
            Self::NeedsImprovement => "Needs Improvement",
            Self::AtRisk => "At Risk",
        }
    }

    pub fn board_description(&self) -> &'static str {
        match self {
            Self::Strong => {
                "The organization demonstrates strong HIPAA compliance posture with minimal \
                 risk to electronic protected health information."
            }
            Self::Adequate => {
                "The organization maintains adequate HIPAA compliance but should address \
                 identified gaps within established SLA timelines."
            }
            Self::NeedsImprovement => {
                "The organization has notable HIPAA compliance gaps that require prioritized \
                 remediation to reduce risk to electronic protected health information."
            }
            Self::AtRisk => {
                "The organization faces significant HIPAA compliance deficiencies that \
                 present material risk of regulatory penalties and data breaches. \
                 Immediate executive attention is required."
            }
        }
    }
}

impl std::fmt::Display for CompliancePosture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Financial risk exposure estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskExposure {
    /// Tier based on finding severity
    pub tier: PenaltyTier,
    /// Per-violation penalty range (low, high)
    pub per_violation_range: (u64, u64),
    /// Annual cap
    pub annual_cap: u64,
    /// Additional context
    pub notes: String,
}

/// HIPAA penalty tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PenaltyTier {
    /// Tier 1: Lack of knowledge — $137 to $68,928 per violation
    Tier1,
    /// Tier 2: Reasonable cause — $1,379 to $68,928 per violation
    Tier2,
    /// Tier 3: Willful neglect (corrected) — $13,785 to $68,928 per violation
    Tier3,
    /// Tier 4: Willful neglect (not corrected) — $68,928+ per violation
    Tier4,
}

impl PenaltyTier {
    pub fn range(&self) -> (u64, u64) {
        match self {
            Self::Tier1 => (137, 68_928),
            Self::Tier2 => (1_379, 68_928),
            Self::Tier3 => (13_785, 68_928),
            Self::Tier4 => (68_928, 2_067_813),
        }
    }

    pub fn annual_cap(&self) -> u64 {
        match self {
            Self::Tier1 => 68_928,
            Self::Tier2 => 1_723_198,
            Self::Tier3 => 1_723_198,
            Self::Tier4 => 2_067_813,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Tier1 => "Tier 1 — Lack of Knowledge",
            Self::Tier2 => "Tier 2 — Reasonable Cause",
            Self::Tier3 => "Tier 3 — Willful Neglect (Corrected)",
            Self::Tier4 => "Tier 4 — Willful Neglect (Not Corrected)",
        }
    }
}

/// HIPAA compliance scorecard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScorecard {
    /// Overall score (0-100)
    pub overall_score: f64,
    /// Per-safeguard scores
    pub safeguard_scores: Vec<SafeguardScoreEntry>,
    /// Per-HCCRA control statuses
    pub hccra_scores: Vec<HccraScoreEntry>,
    /// Trend indicator vs previous assessment
    pub trend: Trend,
}

/// A single row in the safeguard scorecard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeguardScoreEntry {
    pub safeguard: TechnicalSafeguard,
    pub cfr_citation: String,
    pub score: f64,
    pub status: ComplianceStatus,
    pub finding_count: u32,
    pub critical_high_count: u32,
}

/// A single row in the HCCRA scorecard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HccraScoreEntry {
    pub control: HccraControl,
    pub control_id: String,
    pub status: ComplianceStatus,
    pub finding_count: u32,
    pub critical_high_count: u32,
}

/// Trend vs previous assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Trend {
    Improving,
    Stable,
    Declining,
    NoBaseline,
}

impl std::fmt::Display for Trend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Improving => write!(f, "Improving"),
            Self::Stable => write!(f, "Stable"),
            Self::Declining => write!(f, "Declining"),
            Self::NoBaseline => write!(f, "No Baseline"),
        }
    }
}

/// Detailed findings for a single safeguard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeguardDetail {
    pub safeguard: TechnicalSafeguard,
    pub cfr_citation: String,
    pub description: String,
    pub status: ComplianceStatus,
    pub score: f64,
    pub findings: Vec<HipaaMapping>,
    pub implementation_gaps: Vec<String>,
    pub recommended_actions: Vec<String>,
}

/// Detailed findings for a single HCCRA control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HccraDetail {
    pub control: HccraControl,
    pub control_id: String,
    pub description: String,
    pub status: ComplianceStatus,
    pub finding_count: u32,
    pub mapped_safeguards: Vec<TechnicalSafeguard>,
    pub recommendations: Vec<String>,
}

/// Prioritized remediation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub items: Vec<RemediationItem>,
}

/// A single remediation item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationItem {
    pub priority: u32,
    pub title: String,
    pub affected_safeguards: Vec<TechnicalSafeguard>,
    pub affected_hccra: Vec<HccraControl>,
    pub severity: Severity,
    pub sla_days: u32,
    pub action: String,
}

/// HIPAA report generator
pub struct HipaaReportGenerator {
    organization: String,
    previous_score: Option<f64>,
}

impl HipaaReportGenerator {
    /// Create a new report generator
    pub fn new(organization: impl Into<String>) -> Self {
        Self {
            organization: organization.into(),
            previous_score: None,
        }
    }

    /// Set previous assessment score for trend analysis
    pub fn with_previous_score(mut self, score: f64) -> Self {
        self.previous_score = Some(score);
        self
    }

    /// Generate a complete HIPAA compliance report
    pub fn generate(
        &self,
        compliance_result: &HipaaComplianceResult,
        assessment_start: DateTime<Utc>,
        assessment_end: DateTime<Utc>,
    ) -> HipaaReport {
        let metadata = ReportMetadata {
            title: "HIPAA Security Rule Compliance Assessment Report".into(),
            organization: self.organization.clone(),
            generated_at: Utc::now(),
            assessment_start,
            assessment_end,
            version: "1.0".into(),
            prepared_by: "ForgeScan HIPAA Compliance Engine".into(),
            classification: "CONFIDENTIAL — HIPAA Security Assessment".into(),
            report_id: uuid::Uuid::new_v4(),
        };

        let executive_summary = self.build_executive_summary(compliance_result);
        let scorecard = self.build_scorecard(compliance_result);
        let safeguard_details = self.build_safeguard_details(compliance_result);
        let hccra_details = self.build_hccra_details(compliance_result);
        let remediation_plan = self.build_remediation_plan(compliance_result);

        HipaaReport {
            metadata,
            executive_summary,
            scorecard,
            safeguard_details,
            hccra_details,
            remediation_plan,
        }
    }

    fn build_executive_summary(&self, result: &HipaaComplianceResult) -> ExecutiveSummary {
        let total_findings: u32 = result
            .safeguard_summary
            .values()
            .map(|s| s.total_findings)
            .sum();
        let critical_findings: u32 = result
            .safeguard_summary
            .values()
            .map(|s| s.critical_count)
            .sum();
        let high_findings: u32 = result
            .safeguard_summary
            .values()
            .map(|s| s.high_count)
            .sum();

        let posture = CompliancePosture::from_score(result.overall_score);

        let mut key_risks = Vec::new();
        for (name, status) in &result.safeguard_summary {
            if status.status == ComplianceStatus::NonCompliant {
                key_risks.push(format!(
                    "{} ({}) — {} critical/high findings",
                    name,
                    status.safeguard.cfr_citation(),
                    status.critical_count + status.high_count
                ));
            }
        }

        let mut highlights = Vec::new();
        for (name, status) in &result.safeguard_summary {
            if status.status == ComplianceStatus::Compliant {
                highlights.push(format!("{} — fully compliant", name));
            }
        }

        let mut recommendations = Vec::new();
        if critical_findings > 0 {
            recommendations.push(format!(
                "Immediately address {} critical findings that impact ePHI security",
                critical_findings
            ));
        }
        if key_risks.len() > 1 {
            recommendations.push(
                "Engage cybersecurity remediation resources to address multiple non-compliant \
                 safeguard areas"
                    .into(),
            );
        }

        let non_compliant_hccra: Vec<_> = result
            .hccra_statuses
            .iter()
            .filter(|s| s.status == ComplianceStatus::NonCompliant)
            .collect();
        if !non_compliant_hccra.is_empty() {
            recommendations.push(format!(
                "Prioritize remediation of {} non-compliant HCCRA mandatory controls \
                 to avoid regulatory penalties under the Health Care Cybersecurity \
                 and Resiliency Act of 2025",
                non_compliant_hccra.len()
            ));
        }

        let penalty_tier = if critical_findings > 5 {
            PenaltyTier::Tier3
        } else if critical_findings > 0 {
            PenaltyTier::Tier2
        } else {
            PenaltyTier::Tier1
        };

        let risk_exposure = RiskExposure {
            tier: penalty_tier,
            per_violation_range: penalty_tier.range(),
            annual_cap: penalty_tier.annual_cap(),
            notes: format!(
                "Based on {} total findings across {} HIPAA safeguard areas. \
                 Actual penalties depend on OCR investigation findings.",
                total_findings,
                result.safeguard_summary.len()
            ),
        };

        ExecutiveSummary {
            compliance_posture: posture,
            overall_score: result.overall_score,
            previous_score: self.previous_score,
            total_findings,
            critical_findings,
            high_findings,
            key_risks,
            highlights,
            recommendations,
            risk_exposure,
        }
    }

    fn build_scorecard(&self, result: &HipaaComplianceResult) -> ComplianceScorecard {
        let safeguard_scores: Vec<_> = result
            .safeguard_summary
            .values()
            .map(|s| SafeguardScoreEntry {
                safeguard: s.safeguard,
                cfr_citation: s.safeguard.cfr_citation().to_string(),
                score: s.score,
                status: s.status,
                finding_count: s.total_findings,
                critical_high_count: s.critical_count + s.high_count,
            })
            .collect();

        let hccra_scores: Vec<_> = result
            .hccra_statuses
            .iter()
            .map(|s| HccraScoreEntry {
                control: s.control,
                control_id: s.control.control_id().to_string(),
                status: s.status,
                finding_count: s.finding_count,
                critical_high_count: s.critical_high_count,
            })
            .collect();

        let trend = match self.previous_score {
            None => Trend::NoBaseline,
            Some(prev) => {
                let delta = result.overall_score - prev;
                if delta > 5.0 {
                    Trend::Improving
                } else if delta < -5.0 {
                    Trend::Declining
                } else {
                    Trend::Stable
                }
            }
        };

        ComplianceScorecard {
            overall_score: result.overall_score,
            safeguard_scores,
            hccra_scores,
            trend,
        }
    }

    fn build_safeguard_details(&self, result: &HipaaComplianceResult) -> Vec<SafeguardDetail> {
        let mut details = Vec::new();

        // Group mappings by safeguard
        let mut sg_mappings: HashMap<TechnicalSafeguard, Vec<HipaaMapping>> = HashMap::new();
        for mapping in &result.mappings {
            for sg in &mapping.safeguards {
                sg_mappings.entry(*sg).or_default().push(mapping.clone());
            }
        }

        for sg in TechnicalSafeguard::all() {
            let status = result
                .safeguard_summary
                .get(sg.name())
                .map(|s| s.status)
                .unwrap_or(ComplianceStatus::Compliant);
            let score = result
                .safeguard_summary
                .get(sg.name())
                .map(|s| s.score)
                .unwrap_or(100.0);
            let findings = sg_mappings.remove(sg).unwrap_or_default();

            let implementation_gaps = self.identify_gaps(sg, &findings);
            let recommended_actions = self.recommend_for_safeguard(sg, &findings);

            details.push(SafeguardDetail {
                safeguard: *sg,
                cfr_citation: sg.cfr_citation().to_string(),
                description: sg.description().to_string(),
                status,
                score,
                findings,
                implementation_gaps,
                recommended_actions,
            });
        }

        details
    }

    fn build_hccra_details(&self, result: &HipaaComplianceResult) -> Vec<HccraDetail> {
        result
            .hccra_statuses
            .iter()
            .map(|s| HccraDetail {
                control: s.control,
                control_id: s.control.control_id().to_string(),
                description: s.control.description().to_string(),
                status: s.status,
                finding_count: s.finding_count,
                mapped_safeguards: s.control.mapped_safeguards(),
                recommendations: s.recommendations.clone(),
            })
            .collect()
    }

    fn build_remediation_plan(&self, result: &HipaaComplianceResult) -> RemediationPlan {
        let mut items = Vec::new();
        let mut priority = 1u32;

        // Sort mappings by severity (critical first)
        let mut sorted_mappings = result.mappings.clone();
        sorted_mappings.sort_by(|a, b| b.severity.as_number().cmp(&a.severity.as_number()));

        for mapping in &sorted_mappings {
            if mapping.severity.as_number() < Severity::Medium.as_number() {
                continue; // Only include Medium+ in remediation plan
            }

            let sla = match mapping.severity {
                Severity::Critical => 1,
                Severity::High => 7,
                Severity::Medium => 30,
                _ => 90,
            };

            items.push(RemediationItem {
                priority,
                title: mapping.finding_title.clone(),
                affected_safeguards: mapping.safeguards.clone(),
                affected_hccra: mapping.hccra_controls.clone(),
                severity: mapping.severity,
                sla_days: sla,
                action: format!(
                    "Remediate to restore compliance with {} and {}",
                    mapping
                        .safeguards
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    mapping
                        .hccra_controls
                        .iter()
                        .map(|c| c.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            });
            priority += 1;
        }

        RemediationPlan { items }
    }

    fn identify_gaps(
        &self,
        safeguard: &TechnicalSafeguard,
        findings: &[HipaaMapping],
    ) -> Vec<String> {
        if findings.is_empty() {
            return vec![];
        }
        let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
        let has_high = findings.iter().any(|f| f.severity == Severity::High);

        let mut gaps = Vec::new();
        match safeguard {
            TechnicalSafeguard::AccessControl => {
                if has_critical || has_high {
                    gaps.push(
                        "Access control mechanisms are insufficient to prevent unauthorized \
                         access to ePHI"
                            .into(),
                    );
                }
            }
            TechnicalSafeguard::AuditControls => {
                gaps.push(
                    "Audit logging coverage is incomplete for systems containing ePHI".into(),
                );
            }
            TechnicalSafeguard::Integrity => {
                if has_critical {
                    gaps.push(
                        "Critical integrity controls are missing, allowing potential ePHI \
                         alteration or destruction"
                            .into(),
                    );
                }
            }
            TechnicalSafeguard::TransmissionSecurity => {
                gaps.push(
                    "Transmission security controls require strengthening to protect ePHI \
                     in transit"
                        .into(),
                );
            }
        }
        gaps
    }

    fn recommend_for_safeguard(
        &self,
        safeguard: &TechnicalSafeguard,
        findings: &[HipaaMapping],
    ) -> Vec<String> {
        if findings.is_empty() {
            return vec!["Continue maintaining current compliance posture".into()];
        }
        match safeguard {
            TechnicalSafeguard::AccessControl => vec![
                "Implement or strengthen multi-factor authentication".into(),
                "Review and enforce role-based access controls (RBAC)".into(),
                "Configure automatic session timeouts per §164.312(a)(2)(iii)".into(),
            ],
            TechnicalSafeguard::AuditControls => vec![
                "Deploy centralized logging (SIEM) for all ePHI systems".into(),
                "Enable audit logging on all identified systems".into(),
                "Implement automated alerting for suspicious access patterns".into(),
            ],
            TechnicalSafeguard::Integrity => vec![
                "Apply security patches to address integrity vulnerabilities".into(),
                "Implement file integrity monitoring for ePHI storage".into(),
                "Deploy input validation and output encoding controls".into(),
            ],
            TechnicalSafeguard::TransmissionSecurity => vec![
                "Enforce TLS 1.2+ for all ePHI communications".into(),
                "Disable deprecated protocols (SSLv3, TLS 1.0, TLS 1.1)".into(),
                "Implement certificate management and rotation policies".into(),
            ],
        }
    }

    /// Render the report as JSON
    pub fn to_json(&self, report: &HipaaReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }

    /// Render the executive summary as formatted text for board presentation
    pub fn render_executive_text(&self, report: &HipaaReport) -> String {
        let es = &report.executive_summary;
        let sc = &report.scorecard;

        let mut output = String::new();

        output.push_str("═══════════════════════════════════════════════════════════════\n");
        output.push_str("  HIPAA SECURITY RULE COMPLIANCE — EXECUTIVE SUMMARY\n");
        output.push_str(&format!(
            "  Organization: {}\n",
            report.metadata.organization
        ));
        output.push_str(&format!(
            "  Assessment Date: {}\n",
            report.metadata.generated_at.format("%B %d, %Y")
        ));
        output.push_str(&format!(
            "  Classification: {}\n",
            report.metadata.classification
        ));
        output.push_str("═══════════════════════════════════════════════════════════════\n\n");

        // Compliance Posture
        output.push_str(&format!(
            "  COMPLIANCE POSTURE: {}\n",
            es.compliance_posture.label().to_uppercase()
        ));
        output.push_str(&format!("  Overall Score: {:.0}/100\n", es.overall_score));
        if let Some(prev) = es.previous_score {
            let delta = es.overall_score - prev;
            let arrow = if delta > 0.0 { "↑" } else { "↓" };
            output.push_str(&format!(
                "  Trend: {} {:.1} from previous ({:.0})\n",
                arrow,
                delta.abs(),
                prev
            ));
        }
        output.push_str(&format!("  Trend Status: {}\n\n", sc.trend));
        output.push_str(&format!(
            "  {}\n\n",
            es.compliance_posture.board_description()
        ));

        // Finding Summary
        output.push_str("  ─── FINDING SUMMARY ────────────────────────────────────────\n");
        output.push_str(&format!("  Total Findings:    {}\n", es.total_findings));
        output.push_str(&format!("  Critical:          {}\n", es.critical_findings));
        output.push_str(&format!("  High:              {}\n", es.high_findings));
        output.push_str(&format!(
            "  Medium/Low/Info:   {}\n\n",
            es.total_findings - es.critical_findings - es.high_findings
        ));

        // Safeguard Scorecard
        output.push_str("  ─── HIPAA TECHNICAL SAFEGUARD SCORECARD ────────────────────\n");
        output.push_str(&format!(
            "  {:<28} {:<16} {:>6} {:>10}\n",
            "SAFEGUARD", "STATUS", "SCORE", "FINDINGS"
        ));
        output.push_str(&format!("  {}\n", "─".repeat(64)));
        for entry in &sc.safeguard_scores {
            output.push_str(&format!(
                "  {:<28} {:<16} {:>5.0}% {:>10}\n",
                entry.safeguard.name(),
                entry.status,
                entry.score,
                entry.finding_count,
            ));
        }
        output.push('\n');

        // HCCRA Scorecard
        output.push_str("  ─── HCCRA MANDATORY CONTROL SCORECARD ──────────────────────\n");
        output.push_str(&format!(
            "  {:<8} {:<30} {:<18} {:>10}\n",
            "CTRL", "CONTROL NAME", "STATUS", "FINDINGS"
        ));
        output.push_str(&format!("  {}\n", "─".repeat(70)));
        for entry in &sc.hccra_scores {
            output.push_str(&format!(
                "  {:<8} {:<30} {:<18} {:>10}\n",
                entry.control_id,
                entry.control.name(),
                entry.status,
                entry.finding_count,
            ));
        }
        output.push('\n');

        // Key Risks
        if !es.key_risks.is_empty() {
            output.push_str("  ─── KEY RISKS ──────────────────────────────────────────────\n");
            for (i, risk) in es.key_risks.iter().enumerate() {
                output.push_str(&format!("  {}. {}\n", i + 1, risk));
            }
            output.push('\n');
        }

        // Recommendations
        if !es.recommendations.is_empty() {
            output.push_str("  ─── BOARD RECOMMENDATIONS ──────────────────────────────────\n");
            for (i, rec) in es.recommendations.iter().enumerate() {
                output.push_str(&format!("  {}. {}\n", i + 1, rec));
            }
            output.push('\n');
        }

        // Risk Exposure
        output.push_str("  ─── REGULATORY RISK EXPOSURE ───────────────────────────────\n");
        output.push_str(&format!(
            "  Penalty Tier:       {}\n",
            es.risk_exposure.tier.label()
        ));
        output.push_str(&format!(
            "  Per-Violation Range: ${:>10} — ${:>10}\n",
            format_dollars(es.risk_exposure.per_violation_range.0),
            format_dollars(es.risk_exposure.per_violation_range.1),
        ));
        output.push_str(&format!(
            "  Annual Cap:         ${}\n",
            format_dollars(es.risk_exposure.annual_cap)
        ));
        output.push_str(&format!("  Note: {}\n", es.risk_exposure.notes));

        output.push_str("\n═══════════════════════════════════════════════════════════════\n");

        output
    }
}

/// Format dollar amount with commas
fn format_dollars(amount: u64) -> String {
    let s = amount.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapper::HipaaMapper;
    use forgescan_core::{CheckCategory, Finding};

    fn sample_findings() -> Vec<Finding> {
        vec![
            {
                let mut f = Finding::new("Weak SSL Configuration", Severity::High)
                    .with_description("TLS 1.0 enabled on ePHI-handling server");
                f.category = CheckCategory::Network;
                f.cwe_ids = vec!["CWE-327".into()];
                f
            },
            {
                let mut f = Finding::new("Default Credentials", Severity::Critical)
                    .with_description("Service accepts default password for admin login");
                f.category = CheckCategory::Configuration;
                f.cwe_ids = vec!["CWE-798".into()];
                f
            },
            {
                let mut f = Finding::new("SQL Injection", Severity::Critical)
                    .with_description("Web application is vulnerable to SQL injection");
                f.category = CheckCategory::WebApp;
                f.cwe_ids = vec!["CWE-89".into()];
                f
            },
        ]
    }

    #[test]
    fn test_generate_report() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&sample_findings());

        let generator = HipaaReportGenerator::new("Test Hospital");
        let now = Utc::now();
        let report = generator.generate(&result, now - chrono::Duration::hours(2), now);

        assert_eq!(report.metadata.organization, "Test Hospital");
        assert!(!report.safeguard_details.is_empty());
        assert!(!report.hccra_details.is_empty());
        assert_eq!(report.hccra_details.len(), 7);
    }

    #[test]
    fn test_executive_summary_posture() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&sample_findings());
        let generator = HipaaReportGenerator::new("Test Clinic");
        let now = Utc::now();
        let report = generator.generate(&result, now, now);

        // With critical findings, posture should not be "Strong"
        assert_ne!(
            report.executive_summary.compliance_posture,
            CompliancePosture::Strong
        );
        assert!(report.executive_summary.critical_findings > 0);
    }

    #[test]
    fn test_scorecard_has_all_safeguards() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&sample_findings());
        let generator = HipaaReportGenerator::new("Test");
        let now = Utc::now();
        let report = generator.generate(&result, now, now);

        assert_eq!(report.scorecard.safeguard_scores.len(), 4);
    }

    #[test]
    fn test_remediation_plan_ordered_by_severity() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&sample_findings());
        let generator = HipaaReportGenerator::new("Test");
        let now = Utc::now();
        let report = generator.generate(&result, now, now);

        let plan = &report.remediation_plan;
        assert!(!plan.items.is_empty());
        // First items should be Critical
        if plan.items.len() >= 2 {
            assert!(plan.items[0].severity.as_number() >= plan.items[1].severity.as_number());
        }
    }

    #[test]
    fn test_render_executive_text() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&sample_findings());
        let generator = HipaaReportGenerator::new("Acme Health System");
        let now = Utc::now();
        let report = generator.generate(&result, now, now);

        let text = generator.render_executive_text(&report);
        assert!(text.contains("HIPAA SECURITY RULE COMPLIANCE"));
        assert!(text.contains("Acme Health System"));
        assert!(text.contains("SAFEGUARD"));
        assert!(text.contains("HCCRA"));
    }

    #[test]
    fn test_trend_calculation() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&[]);
        let generator = HipaaReportGenerator::new("Test").with_previous_score(80.0);
        let now = Utc::now();
        let report = generator.generate(&result, now, now);

        assert_eq!(report.scorecard.trend, Trend::Improving);
    }

    #[test]
    fn test_format_dollars() {
        assert_eq!(format_dollars(137), "137");
        assert_eq!(format_dollars(1_379), "1,379");
        assert_eq!(format_dollars(68_928), "68,928");
        assert_eq!(format_dollars(2_067_813), "2,067,813");
    }

    #[test]
    fn test_report_json_serialization() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&sample_findings());
        let generator = HipaaReportGenerator::new("Test");
        let now = Utc::now();
        let report = generator.generate(&result, now, now);

        let json = generator.to_json(&report);
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("executive_summary"));
        assert!(json_str.contains("scorecard"));
    }
}
