//! HIPAA Compliance Auto-Mapping Engine
//!
//! Automatically maps scan findings to relevant HIPAA technical safeguards
//! and HCCRA mandatory controls based on finding category, CWE IDs,
//! vulnerability type, and service context.

use crate::hccra::{ComplianceStatus, HccraControl, HccraControlStatus};
use crate::safeguards::TechnicalSafeguard;
use forgescan_core::{CheckCategory, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A mapping from a finding to one or more HIPAA safeguards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaMapping {
    /// The finding ID
    pub finding_id: uuid::Uuid,
    /// Finding title (for readability)
    pub finding_title: String,
    /// Finding severity
    pub severity: Severity,
    /// Mapped HIPAA technical safeguards
    pub safeguards: Vec<TechnicalSafeguard>,
    /// Mapped HCCRA controls
    pub hccra_controls: Vec<HccraControl>,
    /// Implementation specifications impacted
    pub impacted_specs: Vec<String>,
    /// Rationale for the mapping
    pub rationale: String,
}

/// Result of mapping a complete scan to HIPAA compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaComplianceResult {
    /// Individual finding-to-safeguard mappings
    pub mappings: Vec<HipaaMapping>,
    /// Safeguard-level compliance summary
    pub safeguard_summary: HashMap<String, SafeguardStatus>,
    /// HCCRA control compliance statuses
    pub hccra_statuses: Vec<HccraControlStatus>,
    /// Overall compliance score (0-100)
    pub overall_score: f64,
    /// Assessment timestamp
    pub assessed_at: chrono::DateTime<chrono::Utc>,
}

/// Status for a single HIPAA safeguard based on findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeguardStatus {
    /// The safeguard
    pub safeguard: TechnicalSafeguard,
    /// Compliance status
    pub status: ComplianceStatus,
    /// Total findings mapped to this safeguard
    pub total_findings: u32,
    /// Critical findings
    pub critical_count: u32,
    /// High findings
    pub high_count: u32,
    /// Medium findings
    pub medium_count: u32,
    /// Low/Info findings
    pub low_info_count: u32,
    /// Compliance score for this safeguard (0-100)
    pub score: f64,
}

/// The HIPAA compliance mapping engine
pub struct HipaaMapper {
    /// CWE to safeguard mappings
    cwe_safeguard_map: HashMap<String, Vec<TechnicalSafeguard>>,
    /// CWE to HCCRA control mappings
    cwe_hccra_map: HashMap<String, Vec<HccraControl>>,
}

impl Default for HipaaMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl HipaaMapper {
    /// Create a new HIPAA mapper with built-in mapping rules
    pub fn new() -> Self {
        let mut mapper = Self {
            cwe_safeguard_map: HashMap::new(),
            cwe_hccra_map: HashMap::new(),
        };
        mapper.load_cwe_mappings();
        mapper
    }

    /// Map a collection of findings to HIPAA compliance results
    pub fn map_findings(&self, findings: &[Finding]) -> HipaaComplianceResult {
        let mut mappings = Vec::new();
        let mut safeguard_counts: HashMap<TechnicalSafeguard, SafeguardCounts> = HashMap::new();
        let mut hccra_counts: HashMap<HccraControl, HccraCounts> = HashMap::new();

        // Initialize counts for all safeguards and controls
        for sg in TechnicalSafeguard::all() {
            safeguard_counts.insert(*sg, SafeguardCounts::default());
        }
        for ctrl in HccraControl::all() {
            hccra_counts.insert(*ctrl, HccraCounts::default());
        }

        for finding in findings {
            let mapping = self.map_single_finding(finding);

            // Accumulate safeguard counts
            for sg in &mapping.safeguards {
                let counts = safeguard_counts.entry(*sg).or_default();
                counts.total += 1;
                match finding.severity {
                    Severity::Critical => counts.critical += 1,
                    Severity::High => counts.high += 1,
                    Severity::Medium => counts.medium += 1,
                    _ => counts.low_info += 1,
                }
            }

            // Accumulate HCCRA counts
            for ctrl in &mapping.hccra_controls {
                let counts = hccra_counts.entry(*ctrl).or_default();
                counts.total += 1;
                if matches!(finding.severity, Severity::Critical | Severity::High) {
                    counts.critical_high += 1;
                }
            }

            mappings.push(mapping);
        }

        // Build safeguard summary
        let safeguard_summary = safeguard_counts
            .into_iter()
            .map(|(sg, counts)| {
                let score = Self::calculate_safeguard_score(&counts);
                let status = Self::determine_compliance_status(&counts);
                (
                    sg.name().to_string(),
                    SafeguardStatus {
                        safeguard: sg,
                        status,
                        total_findings: counts.total,
                        critical_count: counts.critical,
                        high_count: counts.high,
                        medium_count: counts.medium,
                        low_info_count: counts.low_info,
                        score,
                    },
                )
            })
            .collect();

        // Build HCCRA statuses
        let hccra_statuses = hccra_counts
            .into_iter()
            .map(|(ctrl, counts)| HccraControlStatus {
                control: ctrl,
                status: if counts.critical_high > 0 {
                    ComplianceStatus::NonCompliant
                } else if counts.total > 0 {
                    ComplianceStatus::PartiallyCompliant
                } else {
                    ComplianceStatus::Compliant
                },
                finding_count: counts.total,
                critical_high_count: counts.critical_high,
                evidence: Vec::new(),
                recommendations: Self::generate_recommendations(ctrl, counts.total),
            })
            .collect();

        // Calculate overall score
        let overall_score = Self::calculate_overall_score(&safeguard_summary);

        HipaaComplianceResult {
            mappings,
            safeguard_summary,
            hccra_statuses,
            overall_score,
            assessed_at: chrono::Utc::now(),
        }
    }

    /// Map a single finding to HIPAA safeguards and HCCRA controls
    fn map_single_finding(&self, finding: &Finding) -> HipaaMapping {
        let mut safeguards = Vec::new();
        let mut hccra_controls = Vec::new();
        let mut impacted_specs = Vec::new();
        let mut rationale_parts = Vec::new();

        // 1. Map by CWE IDs (most precise)
        for cwe in &finding.cwe_ids {
            if let Some(sgs) = self.cwe_safeguard_map.get(cwe) {
                for sg in sgs {
                    if !safeguards.contains(sg) {
                        safeguards.push(*sg);
                    }
                }
                rationale_parts.push(format!("{} maps to HIPAA technical safeguards", cwe));
            }
            if let Some(ctrls) = self.cwe_hccra_map.get(cwe) {
                for ctrl in ctrls {
                    if !hccra_controls.contains(ctrl) {
                        hccra_controls.push(*ctrl);
                    }
                }
            }
        }

        // 2. Map by finding category (broader fallback)
        let category_safeguards = self.map_by_category(finding.category);
        for sg in &category_safeguards {
            if !safeguards.contains(sg) {
                safeguards.push(*sg);
            }
        }

        let category_hccra = self.map_category_to_hccra(finding.category);
        for ctrl in &category_hccra {
            if !hccra_controls.contains(ctrl) {
                hccra_controls.push(*ctrl);
            }
        }

        if !category_safeguards.is_empty() {
            rationale_parts.push(format!(
                "Category '{}' implies HIPAA safeguard relevance",
                finding.category
            ));
        }

        // 3. Map by title/description keyword analysis
        let keyword_mappings = self.map_by_keywords(&finding.title, &finding.description);
        for (sg, reason) in &keyword_mappings.safeguard_reasons {
            if !safeguards.contains(sg) {
                safeguards.push(*sg);
                rationale_parts.push(reason.clone());
            }
        }
        for ctrl in &keyword_mappings.hccra {
            if !hccra_controls.contains(ctrl) {
                hccra_controls.push(*ctrl);
            }
        }

        // 4. Derive impacted implementation specifications
        for sg in &safeguards {
            impacted_specs.extend(self.impacted_impl_specs(sg, finding));
        }

        // Default: if nothing mapped, at least map to Integrity (catch-all for vulns)
        if safeguards.is_empty() {
            safeguards.push(TechnicalSafeguard::Integrity);
            rationale_parts.push("Default mapping: vulnerabilities impact ePHI integrity".into());
        }
        if hccra_controls.is_empty() {
            hccra_controls.push(HccraControl::VulnerabilityManagement);
        }

        let rationale = if rationale_parts.is_empty() {
            "Mapped by default vulnerability-to-integrity rule".into()
        } else {
            rationale_parts.join("; ")
        };

        HipaaMapping {
            finding_id: finding.id,
            finding_title: finding.title.clone(),
            severity: finding.severity,
            safeguards,
            hccra_controls,
            impacted_specs,
            rationale,
        }
    }

    /// Map finding category to HIPAA technical safeguards
    fn map_by_category(&self, category: CheckCategory) -> Vec<TechnicalSafeguard> {
        match category {
            CheckCategory::Network => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::TransmissionSecurity,
            ],
            CheckCategory::Vulnerability => vec![
                TechnicalSafeguard::Integrity,
                TechnicalSafeguard::AccessControl,
            ],
            CheckCategory::Configuration => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::AuditControls,
            ],
            CheckCategory::WebApp => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::Integrity,
                TechnicalSafeguard::TransmissionSecurity,
            ],
            CheckCategory::Cloud => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::AuditControls,
                TechnicalSafeguard::TransmissionSecurity,
            ],
            CheckCategory::IoMT => vec![
                TechnicalSafeguard::AccessControl,
                TechnicalSafeguard::Integrity,
                TechnicalSafeguard::TransmissionSecurity,
            ],
        }
    }

    /// Map finding category to HCCRA controls
    fn map_category_to_hccra(&self, category: CheckCategory) -> Vec<HccraControl> {
        match category {
            CheckCategory::Network => vec![
                HccraControl::NetworkSegmentation,
                HccraControl::AuditLogging,
            ],
            CheckCategory::Vulnerability => vec![HccraControl::VulnerabilityManagement],
            CheckCategory::Configuration => {
                vec![HccraControl::MultiFactorAuth, HccraControl::AuditLogging]
            }
            CheckCategory::WebApp => vec![
                HccraControl::VulnerabilityManagement,
                HccraControl::Encryption,
            ],
            CheckCategory::Cloud => vec![
                HccraControl::Encryption,
                HccraControl::MultiFactorAuth,
                HccraControl::SupplyChainRisk,
            ],
            CheckCategory::IoMT => vec![
                HccraControl::NetworkSegmentation,
                HccraControl::VulnerabilityManagement,
                HccraControl::SupplyChainRisk,
            ],
        }
    }

    /// Keyword-based mapping for additional precision
    fn map_by_keywords(&self, title: &str, description: &str) -> KeywordMappingResult {
        let combined = format!("{} {}", title, description).to_lowercase();
        let mut result = KeywordMappingResult::default();

        // Encryption-related
        if combined.contains("ssl")
            || combined.contains("tls")
            || combined.contains("encrypt")
            || combined.contains("cleartext")
            || combined.contains("plaintext")
            || combined.contains("unencrypted")
        {
            result.safeguard_reasons.push((
                TechnicalSafeguard::TransmissionSecurity,
                "Finding relates to encryption/transmission security".into(),
            ));
            result.hccra.push(HccraControl::Encryption);
        }

        // Authentication-related
        if combined.contains("auth")
            || combined.contains("password")
            || combined.contains("credential")
            || combined.contains("login")
            || combined.contains("session")
            || combined.contains("mfa")
            || combined.contains("multi-factor")
        {
            result.safeguard_reasons.push((
                TechnicalSafeguard::AccessControl,
                "Finding relates to authentication/access control".into(),
            ));
            result.hccra.push(HccraControl::MultiFactorAuth);
        }

        // Audit/logging-related
        if combined.contains("audit")
            || combined.contains("log")
            || combined.contains("monitor")
            || combined.contains("tracking")
        {
            result.safeguard_reasons.push((
                TechnicalSafeguard::AuditControls,
                "Finding relates to audit logging/monitoring".into(),
            ));
            result.hccra.push(HccraControl::AuditLogging);
        }

        // Integrity-related
        if combined.contains("injection")
            || combined.contains("tamper")
            || combined.contains("integrity")
            || combined.contains("corrupt")
            || combined.contains("modif")
        {
            result.safeguard_reasons.push((
                TechnicalSafeguard::Integrity,
                "Finding relates to data integrity".into(),
            ));
        }

        // Network segmentation
        if combined.contains("segment")
            || combined.contains("firewall")
            || combined.contains("network exposure")
            || combined.contains("lateral movement")
        {
            result.hccra.push(HccraControl::NetworkSegmentation);
        }

        // Supply chain
        if combined.contains("supply chain")
            || combined.contains("third-party")
            || combined.contains("vendor")
            || combined.contains("dependency")
            || combined.contains("library")
        {
            result.hccra.push(HccraControl::SupplyChainRisk);
        }

        result
    }

    /// Determine which implementation specifications are impacted
    fn impacted_impl_specs(
        &self,
        safeguard: &TechnicalSafeguard,
        finding: &Finding,
    ) -> Vec<String> {
        let combined = format!("{} {}", finding.title, finding.description).to_lowercase();

        match safeguard {
            TechnicalSafeguard::AccessControl => {
                let mut specs = Vec::new();
                if combined.contains("user") || combined.contains("identity") {
                    specs.push("AC-1: Unique User Identification".into());
                }
                if combined.contains("session") || combined.contains("timeout") {
                    specs.push("AC-3: Automatic Logoff".into());
                }
                if combined.contains("encrypt") || combined.contains("decrypt") {
                    specs.push("AC-4: Encryption and Decryption".into());
                }
                specs
            }
            TechnicalSafeguard::AuditControls => {
                vec!["AU-1: Audit Controls".into()]
            }
            TechnicalSafeguard::Integrity => {
                vec!["IN-1: Mechanism to Authenticate ePHI".into()]
            }
            TechnicalSafeguard::TransmissionSecurity => {
                let mut specs = Vec::new();
                if combined.contains("integrity")
                    || combined.contains("tamper")
                    || combined.contains("modif")
                {
                    specs.push("TS-1: Integrity Controls".into());
                }
                if combined.contains("encrypt")
                    || combined.contains("ssl")
                    || combined.contains("tls")
                    || combined.contains("cleartext")
                {
                    specs.push("TS-2: Encryption".into());
                }
                if specs.is_empty() {
                    specs.push("TS-2: Encryption".into());
                }
                specs
            }
        }
    }

    /// Calculate compliance score for a safeguard (100 = fully compliant)
    fn calculate_safeguard_score(counts: &SafeguardCounts) -> f64 {
        if counts.total == 0 {
            return 100.0;
        }
        // Weighted penalty: critical=25, high=15, medium=5, low/info=1
        let penalty = (counts.critical as f64 * 25.0)
            + (counts.high as f64 * 15.0)
            + (counts.medium as f64 * 5.0)
            + (counts.low_info as f64 * 1.0);
        (100.0 - penalty).max(0.0)
    }

    /// Determine compliance status from counts
    fn determine_compliance_status(counts: &SafeguardCounts) -> ComplianceStatus {
        if counts.total == 0 {
            ComplianceStatus::Compliant
        } else if counts.critical > 0 || counts.high > 0 {
            ComplianceStatus::NonCompliant
        } else {
            ComplianceStatus::PartiallyCompliant
        }
    }

    /// Calculate overall HIPAA compliance score from all safeguards
    fn calculate_overall_score(summary: &HashMap<String, SafeguardStatus>) -> f64 {
        if summary.is_empty() {
            return 100.0;
        }
        let total: f64 = summary.values().map(|s| s.score).sum();
        total / summary.len() as f64
    }

    /// Generate recommendations for an HCCRA control based on finding count
    fn generate_recommendations(control: HccraControl, finding_count: u32) -> Vec<String> {
        if finding_count == 0 {
            return vec![];
        }
        match control {
            HccraControl::MultiFactorAuth => vec![
                "Implement MFA for all remote access to ePHI systems".into(),
                "Review and enforce authentication policies for privileged accounts".into(),
            ],
            HccraControl::Encryption => vec![
                "Encrypt ePHI at rest using AES-256 or equivalent".into(),
                "Enforce TLS 1.2+ for all ePHI transmissions".into(),
                "Disable deprecated cipher suites and protocols".into(),
            ],
            HccraControl::NetworkSegmentation => vec![
                "Segment ePHI systems into dedicated VLANs".into(),
                "Implement micro-segmentation for medical device networks".into(),
                "Review firewall rules between network zones".into(),
            ],
            HccraControl::VulnerabilityManagement => vec![
                "Apply critical patches within 30 days per HCCRA mandate".into(),
                "Conduct vulnerability assessments at least every 6 months".into(),
                "Implement compensating controls for unpatchable medical devices".into(),
            ],
            HccraControl::IncidentResponse => vec![
                "Update incident response plan to include findings from this scan".into(),
                "Test incident response procedures within 30 days".into(),
            ],
            HccraControl::AuditLogging => vec![
                "Ensure audit logging is enabled on all ePHI systems".into(),
                "Implement centralized log collection (SIEM)".into(),
                "Verify 6-year log retention policy compliance".into(),
            ],
            HccraControl::SupplyChainRisk => vec![
                "Assess third-party vendor security posture for identified services".into(),
                "Review Business Associate Agreements for cybersecurity requirements".into(),
            ],
        }
    }

    /// Load CWE-to-safeguard mapping rules
    fn load_cwe_mappings(&mut self) {
        // --- Access Control ---
        // Broken authentication / authorization
        for cwe in [
            "CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-284", "CWE-269", "CWE-798", "CWE-521",
            "CWE-620", "CWE-307", "CWE-308", "CWE-384", "CWE-613",
        ] {
            self.cwe_safeguard_map
                .entry(cwe.into())
                .or_default()
                .push(TechnicalSafeguard::AccessControl);
            self.cwe_hccra_map
                .entry(cwe.into())
                .or_default()
                .push(HccraControl::MultiFactorAuth);
        }

        // --- Transmission Security ---
        // Cryptographic issues
        for cwe in [
            "CWE-311", "CWE-319", "CWE-326", "CWE-327", "CWE-328", "CWE-757", "CWE-295", "CWE-297",
            "CWE-523",
        ] {
            self.cwe_safeguard_map
                .entry(cwe.into())
                .or_default()
                .push(TechnicalSafeguard::TransmissionSecurity);
            self.cwe_hccra_map
                .entry(cwe.into())
                .or_default()
                .push(HccraControl::Encryption);
        }

        // --- Integrity ---
        // Injection / data tampering
        for cwe in [
            "CWE-89", "CWE-79", "CWE-94", "CWE-78", "CWE-77", "CWE-352", "CWE-434", "CWE-502",
            "CWE-611", "CWE-918",
        ] {
            self.cwe_safeguard_map
                .entry(cwe.into())
                .or_default()
                .push(TechnicalSafeguard::Integrity);
            self.cwe_hccra_map
                .entry(cwe.into())
                .or_default()
                .push(HccraControl::VulnerabilityManagement);
        }

        // --- Audit Controls ---
        // Logging / information exposure
        for cwe in ["CWE-778", "CWE-223", "CWE-532", "CWE-209", "CWE-200"] {
            self.cwe_safeguard_map
                .entry(cwe.into())
                .or_default()
                .push(TechnicalSafeguard::AuditControls);
            self.cwe_hccra_map
                .entry(cwe.into())
                .or_default()
                .push(HccraControl::AuditLogging);
        }
    }
}

#[derive(Default)]
struct SafeguardCounts {
    total: u32,
    critical: u32,
    high: u32,
    medium: u32,
    low_info: u32,
}

#[derive(Default)]
struct HccraCounts {
    total: u32,
    critical_high: u32,
}

#[derive(Default)]
struct KeywordMappingResult {
    safeguard_reasons: Vec<(TechnicalSafeguard, String)>,
    hccra: Vec<HccraControl>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgescan_core::Finding;

    #[test]
    fn test_map_ssl_finding() {
        let mapper = HipaaMapper::new();
        let finding = Finding::new("Weak SSL/TLS Configuration", Severity::High)
            .with_description("Server supports TLS 1.0 which is deprecated");

        let result = mapper.map_findings(&[finding]);
        assert!(!result.mappings.is_empty());

        let mapping = &result.mappings[0];
        assert!(mapping
            .safeguards
            .contains(&TechnicalSafeguard::TransmissionSecurity));
        assert!(mapping.hccra_controls.contains(&HccraControl::Encryption));
    }

    #[test]
    fn test_map_auth_finding() {
        let mapper = HipaaMapper::new();
        let mut finding = Finding::new("Default Credentials Detected", Severity::Critical)
            .with_description("Service accepts default username and password");
        finding.cwe_ids = vec!["CWE-798".into()];

        let result = mapper.map_findings(&[finding]);
        let mapping = &result.mappings[0];
        assert!(mapping
            .safeguards
            .contains(&TechnicalSafeguard::AccessControl));
        assert!(mapping
            .hccra_controls
            .contains(&HccraControl::MultiFactorAuth));
    }

    #[test]
    fn test_map_injection_finding() {
        let mapper = HipaaMapper::new();
        let mut finding = Finding::new("SQL Injection Vulnerability", Severity::Critical)
            .with_description("Application is vulnerable to SQL injection attacks");
        finding.category = CheckCategory::WebApp;
        finding.cwe_ids = vec!["CWE-89".into()];

        let result = mapper.map_findings(&[finding]);
        let mapping = &result.mappings[0];
        assert!(mapping.safeguards.contains(&TechnicalSafeguard::Integrity));
        assert!(mapping
            .hccra_controls
            .contains(&HccraControl::VulnerabilityManagement));
    }

    #[test]
    fn test_compliance_score_no_findings() {
        let mapper = HipaaMapper::new();
        let result = mapper.map_findings(&[]);
        assert_eq!(result.overall_score, 100.0);
    }

    #[test]
    fn test_critical_finding_non_compliant() {
        let mapper = HipaaMapper::new();
        let finding = Finding::new("Critical Vulnerability", Severity::Critical);
        let result = mapper.map_findings(&[finding]);

        // At least one safeguard should be non-compliant
        assert!(result
            .safeguard_summary
            .values()
            .any(|s| s.status == ComplianceStatus::NonCompliant));
    }

    #[test]
    fn test_hccra_recommendations_generated() {
        let mapper = HipaaMapper::new();
        let finding = Finding::new("Unpatched Service", Severity::High)
            .with_description("Service has known vulnerability");
        let result = mapper.map_findings(&[finding]);

        let vuln_mgmt = result
            .hccra_statuses
            .iter()
            .find(|s| s.control == HccraControl::VulnerabilityManagement);
        assert!(vuln_mgmt.is_some());
        if vuln_mgmt.unwrap().finding_count > 0 {
            assert!(!vuln_mgmt.unwrap().recommendations.is_empty());
        }
    }

    #[test]
    fn test_all_categories_produce_mappings() {
        let mapper = HipaaMapper::new();
        let categories = [
            CheckCategory::Network,
            CheckCategory::Vulnerability,
            CheckCategory::Configuration,
            CheckCategory::WebApp,
            CheckCategory::Cloud,
            CheckCategory::IoMT,
        ];
        for cat in categories {
            let mut finding = Finding::new("Test Finding", Severity::Medium);
            finding.category = cat;
            let result = mapper.map_findings(&[finding]);
            assert!(
                !result.mappings[0].safeguards.is_empty(),
                "Category {:?} produced no safeguard mappings",
                cat
            );
        }
    }
}
