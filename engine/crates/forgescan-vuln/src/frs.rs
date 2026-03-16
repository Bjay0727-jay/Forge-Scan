//! Forge Risk Score (FRS) Calculator
//!
//! FRS is a proprietary risk scoring system that goes beyond CVSS to provide
//! context-aware risk prioritization based on:
//! - CVSS base score
//! - Exploit availability
//! - CISA KEV status
//! - Asset criticality
//! - Network exposure
//! - Threat intelligence

use serde::{Deserialize, Serialize};

/// Forge Risk Score calculator
pub struct FrsCalculator {
    /// Weight for CVSS score
    cvss_weight: f64,
    /// Weight for exploit availability
    exploit_weight: f64,
    /// Weight for KEV status
    kev_weight: f64,
    /// Weight for network exposure
    exposure_weight: f64,
    /// Weight for asset criticality
    criticality_weight: f64,
}

impl Default for FrsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrsCalculator {
    /// Create a new FRS calculator with default weights
    pub fn new() -> Self {
        Self {
            cvss_weight: 0.35,
            exploit_weight: 0.20,
            kev_weight: 0.20,
            exposure_weight: 0.15,
            criticality_weight: 0.10,
        }
    }

    /// Create calculator with custom weights
    pub fn with_weights(
        cvss: f64,
        exploit: f64,
        kev: f64,
        exposure: f64,
        criticality: f64,
    ) -> Self {
        // Normalize weights to sum to 1.0
        let total = cvss + exploit + kev + exposure + criticality;
        Self {
            cvss_weight: cvss / total,
            exploit_weight: exploit / total,
            kev_weight: kev / total,
            exposure_weight: exposure / total,
            criticality_weight: criticality / total,
        }
    }

    /// Calculate FRS score
    pub fn calculate(
        &self,
        cvss_score: f64,
        is_kev: bool,
        is_internet_facing: bool,
        has_exploit: bool,
        asset_criticality: f64,
    ) -> FrsScore {
        let factors = RiskFactors {
            cvss_score,
            is_kev,
            is_internet_facing,
            has_exploit,
            asset_criticality,
            threat_intel_score: 0.0,
            days_since_published: None,
            patch_available: true,
        };

        self.calculate_with_factors(&factors)
    }

    /// Calculate FRS score with full risk factors
    pub fn calculate_with_factors(&self, factors: &RiskFactors) -> FrsScore {
        // Normalize CVSS to 0-1 scale
        let cvss_normalized = factors.cvss_score / 10.0;

        // Exploit availability score (0 or 1)
        let exploit_score = if factors.has_exploit { 1.0 } else { 0.0 };

        // KEV score (0 or 1, with time decay for older KEVs)
        let kev_score = if factors.is_kev { 1.0 } else { 0.0 };

        // Exposure score based on network position
        let exposure_score = if factors.is_internet_facing { 1.0 } else { 0.3 };

        // Asset criticality (0-1 scale)
        let criticality_score = factors.asset_criticality.clamp(0.0, 1.0);

        // Calculate weighted score
        let raw_score = (cvss_normalized * self.cvss_weight)
            + (exploit_score * self.exploit_weight)
            + (kev_score * self.kev_weight)
            + (exposure_score * self.exposure_weight)
            + (criticality_score * self.criticality_weight);

        // Apply modifiers
        let mut modified_score = raw_score;

        // Boost for KEV + exploit combination
        if factors.is_kev && factors.has_exploit {
            modified_score *= 1.15;
        }

        // Boost for critical CVSS + internet facing
        if factors.cvss_score >= 9.0 && factors.is_internet_facing {
            modified_score *= 1.10;
        }

        // Slight reduction if patch is available
        if factors.patch_available {
            modified_score *= 0.95;
        }

        // Age penalty for very old vulnerabilities
        if let Some(days) = factors.days_since_published {
            if days > 365 * 2 {
                // More than 2 years old
                modified_score *= 0.90;
            }
        }

        // Scale to 0-100 and clamp
        let final_score = (modified_score * 100.0).clamp(0.0, 100.0);

        FrsScore {
            score: final_score,
            rating: FrsRating::from_score(final_score),
            factors: factors.clone(),
            breakdown: FrsBreakdown {
                cvss_contribution: cvss_normalized * self.cvss_weight * 100.0,
                exploit_contribution: exploit_score * self.exploit_weight * 100.0,
                kev_contribution: kev_score * self.kev_weight * 100.0,
                exposure_contribution: exposure_score * self.exposure_weight * 100.0,
                criticality_contribution: criticality_score * self.criticality_weight * 100.0,
            },
        }
    }
}

/// Forge Risk Score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrsScore {
    /// Numeric score (0-100)
    pub score: f64,
    /// Risk rating
    pub rating: FrsRating,
    /// Risk factors used in calculation
    pub factors: RiskFactors,
    /// Score breakdown by factor
    pub breakdown: FrsBreakdown,
}

impl FrsScore {
    /// Get a human-readable description of the risk
    pub fn description(&self) -> String {
        match self.rating {
            FrsRating::Critical => {
                "Immediate action required. High likelihood of active exploitation.".into()
            }
            FrsRating::High => {
                "Urgent remediation needed. Significant risk of exploitation.".into()
            }
            FrsRating::Medium => "Remediation recommended within 30 days.".into(),
            FrsRating::Low => "Address during regular maintenance cycles.".into(),
            FrsRating::Minimal => "Monitor only. Low risk to the environment.".into(),
        }
    }

    /// Get SLA deadline in days based on rating
    pub fn sla_days(&self) -> u32 {
        match self.rating {
            FrsRating::Critical => 1,
            FrsRating::High => 7,
            FrsRating::Medium => 30,
            FrsRating::Low => 90,
            FrsRating::Minimal => 180,
        }
    }
}

/// FRS risk rating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrsRating {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

impl FrsRating {
    /// Get rating from numeric score
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 90.0 => FrsRating::Critical,
            s if s >= 70.0 => FrsRating::High,
            s if s >= 40.0 => FrsRating::Medium,
            s if s >= 20.0 => FrsRating::Low,
            _ => FrsRating::Minimal,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            FrsRating::Critical => "CRITICAL",
            FrsRating::High => "HIGH",
            FrsRating::Medium => "MEDIUM",
            FrsRating::Low => "LOW",
            FrsRating::Minimal => "MINIMAL",
        }
    }
}

impl std::fmt::Display for FrsRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk factors for FRS calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    /// CVSS v3 base score (0-10)
    pub cvss_score: f64,
    /// Is in CISA KEV catalog
    pub is_kev: bool,
    /// Is the affected asset internet-facing
    pub is_internet_facing: bool,
    /// Is there a public exploit available
    pub has_exploit: bool,
    /// Asset criticality (0-1 scale)
    pub asset_criticality: f64,
    /// Threat intelligence score (0-1 scale)
    pub threat_intel_score: f64,
    /// Days since vulnerability was published
    pub days_since_published: Option<u32>,
    /// Is a patch available
    pub patch_available: bool,
}

impl Default for RiskFactors {
    fn default() -> Self {
        Self {
            cvss_score: 5.0,
            is_kev: false,
            is_internet_facing: false,
            has_exploit: false,
            asset_criticality: 0.5,
            threat_intel_score: 0.0,
            days_since_published: None,
            patch_available: true,
        }
    }
}

/// Score breakdown by contributing factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrsBreakdown {
    pub cvss_contribution: f64,
    pub exploit_contribution: f64,
    pub kev_contribution: f64,
    pub exposure_contribution: f64,
    pub criticality_contribution: f64,
}

/// Extended FRS calculator for medical/IoT devices
///
/// Augments the base FRS score with patient safety impact, regulatory context,
/// and device criticality factors specific to healthcare environments.
pub struct MedicalFrsCalculator {
    base: FrsCalculator,
}

impl Default for MedicalFrsCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl MedicalFrsCalculator {
    pub fn new() -> Self {
        Self {
            base: FrsCalculator::new(),
        }
    }

    pub fn with_base(base: FrsCalculator) -> Self {
        Self { base }
    }

    /// Calculate FRS with medical device context
    pub fn calculate_medical_frs(
        &self,
        factors: &RiskFactors,
        medical_factors: &MedicalRiskFactors,
    ) -> MedicalFrsScore {
        let base_score = self.base.calculate_with_factors(factors);
        let mut medical_score = base_score.score;

        // Patient impact multiplier (life-support devices get highest boost)
        medical_score *= medical_factors.patient_impact.risk_multiplier();

        // Regulatory violation boost
        if medical_factors.is_regulatory_violation {
            medical_score *= 1.15;
        }

        // Device is FDA Class III (highest risk category)
        if medical_factors.fda_class == forgescan_core::FdaDeviceClass::ClassIII {
            medical_score *= 1.10;
        }

        // No patch available for medical device (common with legacy equipment)
        if !medical_factors.patch_available {
            medical_score *= 1.10;
        }

        // Device has known FDA recall or safety alert
        if medical_factors.has_fda_recall {
            medical_score *= 1.20;
        }

        // Time-critical clinical workflow dependency
        if medical_factors.time_critical_workflow {
            medical_score *= 1.15;
        }

        medical_score = medical_score.clamp(0.0, 100.0);

        MedicalFrsScore {
            base_frs: base_score,
            medical_score,
            medical_rating: FrsRating::from_score(medical_score),
            medical_factors: medical_factors.clone(),
        }
    }
}

/// Medical-specific risk factors for FRS calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MedicalRiskFactors {
    /// Patient safety impact level
    pub patient_impact: forgescan_core::PatientImpact,
    /// FDA device classification
    pub fda_class: forgescan_core::FdaDeviceClass,
    /// Whether the finding constitutes a regulatory violation (HIPAA, FDA)
    pub is_regulatory_violation: bool,
    /// Whether a vendor patch is available for this device
    pub patch_available: bool,
    /// Whether the device has an active FDA recall or safety alert
    pub has_fda_recall: bool,
    /// Whether the device is part of a time-critical clinical workflow
    pub time_critical_workflow: bool,
    /// Clinical workflow context (e.g., "ICU ventilator", "OR imaging")
    pub workflow_context: Option<String>,
}

impl Default for MedicalRiskFactors {
    fn default() -> Self {
        Self {
            patient_impact: forgescan_core::PatientImpact::None,
            fda_class: forgescan_core::FdaDeviceClass::NotRegulated,
            is_regulatory_violation: false,
            patch_available: true,
            has_fda_recall: false,
            time_critical_workflow: false,
            workflow_context: None,
        }
    }
}

/// FRS score with medical device context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MedicalFrsScore {
    /// Base FRS score (standard IT risk)
    pub base_frs: FrsScore,
    /// Medical-adjusted score (0-100)
    pub medical_score: f64,
    /// Medical-adjusted rating
    pub medical_rating: FrsRating,
    /// Medical risk factors used
    pub medical_factors: MedicalRiskFactors,
}

impl MedicalFrsScore {
    /// Get SLA deadline adjusted for medical device context
    pub fn medical_sla_days(&self) -> u32 {
        let base_sla = self.medical_rating.sla_days();

        // Life-support devices get halved SLA deadlines
        if self.medical_factors.patient_impact.is_time_critical() {
            return (base_sla / 2).max(1);
        }

        // Direct patient care devices get 75% of standard SLA
        if self.medical_factors.patient_impact.is_direct_patient_care() {
            return (base_sla * 3 / 4).max(1);
        }

        base_sla
    }

    /// Human-readable description including medical context
    pub fn medical_description(&self) -> String {
        let base_desc = self.base_frs.description();
        let impact_desc = match self.medical_factors.patient_impact {
            forgescan_core::PatientImpact::LifeSupport => {
                " LIFE-CRITICAL: Device supports patient vital functions."
            }
            forgescan_core::PatientImpact::DirectCare => {
                " Patient care device: remediation requires clinical coordination."
            }
            forgescan_core::PatientImpact::Indirect => {
                " Healthcare operations impact: coordinate with clinical IT."
            }
            forgescan_core::PatientImpact::None => "",
        };
        format!("{}{}", base_desc, impact_desc)
    }
}

impl FrsRating {
    /// Get SLA deadline in days based on rating
    fn sla_days(&self) -> u32 {
        match self {
            FrsRating::Critical => 1,
            FrsRating::High => 7,
            FrsRating::Medium => 30,
            FrsRating::Low => 90,
            FrsRating::Minimal => 180,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frs_critical() {
        let calc = FrsCalculator::new();

        // High CVSS + KEV + exploit + internet facing + critical asset
        let score = calc.calculate(9.8, true, true, true, 1.0);

        assert!(score.score >= 90.0);
        assert_eq!(score.rating, FrsRating::Critical);
    }

    #[test]
    fn test_frs_low() {
        let calc = FrsCalculator::new();

        // Low CVSS + no KEV + no exploit + internal + low criticality
        let score = calc.calculate(3.0, false, false, false, 0.2);

        assert!(score.score < 40.0);
        assert!(matches!(score.rating, FrsRating::Low | FrsRating::Minimal));
    }

    #[test]
    fn test_frs_kev_boost() {
        let calc = FrsCalculator::new();

        let without_kev = calc.calculate(7.5, false, true, false, 0.5);
        let with_kev = calc.calculate(7.5, true, true, false, 0.5);

        assert!(with_kev.score > without_kev.score);
    }

    #[test]
    fn test_sla_days() {
        assert_eq!(
            FrsScore {
                score: 95.0,
                rating: FrsRating::Critical,
                factors: RiskFactors::default(),
                breakdown: FrsBreakdown {
                    cvss_contribution: 0.0,
                    exploit_contribution: 0.0,
                    kev_contribution: 0.0,
                    exposure_contribution: 0.0,
                    criticality_contribution: 0.0,
                },
            }
            .sla_days(),
            1
        );
    }

    #[test]
    fn test_medical_frs_life_support_boost() {
        let calc = MedicalFrsCalculator::new();

        let factors = RiskFactors {
            cvss_score: 7.5,
            is_kev: false,
            is_internet_facing: false,
            has_exploit: false,
            asset_criticality: 0.5,
            threat_intel_score: 0.0,
            days_since_published: None,
            patch_available: true,
        };

        let normal_factors = MedicalRiskFactors::default();
        let life_support_factors = MedicalRiskFactors {
            patient_impact: forgescan_core::PatientImpact::LifeSupport,
            fda_class: forgescan_core::FdaDeviceClass::ClassIII,
            time_critical_workflow: true,
            ..Default::default()
        };

        let normal_score = calc.calculate_medical_frs(&factors, &normal_factors);
        let life_support_score = calc.calculate_medical_frs(&factors, &life_support_factors);

        // Life support should score significantly higher
        assert!(life_support_score.medical_score > normal_score.medical_score);
    }

    #[test]
    fn test_medical_frs_fda_recall_boost() {
        let calc = MedicalFrsCalculator::new();

        let factors = RiskFactors {
            cvss_score: 6.0,
            ..Default::default()
        };

        let no_recall = MedicalRiskFactors::default();
        let with_recall = MedicalRiskFactors {
            has_fda_recall: true,
            ..Default::default()
        };

        let score_no_recall = calc.calculate_medical_frs(&factors, &no_recall);
        let score_with_recall = calc.calculate_medical_frs(&factors, &with_recall);

        assert!(score_with_recall.medical_score > score_no_recall.medical_score);
    }

    #[test]
    fn test_medical_sla_reduction() {
        let calc = MedicalFrsCalculator::new();

        let factors = RiskFactors {
            cvss_score: 9.0,
            is_kev: true,
            is_internet_facing: true,
            has_exploit: true,
            asset_criticality: 0.9,
            ..Default::default()
        };

        let life_support = MedicalRiskFactors {
            patient_impact: forgescan_core::PatientImpact::LifeSupport,
            fda_class: forgescan_core::FdaDeviceClass::ClassIII,
            ..Default::default()
        };

        let score = calc.calculate_medical_frs(&factors, &life_support);
        // Life-support critical finding: SLA should be at most 1 day
        assert!(score.medical_sla_days() <= 1);
    }
}
