//! Severity levels and check categories

use serde::{Deserialize, Serialize};

/// Severity level for findings
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding, no security impact
    #[default]
    Info,
    /// Low severity, minimal risk
    Low,
    /// Medium severity, moderate risk
    Medium,
    /// High severity, significant risk
    High,
    /// Critical severity, immediate action required
    Critical,
}

impl Severity {
    /// Convert CVSS 3.x score to severity
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s >= 0.1 => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Get numeric value for sorting/comparison
    pub fn as_number(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Get display string
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Category of vulnerability check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckCategory {
    /// Network discovery (host, port, service detection)
    Network,
    /// Vulnerability detection (CVE matching, version checks)
    Vulnerability,
    /// Configuration auditing (CIS, STIG, compliance)
    Configuration,
    /// Web application security (OWASP Top 10)
    WebApp,
    /// Cloud misconfiguration (AWS, Azure, GCP)
    Cloud,
    /// IoT/IoMT device security (medical devices, industrial protocols)
    #[serde(alias = "iot", alias = "iomt")]
    IoMT,
}

impl CheckCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckCategory::Network => "network",
            CheckCategory::Vulnerability => "vulnerability",
            CheckCategory::Configuration => "configuration",
            CheckCategory::WebApp => "webapp",
            CheckCategory::Cloud => "cloud",
            CheckCategory::IoMT => "iomt",
        }
    }
}

impl std::fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Medical/IoT device classification for risk scoring and safe-scan decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    /// Not a medical/IoT device or classification unknown
    Unknown,
    /// Medical imaging systems (PACS, CT, MRI, ultrasound, X-ray)
    MedicalImaging,
    /// Patient vital sign monitors (ECG, BP, SpO2)
    PatientMonitor,
    /// Drug delivery systems (infusion pumps)
    InfusionPump,
    /// Respiratory support (ventilators, CPAP)
    Ventilator,
    /// Clinical laboratory analyzers
    ClinicalAnalyzer,
    /// HL7/FHIR integration engines and message routers
    HL7Router,
    /// DICOM servers and PACS storage
    DICOMServer,
    /// Electronic Health Record systems
    EHRSystem,
    /// Building automation (HVAC, access control) in healthcare facilities
    BuildingAutomation,
    /// Industrial control (pharmacy automation, sterilization)
    IndustrialControl,
    /// Generic IoT device (non-medical)
    GenericIoT,
}

impl DeviceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceClass::Unknown => "unknown",
            DeviceClass::MedicalImaging => "medical_imaging",
            DeviceClass::PatientMonitor => "patient_monitor",
            DeviceClass::InfusionPump => "infusion_pump",
            DeviceClass::Ventilator => "ventilator",
            DeviceClass::ClinicalAnalyzer => "clinical_analyzer",
            DeviceClass::HL7Router => "hl7_router",
            DeviceClass::DICOMServer => "dicom_server",
            DeviceClass::EHRSystem => "ehr_system",
            DeviceClass::BuildingAutomation => "building_automation",
            DeviceClass::IndustrialControl => "industrial_control",
            DeviceClass::GenericIoT => "generic_iot",
        }
    }

    /// Whether this device class is life-critical (requires safe-scan mode)
    pub fn is_life_critical(&self) -> bool {
        matches!(
            self,
            DeviceClass::Ventilator | DeviceClass::InfusionPump | DeviceClass::PatientMonitor
        )
    }

    /// Whether this device class involves direct patient care
    pub fn is_patient_care(&self) -> bool {
        matches!(
            self,
            DeviceClass::Ventilator
                | DeviceClass::InfusionPump
                | DeviceClass::PatientMonitor
                | DeviceClass::MedicalImaging
                | DeviceClass::ClinicalAnalyzer
        )
    }
}

impl std::fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Patient safety impact level for IoMT risk scoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatientImpact {
    /// No direct patient impact
    None,
    /// Indirect impact (hospital operations, scheduling)
    Indirect,
    /// Direct patient care impact (diagnostics, treatment)
    DirectCare,
    /// Life-sustaining device (ventilator, infusion pump in critical care)
    LifeSupport,
}

impl PatientImpact {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatientImpact::None => "none",
            PatientImpact::Indirect => "indirect",
            PatientImpact::DirectCare => "direct_care",
            PatientImpact::LifeSupport => "life_support",
        }
    }

    /// Whether this impact level involves direct patient care
    pub fn is_direct_patient_care(&self) -> bool {
        matches!(self, PatientImpact::DirectCare | PatientImpact::LifeSupport)
    }

    /// Whether this impact level is time-critical
    pub fn is_time_critical(&self) -> bool {
        matches!(self, PatientImpact::LifeSupport)
    }

    /// Risk multiplier for FRS scoring
    pub fn risk_multiplier(&self) -> f64 {
        match self {
            PatientImpact::None => 1.0,
            PatientImpact::Indirect => 1.1,
            PatientImpact::DirectCare => 1.3,
            PatientImpact::LifeSupport => 1.5,
        }
    }
}

impl std::fmt::Display for PatientImpact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// FDA device classification for regulatory context
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FdaDeviceClass {
    /// Class I: Lowest risk (tongue depressors, bandages)
    ClassI,
    /// Class II: Moderate risk (powered wheelchairs, infusion pumps)
    ClassII,
    /// Class III: Highest risk (pacemakers, ventilators)
    ClassIII,
    /// Not FDA-regulated
    NotRegulated,
}

impl FdaDeviceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            FdaDeviceClass::ClassI => "class_i",
            FdaDeviceClass::ClassII => "class_ii",
            FdaDeviceClass::ClassIII => "class_iii",
            FdaDeviceClass::NotRegulated => "not_regulated",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_to_severity() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
