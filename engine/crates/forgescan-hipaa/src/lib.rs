//! ForgeScan HIPAA — Native HIPAA Compliance Mapping Engine
//!
//! Provides automated mapping between scan findings and HIPAA Security Rule
//! requirements, including:
//!
//! - **Auto-mapping** of every vulnerability finding to the relevant HIPAA
//!   technical safeguard (Access Control, Audit Controls, Integrity,
//!   Transmission Security)
//! - **HCCRA compliance** mapping to the 7 mandatory controls from the
//!   Health Care Cybersecurity and Resiliency Act of 2025
//! - **Board-ready executive summaries** with HIPAA compliance scorecards
//! - **Bidirectional ForgeComply 360 integration** for continuous compliance
//!   evidence collection

pub mod fc360;
pub mod hccra;
pub mod mapper;
pub mod pdf;
pub mod report;
pub mod safeguards;

pub use fc360::{ComplianceEvidence, EvidenceType, Fc360Client, Fc360Config};
pub use hccra::{ComplianceStatus, HccraControl, HccraControlStatus};
pub use mapper::{HipaaComplianceResult, HipaaMapper, HipaaMapping};
pub use report::{
    CompliancePosture, ComplianceScorecard, ExecutiveSummary, HipaaReport, HipaaReportGenerator,
};
pub use safeguards::{ImplementationSpec, RequirementType, TechnicalSafeguard};
