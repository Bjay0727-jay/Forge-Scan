//! HIPAA Security Rule Technical Safeguard definitions
//!
//! Maps to 45 CFR Part 164, Subpart C — the four technical safeguard standards
//! and their implementation specifications.

use serde::{Deserialize, Serialize};

/// HIPAA Security Rule Technical Safeguard standard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TechnicalSafeguard {
    /// §164.312(a) — Access Control
    /// Implement technical policies to allow access only to authorized persons.
    AccessControl,
    /// §164.312(b) — Audit Controls
    /// Implement mechanisms to record and examine activity in systems containing ePHI.
    AuditControls,
    /// §164.312(c)(1) — Integrity
    /// Implement policies to protect ePHI from improper alteration or destruction.
    Integrity,
    /// §164.312(e)(1) — Transmission Security
    /// Implement measures to guard against unauthorized access to ePHI during transmission.
    TransmissionSecurity,
}

impl TechnicalSafeguard {
    /// CFR citation for this safeguard
    pub fn cfr_citation(&self) -> &'static str {
        match self {
            Self::AccessControl => "§164.312(a)",
            Self::AuditControls => "§164.312(b)",
            Self::Integrity => "§164.312(c)(1)",
            Self::TransmissionSecurity => "§164.312(e)(1)",
        }
    }

    /// Human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::AccessControl => "Access Control",
            Self::AuditControls => "Audit Controls",
            Self::Integrity => "Integrity",
            Self::TransmissionSecurity => "Transmission Security",
        }
    }

    /// Full regulatory description
    pub fn description(&self) -> &'static str {
        match self {
            Self::AccessControl => {
                "Implement technical policies and procedures for electronic information \
                 systems that maintain electronic protected health information to allow \
                 access only to those persons or software programs that have been \
                 granted access rights as specified in §164.308(a)(4)."
            }
            Self::AuditControls => {
                "Implement hardware, software, and/or procedural mechanisms that record \
                 and examine activity in information systems that contain or use \
                 electronic protected health information."
            }
            Self::Integrity => {
                "Implement policies and procedures to protect electronic protected health \
                 information from improper alteration or destruction."
            }
            Self::TransmissionSecurity => {
                "Implement technical security measures to guard against unauthorized \
                 access to electronic protected health information that is being \
                 transmitted over an electronic communications network."
            }
        }
    }

    /// All safeguards
    pub fn all() -> &'static [TechnicalSafeguard] {
        &[
            Self::AccessControl,
            Self::AuditControls,
            Self::Integrity,
            Self::TransmissionSecurity,
        ]
    }
}

impl std::fmt::Display for TechnicalSafeguard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.cfr_citation())
    }
}

/// Implementation specification within a technical safeguard
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImplementationSpec {
    /// Parent safeguard
    pub safeguard: TechnicalSafeguard,
    /// Specification identifier (e.g., "AC-1", "AC-2")
    pub spec_id: String,
    /// Specification name
    pub name: String,
    /// Whether this is Required (R) or Addressable (A)
    pub requirement_type: RequirementType,
    /// CFR citation for this specific spec
    pub cfr_citation: String,
    /// Description
    pub description: String,
}

/// Whether a HIPAA implementation specification is Required or Addressable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequirementType {
    /// Must be implemented
    Required,
    /// Must be assessed; implement if reasonable and appropriate
    Addressable,
}

impl std::fmt::Display for RequirementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required => write!(f, "Required"),
            Self::Addressable => write!(f, "Addressable"),
        }
    }
}

/// Build the complete set of HIPAA technical safeguard implementation specifications
pub fn technical_safeguard_specs() -> Vec<ImplementationSpec> {
    vec![
        // §164.312(a) — Access Control
        ImplementationSpec {
            safeguard: TechnicalSafeguard::AccessControl,
            spec_id: "AC-1".into(),
            name: "Unique User Identification".into(),
            requirement_type: RequirementType::Required,
            cfr_citation: "§164.312(a)(2)(i)".into(),
            description: "Assign a unique name and/or number for identifying and tracking \
                          user identity."
                .into(),
        },
        ImplementationSpec {
            safeguard: TechnicalSafeguard::AccessControl,
            spec_id: "AC-2".into(),
            name: "Emergency Access Procedure".into(),
            requirement_type: RequirementType::Required,
            cfr_citation: "§164.312(a)(2)(ii)".into(),
            description: "Establish (and implement as needed) procedures for obtaining \
                          necessary electronic protected health information during an emergency."
                .into(),
        },
        ImplementationSpec {
            safeguard: TechnicalSafeguard::AccessControl,
            spec_id: "AC-3".into(),
            name: "Automatic Logoff".into(),
            requirement_type: RequirementType::Addressable,
            cfr_citation: "§164.312(a)(2)(iii)".into(),
            description: "Implement electronic procedures that terminate an electronic \
                          session after a predetermined time of inactivity."
                .into(),
        },
        ImplementationSpec {
            safeguard: TechnicalSafeguard::AccessControl,
            spec_id: "AC-4".into(),
            name: "Encryption and Decryption".into(),
            requirement_type: RequirementType::Addressable,
            cfr_citation: "§164.312(a)(2)(iv)".into(),
            description: "Implement a mechanism to encrypt and decrypt electronic protected \
                          health information."
                .into(),
        },
        // §164.312(b) — Audit Controls
        ImplementationSpec {
            safeguard: TechnicalSafeguard::AuditControls,
            spec_id: "AU-1".into(),
            name: "Audit Controls".into(),
            requirement_type: RequirementType::Required,
            cfr_citation: "§164.312(b)".into(),
            description: "Implement hardware, software, and/or procedural mechanisms that \
                          record and examine activity in information systems that contain \
                          or use electronic protected health information."
                .into(),
        },
        // §164.312(c)(1) — Integrity
        ImplementationSpec {
            safeguard: TechnicalSafeguard::Integrity,
            spec_id: "IN-1".into(),
            name: "Mechanism to Authenticate Electronic Protected Health Information".into(),
            requirement_type: RequirementType::Addressable,
            cfr_citation: "§164.312(c)(2)".into(),
            description: "Implement electronic mechanisms to corroborate that electronic \
                          protected health information has not been altered or destroyed \
                          in an unauthorized manner."
                .into(),
        },
        // §164.312(e)(1) — Transmission Security
        ImplementationSpec {
            safeguard: TechnicalSafeguard::TransmissionSecurity,
            spec_id: "TS-1".into(),
            name: "Integrity Controls".into(),
            requirement_type: RequirementType::Addressable,
            cfr_citation: "§164.312(e)(2)(i)".into(),
            description: "Implement security measures to ensure that electronically \
                          transmitted electronic protected health information is not \
                          improperly modified without detection until disposed of."
                .into(),
        },
        ImplementationSpec {
            safeguard: TechnicalSafeguard::TransmissionSecurity,
            spec_id: "TS-2".into(),
            name: "Encryption".into(),
            requirement_type: RequirementType::Addressable,
            cfr_citation: "§164.312(e)(2)(ii)".into(),
            description: "Implement a mechanism to encrypt electronic protected health \
                          information whenever deemed appropriate."
                .into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_safeguards() {
        assert_eq!(TechnicalSafeguard::all().len(), 4);
    }

    #[test]
    fn test_specs_cover_all_safeguards() {
        let specs = technical_safeguard_specs();
        for safeguard in TechnicalSafeguard::all() {
            assert!(
                specs.iter().any(|s| s.safeguard == *safeguard),
                "Missing specs for {:?}",
                safeguard
            );
        }
    }

    #[test]
    fn test_cfr_citations() {
        assert_eq!(
            TechnicalSafeguard::AccessControl.cfr_citation(),
            "§164.312(a)"
        );
        assert_eq!(
            TechnicalSafeguard::TransmissionSecurity.cfr_citation(),
            "§164.312(e)(1)"
        );
    }
}
