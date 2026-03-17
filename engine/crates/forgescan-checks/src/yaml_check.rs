//! YAML-based check definitions

use forgescan_core::{
    Check, CheckCategory, CheckContext, CheckMetadata, CheckResult, ComplianceRef, Finding,
    Severity,
};
use serde::{Deserialize, Serialize};

/// A check defined in YAML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlCheckDefinition {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub category: String,
    pub severity: String,
    #[serde(default)]
    pub cve_ids: Vec<String>,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub compliance: Vec<YamlComplianceRef>,
    pub detection: YamlDetection,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled_by_default: bool,
    #[serde(default)]
    pub mode: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlComplianceRef {
    pub framework: String,
    pub control: String,
    #[serde(default)]
    pub level: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum YamlDetection {
    #[serde(rename = "version-match")]
    VersionMatch {
        cpe: String,
        #[serde(default)]
        affected_versions: Vec<String>,
        #[serde(default)]
        banner_pattern: Option<String>,
    },
    #[serde(rename = "banner-match")]
    BannerMatch { pattern: String },
    #[serde(rename = "active-probe")]
    ActiveProbe {
        method: String,
        path: String,
        #[serde(default)]
        match_response: Option<String>,
        #[serde(default)]
        match_status: Option<u16>,
    },
    #[serde(rename = "file-permission")]
    FilePermission {
        path: String,
        expected_mode: String,
        #[serde(default)]
        expected_owner: Option<String>,
        #[serde(default)]
        expected_group: Option<String>,
    },
    #[serde(rename = "config-value")]
    ConfigValue {
        file: String,
        key: String,
        expected: String,
        #[serde(default)]
        format: Option<String>,
    },
}

/// A check loaded from YAML definition
pub struct YamlCheck {
    definition: YamlCheckDefinition,
    metadata: CheckMetadata,
}

impl YamlCheck {
    /// Parse a YAML check definition from a string
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let definition: YamlCheckDefinition = serde_yaml::from_str(yaml)?;
        let metadata = Self::build_metadata(&definition);
        Ok(Self {
            definition,
            metadata,
        })
    }

    fn build_metadata(def: &YamlCheckDefinition) -> CheckMetadata {
        let category = match def.category.to_lowercase().as_str() {
            "network" => CheckCategory::Network,
            "vulnerability" | "vuln" => CheckCategory::Vulnerability,
            "configuration" | "config" => CheckCategory::Configuration,
            "webapp" | "web" => CheckCategory::WebApp,
            "cloud" => CheckCategory::Cloud,
            _ => CheckCategory::Vulnerability,
        };

        let severity = match def.severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        };

        let mut metadata = CheckMetadata::new(&def.id, &def.name, category, severity)
            .with_description(&def.description);

        for cve in &def.cve_ids {
            metadata = metadata.with_cve(cve);
        }

        for cwe in &def.cwe_ids {
            metadata = metadata.with_cwe(cwe);
        }

        for comp in &def.compliance {
            let mut cr = ComplianceRef::new(&comp.framework, &comp.control);
            if let Some(level) = comp.level {
                cr = cr.with_level(level);
            }
            metadata = metadata.with_compliance(cr);
        }

        for reference in &def.references {
            metadata = metadata.with_reference(reference);
        }

        metadata.enabled_by_default = def.enabled_by_default;

        metadata
    }

    /// Get the detection configuration
    pub fn detection(&self) -> &YamlDetection {
        &self.definition.detection
    }
}

impl Check for YamlCheck {
    fn id(&self) -> &str {
        &self.definition.id
    }

    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    fn execute(&self, ctx: &CheckContext) -> CheckResult {
        match &self.definition.detection {
            YamlDetection::VersionMatch {
                cpe,
                affected_versions,
                banner_pattern,
            } => self.check_version_match(ctx, cpe, affected_versions, banner_pattern.as_deref()),
            YamlDetection::BannerMatch { pattern } => self.check_banner_match(ctx, pattern),
            YamlDetection::ActiveProbe {
                method: _,
                path: _,
                match_response: _,
                match_status: _,
            } => {
                // Active probing would be implemented here
                // For now, return empty (requires HTTP client)
                Ok(vec![])
            }
            YamlDetection::FilePermission {
                path: _,
                expected_mode: _,
                expected_owner: _,
                expected_group: _,
            } => {
                // File permission check requires agent mode
                // Implementation in forgescan-config-audit
                Ok(vec![])
            }
            YamlDetection::ConfigValue {
                file: _,
                key: _,
                expected: _,
                format: _,
            } => {
                // Config value check requires agent mode
                Ok(vec![])
            }
        }
    }
}

impl YamlCheck {
    fn check_version_match(
        &self,
        ctx: &CheckContext,
        cpe_pattern: &str,
        _affected_versions: &[String],
        banner_pattern: Option<&str>,
    ) -> CheckResult {
        // Check if the detected CPE matches
        if let Some(detected_cpe) = &ctx.cpe {
            // Simple CPE prefix match (full CPE matching would be more complex)
            if detected_cpe.starts_with(cpe_pattern.trim_end_matches('*')) {
                // Version matched - create finding
                return Ok(vec![self.create_finding(ctx)]);
            }
        }

        // Check banner pattern if provided
        if let (Some(pattern), Some(banner)) = (banner_pattern, &ctx.banner) {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(banner) {
                    return Ok(vec![self.create_finding(ctx)]);
                }
            }
        }

        Ok(vec![])
    }

    fn check_banner_match(&self, ctx: &CheckContext, pattern: &str) -> CheckResult {
        if let Some(banner) = &ctx.banner {
            if let Ok(re) = regex::Regex::new(pattern) {
                if re.is_match(banner) {
                    return Ok(vec![self.create_finding(ctx)]);
                }
            }
        }
        Ok(vec![])
    }

    fn create_finding(&self, ctx: &CheckContext) -> Finding {
        let mut builder = Finding::builder(&self.definition.id, ctx.target_str())
            .check_name(&self.definition.name)
            .title(&self.definition.name)
            .description(&self.definition.description)
            .severity(self.metadata.severity)
            .category(self.metadata.category)
            .detection_method("yaml-check");

        if let Some(port) = ctx.port {
            if let Some(proto) = &ctx.protocol {
                builder = builder.port(port, proto);
            }
        }

        if let Some(service) = &ctx.service {
            builder = builder.service(service, ctx.service_version.clone());
        }

        if let Some(cpe) = &ctx.cpe {
            builder = builder.cpe(cpe);
        }

        for cve in &self.definition.cve_ids {
            builder = builder.cve(cve);
        }

        for cwe in &self.definition.cwe_ids {
            builder = builder.cwe(cwe);
        }

        if let Some(banner) = &ctx.banner {
            builder = builder.evidence(format!("Banner: {}", banner));
        }

        if let Some(remediation) = &self.definition.remediation {
            builder = builder.remediation(remediation);
        }

        for reference in &self.definition.references {
            builder = builder.reference(reference);
        }

        for comp in &self.definition.compliance {
            let cr = ComplianceRef::new(&comp.framework, &comp.control);
            builder = builder.compliance(cr);
        }

        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yaml_check() {
        let yaml = r#"
id: "FSC-VULN-0001"
name: "Apache Path Traversal"
description: "Detects CVE-2021-41773"
category: vuln
severity: critical
cve_ids:
  - CVE-2021-41773
cwe_ids:
  - CWE-22
compliance:
  - framework: "NIST-800-53"
    control: "SI-2"
detection:
  type: version-match
  cpe: "cpe:2.3:a:apache:http_server:*"
  affected_versions:
    - ">= 2.4.49"
    - "< 2.4.51"
  banner_pattern: "Apache/2\\.4\\.(49|50)"
remediation: "Upgrade to Apache 2.4.51 or later"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
"#;

        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert_eq!(check.id(), "FSC-VULN-0001");
        assert_eq!(check.metadata().severity, Severity::Critical);
        assert_eq!(check.metadata().cve_ids, vec!["CVE-2021-41773"]);
    }

    #[test]
    fn test_parse_banner_match_check() {
        let yaml = r#"
id: "FSC-BAN-0001"
name: "OpenSSH Banner Check"
description: "Detects OpenSSH via banner"
category: network
severity: low
detection:
  type: banner-match
  pattern: "OpenSSH_[0-9]+"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert_eq!(check.id(), "FSC-BAN-0001");
        assert_eq!(check.metadata().category, CheckCategory::Network);
        assert_eq!(check.metadata().severity, Severity::Low);
        match check.detection() {
            YamlDetection::BannerMatch { pattern } => {
                assert_eq!(pattern, "OpenSSH_[0-9]+");
            }
            _ => panic!("Expected BannerMatch detection type"),
        }
    }

    #[test]
    fn test_parse_active_probe_check() {
        let yaml = r#"
id: "FSC-WEB-0001"
name: "Web Server Probe"
description: "Active probe for web server"
category: webapp
severity: medium
detection:
  type: active-probe
  method: GET
  path: "/.env"
  match_response: "DB_PASSWORD"
  match_status: 200
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert_eq!(check.id(), "FSC-WEB-0001");
        assert_eq!(check.metadata().category, CheckCategory::WebApp);
        match check.detection() {
            YamlDetection::ActiveProbe {
                method,
                path,
                match_response,
                match_status,
            } => {
                assert_eq!(method, "GET");
                assert_eq!(path, "/.env");
                assert_eq!(match_response.as_deref(), Some("DB_PASSWORD"));
                assert_eq!(*match_status, Some(200));
            }
            _ => panic!("Expected ActiveProbe detection type"),
        }
    }

    #[test]
    fn test_parse_file_permission_check() {
        let yaml = r#"
id: "FSC-CFG-0001"
name: "SSH Key Permissions"
description: "Check SSH key file permissions"
category: config
severity: high
detection:
  type: file-permission
  path: "/etc/ssh/sshd_config"
  expected_mode: "0600"
  expected_owner: "root"
  expected_group: "root"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert_eq!(check.id(), "FSC-CFG-0001");
        assert_eq!(check.metadata().category, CheckCategory::Configuration);
        match check.detection() {
            YamlDetection::FilePermission {
                path,
                expected_mode,
                expected_owner,
                expected_group,
            } => {
                assert_eq!(path, "/etc/ssh/sshd_config");
                assert_eq!(expected_mode, "0600");
                assert_eq!(expected_owner.as_deref(), Some("root"));
                assert_eq!(expected_group.as_deref(), Some("root"));
            }
            _ => panic!("Expected FilePermission detection type"),
        }
    }

    #[test]
    fn test_parse_config_value_check() {
        let yaml = r#"
id: "FSC-CFG-0002"
name: "SSH Root Login"
description: "Check that root login is disabled"
category: configuration
severity: high
detection:
  type: config-value
  file: "/etc/ssh/sshd_config"
  key: "PermitRootLogin"
  expected: "no"
  format: "sshd_config"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert_eq!(check.id(), "FSC-CFG-0002");
        match check.detection() {
            YamlDetection::ConfigValue {
                file,
                key,
                expected,
                format,
            } => {
                assert_eq!(file, "/etc/ssh/sshd_config");
                assert_eq!(key, "PermitRootLogin");
                assert_eq!(expected, "no");
                assert_eq!(format.as_deref(), Some("sshd_config"));
            }
            _ => panic!("Expected ConfigValue detection type"),
        }
    }

    #[test]
    fn test_parse_malformed_yaml_missing_id() {
        let yaml = r#"
name: "Missing ID Check"
category: vuln
severity: high
detection:
  type: banner-match
  pattern: "test"
"#;
        let result = YamlCheck::from_yaml(yaml);
        assert!(result.is_err(), "Should fail when 'id' field is missing");
    }

    #[test]
    fn test_parse_malformed_yaml_missing_detection() {
        let yaml = r#"
id: "FSC-BAD-0001"
name: "No Detection"
category: vuln
severity: high
"#;
        let result = YamlCheck::from_yaml(yaml);
        assert!(
            result.is_err(),
            "Should fail when 'detection' block is missing"
        );
    }

    #[test]
    fn test_parse_malformed_yaml_invalid_detection_type() {
        let yaml = r#"
id: "FSC-BAD-0002"
name: "Bad Detection Type"
category: vuln
severity: high
detection:
  type: nonexistent-type
  foo: bar
"#;
        let result = YamlCheck::from_yaml(yaml);
        assert!(
            result.is_err(),
            "Should fail when detection type is unknown"
        );
    }

    #[test]
    fn test_category_mapping() {
        let make_yaml = |cat: &str| {
            format!(
                r#"
id: "FSC-CAT-0001"
name: "Category Test"
category: {cat}
severity: low
detection:
  type: banner-match
  pattern: "test"
"#
            )
        };

        let cases = vec![
            ("network", CheckCategory::Network),
            ("vulnerability", CheckCategory::Vulnerability),
            ("vuln", CheckCategory::Vulnerability),
            ("configuration", CheckCategory::Configuration),
            ("config", CheckCategory::Configuration),
            ("webapp", CheckCategory::WebApp),
            ("web", CheckCategory::WebApp),
            ("cloud", CheckCategory::Cloud),
            ("unknowncategory", CheckCategory::Vulnerability),
        ];

        for (input, expected) in cases {
            let check = YamlCheck::from_yaml(&make_yaml(input)).unwrap();
            assert_eq!(
                check.metadata().category,
                expected,
                "Category '{}' should map to {:?}",
                input,
                expected
            );
        }
    }

    #[test]
    fn test_severity_mapping() {
        let make_yaml = |sev: &str| {
            format!(
                r#"
id: "FSC-SEV-0001"
name: "Severity Test"
category: vuln
severity: {sev}
detection:
  type: banner-match
  pattern: "test"
"#
            )
        };

        let cases = vec![
            ("critical", Severity::Critical),
            ("high", Severity::High),
            ("medium", Severity::Medium),
            ("low", Severity::Low),
            ("unknownseverity", Severity::Info),
        ];

        for (input, expected) in cases {
            let check = YamlCheck::from_yaml(&make_yaml(input)).unwrap();
            assert_eq!(
                check.metadata().severity,
                expected,
                "Severity '{}' should map to {:?}",
                input,
                expected
            );
        }
    }

    #[test]
    fn test_yaml_check_execute_version_match_cpe_hit() {
        use forgescan_core::{CheckContext, ScanTarget};

        let yaml = r#"
id: "FSC-VULN-1001"
name: "Apache Version Match"
description: "Test version match"
category: vuln
severity: high
detection:
  type: version-match
  cpe: "cpe:2.3:a:apache:http_server:*"
  affected_versions:
    - ">= 2.4.49"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        let mut ctx = CheckContext::new(ScanTarget::parse("192.168.1.1").unwrap());
        ctx.cpe = Some("cpe:2.3:a:apache:http_server:2.4.49".to_string());

        let findings = check.execute(&ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id, "FSC-VULN-1001");
    }

    #[test]
    fn test_yaml_check_execute_version_match_no_match() {
        use forgescan_core::{CheckContext, ScanTarget};

        let yaml = r#"
id: "FSC-VULN-1002"
name: "Apache Version Match"
description: "Test version match"
category: vuln
severity: high
detection:
  type: version-match
  cpe: "cpe:2.3:a:apache:http_server:*"
  affected_versions:
    - ">= 2.4.49"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        let mut ctx = CheckContext::new(ScanTarget::parse("192.168.1.1").unwrap());
        ctx.cpe = Some("cpe:2.3:a:nginx:nginx:1.21.0".to_string());

        let findings = check.execute(&ctx).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_yaml_check_execute_banner_match_hit() {
        use forgescan_core::{CheckContext, ScanTarget};

        let yaml = r#"
id: "FSC-BAN-1001"
name: "OpenSSH Banner"
description: "Detect OpenSSH"
category: network
severity: low
detection:
  type: banner-match
  pattern: "OpenSSH_[0-9]+"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        let mut ctx = CheckContext::new(ScanTarget::parse("192.168.1.1").unwrap());
        ctx.banner = Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3".to_string());

        let findings = check.execute(&ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_id, "FSC-BAN-1001");
    }

    #[test]
    fn test_yaml_check_execute_banner_match_miss() {
        use forgescan_core::{CheckContext, ScanTarget};

        let yaml = r#"
id: "FSC-BAN-1002"
name: "OpenSSH Banner"
description: "Detect OpenSSH"
category: network
severity: low
detection:
  type: banner-match
  pattern: "OpenSSH_[0-9]+"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        let mut ctx = CheckContext::new(ScanTarget::parse("192.168.1.1").unwrap());
        ctx.banner = Some("Dropbear SSH 2020.81".to_string());

        let findings = check.execute(&ctx).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_yaml_check_compliance_preserved() {
        let yaml = r#"
id: "FSC-COMP-0001"
name: "Compliance Check"
description: "Has compliance mappings"
category: vuln
severity: high
compliance:
  - framework: "NIST-800-53"
    control: "SI-2"
    level: 1
  - framework: "PCI-DSS"
    control: "6.2"
detection:
  type: banner-match
  pattern: "test"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        let compliance = &check.metadata().compliance;
        assert_eq!(compliance.len(), 2);
        assert_eq!(compliance[0].framework, "NIST-800-53");
        assert_eq!(compliance[0].control_id, "SI-2");
        assert_eq!(compliance[1].framework, "PCI-DSS");
        assert_eq!(compliance[1].control_id, "6.2");
    }

    #[test]
    fn test_yaml_check_enabled_by_default_true() {
        let yaml = r#"
id: "FSC-DEF-0001"
name: "Default Enabled"
category: vuln
severity: low
detection:
  type: banner-match
  pattern: "test"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert!(
            check.metadata().enabled_by_default,
            "Should default to true when field is omitted"
        );
    }

    #[test]
    fn test_yaml_check_enabled_by_default_false() {
        let yaml = r#"
id: "FSC-DEF-0002"
name: "Default Disabled"
category: vuln
severity: low
enabled_by_default: false
detection:
  type: banner-match
  pattern: "test"
"#;
        let check = YamlCheck::from_yaml(yaml).unwrap();
        assert!(
            !check.metadata().enabled_by_default,
            "Should be false when explicitly set to false"
        );
    }
}
