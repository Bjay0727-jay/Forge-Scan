//! Cloud security check definitions

use crate::CloudCheckCategory;
use forgescan_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Cloud resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    /// Resource ID
    pub id: String,
    /// Resource ARN (AWS) or equivalent
    pub arn: Option<String>,
    /// Resource type (e.g., "aws:s3:bucket")
    pub resource_type: String,
    /// Resource name
    pub name: String,
    /// Region
    pub region: String,
    /// Resource tags
    pub tags: HashMap<String, String>,
    /// Creation time
    pub created_at: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Cloud check trait
pub trait CloudCheck: Send + Sync {
    /// Check ID
    fn id(&self) -> &str;

    /// Check name
    fn name(&self) -> &str;

    /// Check description
    fn description(&self) -> &str;

    /// Check category
    fn category(&self) -> CloudCheckCategory;

    /// Default severity
    fn severity(&self) -> Severity;

    /// Resource types this check applies to
    fn resource_types(&self) -> &[&str];

    /// Execute check against a resource
    fn check(&self, resource: &CloudResource) -> CloudCheckResult;
}

/// Result of a cloud check
#[derive(Debug, Clone)]
pub struct CloudCheckResult {
    /// Check ID
    pub check_id: String,
    /// Resource ID
    pub resource_id: String,
    /// Pass/fail status
    pub passed: bool,
    /// Finding if failed
    pub finding: Option<Finding>,
    /// Additional context
    pub context: HashMap<String, String>,
}

impl CloudCheckResult {
    /// Create a passing result
    pub fn pass(check_id: &str, resource_id: &str) -> Self {
        Self {
            check_id: check_id.to_string(),
            resource_id: resource_id.to_string(),
            passed: true,
            finding: None,
            context: HashMap::new(),
        }
    }

    /// Create a failing result
    pub fn fail(check_id: &str, resource_id: &str, finding: Finding) -> Self {
        Self {
            check_id: check_id.to_string(),
            resource_id: resource_id.to_string(),
            passed: false,
            finding: Some(finding),
            context: HashMap::new(),
        }
    }

    /// Add context
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

/// AWS S3 public access check
pub struct S3PublicAccessCheck;

impl CloudCheck for S3PublicAccessCheck {
    fn id(&self) -> &str {
        "AWS-S3-001"
    }

    fn name(&self) -> &str {
        "S3 Bucket Public Access"
    }

    fn description(&self) -> &str {
        "Ensure S3 buckets do not allow public access"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Storage
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:s3:bucket"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let public_access = resource
            .metadata
            .get("public_access_block")
            .and_then(|v| v.as_object());

        if let Some(pab) = public_access {
            let block_public_acls = pab
                .get("BlockPublicAcls")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let block_public_policy = pab
                .get("BlockPublicPolicy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let ignore_public_acls = pab
                .get("IgnorePublicAcls")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let restrict_public_buckets = pab
                .get("RestrictPublicBuckets")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if block_public_acls && block_public_policy && ignore_public_acls && restrict_public_buckets {
                return CloudCheckResult::pass(self.id(), &resource.id);
            }
        }

        let finding = Finding::new(
            format!("S3 bucket '{}' allows public access", resource.name),
            self.severity(),
        )
        .with_description("S3 bucket does not have all public access blocks enabled")
        .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
        .with_remediation(
            "Enable all public access block settings: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, RestrictPublicBuckets",
        );

        CloudCheckResult::fail(self.id(), &resource.id, finding)
    }
}

/// AWS S3 encryption check
pub struct S3EncryptionCheck;

impl CloudCheck for S3EncryptionCheck {
    fn id(&self) -> &str {
        "AWS-S3-002"
    }

    fn name(&self) -> &str {
        "S3 Bucket Encryption"
    }

    fn description(&self) -> &str {
        "Ensure S3 buckets have server-side encryption enabled"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Encryption
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:s3:bucket"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let encryption = resource
            .metadata
            .get("encryption")
            .and_then(|v| v.as_str());

        match encryption {
            Some("AES256") | Some("aws:kms") => {
                CloudCheckResult::pass(self.id(), &resource.id)
            }
            _ => {
                let finding = Finding::new(
                    format!("S3 bucket '{}' lacks encryption", resource.name),
                    self.severity(),
                )
                .with_description("S3 bucket does not have server-side encryption enabled")
                .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
                .with_remediation("Enable server-side encryption with AES-256 or AWS KMS");

                CloudCheckResult::fail(self.id(), &resource.id, finding)
            }
        }
    }
}

/// AWS IAM root account MFA check
pub struct IamRootMfaCheck;

impl CloudCheck for IamRootMfaCheck {
    fn id(&self) -> &str {
        "AWS-IAM-001"
    }

    fn name(&self) -> &str {
        "Root Account MFA"
    }

    fn description(&self) -> &str {
        "Ensure MFA is enabled for the root account"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Identity
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:iam:root"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let mfa_enabled = resource
            .metadata
            .get("mfa_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if mfa_enabled {
            CloudCheckResult::pass(self.id(), &resource.id)
        } else {
            let finding = Finding::new(
                "Root account does not have MFA enabled",
                self.severity(),
            )
            .with_description(
                "The AWS root account should have MFA enabled to prevent unauthorized access",
            )
            .with_affected_asset("arn:aws:iam::*:root")
            .with_remediation("Enable MFA for the root account using a hardware or virtual MFA device");

            CloudCheckResult::fail(self.id(), &resource.id, finding)
        }
    }
}

/// AWS IAM password policy check
pub struct IamPasswordPolicyCheck;

impl CloudCheck for IamPasswordPolicyCheck {
    fn id(&self) -> &str {
        "AWS-IAM-002"
    }

    fn name(&self) -> &str {
        "IAM Password Policy"
    }

    fn description(&self) -> &str {
        "Ensure IAM password policy meets security requirements"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Identity
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:iam:password-policy"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let policy = &resource.metadata;

        let min_length = policy
            .get("minimum_length")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let require_uppercase = policy
            .get("require_uppercase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let require_lowercase = policy
            .get("require_lowercase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let require_numbers = policy
            .get("require_numbers")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let require_symbols = policy
            .get("require_symbols")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let max_age = policy
            .get("max_password_age")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let mut issues = Vec::new();

        if min_length < 14 {
            issues.push("Minimum password length should be at least 14");
        }
        if !require_uppercase {
            issues.push("Password should require uppercase letters");
        }
        if !require_lowercase {
            issues.push("Password should require lowercase letters");
        }
        if !require_numbers {
            issues.push("Password should require numbers");
        }
        if !require_symbols {
            issues.push("Password should require symbols");
        }
        if max_age == 0 || max_age > 90 {
            issues.push("Password max age should be 90 days or less");
        }

        if issues.is_empty() {
            CloudCheckResult::pass(self.id(), &resource.id)
        } else {
            let finding = Finding::new(
                "IAM password policy is weak",
                self.severity(),
            )
            .with_description(issues.join("; "))
            .with_affected_asset("arn:aws:iam::*:password-policy")
            .with_remediation(
                "Update IAM password policy to require: 14+ chars, uppercase, lowercase, numbers, symbols, 90-day max age",
            );

            CloudCheckResult::fail(self.id(), &resource.id, finding)
        }
    }
}

/// AWS EC2 public IP check
pub struct Ec2PublicIpCheck;

impl CloudCheck for Ec2PublicIpCheck {
    fn id(&self) -> &str {
        "AWS-EC2-001"
    }

    fn name(&self) -> &str {
        "EC2 Instance Public IP"
    }

    fn description(&self) -> &str {
        "Identify EC2 instances with public IP addresses"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Network
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:ec2:instance"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let public_ip = resource
            .metadata
            .get("public_ip")
            .and_then(|v| v.as_str());

        if public_ip.is_some() {
            let finding = Finding::new(
                format!("EC2 instance '{}' has public IP", resource.name),
                self.severity(),
            )
            .with_description(format!(
                "EC2 instance has public IP: {}",
                public_ip.unwrap()
            ))
            .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
            .with_remediation(
                "Consider using private subnets with NAT gateway, or restrict security group ingress",
            );

            CloudCheckResult::fail(self.id(), &resource.id, finding)
        } else {
            CloudCheckResult::pass(self.id(), &resource.id)
        }
    }
}

/// AWS Security Group open check
pub struct SecurityGroupOpenCheck;

impl CloudCheck for SecurityGroupOpenCheck {
    fn id(&self) -> &str {
        "AWS-EC2-002"
    }

    fn name(&self) -> &str {
        "Security Group Open Access"
    }

    fn description(&self) -> &str {
        "Ensure security groups don't allow unrestricted access"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Network
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:ec2:security-group"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let ingress = resource
            .metadata
            .get("ingress_rules")
            .and_then(|v| v.as_array());

        if let Some(rules) = ingress {
            for rule in rules {
                let cidr = rule.get("cidr").and_then(|v| v.as_str()).unwrap_or("");
                let port = rule.get("port").and_then(|v| v.as_u64()).unwrap_or(0);

                // Check for 0.0.0.0/0 access to sensitive ports
                if cidr == "0.0.0.0/0" || cidr == "::/0" {
                    let sensitive_ports = [22, 3389, 3306, 5432, 27017, 6379, 9200];
                    if sensitive_ports.contains(&(port as u16)) {
                        let finding = Finding::new(
                            format!(
                                "Security group '{}' allows unrestricted access to port {}",
                                resource.name, port
                            ),
                            self.severity(),
                        )
                        .with_description(format!(
                            "Ingress rule allows {} from 0.0.0.0/0",
                            port
                        ))
                        .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
                        .with_remediation(
                            "Restrict CIDR range to specific IPs or use VPN/bastion host",
                        );

                        return CloudCheckResult::fail(self.id(), &resource.id, finding);
                    }
                }
            }
        }

        CloudCheckResult::pass(self.id(), &resource.id)
    }
}

/// AWS RDS encryption check
pub struct RdsEncryptionCheck;

impl CloudCheck for RdsEncryptionCheck {
    fn id(&self) -> &str {
        "AWS-RDS-001"
    }

    fn name(&self) -> &str {
        "RDS Instance Encryption"
    }

    fn description(&self) -> &str {
        "Ensure RDS instances have encryption at rest enabled"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Database
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:rds:instance"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let encrypted = resource
            .metadata
            .get("storage_encrypted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if encrypted {
            CloudCheckResult::pass(self.id(), &resource.id)
        } else {
            let finding = Finding::new(
                format!("RDS instance '{}' is not encrypted", resource.name),
                self.severity(),
            )
            .with_description("RDS instance does not have encryption at rest enabled")
            .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
            .with_remediation(
                "Enable encryption at rest for RDS instance (requires snapshot and restore for existing instances)",
            );

            CloudCheckResult::fail(self.id(), &resource.id, finding)
        }
    }
}

/// AWS RDS public access check
pub struct RdsPublicAccessCheck;

impl CloudCheck for RdsPublicAccessCheck {
    fn id(&self) -> &str {
        "AWS-RDS-002"
    }

    fn name(&self) -> &str {
        "RDS Public Accessibility"
    }

    fn description(&self) -> &str {
        "Ensure RDS instances are not publicly accessible"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Database
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:rds:instance"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let publicly_accessible = resource
            .metadata
            .get("publicly_accessible")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !publicly_accessible {
            CloudCheckResult::pass(self.id(), &resource.id)
        } else {
            let finding = Finding::new(
                format!("RDS instance '{}' is publicly accessible", resource.name),
                self.severity(),
            )
            .with_description("RDS instance is configured to be publicly accessible")
            .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
            .with_remediation("Disable public accessibility and use VPC security groups");

            CloudCheckResult::fail(self.id(), &resource.id, finding)
        }
    }
}

/// AWS CloudTrail enabled check
pub struct CloudTrailEnabledCheck;

impl CloudCheck for CloudTrailEnabledCheck {
    fn id(&self) -> &str {
        "AWS-LOG-001"
    }

    fn name(&self) -> &str {
        "CloudTrail Enabled"
    }

    fn description(&self) -> &str {
        "Ensure CloudTrail is enabled in all regions"
    }

    fn category(&self) -> CloudCheckCategory {
        CloudCheckCategory::Logging
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn resource_types(&self) -> &[&str] {
        &["aws:cloudtrail:trail"]
    }

    fn check(&self, resource: &CloudResource) -> CloudCheckResult {
        let is_multi_region = resource
            .metadata
            .get("is_multi_region")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let is_logging = resource
            .metadata
            .get("is_logging")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if is_multi_region && is_logging {
            CloudCheckResult::pass(self.id(), &resource.id)
        } else {
            let finding = Finding::new(
                "CloudTrail is not properly configured",
                self.severity(),
            )
            .with_description(if !is_multi_region {
                "CloudTrail is not configured for all regions"
            } else {
                "CloudTrail logging is disabled"
            })
            .with_affected_asset(resource.arn.as_deref().unwrap_or(&resource.id))
            .with_remediation("Enable multi-region CloudTrail with logging enabled");

            CloudCheckResult::fail(self.id(), &resource.id, finding)
        }
    }
}

/// Get all built-in AWS checks
pub fn aws_checks() -> Vec<Box<dyn CloudCheck>> {
    vec![
        Box::new(S3PublicAccessCheck),
        Box::new(S3EncryptionCheck),
        Box::new(IamRootMfaCheck),
        Box::new(IamPasswordPolicyCheck),
        Box::new(Ec2PublicIpCheck),
        Box::new(SecurityGroupOpenCheck),
        Box::new(RdsEncryptionCheck),
        Box::new(RdsPublicAccessCheck),
        Box::new(CloudTrailEnabledCheck),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_public_access_check() {
        let check = S3PublicAccessCheck;

        // Secure bucket
        let secure_bucket = CloudResource {
            id: "bucket-1".into(),
            arn: Some("arn:aws:s3:::bucket-1".into()),
            resource_type: "aws:s3:bucket".into(),
            name: "secure-bucket".into(),
            region: "us-east-1".into(),
            tags: HashMap::new(),
            created_at: None,
            metadata: {
                let mut m = HashMap::new();
                m.insert(
                    "public_access_block".into(),
                    serde_json::json!({
                        "BlockPublicAcls": true,
                        "BlockPublicPolicy": true,
                        "IgnorePublicAcls": true,
                        "RestrictPublicBuckets": true
                    }),
                );
                m
            },
        };

        let result = check.check(&secure_bucket);
        assert!(result.passed);

        // Insecure bucket
        let insecure_bucket = CloudResource {
            id: "bucket-2".into(),
            arn: Some("arn:aws:s3:::bucket-2".into()),
            resource_type: "aws:s3:bucket".into(),
            name: "insecure-bucket".into(),
            region: "us-east-1".into(),
            tags: HashMap::new(),
            created_at: None,
            metadata: HashMap::new(),
        };

        let result = check.check(&insecure_bucket);
        assert!(!result.passed);
    }
}
