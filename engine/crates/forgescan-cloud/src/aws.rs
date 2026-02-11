//! AWS security scanner implementation

use crate::checks::{aws_checks, CloudCheck, CloudCheckResult, CloudResource};
use crate::{CloudProvider, CloudScanConfig, CloudScanResult, CloudScanStats};
use aws_config::SdkConfig;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_iam::Client as IamClient;
use aws_sdk_s3::Client as S3Client;
use forgescan_core::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, info, warn};

/// AWS configuration
#[derive(Debug, Clone)]
pub struct AwsConfig {
    /// AWS SDK configuration
    sdk_config: SdkConfig,
    /// Account ID
    account_id: String,
    /// Default region
    region: String,
}

impl AwsConfig {
    /// Load from environment/profile
    pub async fn from_env() -> anyhow::Result<Self> {
        let sdk_config = aws_config::load_from_env().await;
        let region = sdk_config
            .region()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "us-east-1".to_string());

        // Get account ID from STS
        let sts = aws_sdk_sts::Client::new(&sdk_config);
        let identity = sts.get_caller_identity().send().await?;
        let account_id = identity.account().unwrap_or_default().to_string();

        Ok(Self {
            sdk_config,
            account_id,
            region,
        })
    }

    /// Create with explicit credentials
    pub async fn with_credentials(
        access_key: &str,
        secret_key: &str,
        region: &str,
    ) -> anyhow::Result<Self> {
        use aws_credential_types::Credentials;

        let credentials = Credentials::new(access_key, secret_key, None, None, "forgescan");

        let sdk_config = aws_config::from_env()
            .credentials_provider(credentials)
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;

        let sts = aws_sdk_sts::Client::new(&sdk_config);
        let identity = sts.get_caller_identity().send().await?;
        let account_id = identity.account().unwrap_or_default().to_string();

        Ok(Self {
            sdk_config,
            account_id,
            region: region.to_string(),
        })
    }

    /// Create with assumed role
    pub async fn assume_role(base_config: &AwsConfig, role_arn: &str) -> anyhow::Result<Self> {
        use aws_credential_types::provider::ProvideCredentials;

        let sts = aws_sdk_sts::Client::new(&base_config.sdk_config);

        let assumed = sts
            .assume_role()
            .role_arn(role_arn)
            .role_session_name("forgescan")
            .send()
            .await?;

        let creds = assumed.credentials().ok_or_else(|| {
            anyhow::anyhow!("No credentials returned from assume role")
        })?;

        let credentials = aws_credential_types::Credentials::new(
            creds.access_key_id(),
            creds.secret_access_key(),
            Some(creds.session_token().to_string()),
            None,
            "forgescan-assumed",
        );

        let sdk_config = aws_config::from_env()
            .credentials_provider(credentials)
            .region(aws_config::Region::new(base_config.region.clone()))
            .load()
            .await;

        // Get the account ID of the assumed role
        let new_sts = aws_sdk_sts::Client::new(&sdk_config);
        let identity = new_sts.get_caller_identity().send().await?;
        let account_id = identity.account().unwrap_or_default().to_string();

        Ok(Self {
            sdk_config,
            account_id,
            region: base_config.region.clone(),
        })
    }
}

/// AWS scanner
pub struct AwsScanner {
    config: AwsConfig,
    ec2: Ec2Client,
    s3: S3Client,
    iam: IamClient,
    checks: Vec<Box<dyn CloudCheck>>,
}

impl AwsScanner {
    /// Create a new AWS scanner
    pub async fn new(config: AwsConfig) -> anyhow::Result<Self> {
        let ec2 = Ec2Client::new(&config.sdk_config);
        let s3 = S3Client::new(&config.sdk_config);
        let iam = IamClient::new(&config.sdk_config);

        Ok(Self {
            config,
            ec2,
            s3,
            iam,
            checks: aws_checks(),
        })
    }

    /// Scan all resource types
    pub async fn scan_all(&self, config: &CloudScanConfig) -> anyhow::Result<CloudScanResult> {
        let start = Instant::now();
        info!("Starting AWS security scan for account {}", self.config.account_id);

        let mut resources = Vec::new();
        let mut findings = Vec::new();
        let mut stats = CloudScanStats::default();

        // Collect resources based on configuration
        let resource_types: Vec<&str> = if config.resource_types.is_empty() {
            vec!["s3", "ec2", "iam", "rds", "cloudtrail"]
        } else {
            config.resource_types.iter().map(|s| s.as_str()).collect()
        };

        // S3 Buckets
        if resource_types.iter().any(|t| *t == "s3" || t.starts_with("aws:s3")) {
            match self.collect_s3_buckets().await {
                Ok(buckets) => resources.extend(buckets),
                Err(e) => warn!("Failed to collect S3 buckets: {}", e),
            }
        }

        // EC2 Instances
        if resource_types.iter().any(|t| *t == "ec2" || t.starts_with("aws:ec2")) {
            match self.collect_ec2_instances(&config.regions).await {
                Ok(instances) => resources.extend(instances),
                Err(e) => warn!("Failed to collect EC2 instances: {}", e),
            }

            match self.collect_security_groups(&config.regions).await {
                Ok(sgs) => resources.extend(sgs),
                Err(e) => warn!("Failed to collect security groups: {}", e),
            }
        }

        // IAM
        if resource_types.iter().any(|t| *t == "iam" || t.starts_with("aws:iam")) {
            match self.collect_iam_resources().await {
                Ok(iam_resources) => resources.extend(iam_resources),
                Err(e) => warn!("Failed to collect IAM resources: {}", e),
            }
        }

        stats.resources_scanned = resources.len() as u32;

        // Run checks
        for resource in &resources {
            for check in &self.checks {
                // Check if this check applies to this resource type
                if !check.resource_types().iter().any(|t| *t == resource.resource_type) {
                    continue;
                }

                // Skip disabled checks
                if config.skip_checks.contains(&check.id().to_string()) {
                    continue;
                }

                stats.checks_performed += 1;

                let result = check.check(resource);

                if result.passed {
                    stats.checks_passed += 1;
                } else {
                    stats.checks_failed += 1;
                    if let Some(finding) = result.finding {
                        findings.push(finding);
                    }
                }
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            "AWS scan complete: {} resources, {} checks, {} findings in {}ms",
            stats.resources_scanned,
            stats.checks_performed,
            findings.len(),
            stats.duration_ms
        );

        Ok(CloudScanResult {
            provider: CloudProvider::Aws,
            account_id: self.config.account_id.clone(),
            regions: config.regions.clone(),
            resources,
            findings,
            stats,
        })
    }

    /// Collect S3 buckets
    async fn collect_s3_buckets(&self) -> anyhow::Result<Vec<CloudResource>> {
        debug!("Collecting S3 buckets");
        let mut resources = Vec::new();

        let buckets = self.s3.list_buckets().send().await?;

        for bucket in buckets.buckets().unwrap_or_default() {
            let name = bucket.name().unwrap_or_default();

            // Get bucket details
            let mut metadata = HashMap::new();

            // Get public access block
            match self
                .s3
                .get_public_access_block()
                .bucket(name)
                .send()
                .await
            {
                Ok(pab) => {
                    if let Some(config) = pab.public_access_block_configuration() {
                        metadata.insert(
                            "public_access_block".to_string(),
                            serde_json::json!({
                                "BlockPublicAcls": config.block_public_acls(),
                                "BlockPublicPolicy": config.block_public_policy(),
                                "IgnorePublicAcls": config.ignore_public_acls(),
                                "RestrictPublicBuckets": config.restrict_public_buckets(),
                            }),
                        );
                    }
                }
                Err(_) => {
                    // Public access block not configured
                }
            }

            // Get encryption
            match self
                .s3
                .get_bucket_encryption()
                .bucket(name)
                .send()
                .await
            {
                Ok(enc) => {
                    if let Some(config) = enc.server_side_encryption_configuration() {
                        if let Some(rule) = config.rules().first() {
                            if let Some(sse) = rule.apply_server_side_encryption_by_default() {
                                let algo = sse.sse_algorithm();
                                metadata.insert(
                                    "encryption".to_string(),
                                    serde_json::Value::String(format!("{:?}", algo)),
                                );
                            }
                        }
                    }
                }
                Err(_) => {}
            }

            // Get versioning
            match self.s3.get_bucket_versioning().bucket(name).send().await {
                Ok(versioning) => {
                    let status = versioning.status();
                    metadata.insert(
                        "versioning".to_string(),
                        serde_json::Value::String(format!("{:?}", status)),
                    );
                }
                Err(_) => {}
            }

            // Get tags
            let tags = match self.s3.get_bucket_tagging().bucket(name).send().await {
                Ok(tagging) => tagging
                    .tag_set()
                    .iter()
                    .map(|t| (t.key().to_string(), t.value().to_string()))
                    .collect(),
                Err(_) => HashMap::new(),
            };

            resources.push(CloudResource {
                id: name.to_string(),
                arn: Some(format!("arn:aws:s3:::{}", name)),
                resource_type: "aws:s3:bucket".to_string(),
                name: name.to_string(),
                region: "global".to_string(), // S3 buckets are global
                tags,
                created_at: bucket.creation_date().map(|d| d.to_string()),
                metadata,
            });
        }

        debug!("Found {} S3 buckets", resources.len());
        Ok(resources)
    }

    /// Collect EC2 instances
    async fn collect_ec2_instances(&self, regions: &[String]) -> anyhow::Result<Vec<CloudResource>> {
        debug!("Collecting EC2 instances");
        let mut resources = Vec::new();

        let instances = self.ec2.describe_instances().send().await?;

        for reservation in instances.reservations().unwrap_or_default() {
            for instance in reservation.instances().unwrap_or_default() {
                let instance_id = instance.instance_id().unwrap_or_default();

                let mut metadata = HashMap::new();

                // Public IP
                if let Some(public_ip) = instance.public_ip_address() {
                    metadata.insert(
                        "public_ip".to_string(),
                        serde_json::Value::String(public_ip.to_string()),
                    );
                }

                // Private IP
                if let Some(private_ip) = instance.private_ip_address() {
                    metadata.insert(
                        "private_ip".to_string(),
                        serde_json::Value::String(private_ip.to_string()),
                    );
                }

                // Instance type
                if let Some(instance_type) = instance.instance_type() {
                    metadata.insert(
                        "instance_type".to_string(),
                        serde_json::Value::String(format!("{:?}", instance_type)),
                    );
                }

                // State
                if let Some(state) = instance.state() {
                    if let Some(state_name) = state.name() {
                        metadata.insert(
                            "state".to_string(),
                            serde_json::Value::String(format!("{:?}", state_name)),
                        );
                    }
                }

                // Security groups
                let sg_ids: Vec<String> = instance
                    .security_groups()
                    .iter()
                    .filter_map(|sg| sg.group_id().map(String::from))
                    .collect();
                metadata.insert(
                    "security_groups".to_string(),
                    serde_json::Value::Array(sg_ids.into_iter().map(serde_json::Value::String).collect()),
                );

                // Tags
                let tags: HashMap<String, String> = instance
                    .tags()
                    .iter()
                    .map(|t| {
                        (
                            t.key().unwrap_or_default().to_string(),
                            t.value().unwrap_or_default().to_string(),
                        )
                    })
                    .collect();

                let name = tags.get("Name").cloned().unwrap_or_else(|| instance_id.to_string());

                resources.push(CloudResource {
                    id: instance_id.to_string(),
                    arn: Some(format!(
                        "arn:aws:ec2:{}:{}:instance/{}",
                        self.config.region, self.config.account_id, instance_id
                    )),
                    resource_type: "aws:ec2:instance".to_string(),
                    name,
                    region: self.config.region.clone(),
                    tags,
                    created_at: instance.launch_time().map(|t| t.to_string()),
                    metadata,
                });
            }
        }

        debug!("Found {} EC2 instances", resources.len());
        Ok(resources)
    }

    /// Collect security groups
    async fn collect_security_groups(&self, _regions: &[String]) -> anyhow::Result<Vec<CloudResource>> {
        debug!("Collecting security groups");
        let mut resources = Vec::new();

        let sgs = self.ec2.describe_security_groups().send().await?;

        for sg in sgs.security_groups().unwrap_or_default() {
            let sg_id = sg.group_id().unwrap_or_default();

            let mut metadata = HashMap::new();

            // Ingress rules
            let ingress_rules: Vec<serde_json::Value> = sg
                .ip_permissions()
                .iter()
                .flat_map(|perm| {
                    perm.ip_ranges().iter().map(move |range| {
                        serde_json::json!({
                            "cidr": range.cidr_ip().unwrap_or_default(),
                            "port": perm.from_port().unwrap_or_default(),
                            "protocol": perm.ip_protocol().unwrap_or_default(),
                        })
                    })
                })
                .collect();

            metadata.insert(
                "ingress_rules".to_string(),
                serde_json::Value::Array(ingress_rules),
            );

            // Egress rules
            let egress_rules: Vec<serde_json::Value> = sg
                .ip_permissions_egress()
                .iter()
                .flat_map(|perm| {
                    perm.ip_ranges().iter().map(move |range| {
                        serde_json::json!({
                            "cidr": range.cidr_ip().unwrap_or_default(),
                            "port": perm.from_port().unwrap_or_default(),
                            "protocol": perm.ip_protocol().unwrap_or_default(),
                        })
                    })
                })
                .collect();

            metadata.insert(
                "egress_rules".to_string(),
                serde_json::Value::Array(egress_rules),
            );

            // VPC ID
            if let Some(vpc_id) = sg.vpc_id() {
                metadata.insert(
                    "vpc_id".to_string(),
                    serde_json::Value::String(vpc_id.to_string()),
                );
            }

            // Tags
            let tags: HashMap<String, String> = sg
                .tags()
                .iter()
                .map(|t| {
                    (
                        t.key().unwrap_or_default().to_string(),
                        t.value().unwrap_or_default().to_string(),
                    )
                })
                .collect();

            let name = sg.group_name().unwrap_or(sg_id).to_string();

            resources.push(CloudResource {
                id: sg_id.to_string(),
                arn: Some(format!(
                    "arn:aws:ec2:{}:{}:security-group/{}",
                    self.config.region, self.config.account_id, sg_id
                )),
                resource_type: "aws:ec2:security-group".to_string(),
                name,
                region: self.config.region.clone(),
                tags,
                created_at: None,
                metadata,
            });
        }

        debug!("Found {} security groups", resources.len());
        Ok(resources)
    }

    /// Collect IAM resources
    async fn collect_iam_resources(&self) -> anyhow::Result<Vec<CloudResource>> {
        debug!("Collecting IAM resources");
        let mut resources = Vec::new();

        // Get password policy
        match self.iam.get_account_password_policy().send().await {
            Ok(policy) => {
                if let Some(pp) = policy.password_policy() {
                    let mut metadata = HashMap::new();
                    metadata.insert(
                        "minimum_length".to_string(),
                        serde_json::Value::Number(pp.minimum_password_length().into()),
                    );
                    metadata.insert(
                        "require_uppercase".to_string(),
                        serde_json::Value::Bool(pp.require_uppercase_characters()),
                    );
                    metadata.insert(
                        "require_lowercase".to_string(),
                        serde_json::Value::Bool(pp.require_lowercase_characters()),
                    );
                    metadata.insert(
                        "require_numbers".to_string(),
                        serde_json::Value::Bool(pp.require_numbers()),
                    );
                    metadata.insert(
                        "require_symbols".to_string(),
                        serde_json::Value::Bool(pp.require_symbols()),
                    );
                    if let Some(max_age) = pp.max_password_age() {
                        metadata.insert(
                            "max_password_age".to_string(),
                            serde_json::Value::Number(max_age.into()),
                        );
                    }

                    resources.push(CloudResource {
                        id: "password-policy".to_string(),
                        arn: Some(format!(
                            "arn:aws:iam::{}:password-policy",
                            self.config.account_id
                        )),
                        resource_type: "aws:iam:password-policy".to_string(),
                        name: "Password Policy".to_string(),
                        region: "global".to_string(),
                        tags: HashMap::new(),
                        created_at: None,
                        metadata,
                    });
                }
            }
            Err(e) => {
                debug!("No password policy: {}", e);
            }
        }

        // Get account summary for root MFA status
        match self.iam.get_account_summary().send().await {
            Ok(summary) => {
                if let Some(summary_map) = summary.summary_map() {
                    let mfa_enabled = summary_map
                        .get(&aws_sdk_iam::types::SummaryKeyType::AccountMfaEnabled)
                        .copied()
                        .unwrap_or(0)
                        > 0;

                    let mut metadata = HashMap::new();
                    metadata.insert(
                        "mfa_enabled".to_string(),
                        serde_json::Value::Bool(mfa_enabled),
                    );

                    resources.push(CloudResource {
                        id: "root".to_string(),
                        arn: Some(format!("arn:aws:iam::{}:root", self.config.account_id)),
                        resource_type: "aws:iam:root".to_string(),
                        name: "Root Account".to_string(),
                        region: "global".to_string(),
                        tags: HashMap::new(),
                        created_at: None,
                        metadata,
                    });
                }
            }
            Err(e) => {
                warn!("Failed to get account summary: {}", e);
            }
        }

        debug!("Found {} IAM resources", resources.len());
        Ok(resources)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests would require AWS credentials
    // Unit tests focus on check logic
}
