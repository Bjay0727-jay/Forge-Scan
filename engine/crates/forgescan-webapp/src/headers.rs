//! Security header analysis

use crate::client::HttpResponse;
use crate::OwaspCategory;
use forgescan_core::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Security header analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderAnalysis {
    /// Content-Security-Policy
    pub csp: HeaderStatus,
    /// X-Frame-Options
    pub x_frame_options: HeaderStatus,
    /// X-Content-Type-Options
    pub x_content_type_options: HeaderStatus,
    /// X-XSS-Protection
    pub x_xss_protection: HeaderStatus,
    /// Strict-Transport-Security
    pub hsts: HeaderStatus,
    /// Referrer-Policy
    pub referrer_policy: HeaderStatus,
    /// Permissions-Policy (formerly Feature-Policy)
    pub permissions_policy: HeaderStatus,
    /// X-Permitted-Cross-Domain-Policies
    pub x_permitted_cross_domain: HeaderStatus,
    /// Cache-Control
    pub cache_control: HeaderStatus,
    /// Server header (information disclosure)
    pub server: HeaderStatus,
    /// X-Powered-By (information disclosure)
    pub x_powered_by: HeaderStatus,
    /// Cross-Origin-Opener-Policy
    pub coop: HeaderStatus,
    /// Cross-Origin-Embedder-Policy
    pub coep: HeaderStatus,
    /// Cross-Origin-Resource-Policy
    pub corp: HeaderStatus,
}

/// Status of a security header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderStatus {
    /// Header name
    pub name: String,
    /// Header value if present
    pub value: Option<String>,
    /// Status
    pub status: HeaderCheckStatus,
    /// Recommendation
    pub recommendation: Option<String>,
}

/// Header check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeaderCheckStatus {
    /// Header is present and correctly configured
    Present,
    /// Header is missing
    Missing,
    /// Header has insecure value
    Insecure,
    /// Header should not be present (information disclosure)
    ShouldNotBePresent,
}

/// Security headers analyzer
pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Analyze security headers from HTTP response
    pub fn analyze(response: &HttpResponse) -> HeaderAnalysis {
        HeaderAnalysis {
            csp: Self::check_csp(response),
            x_frame_options: Self::check_x_frame_options(response),
            x_content_type_options: Self::check_x_content_type_options(response),
            x_xss_protection: Self::check_x_xss_protection(response),
            hsts: Self::check_hsts(response),
            referrer_policy: Self::check_referrer_policy(response),
            permissions_policy: Self::check_permissions_policy(response),
            x_permitted_cross_domain: Self::check_x_permitted_cross_domain(response),
            cache_control: Self::check_cache_control(response),
            server: Self::check_server(response),
            x_powered_by: Self::check_x_powered_by(response),
            coop: Self::check_coop(response),
            coep: Self::check_coep(response),
            corp: Self::check_corp(response),
        }
    }

    fn check_csp(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("content-security-policy");
        let report_only = response.header("content-security-policy-report-only");

        match (value, report_only) {
            (Some(v), _) => {
                // Check for unsafe directives
                if v.contains("'unsafe-inline'") || v.contains("'unsafe-eval'") {
                    HeaderStatus {
                        name: "Content-Security-Policy".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Insecure,
                        recommendation: Some(
                            "Remove 'unsafe-inline' and 'unsafe-eval' from CSP".into(),
                        ),
                    }
                } else {
                    HeaderStatus {
                        name: "Content-Security-Policy".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: None,
                    }
                }
            }
            (None, Some(v)) => HeaderStatus {
                name: "Content-Security-Policy".into(),
                value: Some(format!("Report-Only: {}", v)),
                status: HeaderCheckStatus::Insecure,
                recommendation: Some("CSP is in report-only mode, enable enforcement".into()),
            },
            _ => HeaderStatus {
                name: "Content-Security-Policy".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add Content-Security-Policy header to prevent XSS attacks".into(),
                ),
            },
        }
    }

    fn check_x_frame_options(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("x-frame-options");

        match value {
            Some(v) => {
                let v_upper = v.to_uppercase();
                if v_upper == "DENY" || v_upper == "SAMEORIGIN" {
                    HeaderStatus {
                        name: "X-Frame-Options".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: None,
                    }
                } else {
                    HeaderStatus {
                        name: "X-Frame-Options".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Insecure,
                        recommendation: Some("Set X-Frame-Options to DENY or SAMEORIGIN".into()),
                    }
                }
            }
            None => HeaderStatus {
                name: "X-Frame-Options".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add X-Frame-Options header to prevent clickjacking".into(),
                ),
            },
        }
    }

    fn check_x_content_type_options(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("x-content-type-options");

        match value {
            Some(v) if v.to_lowercase() == "nosniff" => HeaderStatus {
                name: "X-Content-Type-Options".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Present,
                recommendation: None,
            },
            Some(v) => HeaderStatus {
                name: "X-Content-Type-Options".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Insecure,
                recommendation: Some("Set X-Content-Type-Options to 'nosniff'".into()),
            },
            None => HeaderStatus {
                name: "X-Content-Type-Options".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add X-Content-Type-Options: nosniff to prevent MIME sniffing".into(),
                ),
            },
        }
    }

    fn check_x_xss_protection(response: &HttpResponse) -> HeaderStatus {
        // Note: This header is deprecated in modern browsers
        let value = response.header("x-xss-protection");

        match value {
            Some(v) => {
                if v.contains("1") && v.contains("block") {
                    HeaderStatus {
                        name: "X-XSS-Protection".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: Some(
                            "X-XSS-Protection is deprecated, use CSP instead".into(),
                        ),
                    }
                } else if v == "0" {
                    // Explicitly disabled is ok if CSP is present
                    HeaderStatus {
                        name: "X-XSS-Protection".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: None,
                    }
                } else {
                    HeaderStatus {
                        name: "X-XSS-Protection".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Insecure,
                        recommendation: Some(
                            "Set X-XSS-Protection to '1; mode=block' or '0' with CSP".into(),
                        ),
                    }
                }
            }
            None => HeaderStatus {
                name: "X-XSS-Protection".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add X-XSS-Protection header (or rely on CSP in modern browsers)".into(),
                ),
            },
        }
    }

    fn check_hsts(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("strict-transport-security");

        match value {
            Some(v) => {
                // Check max-age
                let has_good_max_age = v
                    .split(';')
                    .find(|p| p.trim().starts_with("max-age"))
                    .and_then(|p| p.split('=').nth(1))
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(|age| age >= 31536000) // 1 year
                    .unwrap_or(false);

                let has_subdomains = v.to_lowercase().contains("includesubdomains");
                let has_preload = v.to_lowercase().contains("preload");

                if has_good_max_age && has_subdomains {
                    HeaderStatus {
                        name: "Strict-Transport-Security".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: if !has_preload {
                            Some("Consider adding 'preload' directive for HSTS preload list".into())
                        } else {
                            None
                        },
                    }
                } else {
                    HeaderStatus {
                        name: "Strict-Transport-Security".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Insecure,
                        recommendation: Some(
                            "Set max-age to at least 31536000 and include includeSubDomains".into(),
                        ),
                    }
                }
            }
            None => HeaderStatus {
                name: "Strict-Transport-Security".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add HSTS header to enforce HTTPS connections".into(),
                ),
            },
        }
    }

    fn check_referrer_policy(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("referrer-policy");
        let safe_policies = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ];

        match value {
            Some(v) => {
                if safe_policies.iter().any(|p| v.to_lowercase().contains(p)) {
                    HeaderStatus {
                        name: "Referrer-Policy".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: None,
                    }
                } else {
                    HeaderStatus {
                        name: "Referrer-Policy".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Insecure,
                        recommendation: Some(
                            "Use a restrictive Referrer-Policy like 'strict-origin-when-cross-origin'".into(),
                        ),
                    }
                }
            }
            None => HeaderStatus {
                name: "Referrer-Policy".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add Referrer-Policy header to control referrer information".into(),
                ),
            },
        }
    }

    fn check_permissions_policy(response: &HttpResponse) -> HeaderStatus {
        let value = response
            .header("permissions-policy")
            .or_else(|| response.header("feature-policy"));

        match value {
            Some(v) => HeaderStatus {
                name: "Permissions-Policy".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Present,
                recommendation: None,
            },
            None => HeaderStatus {
                name: "Permissions-Policy".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add Permissions-Policy to control browser features".into(),
                ),
            },
        }
    }

    fn check_x_permitted_cross_domain(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("x-permitted-cross-domain-policies");

        match value {
            Some(v) if v.to_lowercase() == "none" => HeaderStatus {
                name: "X-Permitted-Cross-Domain-Policies".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Present,
                recommendation: None,
            },
            Some(v) => HeaderStatus {
                name: "X-Permitted-Cross-Domain-Policies".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Insecure,
                recommendation: Some("Set to 'none' to prevent Flash/PDF cross-domain access".into()),
            },
            None => HeaderStatus {
                name: "X-Permitted-Cross-Domain-Policies".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some("Add header to prevent Flash/PDF cross-domain access".into()),
            },
        }
    }

    fn check_cache_control(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("cache-control");

        match value {
            Some(v) => {
                let v_lower = v.to_lowercase();
                if v_lower.contains("no-store") || v_lower.contains("private") {
                    HeaderStatus {
                        name: "Cache-Control".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: None,
                    }
                } else {
                    HeaderStatus {
                        name: "Cache-Control".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Insecure,
                        recommendation: Some(
                            "For sensitive pages, use 'no-store' or 'private'".into(),
                        ),
                    }
                }
            }
            None => HeaderStatus {
                name: "Cache-Control".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some("Add Cache-Control header for sensitive content".into()),
            },
        }
    }

    fn check_server(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("server");

        match value {
            Some(v) => {
                // Check if server header reveals version info
                let reveals_version = v.chars().any(|c| c.is_numeric())
                    || v.to_lowercase().contains("version");

                if reveals_version {
                    HeaderStatus {
                        name: "Server".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::ShouldNotBePresent,
                        recommendation: Some(
                            "Remove version information from Server header".into(),
                        ),
                    }
                } else {
                    HeaderStatus {
                        name: "Server".into(),
                        value: Some(v.clone()),
                        status: HeaderCheckStatus::Present,
                        recommendation: Some(
                            "Consider removing or obfuscating Server header".into(),
                        ),
                    }
                }
            }
            None => HeaderStatus {
                name: "Server".into(),
                value: None,
                status: HeaderCheckStatus::Present, // Good - not present
                recommendation: None,
            },
        }
    }

    fn check_x_powered_by(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("x-powered-by");

        match value {
            Some(v) => HeaderStatus {
                name: "X-Powered-By".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::ShouldNotBePresent,
                recommendation: Some(
                    "Remove X-Powered-By header to prevent information disclosure".into(),
                ),
            },
            None => HeaderStatus {
                name: "X-Powered-By".into(),
                value: None,
                status: HeaderCheckStatus::Present, // Good - not present
                recommendation: None,
            },
        }
    }

    fn check_coop(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("cross-origin-opener-policy");

        match value {
            Some(v) => HeaderStatus {
                name: "Cross-Origin-Opener-Policy".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Present,
                recommendation: None,
            },
            None => HeaderStatus {
                name: "Cross-Origin-Opener-Policy".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add COOP header for cross-origin isolation".into(),
                ),
            },
        }
    }

    fn check_coep(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("cross-origin-embedder-policy");

        match value {
            Some(v) => HeaderStatus {
                name: "Cross-Origin-Embedder-Policy".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Present,
                recommendation: None,
            },
            None => HeaderStatus {
                name: "Cross-Origin-Embedder-Policy".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add COEP header for cross-origin isolation".into(),
                ),
            },
        }
    }

    fn check_corp(response: &HttpResponse) -> HeaderStatus {
        let value = response.header("cross-origin-resource-policy");

        match value {
            Some(v) => HeaderStatus {
                name: "Cross-Origin-Resource-Policy".into(),
                value: Some(v.clone()),
                status: HeaderCheckStatus::Present,
                recommendation: None,
            },
            None => HeaderStatus {
                name: "Cross-Origin-Resource-Policy".into(),
                value: None,
                status: HeaderCheckStatus::Missing,
                recommendation: Some(
                    "Add CORP header to control resource loading".into(),
                ),
            },
        }
    }
}

impl HeaderAnalysis {
    /// Convert analysis to security findings
    pub fn to_findings(&self, url: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        let headers = [
            &self.csp,
            &self.x_frame_options,
            &self.x_content_type_options,
            &self.hsts,
            &self.referrer_policy,
            &self.server,
            &self.x_powered_by,
        ];

        for header in headers {
            if let Some(finding) = header_to_finding(header, url) {
                findings.push(finding);
            }
        }

        findings
    }

    /// Get security score (0-100)
    pub fn score(&self) -> u32 {
        let headers = [
            (&self.csp, 15),
            (&self.x_frame_options, 10),
            (&self.x_content_type_options, 10),
            (&self.hsts, 15),
            (&self.referrer_policy, 10),
            (&self.permissions_policy, 10),
            (&self.server, 10),
            (&self.x_powered_by, 10),
            (&self.coop, 5),
            (&self.coep, 5),
        ];

        let mut score = 0;
        for (header, weight) in headers {
            match header.status {
                HeaderCheckStatus::Present => score += weight,
                HeaderCheckStatus::Missing => {}
                HeaderCheckStatus::Insecure => score += weight / 2,
                HeaderCheckStatus::ShouldNotBePresent => {}
            }
        }

        score
    }
}

fn header_to_finding(header: &HeaderStatus, url: &str) -> Option<Finding> {
    match header.status {
        HeaderCheckStatus::Missing => Some(Finding::new(
            format!("Missing {} header", header.name),
            Severity::Medium,
        )
        .with_description(
            header
                .recommendation
                .clone()
                .unwrap_or_else(|| format!("{} header is not set", header.name)),
        )
        .with_affected_asset(url)),

        HeaderCheckStatus::Insecure => Some(Finding::new(
            format!("Insecure {} header configuration", header.name),
            Severity::Medium,
        )
        .with_description(header.recommendation.clone().unwrap_or_default())
        .with_affected_asset(url)
        .with_evidence(format!(
            "Current value: {}",
            header.value.as_deref().unwrap_or("N/A")
        ))),

        HeaderCheckStatus::ShouldNotBePresent => Some(Finding::new(
            format!("{} header reveals information", header.name),
            Severity::Low,
        )
        .with_description(header.recommendation.clone().unwrap_or_default())
        .with_affected_asset(url)
        .with_evidence(format!(
            "Value: {}",
            header.value.as_deref().unwrap_or("N/A")
        ))),

        HeaderCheckStatus::Present => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_header_analysis() {
        let response = HttpResponse {
            status: 200,
            headers: [
                ("content-security-policy".to_string(), "default-src 'self'".to_string()),
                ("x-frame-options".to_string(), "DENY".to_string()),
                ("x-content-type-options".to_string(), "nosniff".to_string()),
                ("strict-transport-security".to_string(), "max-age=31536000; includeSubDomains".to_string()),
            ].into_iter().collect(),
            body: String::new(),
            final_url: "https://example.com".to_string(),
            response_time_ms: 100,
            tls_version: None,
        };

        let analysis = SecurityHeaders::analyze(&response);

        assert_eq!(analysis.csp.status, HeaderCheckStatus::Present);
        assert_eq!(analysis.x_frame_options.status, HeaderCheckStatus::Present);
        assert_eq!(analysis.x_content_type_options.status, HeaderCheckStatus::Present);
        assert_eq!(analysis.hsts.status, HeaderCheckStatus::Present);
    }

    #[test]
    fn test_score_calculation() {
        let response = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: String::new(),
            final_url: "https://example.com".to_string(),
            response_time_ms: 100,
            tls_version: None,
        };

        let analysis = SecurityHeaders::analyze(&response);
        // With no headers, score should be 0
        assert_eq!(analysis.score(), 0);
    }
}
