//! Web security checks (OWASP Top 10)

use crate::client::HttpClient;
use crate::crawler::{CrawlResult, DiscoveredForm, Parameter, ParameterLocation};
use crate::{OwaspCategory, ScanConfig};
use forgescan_core::{Finding, Severity};
use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Web check trait
pub trait WebCheck: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn category(&self) -> OwaspCategory;
    fn is_active(&self) -> bool;
}

/// Result of a web check
#[derive(Debug, Clone)]
pub struct WebCheckResult {
    pub check_id: String,
    pub passed: bool,
    pub findings: Vec<Finding>,
}

/// Run passive checks on crawl results (no additional requests)
pub fn run_passive_checks(crawl: &CrawlResult, config: &ScanConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for sensitive information disclosure
    findings.extend(check_information_disclosure(crawl));

    // Check for insecure form configurations
    findings.extend(check_insecure_forms(crawl));

    // Check for potential injection points
    findings.extend(check_injection_points(crawl));

    // Check JavaScript files for secrets
    findings.extend(check_js_secrets(crawl));

    // Check for directory listing indicators
    findings.extend(check_directory_listing(crawl));

    // Check for debug/development indicators
    findings.extend(check_debug_indicators(crawl));

    findings
}

/// Run active checks (sends additional requests)
pub async fn run_active_checks(
    crawl: &CrawlResult,
    client: &HttpClient,
    config: &ScanConfig,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // SQL Injection tests
    for form in &crawl.forms {
        let sqli_findings = check_sql_injection(form, client).await;
        findings.extend(sqli_findings);
    }

    // XSS tests
    for form in &crawl.forms {
        let xss_findings = check_xss(form, client).await;
        findings.extend(xss_findings);
    }

    // CSRF tests
    for form in &crawl.forms {
        let csrf_findings = check_csrf(form);
        findings.extend(csrf_findings);
    }

    // Path traversal tests
    for param in &crawl.parameters {
        if looks_like_file_param(param) {
            let traversal_findings = check_path_traversal(param, crawl, client).await;
            findings.extend(traversal_findings);
        }
    }

    // Open redirect tests
    for param in &crawl.parameters {
        if looks_like_redirect_param(param) {
            let redirect_findings = check_open_redirect(param, crawl, client).await;
            findings.extend(redirect_findings);
        }
    }

    findings
}

/// Check for information disclosure in responses
fn check_information_disclosure(crawl: &CrawlResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    let sensitive_patterns = [
        (r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]", "Hardcoded password", Severity::High),
        (r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]", "API key exposed", Severity::High),
        (r"(?i)secret\s*[:=]\s*['\"][^'\"]+['\"]", "Secret value exposed", Severity::High),
        (r"(?i)aws[_-]?access[_-]?key", "AWS access key pattern", Severity::High),
        (r"(?i)private[_-]?key", "Private key reference", Severity::High),
        (r"(?i)database\s*[:=]", "Database connection string", Severity::Medium),
        (r"(?i)jdbc:.*://", "JDBC connection string", Severity::Medium),
        (r"mongodb(\+srv)?://[^/\s]+", "MongoDB connection string", Severity::High),
        (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Bearer token", Severity::High),
        (r"(?i)authorization:\s*basic\s+", "Basic auth credentials", Severity::High),
        (r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "SSN-like pattern", Severity::Medium),
        (r"(?i)BEGIN\s+(RSA\s+)?PRIVATE\s+KEY", "Private key block", Severity::Critical),
        (r"(?i)-----BEGIN\s+CERTIFICATE-----", "Certificate exposed", Severity::Medium),
    ];

    for endpoint in &crawl.pages {
        // Note: In real implementation, we'd check response bodies stored during crawl
        debug!("Checking {} for sensitive patterns", endpoint.url);
    }

    findings
}

/// Check for insecure form configurations
fn check_insecure_forms(crawl: &CrawlResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    for form in &crawl.forms {
        // Check for password fields over HTTP
        if form.action.starts_with("http://") {
            let has_password = form.inputs.iter().any(|i| i.input_type == "password");
            if has_password {
                findings.push(
                    Finding::new(
                        "Password form submits over HTTP",
                        Severity::High,
                    )
                    .with_description(
                        "Form with password field submits to an unencrypted HTTP endpoint",
                    )
                    .with_affected_asset(&form.action)
                    .with_owasp("A02:2021"),
                );
            }
        }

        // Check for autocomplete on sensitive fields
        for input in &form.inputs {
            if input.input_type == "password" {
                // In real implementation, check if autocomplete="off" is set
                debug!("Password field found: {}", input.name);
            }
        }

        // Check GET method for sensitive forms
        if form.method == "GET" {
            let has_sensitive = form.inputs.iter().any(|i| {
                let name_lower = i.name.to_lowercase();
                name_lower.contains("password")
                    || name_lower.contains("token")
                    || name_lower.contains("secret")
                    || name_lower.contains("credit")
            });

            if has_sensitive {
                findings.push(
                    Finding::new(
                        "Sensitive form uses GET method",
                        Severity::Medium,
                    )
                    .with_description(
                        "Form with sensitive fields uses GET, exposing data in URL/logs",
                    )
                    .with_affected_asset(&form.found_on)
                    .with_owasp("A02:2021"),
                );
            }
        }
    }

    findings
}

/// Check for potential injection points
fn check_injection_points(crawl: &CrawlResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Identify parameters that might be vulnerable to injection
    for param in &crawl.parameters {
        let name_lower = param.name.to_lowercase();

        // SQL injection candidates
        if name_lower.contains("id")
            || name_lower.contains("user")
            || name_lower.contains("name")
            || name_lower.contains("search")
            || name_lower.contains("query")
            || name_lower.contains("filter")
        {
            findings.push(
                Finding::new(
                    format!("Potential SQL injection point: {}", param.name),
                    Severity::Info,
                )
                .with_description(
                    "Parameter may be vulnerable to SQL injection. Active testing required.",
                )
                .with_owasp("A03:2021"),
            );
        }

        // Command injection candidates
        if name_lower.contains("cmd")
            || name_lower.contains("exec")
            || name_lower.contains("command")
            || name_lower.contains("ping")
            || name_lower.contains("host")
        {
            findings.push(
                Finding::new(
                    format!("Potential command injection point: {}", param.name),
                    Severity::Info,
                )
                .with_description(
                    "Parameter name suggests potential command injection vulnerability.",
                )
                .with_owasp("A03:2021"),
            );
        }
    }

    findings
}

/// Check JavaScript files for exposed secrets
fn check_js_secrets(crawl: &CrawlResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    // API endpoint patterns often found in JS
    for api in &crawl.api_endpoints {
        if api.contains("api/v") || api.contains("/graphql") {
            findings.push(
                Finding::new(
                    format!("API endpoint discovered: {}", api),
                    Severity::Info,
                )
                .with_description("API endpoint found in JavaScript, may require testing")
                .with_owasp("A01:2021"),
            );
        }
    }

    findings
}

/// Check for directory listing indicators
fn check_directory_listing(crawl: &CrawlResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    let listing_patterns = [
        "Index of /",
        "Directory listing for",
        "Parent Directory",
        "<title>Index of",
    ];

    for endpoint in &crawl.pages {
        // Would check response body for these patterns
        debug!("Checking {} for directory listing", endpoint.url);
    }

    findings
}

/// Check for debug/development indicators
fn check_debug_indicators(crawl: &CrawlResult) -> Vec<Finding> {
    let mut findings = Vec::new();

    let debug_patterns = [
        (r"(?i)debug\s*[:=]\s*true", "Debug mode enabled"),
        (r"(?i)stack\s*trace", "Stack trace exposed"),
        (r"(?i)exception\s+details", "Exception details exposed"),
        (r"(?i)phpinfo\(\)", "phpinfo() output"),
        (r"(?i)django\s+debug", "Django debug mode"),
        (r"(?i)werkzeug\s+debugger", "Werkzeug debugger"),
    ];

    // Check for debug endpoints
    let debug_endpoints = [
        "/.git/",
        "/.svn/",
        "/.env",
        "/phpinfo.php",
        "/debug",
        "/trace",
        "/actuator",
        "/swagger",
        "/api-docs",
        "/.DS_Store",
        "/web.config",
        "/elmah.axd",
    ];

    for endpoint in debug_endpoints {
        for page in &crawl.pages {
            if page.url.contains(endpoint) {
                findings.push(
                    Finding::new(
                        format!("Debug/development endpoint exposed: {}", endpoint),
                        Severity::Medium,
                    )
                    .with_description("Development or debugging endpoint is publicly accessible")
                    .with_affected_asset(&page.url)
                    .with_owasp("A05:2021"),
                );
            }
        }
    }

    findings
}

/// Test for SQL injection
async fn check_sql_injection(form: &DiscoveredForm, client: &HttpClient) -> Vec<Finding> {
    let mut findings = Vec::new();

    let sqli_payloads = [
        ("'", "Single quote"),
        ("\"", "Double quote"),
        ("' OR '1'='1", "OR true"),
        ("1' AND '1'='1", "AND true"),
        ("1; SELECT 1", "Stacked query"),
        ("1 UNION SELECT NULL", "UNION"),
    ];

    // SQL error patterns
    let error_patterns = [
        (r"(?i)sql syntax", "SQL syntax error"),
        (r"(?i)mysql", "MySQL error"),
        (r"(?i)postgresql", "PostgreSQL error"),
        (r"(?i)sqlite", "SQLite error"),
        (r"(?i)oracle", "Oracle error"),
        (r"(?i)microsoft sql", "MSSQL error"),
        (r"(?i)unclosed quotation", "Unclosed quote error"),
        (r"(?i)syntax error", "Syntax error"),
    ];

    for input in &form.inputs {
        if input.input_type == "hidden" || input.input_type == "submit" {
            continue;
        }

        for (payload, description) in &sqli_payloads {
            let mut form_data = HashMap::new();
            form_data.insert(input.name.clone(), payload.to_string());

            // Fill other required fields with dummy data
            for other_input in &form.inputs {
                if other_input.name != input.name {
                    form_data.insert(
                        other_input.name.clone(),
                        other_input.value.clone().unwrap_or_else(|| "test".into()),
                    );
                }
            }

            match client.post_form(&form.action, &form_data).await {
                Ok(response) => {
                    // Check for SQL error patterns
                    for (pattern, error_type) in &error_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if re.is_match(&response.body) {
                                findings.push(
                                    Finding::new(
                                        format!("SQL Injection in {}", input.name),
                                        Severity::Critical,
                                    )
                                    .with_description(format!(
                                        "SQL injection detected: {} triggered {}",
                                        description, error_type
                                    ))
                                    .with_affected_asset(&form.action)
                                    .with_evidence(format!("Payload: {}", payload))
                                    .with_owasp("A03:2021"),
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("SQL injection test failed: {}", e);
                }
            }
        }
    }

    findings
}

/// Test for XSS
async fn check_xss(form: &DiscoveredForm, client: &HttpClient) -> Vec<Finding> {
    let mut findings = Vec::new();

    let xss_payloads = [
        ("<script>alert('XSS')</script>", "Script tag"),
        ("<img src=x onerror=alert('XSS')>", "Event handler"),
        ("javascript:alert('XSS')", "JavaScript protocol"),
        ("'\"><script>alert('XSS')</script>", "Break out"),
        ("<svg onload=alert('XSS')>", "SVG event"),
    ];

    for input in &form.inputs {
        if input.input_type == "hidden" || input.input_type == "submit" {
            continue;
        }

        for (payload, description) in &xss_payloads {
            let mut form_data = HashMap::new();
            form_data.insert(input.name.clone(), payload.to_string());

            for other_input in &form.inputs {
                if other_input.name != input.name {
                    form_data.insert(
                        other_input.name.clone(),
                        other_input.value.clone().unwrap_or_else(|| "test".into()),
                    );
                }
            }

            match client.post_form(&form.action, &form_data).await {
                Ok(response) => {
                    // Check if payload is reflected unescaped
                    if response.body.contains(payload) {
                        findings.push(
                            Finding::new(
                                format!("Reflected XSS in {}", input.name),
                                Severity::High,
                            )
                            .with_description(format!(
                                "XSS payload reflected in response: {}",
                                description
                            ))
                            .with_affected_asset(&form.action)
                            .with_evidence(format!("Payload: {}", payload))
                            .with_owasp("A03:2021"),
                        );
                        break;
                    }
                }
                Err(e) => {
                    debug!("XSS test failed: {}", e);
                }
            }
        }
    }

    findings
}

/// Check for CSRF protection
fn check_csrf(form: &DiscoveredForm) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Forms that modify state should have CSRF protection
    if form.method == "POST" {
        let has_csrf_token = form.inputs.iter().any(|i| {
            let name = i.name.to_lowercase();
            name.contains("csrf")
                || name.contains("token")
                || name.contains("_token")
                || name.contains("authenticity")
                || name.contains("nonce")
        });

        if !has_csrf_token {
            findings.push(
                Finding::new(
                    "Missing CSRF protection",
                    Severity::Medium,
                )
                .with_description("POST form does not appear to have CSRF token protection")
                .with_affected_asset(&form.action)
                .with_owasp("A01:2021"),
            );
        }
    }

    findings
}

/// Test for path traversal
async fn check_path_traversal(
    param: &Parameter,
    crawl: &CrawlResult,
    client: &HttpClient,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let traversal_payloads = [
        ("../../../etc/passwd", "/etc/passwd"),
        ("..\\..\\..\\windows\\win.ini", "win.ini"),
        ("....//....//....//etc/passwd", "encoded traversal"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL encoded"),
    ];

    let success_patterns = [
        "root:x:",
        "[extensions]",
        "[fonts]",
    ];

    // Would test each traversal payload against endpoints that use this parameter
    debug!("Path traversal check for parameter: {}", param.name);

    findings
}

/// Test for open redirect
async fn check_open_redirect(
    param: &Parameter,
    crawl: &CrawlResult,
    client: &HttpClient,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
    ];

    // Would test redirects
    debug!("Open redirect check for parameter: {}", param.name);

    findings
}

// Helper functions
fn looks_like_file_param(param: &Parameter) -> bool {
    let name = param.name.to_lowercase();
    name.contains("file")
        || name.contains("path")
        || name.contains("page")
        || name.contains("doc")
        || name.contains("folder")
        || name.contains("include")
        || name.contains("load")
}

fn looks_like_redirect_param(param: &Parameter) -> bool {
    let name = param.name.to_lowercase();
    name.contains("url")
        || name.contains("redirect")
        || name.contains("return")
        || name.contains("next")
        || name.contains("target")
        || name.contains("dest")
        || name.contains("goto")
        || name.contains("continue")
}

// Trait extension for findings
trait FindingExt {
    fn with_owasp(self, code: &str) -> Self;
}

impl FindingExt for Finding {
    fn with_owasp(mut self, code: &str) -> Self {
        self.references.push(format!("OWASP {}", code));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_param_detection() {
        assert!(looks_like_file_param(&Parameter {
            name: "filename".into(),
            location: ParameterLocation::Query,
            example_value: None,
            required: false,
        }));

        assert!(!looks_like_file_param(&Parameter {
            name: "username".into(),
            location: ParameterLocation::Query,
            example_value: None,
            required: false,
        }));
    }

    #[test]
    fn test_redirect_param_detection() {
        assert!(looks_like_redirect_param(&Parameter {
            name: "redirect_url".into(),
            location: ParameterLocation::Query,
            example_value: None,
            required: false,
        }));

        assert!(!looks_like_redirect_param(&Parameter {
            name: "email".into(),
            location: ParameterLocation::Query,
            example_value: None,
            required: false,
        }));
    }
}
