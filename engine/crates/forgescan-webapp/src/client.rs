//! HTTP client with security-focused configuration

use crate::{ScanConfig, WebAuth};
use reqwest::{header, Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::debug;

/// HTTP client errors
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Timeout after {0}s")]
    Timeout(u64),

    #[error("SSL/TLS error: {0}")]
    Tls(String),

    #[error("Authentication failed")]
    AuthFailed,
}

/// HTTP response wrapper
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: String,
    /// Final URL (after redirects)
    pub final_url: String,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// TLS version if HTTPS
    pub tls_version: Option<String>,
}

impl HttpResponse {
    /// Check if response is successful (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Check if response is redirect (3xx)
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Check if response is client error (4xx)
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }

    /// Check if response is server error (5xx)
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status)
    }

    /// Get header value (case-insensitive)
    pub fn header(&self, name: &str) -> Option<&String> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v)
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type").map(|s| s.as_str())
    }

    /// Check if response is HTML
    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false)
    }

    /// Check if response is JSON
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false)
    }
}

/// Security-focused HTTP client
pub struct HttpClient {
    client: Client,
    config: ScanConfig,
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration
    pub fn new(config: &ScanConfig) -> Self {
        let mut headers = header::HeaderMap::new();

        // Add custom headers
        for (name, value) in &config.custom_headers {
            if let (Ok(name), Ok(value)) = (
                header::HeaderName::from_bytes(name.as_bytes()),
                header::HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }

        // Build client with security-focused defaults
        let client = Client::builder()
            .user_agent(&config.user_agent)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .connect_timeout(Duration::from_secs(10))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(config.max_redirects as usize)
            } else {
                reqwest::redirect::Policy::none()
            })
            .default_headers(headers)
            // Don't accept invalid certs by default
            .danger_accept_invalid_certs(false)
            // Enable cookie store for session handling
            .cookie_store(true)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            config: config.clone(),
        }
    }

    /// Perform a GET request
    pub async fn get(&self, url: &str) -> Result<HttpResponse, ClientError> {
        self.request(reqwest::Method::GET, url, None, None).await
    }

    /// Perform a POST request with form data
    pub async fn post_form(
        &self,
        url: &str,
        form: &HashMap<String, String>,
    ) -> Result<HttpResponse, ClientError> {
        self.request(reqwest::Method::POST, url, Some(form), None)
            .await
    }

    /// Perform a POST request with JSON body
    pub async fn post_json(
        &self,
        url: &str,
        body: &str,
    ) -> Result<HttpResponse, ClientError> {
        self.request(reqwest::Method::POST, url, None, Some(body))
            .await
    }

    /// Perform a HEAD request
    pub async fn head(&self, url: &str) -> Result<HttpResponse, ClientError> {
        self.request(reqwest::Method::HEAD, url, None, None).await
    }

    /// Perform a custom request
    pub async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        form: Option<&HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<HttpResponse, ClientError> {
        use std::time::Instant;

        debug!("{} {}", method, url);
        let start = Instant::now();

        let mut request = self.client.request(method.clone(), url);

        // Add authentication
        if let Some(auth) = &self.config.auth {
            request = match auth {
                WebAuth::Basic { username, password } => request.basic_auth(username, Some(password)),
                WebAuth::Bearer { token } => request.bearer_auth(token),
                WebAuth::Cookie { name, value } => {
                    request.header(header::COOKIE, format!("{}={}", name, value))
                }
                WebAuth::Form { .. } => request, // Form auth handled separately
            };
        }

        // Add body
        if let Some(form_data) = form {
            request = request.form(form_data);
        } else if let Some(json_body) = body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(json_body.to_string());
        }

        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                ClientError::Timeout(self.config.timeout_seconds)
            } else if e.is_connect() {
                ClientError::ConnectionRefused
            } else {
                ClientError::Request(e)
            }
        })?;

        let response_time_ms = start.elapsed().as_millis() as u64;
        let status = response.status().as_u16();
        let final_url = response.url().to_string();

        // Extract headers
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(name.to_string(), v.to_string());
            }
        }

        // Get body
        let body = response.text().await.unwrap_or_default();

        Ok(HttpResponse {
            status,
            headers,
            body,
            final_url,
            response_time_ms,
            tls_version: None, // Set by TLS analyzer
        })
    }

    /// Perform form-based login
    pub async fn form_login(
        &self,
        login_url: &str,
        username_field: &str,
        password_field: &str,
        username: &str,
        password: &str,
    ) -> Result<HttpResponse, ClientError> {
        let mut form = HashMap::new();
        form.insert(username_field.to_string(), username.to_string());
        form.insert(password_field.to_string(), password.to_string());

        self.post_form(login_url, &form).await
    }

    /// Check if URL is reachable
    pub async fn is_reachable(&self, url: &str) -> bool {
        self.head(url).await.is_ok()
    }

    /// Get robots.txt content
    pub async fn get_robots_txt(&self, base_url: &str) -> Option<String> {
        let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));
        self.get(&robots_url)
            .await
            .ok()
            .filter(|r| r.is_success())
            .map(|r| r.body)
    }

    /// Get sitemap.xml content
    pub async fn get_sitemap(&self, base_url: &str) -> Option<String> {
        let sitemap_url = format!("{}/sitemap.xml", base_url.trim_end_matches('/'));
        self.get(&sitemap_url)
            .await
            .ok()
            .filter(|r| r.is_success())
            .map(|r| r.body)
    }
}

/// Common HTTP methods for testing
pub const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Parse robots.txt and extract disallowed paths
pub fn parse_robots_txt(content: &str) -> Vec<String> {
    let mut disallowed = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("Disallow:") {
            if let Some(path) = line.strip_prefix("Disallow:") {
                let path = path.trim();
                if !path.is_empty() {
                    disallowed.push(path.to_string());
                }
            }
        }
    }

    disallowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_robots_txt() {
        let robots = r#"
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
Sitemap: https://example.com/sitemap.xml
"#;
        let disallowed = parse_robots_txt(robots);
        assert_eq!(disallowed.len(), 2);
        assert!(disallowed.contains(&"/admin/".to_string()));
        assert!(disallowed.contains(&"/private/".to_string()));
    }

    #[test]
    fn test_response_helpers() {
        let response = HttpResponse {
            status: 200,
            headers: [("content-type".to_string(), "text/html".to_string())]
                .into_iter()
                .collect(),
            body: "<html></html>".to_string(),
            final_url: "https://example.com".to_string(),
            response_time_ms: 100,
            tls_version: None,
        };

        assert!(response.is_success());
        assert!(!response.is_redirect());
        assert!(response.is_html());
        assert!(!response.is_json());
    }
}
