//! Web crawler for endpoint discovery

use crate::client::HttpClient;
use crate::ScanConfig;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use tracing::{debug, warn};
use url::Url;

/// Discovered web endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    /// Full URL
    pub url: String,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// URL parameters
    pub parameters: Vec<Parameter>,
    /// Crawl depth
    pub depth: u32,
    /// Response status code
    pub status: Option<u16>,
    /// Content type
    pub content_type: Option<String>,
}

/// URL or form parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    /// Parameter name
    pub name: String,
    /// Parameter location (query, body, path)
    pub location: ParameterLocation,
    /// Example value if found
    pub example_value: Option<String>,
    /// Is parameter required
    pub required: bool,
}

/// Where the parameter is located
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParameterLocation {
    Query,
    Body,
    Path,
    Header,
    Cookie,
}

/// Discovered HTML form
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    /// Form action URL
    pub action: String,
    /// HTTP method
    pub method: String,
    /// Form inputs
    pub inputs: Vec<FormInput>,
    /// Page where form was found
    pub found_on: String,
}

/// Form input field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormInput {
    /// Input name
    pub name: String,
    /// Input type (text, password, hidden, etc.)
    pub input_type: String,
    /// Default value
    pub value: Option<String>,
    /// Is required
    pub required: bool,
}

/// Result of crawling
#[derive(Debug, Clone, Default)]
pub struct CrawlResult {
    /// Discovered pages
    pub pages: Vec<DiscoveredEndpoint>,
    /// Discovered forms
    pub forms: Vec<DiscoveredForm>,
    /// All discovered parameters
    pub parameters: Vec<Parameter>,
    /// JavaScript files found
    pub js_files: Vec<String>,
    /// API endpoints found
    pub api_endpoints: Vec<String>,
    /// Total requests made
    pub requests_made: u32,
}

/// Web crawler
#[allow(dead_code)]
pub struct Crawler<'a> {
    config: &'a ScanConfig,
    client: &'a HttpClient,
    visited: HashSet<String>,
    base_domain: String,
}

impl<'a> Crawler<'a> {
    /// Create a new crawler
    pub fn new(config: &'a ScanConfig, client: &'a HttpClient) -> Self {
        Self {
            config,
            client,
            visited: HashSet::new(),
            base_domain: String::new(),
        }
    }

    /// Crawl a website starting from the given URL
    pub async fn crawl(&self, start_url: &str) -> anyhow::Result<CrawlResult> {
        let mut result = CrawlResult::default();
        let mut queue: VecDeque<(String, u32)> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();

        // Parse base URL
        let base_url = Url::parse(start_url)?;
        let base_domain = base_url.host_str().unwrap_or("").to_string();

        // Check robots.txt if configured
        let disallowed_paths: HashSet<String> = if self.config.respect_robots {
            if let Some(robots) = self.client.get_robots_txt(start_url).await {
                crate::client::parse_robots_txt(&robots)
                    .into_iter()
                    .collect()
            } else {
                HashSet::new()
            }
        } else {
            HashSet::new()
        };

        queue.push_back((start_url.to_string(), 0));

        while let Some((url, depth)) = queue.pop_front() {
            // Check limits
            if visited.len() >= self.config.max_pages as usize {
                debug!("Max pages limit reached");
                break;
            }

            if depth > self.config.max_depth {
                continue;
            }

            // Normalize URL
            let normalized = normalize_url(&url);
            if visited.contains(&normalized) {
                continue;
            }

            // Check if path is disallowed by robots.txt
            if let Ok(parsed) = Url::parse(&url) {
                let path = parsed.path();
                if disallowed_paths.iter().any(|d| path.starts_with(d)) {
                    debug!("Skipping disallowed path: {}", path);
                    continue;
                }
            }

            visited.insert(normalized.clone());

            // Add delay between requests
            if self.config.request_delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    self.config.request_delay_ms,
                ))
                .await;
            }

            // Fetch page
            debug!("Crawling: {} (depth {})", url, depth);
            let response = match self.client.get(&url).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to fetch {}: {}", url, e);
                    continue;
                }
            };

            result.requests_made += 1;

            // Extract URL parameters
            let mut params = Vec::new();
            if let Ok(parsed) = Url::parse(&url) {
                for (name, value) in parsed.query_pairs() {
                    params.push(Parameter {
                        name: name.to_string(),
                        location: ParameterLocation::Query,
                        example_value: Some(value.to_string()),
                        required: false,
                    });
                }
            }

            // Add endpoint
            result.pages.push(DiscoveredEndpoint {
                url: url.clone(),
                method: "GET".to_string(),
                parameters: params.clone(),
                depth,
                status: Some(response.status),
                content_type: response.content_type().map(String::from),
            });

            result.parameters.extend(params);

            // Parse HTML content
            if response.is_html() {
                let links = self.extract_links(&response.body, &base_url);
                let forms = self.extract_forms(&response.body, &url, &base_url);
                let js_files = self.extract_js_files(&response.body, &base_url);

                // Add discovered forms
                for form in forms {
                    // Extract form parameters
                    for input in &form.inputs {
                        result.parameters.push(Parameter {
                            name: input.name.clone(),
                            location: ParameterLocation::Body,
                            example_value: input.value.clone(),
                            required: input.required,
                        });
                    }
                    result.forms.push(form);
                }

                // Add JS files
                result.js_files.extend(js_files);

                // Add links to queue
                for link in links {
                    // Only follow same-domain links
                    if let Ok(parsed) = Url::parse(&link) {
                        if parsed.host_str() == Some(&base_domain) {
                            queue.push_back((link, depth + 1));
                        }
                    }
                }
            }

            // Look for API endpoints
            let api_endpoints = self.find_api_endpoints(&response.body);
            result.api_endpoints.extend(api_endpoints);
        }

        Ok(result)
    }

    /// Extract links from HTML
    fn extract_links(&self, html: &str, base_url: &Url) -> Vec<String> {
        let document = Html::parse_document(html);
        let mut links = Vec::new();

        // Select all anchor tags
        let selector = Selector::parse("a[href]").unwrap();
        for element in document.select(&selector) {
            if let Some(href) = element.value().attr("href") {
                if let Some(absolute) = resolve_url(href, base_url) {
                    links.push(absolute);
                }
            }
        }

        // Also get URLs from other elements
        for tag in &["link", "script", "img", "iframe", "form"] {
            let attr = if *tag == "form" { "action" } else { "src" };
            let attr_selector = format!("{}[{}]", tag, attr);
            let selector = match Selector::parse(&attr_selector) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for element in document.select(&selector) {
                if let Some(url) = element.value().attr(attr) {
                    if let Some(absolute) = resolve_url(url, base_url) {
                        links.push(absolute);
                    }
                }
            }
        }

        links
    }

    /// Extract forms from HTML
    fn extract_forms(&self, html: &str, page_url: &str, base_url: &Url) -> Vec<DiscoveredForm> {
        let document = Html::parse_document(html);
        let mut forms = Vec::new();

        let form_selector = Selector::parse("form").unwrap();
        let input_selector = Selector::parse("input, select, textarea").unwrap();

        for form in document.select(&form_selector) {
            let action = form
                .value()
                .attr("action")
                .map(|a| resolve_url(a, base_url).unwrap_or_else(|| a.to_string()))
                .unwrap_or_else(|| page_url.to_string());

            let method = form.value().attr("method").unwrap_or("GET").to_uppercase();

            let mut inputs = Vec::new();
            for input in form.select(&input_selector) {
                let name = input.value().attr("name").unwrap_or_default().to_string();
                if name.is_empty() {
                    continue;
                }

                let input_type = input.value().attr("type").unwrap_or("text").to_string();

                let value = input.value().attr("value").map(String::from);
                let required = input.value().attr("required").is_some();

                inputs.push(FormInput {
                    name,
                    input_type,
                    value,
                    required,
                });
            }

            forms.push(DiscoveredForm {
                action,
                method,
                inputs,
                found_on: page_url.to_string(),
            });
        }

        forms
    }

    /// Extract JavaScript file URLs
    fn extract_js_files(&self, html: &str, base_url: &Url) -> Vec<String> {
        let document = Html::parse_document(html);
        let mut js_files = Vec::new();

        let selector = Selector::parse("script[src]").unwrap();
        for element in document.select(&selector) {
            if let Some(src) = element.value().attr("src") {
                if let Some(absolute) = resolve_url(src, base_url) {
                    js_files.push(absolute);
                }
            }
        }

        js_files
    }

    /// Find potential API endpoints in content
    fn find_api_endpoints(&self, content: &str) -> Vec<String> {
        let mut endpoints = Vec::new();

        // Common API path patterns
        let patterns = [
            r#"["'](/api/[^"'\s]+)["']"#,
            r#"["'](/v\d+/[^"'\s]+)["']"#,
            r#"["'](/graphql[^"'\s]*)["']"#,
            r#"["'](/rest/[^"'\s]+)["']"#,
            r#"fetch\s*\(\s*["']([^"']+)["']"#,
            r#"axios\.[a-z]+\s*\(\s*["']([^"']+)["']"#,
            r#"\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["']"#,
        ];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(m) = cap.get(1) {
                        endpoints.push(m.as_str().to_string());
                    }
                }
            }
        }

        endpoints
    }
}

/// Normalize URL for comparison
fn normalize_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        // Remove fragment
        parsed.set_fragment(None);
        // Sort query parameters
        parsed.to_string()
    } else {
        url.to_string()
    }
}

/// Resolve relative URL to absolute
fn resolve_url(href: &str, base: &Url) -> Option<String> {
    let href = href.trim();

    // Skip javascript: and data: URLs
    if href.starts_with("javascript:")
        || href.starts_with("data:")
        || href.starts_with("mailto:")
        || href.starts_with("#")
    {
        return None;
    }

    // Parse relative to base
    base.join(href).ok().map(|u| u.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("https://example.com/page#section"),
            "https://example.com/page"
        );
    }

    #[test]
    fn test_resolve_url() {
        let base = Url::parse("https://example.com/path/page").unwrap();

        assert_eq!(
            resolve_url("/absolute", &base),
            Some("https://example.com/absolute".to_string())
        );
        assert_eq!(
            resolve_url("relative", &base),
            Some("https://example.com/path/relative".to_string())
        );
        assert_eq!(resolve_url("javascript:void(0)", &base), None);
        assert_eq!(resolve_url("#fragment", &base), None);
    }
}
