//! Version matching engine for vulnerability detection
//!
//! Matches detected software versions against vulnerability database entries.

use forgescan_core::{CveInfo, Severity};
use forgescan_nvd::{compare_versions, Cpe, CpeMatch, NvdDb, VersionBoundType};
use tracing::debug;

/// Version matcher for correlating detected software with CVEs
pub struct VersionMatcher {
    db: NvdDb,
}

/// Result of a version match attempt
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Whether the version matches a vulnerable range
    pub is_vulnerable: bool,
    /// List of matching CVEs
    pub cves: Vec<CveInfo>,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Match details
    pub details: String,
}

impl VersionMatcher {
    /// Create a new version matcher with NVD database
    pub fn new(db: NvdDb) -> Self {
        Self { db }
    }

    /// Check if a detected service is vulnerable
    pub fn check_vulnerability(&self, vendor: &str, product: &str, version: &str) -> MatchResult {
        let cpe = Cpe::application(vendor, product, version);
        let cpe_string = cpe.to_cpe_string();

        debug!("Checking vulnerability for CPE: {}", cpe_string);

        let cves = self.db.find_vulnerabilities(&cpe_string, version);

        if cves.is_empty() {
            return MatchResult {
                is_vulnerable: false,
                cves: vec![],
                confidence: 90,
                details: format!(
                    "No known vulnerabilities for {} {} {}",
                    vendor, product, version
                ),
            };
        }

        let highest_cvss = cves
            .iter()
            .filter_map(|c| c.cvss_v3_score)
            .fold(0.0_f64, |a, b| a.max(b));

        MatchResult {
            is_vulnerable: true,
            cves,
            confidence: 85,
            details: format!(
                "{} {} {} has known vulnerabilities (highest CVSS: {:.1})",
                vendor, product, version, highest_cvss
            ),
        }
    }

    /// Match a CPE string against the vulnerability database
    pub fn match_cpe(&self, cpe_string: &str) -> MatchResult {
        let cpe = match Cpe::parse(cpe_string) {
            Ok(c) => c,
            Err(e) => {
                return MatchResult {
                    is_vulnerable: false,
                    cves: vec![],
                    confidence: 0,
                    details: format!("Invalid CPE: {}", e),
                };
            }
        };

        self.check_vulnerability(&cpe.vendor, &cpe.product, &cpe.version)
    }

    /// Check multiple version ranges for a product
    pub fn check_version_ranges(
        &self,
        vendor: &str,
        product: &str,
        version: &str,
        ranges: &[VersionRange],
    ) -> Vec<MatchResult> {
        ranges
            .iter()
            .filter(|range| self.version_in_range(version, range))
            .map(|range| {
                let cves = range
                    .cve_ids
                    .iter()
                    .filter_map(|id| self.db.get_cve(id))
                    .collect();

                MatchResult {
                    is_vulnerable: true,
                    cves,
                    confidence: 90,
                    details: format!(
                        "{} {} {} is in vulnerable range {} - {}",
                        vendor,
                        product,
                        version,
                        range.start.as_deref().unwrap_or("*"),
                        range.end.as_deref().unwrap_or("*")
                    ),
                }
            })
            .collect()
    }

    /// Check if version is within a range
    fn version_in_range(&self, version: &str, range: &VersionRange) -> bool {
        if let Some(ref start) = range.start {
            let cmp = compare_versions(version, start);
            if range.start_inclusive {
                if cmp < 0 {
                    return false;
                }
            } else if cmp <= 0 {
                return false;
            }
        }

        if let Some(ref end) = range.end {
            let cmp = compare_versions(version, end);
            if range.end_inclusive {
                if cmp > 0 {
                    return false;
                }
            } else if cmp >= 0 {
                return false;
            }
        }

        true
    }
}

/// A version range specification
#[derive(Debug, Clone)]
pub struct VersionRange {
    /// Start version (None = no lower bound)
    pub start: Option<String>,
    /// Whether start is inclusive
    pub start_inclusive: bool,
    /// End version (None = no upper bound)
    pub end: Option<String>,
    /// Whether end is inclusive
    pub end_inclusive: bool,
    /// Associated CVE IDs
    pub cve_ids: Vec<String>,
}

impl VersionRange {
    /// Create a new version range
    pub fn new(
        start: Option<&str>,
        start_inclusive: bool,
        end: Option<&str>,
        end_inclusive: bool,
    ) -> Self {
        Self {
            start: start.map(String::from),
            start_inclusive,
            end: end.map(String::from),
            end_inclusive,
            cve_ids: Vec::new(),
        }
    }

    /// Add CVE IDs to this range
    pub fn with_cves(mut self, cves: Vec<&str>) -> Self {
        self.cve_ids = cves.into_iter().map(String::from).collect();
        self
    }

    /// Create a range for "< version" (exclusive end)
    pub fn less_than(version: &str) -> Self {
        Self::new(None, false, Some(version), false)
    }

    /// Create a range for "<= version" (inclusive end)
    pub fn less_than_equal(version: &str) -> Self {
        Self::new(None, false, Some(version), true)
    }

    /// Create a range for ">= start AND < end"
    pub fn between(start: &str, end: &str) -> Self {
        Self::new(Some(start), true, Some(end), false)
    }
}

/// Product signature for matching
#[derive(Debug, Clone)]
pub struct ProductSignature {
    /// Vendor name patterns
    pub vendor_patterns: Vec<String>,
    /// Product name patterns
    pub product_patterns: Vec<String>,
    /// CPE vendor
    pub cpe_vendor: String,
    /// CPE product
    pub cpe_product: String,
}

impl ProductSignature {
    /// Check if a detected product matches this signature
    pub fn matches(&self, vendor: &str, product: &str) -> bool {
        let vendor_lower = vendor.to_lowercase();
        let product_lower = product.to_lowercase();

        let vendor_match = self
            .vendor_patterns
            .iter()
            .any(|p| vendor_lower.contains(&p.to_lowercase()));

        let product_match = self
            .product_patterns
            .iter()
            .any(|p| product_lower.contains(&p.to_lowercase()));

        vendor_match && product_match
    }
}

/// Common product signatures for service detection
pub fn common_signatures() -> Vec<ProductSignature> {
    vec![
        ProductSignature {
            vendor_patterns: vec!["apache".into()],
            product_patterns: vec!["http".into(), "httpd".into(), "apache".into()],
            cpe_vendor: "apache".into(),
            cpe_product: "http_server".into(),
        },
        ProductSignature {
            vendor_patterns: vec!["nginx".into()],
            product_patterns: vec!["nginx".into()],
            cpe_vendor: "nginx".into(),
            cpe_product: "nginx".into(),
        },
        ProductSignature {
            vendor_patterns: vec!["openbsd".into(), "openssh".into()],
            product_patterns: vec!["ssh".into(), "openssh".into()],
            cpe_vendor: "openbsd".into(),
            cpe_product: "openssh".into(),
        },
        ProductSignature {
            vendor_patterns: vec!["mysql".into(), "oracle".into()],
            product_patterns: vec!["mysql".into()],
            cpe_vendor: "oracle".into(),
            cpe_product: "mysql".into(),
        },
        ProductSignature {
            vendor_patterns: vec!["postgresql".into()],
            product_patterns: vec!["postgres".into(), "postgresql".into()],
            cpe_vendor: "postgresql".into(),
            cpe_product: "postgresql".into(),
        },
        ProductSignature {
            vendor_patterns: vec!["redis".into()],
            product_patterns: vec!["redis".into()],
            cpe_vendor: "redis".into(),
            cpe_product: "redis".into(),
        },
        ProductSignature {
            vendor_patterns: vec!["microsoft".into()],
            product_patterns: vec!["iis".into()],
            cpe_vendor: "microsoft".into(),
            cpe_product: "internet_information_services".into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_range() {
        let range = VersionRange::between("2.0", "2.17.0");

        let matcher = VersionMatcher::new(NvdDb::in_memory().unwrap());

        assert!(matcher.version_in_range("2.14.1", &range));
        assert!(matcher.version_in_range("2.0", &range));
        assert!(!matcher.version_in_range("2.17.0", &range));
        assert!(!matcher.version_in_range("1.9", &range));
    }

    #[test]
    fn test_product_signature() {
        let sig = ProductSignature {
            vendor_patterns: vec!["apache".into()],
            product_patterns: vec!["http".into()],
            cpe_vendor: "apache".into(),
            cpe_product: "http_server".into(),
        };

        assert!(sig.matches("Apache", "HTTP Server"));
        assert!(sig.matches("apache", "httpd"));
        assert!(!sig.matches("nginx", "nginx"));
    }
}
