//! CPE (Common Platform Enumeration) parsing and matching
//!
//! Implements CPE 2.3 specification for identifying software products
//! and matching them against vulnerability data.

use std::fmt;
use std::str::FromStr;

/// CPE 2.3 formatted string parser and matcher
/// Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpe {
    /// Part: 'a' (application), 'o' (OS), 'h' (hardware)
    pub part: CpePart,
    /// Vendor name
    pub vendor: String,
    /// Product name
    pub product: String,
    /// Version string
    pub version: String,
    /// Update/patch level
    pub update: String,
    /// Edition
    pub edition: String,
    /// Language
    pub language: String,
    /// Software edition
    pub sw_edition: String,
    /// Target software
    pub target_sw: String,
    /// Target hardware
    pub target_hw: String,
    /// Other attributes
    pub other: String,
}

/// CPE part type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpePart {
    Application,
    OperatingSystem,
    Hardware,
    Any,
}

impl Default for CpePart {
    fn default() -> Self {
        CpePart::Any
    }
}

impl fmt::Display for CpePart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpePart::Application => write!(f, "a"),
            CpePart::OperatingSystem => write!(f, "o"),
            CpePart::Hardware => write!(f, "h"),
            CpePart::Any => write!(f, "*"),
        }
    }
}

impl FromStr for CpePart {
    type Err = CpeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "a" => Ok(CpePart::Application),
            "o" => Ok(CpePart::OperatingSystem),
            "h" => Ok(CpePart::Hardware),
            "*" | "" => Ok(CpePart::Any),
            _ => Err(CpeParseError::InvalidPart(s.to_string())),
        }
    }
}

impl Default for Cpe {
    fn default() -> Self {
        Self {
            part: CpePart::Any,
            vendor: "*".to_string(),
            product: "*".to_string(),
            version: "*".to_string(),
            update: "*".to_string(),
            edition: "*".to_string(),
            language: "*".to_string(),
            sw_edition: "*".to_string(),
            target_sw: "*".to_string(),
            target_hw: "*".to_string(),
            other: "*".to_string(),
        }
    }
}

impl Cpe {
    /// Create a new CPE for an application
    pub fn application(vendor: &str, product: &str, version: &str) -> Self {
        Self {
            part: CpePart::Application,
            vendor: vendor.to_lowercase().replace(' ', "_"),
            product: product.to_lowercase().replace(' ', "_"),
            version: version.to_string(),
            ..Default::default()
        }
    }

    /// Create a new CPE for an operating system
    pub fn os(vendor: &str, product: &str, version: &str) -> Self {
        Self {
            part: CpePart::OperatingSystem,
            vendor: vendor.to_lowercase().replace(' ', "_"),
            product: product.to_lowercase().replace(' ', "_"),
            version: version.to_string(),
            ..Default::default()
        }
    }

    /// Parse a CPE 2.3 formatted string
    pub fn parse(cpe_str: &str) -> Result<Self, CpeParseError> {
        let normalized = if cpe_str.starts_with("cpe:2.3:") {
            cpe_str.to_string()
        } else if cpe_str.starts_with("cpe:/") {
            Self::convert_22_to_23(cpe_str)?
        } else {
            return Err(CpeParseError::InvalidPrefix);
        };

        let parts: Vec<&str> = normalized.split(':').collect();
        if parts.len() < 5 {
            return Err(CpeParseError::TooFewComponents);
        }

        let part = parts.get(2).unwrap_or(&"*").parse()?;
        let vendor = Self::unescape(parts.get(3).unwrap_or(&"*"));
        let product = Self::unescape(parts.get(4).unwrap_or(&"*"));
        let version = Self::unescape(parts.get(5).unwrap_or(&"*"));
        let update = Self::unescape(parts.get(6).unwrap_or(&"*"));
        let edition = Self::unescape(parts.get(7).unwrap_or(&"*"));
        let language = Self::unescape(parts.get(8).unwrap_or(&"*"));
        let sw_edition = Self::unescape(parts.get(9).unwrap_or(&"*"));
        let target_sw = Self::unescape(parts.get(10).unwrap_or(&"*"));
        let target_hw = Self::unescape(parts.get(11).unwrap_or(&"*"));
        let other = Self::unescape(parts.get(12).unwrap_or(&"*"));

        Ok(Self {
            part,
            vendor,
            product,
            version,
            update,
            edition,
            language,
            sw_edition,
            target_sw,
            target_hw,
            other,
        })
    }

    fn convert_22_to_23(cpe_22: &str) -> Result<String, CpeParseError> {
        let without_prefix = cpe_22
            .strip_prefix("cpe:/")
            .ok_or(CpeParseError::InvalidPrefix)?;
        let parts: Vec<&str> = without_prefix.split(':').collect();

        let mut result = String::from("cpe:2.3");
        for (i, part) in parts.iter().enumerate() {
            result.push(':');
            if i == 0 {
                result.push_str(part);
            } else {
                result.push_str(&Self::unescape(part));
            }
        }

        while result.matches(':').count() < 12 {
            result.push_str(":*");
        }

        Ok(result)
    }

    fn unescape(s: &str) -> String {
        s.replace("\\:", ":")
            .replace("\\*", "*")
            .replace("\\?", "?")
            .replace("%21", "!")
            .replace("%22", "\"")
            .replace("%23", "#")
            .replace("%24", "$")
            .replace("%25", "%")
            .replace("%26", "&")
            .replace("%27", "'")
            .replace("%28", "(")
            .replace("%29", ")")
            .replace("%2a", "*")
            .replace("%2b", "+")
            .replace("%2c", ",")
            .replace("%2f", "/")
    }

    /// Format as CPE 2.3 string
    pub fn to_cpe_string(&self) -> String {
        format!(
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other
        )
    }

    /// Check if this CPE matches another CPE (with wildcard support)
    pub fn matches(&self, other: &Cpe) -> bool {
        Self::component_matches(&self.part.to_string(), &other.part.to_string())
            && Self::component_matches(&self.vendor, &other.vendor)
            && Self::component_matches(&self.product, &other.product)
            && Self::component_matches(&self.version, &other.version)
    }

    fn component_matches(pattern: &str, value: &str) -> bool {
        if pattern == "*" || value == "*" {
            return true;
        }
        if pattern == "-" || value == "-" {
            return pattern == value;
        }

        let pattern_lower = pattern.to_lowercase();
        let value_lower = value.to_lowercase();

        if pattern_lower.contains('*') {
            let parts: Vec<&str> = pattern_lower.split('*').collect();
            if parts.len() == 2 {
                if parts[0].is_empty() {
                    return value_lower.ends_with(parts[1]);
                } else if parts[1].is_empty() {
                    return value_lower.starts_with(parts[0]);
                } else {
                    return value_lower.starts_with(parts[0]) && value_lower.ends_with(parts[1]);
                }
            }
        }

        pattern_lower == value_lower
    }

    /// Get a simplified identifier for this CPE (vendor:product)
    pub fn identifier(&self) -> String {
        format!("{}:{}", self.vendor, self.product)
    }
}

impl fmt::Display for Cpe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_cpe_string())
    }
}

impl FromStr for Cpe {
    type Err = CpeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cpe::parse(s)
    }
}

/// CPE parsing error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpeParseError {
    InvalidPrefix,
    TooFewComponents,
    InvalidPart(String),
}

impl fmt::Display for CpeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpeParseError::InvalidPrefix => write!(f, "CPE must start with 'cpe:2.3:' or 'cpe:/'"),
            CpeParseError::TooFewComponents => write!(f, "CPE has too few components"),
            CpeParseError::InvalidPart(p) => write!(f, "Invalid CPE part: {}", p),
        }
    }
}

impl std::error::Error for CpeParseError {}

/// CPE match configuration (from NVD)
#[derive(Debug, Clone)]
pub struct CpeMatch {
    pub cpe: Cpe,
    pub vulnerable: bool,
    pub version_start: Option<String>,
    pub version_start_type: VersionBoundType,
    pub version_end: Option<String>,
    pub version_end_type: VersionBoundType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VersionBoundType {
    #[default]
    Including,
    Excluding,
}

impl CpeMatch {
    /// Check if a detected CPE matches this vulnerability pattern
    pub fn matches_cpe(&self, detected: &Cpe) -> bool {
        if !self.cpe.matches(detected) {
            return false;
        }

        if self.version_start.is_none() && self.version_end.is_none() {
            return true;
        }

        let detected_version = &detected.version;
        if detected_version == "*" {
            return true;
        }

        self.version_in_range(detected_version)
    }

    /// Check if a version is within the vulnerable range
    pub fn version_in_range(&self, version: &str) -> bool {
        if let Some(ref start) = self.version_start {
            let cmp = compare_versions(version, start);
            match self.version_start_type {
                VersionBoundType::Including => {
                    if cmp < 0 {
                        return false;
                    }
                }
                VersionBoundType::Excluding => {
                    if cmp <= 0 {
                        return false;
                    }
                }
            }
        }

        if let Some(ref end) = self.version_end {
            let cmp = compare_versions(version, end);
            match self.version_end_type {
                VersionBoundType::Including => {
                    if cmp > 0 {
                        return false;
                    }
                }
                VersionBoundType::Excluding => {
                    if cmp >= 0 {
                        return false;
                    }
                }
            }
        }

        true
    }
}

/// Compare two version strings. Returns -1 if a < b, 0 if a == b, 1 if a > b
pub fn compare_versions(a: &str, b: &str) -> i32 {
    let a_parts = parse_version_parts(a);
    let b_parts = parse_version_parts(b);
    let max_len = a_parts.len().max(b_parts.len());

    for i in 0..max_len {
        let a_part = a_parts.get(i).cloned().unwrap_or(VersionPart::Numeric(0));
        let b_part = b_parts.get(i).cloned().unwrap_or(VersionPart::Numeric(0));

        match (a_part, b_part) {
            (VersionPart::Numeric(a_num), VersionPart::Numeric(b_num)) => {
                if a_num < b_num {
                    return -1;
                }
                if a_num > b_num {
                    return 1;
                }
            }
            (VersionPart::Alpha(a_str), VersionPart::Alpha(b_str)) => match a_str.cmp(&b_str) {
                std::cmp::Ordering::Less => return -1,
                std::cmp::Ordering::Greater => return 1,
                std::cmp::Ordering::Equal => {}
            },
            (VersionPart::Numeric(_), VersionPart::Alpha(_)) => return -1,
            (VersionPart::Alpha(_), VersionPart::Numeric(_)) => return 1,
        }
    }
    0
}

#[derive(Debug, Clone)]
enum VersionPart {
    Numeric(u64),
    Alpha(String),
}

fn parse_version_parts(version: &str) -> Vec<VersionPart> {
    let mut parts = Vec::new();
    let mut current_num = String::new();
    let mut current_alpha = String::new();

    for c in version.chars() {
        if c.is_ascii_digit() {
            if !current_alpha.is_empty() {
                parts.push(VersionPart::Alpha(current_alpha.clone()));
                current_alpha.clear();
            }
            current_num.push(c);
        } else if c.is_alphabetic() {
            if !current_num.is_empty() {
                if let Ok(n) = current_num.parse::<u64>() {
                    parts.push(VersionPart::Numeric(n));
                }
                current_num.clear();
            }
            current_alpha.push(c);
        } else {
            if !current_num.is_empty() {
                if let Ok(n) = current_num.parse::<u64>() {
                    parts.push(VersionPart::Numeric(n));
                }
                current_num.clear();
            }
            if !current_alpha.is_empty() {
                parts.push(VersionPart::Alpha(current_alpha.clone()));
                current_alpha.clear();
            }
        }
    }

    if !current_num.is_empty() {
        if let Ok(n) = current_num.parse::<u64>() {
            parts.push(VersionPart::Numeric(n));
        }
    }
    if !current_alpha.is_empty() {
        parts.push(VersionPart::Alpha(current_alpha));
    }

    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpe_23() {
        let cpe = Cpe::parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.part, CpePart::Application);
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "log4j");
        assert_eq!(cpe.version, "2.14.1");
    }

    #[test]
    fn test_parse_cpe_22() {
        let cpe = Cpe::parse("cpe:/a:apache:http_server:2.4.52").unwrap();
        assert_eq!(cpe.part, CpePart::Application);
        assert_eq!(cpe.vendor, "apache");
        assert_eq!(cpe.product, "http_server");
        assert_eq!(cpe.version, "2.4.52");
    }

    #[test]
    fn test_cpe_matches() {
        let pattern = Cpe::parse("cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*").unwrap();
        let target = Cpe::parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").unwrap();
        assert!(pattern.matches(&target));
    }

    #[test]
    fn test_version_compare() {
        assert_eq!(compare_versions("1.0", "1.0"), 0);
        assert_eq!(compare_versions("1.0", "2.0"), -1);
        assert_eq!(compare_versions("2.0", "1.0"), 1);
        assert_eq!(compare_versions("1.0.1", "1.0"), 1);
        assert_eq!(compare_versions("1.10", "1.9"), 1);
        assert_eq!(compare_versions("2.14.1", "2.17.0"), -1);
    }

    #[test]
    fn test_cpe_match_version_range() {
        let cpe_match = CpeMatch {
            cpe: Cpe::parse("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*").unwrap(),
            vulnerable: true,
            version_start: Some("2.0".to_string()),
            version_start_type: VersionBoundType::Including,
            version_end: Some("2.17.0".to_string()),
            version_end_type: VersionBoundType::Excluding,
        };

        assert!(cpe_match.version_in_range("2.14.1"));
        assert!(cpe_match.version_in_range("2.0"));
        assert!(!cpe_match.version_in_range("2.17.0"));
        assert!(!cpe_match.version_in_range("1.9"));
    }
}
