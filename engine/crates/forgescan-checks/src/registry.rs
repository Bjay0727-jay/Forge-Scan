//! Check registry - index of all available checks

use forgescan_core::{Check, CheckCategory, CheckMetadata, Severity};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry of all available vulnerability checks
pub struct CheckRegistry {
    /// Checks indexed by ID
    checks: HashMap<String, Arc<dyn Check>>,
    /// Check metadata indexed by ID (for filtering without loading full check)
    metadata: HashMap<String, CheckMetadata>,
}

impl CheckRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            checks: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Register a check
    pub fn register(&mut self, check: Arc<dyn Check>) {
        let id = check.id().to_string();
        let metadata = check.metadata().clone();
        self.checks.insert(id.clone(), check);
        self.metadata.insert(id, metadata);
    }

    /// Get a check by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn Check>> {
        self.checks.get(id).cloned()
    }

    /// Get check metadata by ID
    pub fn get_metadata(&self, id: &str) -> Option<&CheckMetadata> {
        self.metadata.get(id)
    }

    /// Get all check IDs
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.checks.keys().map(|s| s.as_str())
    }

    /// Get all checks
    pub fn all(&self) -> impl Iterator<Item = Arc<dyn Check>> + '_ {
        self.checks.values().cloned()
    }

    /// Get number of registered checks
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Filter checks by category
    pub fn by_category(&self, category: CheckCategory) -> Vec<Arc<dyn Check>> {
        self.checks
            .values()
            .filter(|c| c.metadata().category == category)
            .cloned()
            .collect()
    }

    /// Filter checks by minimum severity
    pub fn by_min_severity(&self, min_severity: Severity) -> Vec<Arc<dyn Check>> {
        self.checks
            .values()
            .filter(|c| c.metadata().severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Filter checks by tag
    pub fn by_tag(&self, tag: &str) -> Vec<Arc<dyn Check>> {
        self.checks
            .values()
            .filter(|c| c.metadata().tags.iter().any(|t| t == tag))
            .cloned()
            .collect()
    }

    /// Get checks that are enabled by default
    pub fn enabled_by_default(&self) -> Vec<Arc<dyn Check>> {
        self.checks
            .values()
            .filter(|c| c.metadata().enabled_by_default)
            .cloned()
            .collect()
    }

    /// Filter checks by IDs
    pub fn by_ids(&self, ids: &[String]) -> Vec<Arc<dyn Check>> {
        ids.iter()
            .filter_map(|id| self.checks.get(id).cloned())
            .collect()
    }
}

impl Default for CheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgescan_core::{CheckContext, CheckResult};

    struct TestCheck {
        metadata: CheckMetadata,
    }

    impl Check for TestCheck {
        fn id(&self) -> &str {
            &self.metadata.id
        }

        fn metadata(&self) -> &CheckMetadata {
            &self.metadata
        }

        fn execute(&self, _ctx: &CheckContext) -> CheckResult {
            Ok(vec![])
        }
    }

    #[test]
    fn test_registry() {
        let mut registry = CheckRegistry::new();

        let check = Arc::new(TestCheck {
            metadata: CheckMetadata::new(
                "TEST-001",
                "Test Check",
                CheckCategory::Vulnerability,
                Severity::High,
            ),
        });

        registry.register(check);

        assert_eq!(registry.len(), 1);
        assert!(registry.get("TEST-001").is_some());
        assert!(registry.get("INVALID").is_none());
    }

    fn make_check(id: &str, category: CheckCategory, severity: Severity) -> Arc<dyn Check> {
        Arc::new(TestCheck {
            metadata: CheckMetadata::new(id, format!("{} Check", id), category, severity),
        })
    }

    fn make_check_with_tags(
        id: &str,
        category: CheckCategory,
        severity: Severity,
        tags: Vec<&str>,
    ) -> Arc<dyn Check> {
        let mut meta = CheckMetadata::new(id, format!("{} Check", id), category, severity);
        for tag in tags {
            meta = meta.with_tag(tag);
        }
        Arc::new(TestCheck { metadata: meta })
    }

    fn make_check_with_enabled(
        id: &str,
        category: CheckCategory,
        severity: Severity,
        enabled: bool,
    ) -> Arc<dyn Check> {
        let mut meta = CheckMetadata::new(id, format!("{} Check", id), category, severity);
        meta.enabled_by_default = enabled;
        Arc::new(TestCheck { metadata: meta })
    }

    #[test]
    fn test_registry_empty() {
        let registry = CheckRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_multiple_checks() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "A-001",
            CheckCategory::Vulnerability,
            Severity::High,
        ));
        registry.register(make_check("A-002", CheckCategory::Network, Severity::Low));
        registry.register(make_check(
            "A-003",
            CheckCategory::Cloud,
            Severity::Critical,
        ));
        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
    }

    #[test]
    fn test_registry_by_category() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "V-001",
            CheckCategory::Vulnerability,
            Severity::High,
        ));
        registry.register(make_check("N-001", CheckCategory::Network, Severity::Low));
        registry.register(make_check(
            "V-002",
            CheckCategory::Vulnerability,
            Severity::Medium,
        ));
        registry.register(make_check(
            "C-001",
            CheckCategory::Cloud,
            Severity::Critical,
        ));

        let vulns = registry.by_category(CheckCategory::Vulnerability);
        assert_eq!(vulns.len(), 2);

        let networks = registry.by_category(CheckCategory::Network);
        assert_eq!(networks.len(), 1);

        let webapps = registry.by_category(CheckCategory::WebApp);
        assert_eq!(webapps.len(), 0);
    }

    #[test]
    fn test_registry_by_min_severity() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "I-001",
            CheckCategory::Vulnerability,
            Severity::Info,
        ));
        registry.register(make_check(
            "L-001",
            CheckCategory::Vulnerability,
            Severity::Low,
        ));
        registry.register(make_check(
            "M-001",
            CheckCategory::Vulnerability,
            Severity::Medium,
        ));
        registry.register(make_check(
            "H-001",
            CheckCategory::Vulnerability,
            Severity::High,
        ));
        registry.register(make_check(
            "C-001",
            CheckCategory::Vulnerability,
            Severity::Critical,
        ));

        let high_and_above = registry.by_min_severity(Severity::High);
        assert_eq!(high_and_above.len(), 2);
        for check in &high_and_above {
            assert!(check.metadata().severity >= Severity::High);
        }
    }

    #[test]
    fn test_registry_by_tag() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check_with_tags(
            "T-001",
            CheckCategory::Vulnerability,
            Severity::High,
            vec!["ssh", "remote"],
        ));
        registry.register(make_check_with_tags(
            "T-002",
            CheckCategory::Network,
            Severity::Low,
            vec!["http", "remote"],
        ));
        registry.register(make_check_with_tags(
            "T-003",
            CheckCategory::Configuration,
            Severity::Medium,
            vec!["ssh", "local"],
        ));

        let ssh_checks = registry.by_tag("ssh");
        assert_eq!(ssh_checks.len(), 2);

        let remote_checks = registry.by_tag("remote");
        assert_eq!(remote_checks.len(), 2);

        let missing_tag = registry.by_tag("nonexistent");
        assert_eq!(missing_tag.len(), 0);
    }

    #[test]
    fn test_registry_enabled_by_default() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check_with_enabled(
            "E-001",
            CheckCategory::Vulnerability,
            Severity::High,
            true,
        ));
        registry.register(make_check_with_enabled(
            "E-002",
            CheckCategory::Vulnerability,
            Severity::Low,
            false,
        ));
        registry.register(make_check_with_enabled(
            "E-003",
            CheckCategory::Network,
            Severity::Medium,
            true,
        ));

        let enabled = registry.enabled_by_default();
        assert_eq!(enabled.len(), 2);
        for check in &enabled {
            assert!(check.metadata().enabled_by_default);
        }
    }

    #[test]
    fn test_registry_by_ids() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "ID-001",
            CheckCategory::Vulnerability,
            Severity::High,
        ));
        registry.register(make_check("ID-002", CheckCategory::Network, Severity::Low));
        registry.register(make_check(
            "ID-003",
            CheckCategory::Cloud,
            Severity::Critical,
        ));

        let ids = vec!["ID-001".to_string(), "ID-003".to_string()];
        let result = registry.by_ids(&ids);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_registry_by_ids_missing() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "ID-001",
            CheckCategory::Vulnerability,
            Severity::High,
        ));

        let ids = vec!["NONEXISTENT-001".to_string()];
        let result = registry.by_ids(&ids);
        assert!(result.is_empty());
    }

    #[test]
    fn test_registry_ids_iterator() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "IT-001",
            CheckCategory::Vulnerability,
            Severity::High,
        ));
        registry.register(make_check("IT-002", CheckCategory::Network, Severity::Low));
        registry.register(make_check(
            "IT-003",
            CheckCategory::Cloud,
            Severity::Critical,
        ));

        let mut ids: Vec<&str> = registry.ids().collect();
        ids.sort();
        assert_eq!(ids, vec!["IT-001", "IT-002", "IT-003"]);
    }

    #[test]
    fn test_registry_get_metadata() {
        let mut registry = CheckRegistry::new();
        registry.register(make_check(
            "META-001",
            CheckCategory::Network,
            Severity::Medium,
        ));

        let metadata = registry.get_metadata("META-001");
        assert!(metadata.is_some());
        let metadata = metadata.unwrap();
        assert_eq!(metadata.id, "META-001");
        assert_eq!(metadata.category, CheckCategory::Network);
        assert_eq!(metadata.severity, Severity::Medium);

        assert!(registry.get_metadata("NONEXISTENT").is_none());
    }
}
