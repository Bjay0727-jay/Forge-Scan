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
    use forgescan_core::{CheckContext, CheckResult, ScanTarget};

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
}
