//! Check loader - loads check definitions from files

use crate::{CheckRegistry, YamlCheck};
use forgescan_core::{Check, Error, Result};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Load all checks from a directory
pub fn load_checks_from_dir(dir: impl AsRef<Path>) -> Result<CheckRegistry> {
    let dir = dir.as_ref();
    let mut registry = CheckRegistry::new();

    if !dir.exists() {
        return Err(Error::FileNotFound {
            path: dir.display().to_string(),
        });
    }

    info!("Loading checks from: {}", dir.display());
    load_recursive(&mut registry, dir)?;

    info!("Loaded {} checks", registry.len());
    Ok(registry)
}

fn load_recursive(registry: &mut CheckRegistry, dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();

        if path.is_dir() {
            load_recursive(registry, &path)?;
        } else if let Some(ext) = path.extension() {
            if ext == "yaml" || ext == "yml" {
                match load_yaml_check(&path) {
                    Ok(check) => {
                        debug!("Loaded check: {} from {}", check.id(), path.display());
                        registry.register(Arc::new(check));
                    }
                    Err(e) => {
                        warn!("Failed to load check from {}: {}", path.display(), e);
                    }
                }
            }
        }
    }

    Ok(())
}

fn load_yaml_check(path: &Path) -> Result<YamlCheck> {
    let content = std::fs::read_to_string(path).map_err(Error::Io)?;

    YamlCheck::from_yaml(&content).map_err(|e| Error::InvalidCheckDefinition {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_load_checks_from_dir() {
        let tmp_dir = TempDir::new().unwrap();
        let check_path = tmp_dir.path().join("test-check.yaml");

        let yaml = r#"
id: "TEST-001"
name: "Test Check"
category: vuln
severity: high
detection:
  type: banner-match
  pattern: "test"
"#;

        let mut file = std::fs::File::create(&check_path).unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let registry = load_checks_from_dir(tmp_dir.path()).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("TEST-001").is_some());
    }

    fn valid_yaml_check(id: &str) -> String {
        format!(
            r#"
id: "{id}"
name: "Check {id}"
category: vuln
severity: high
detection:
  type: banner-match
  pattern: "test"
"#
        )
    }

    #[test]
    fn test_load_empty_dir() {
        let tmp_dir = TempDir::new().unwrap();
        let registry = load_checks_from_dir(tmp_dir.path()).unwrap();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_load_nested_dirs() {
        let tmp_dir = TempDir::new().unwrap();

        // Create a nested subdirectory structure
        let sub1 = tmp_dir.path().join("subdir1");
        let sub2 = tmp_dir.path().join("subdir1").join("subdir2");
        std::fs::create_dir_all(&sub2).unwrap();

        // Place YAML files at different levels
        std::fs::write(
            tmp_dir.path().join("root-check.yaml"),
            valid_yaml_check("ROOT-001"),
        )
        .unwrap();
        std::fs::write(sub1.join("sub1-check.yaml"), valid_yaml_check("SUB1-001")).unwrap();
        std::fs::write(sub2.join("sub2-check.yaml"), valid_yaml_check("SUB2-001")).unwrap();

        let registry = load_checks_from_dir(tmp_dir.path()).unwrap();
        assert_eq!(registry.len(), 3);
        assert!(registry.get("ROOT-001").is_some());
        assert!(registry.get("SUB1-001").is_some());
        assert!(registry.get("SUB2-001").is_some());
    }

    #[test]
    fn test_load_skips_non_yaml() {
        let tmp_dir = TempDir::new().unwrap();

        std::fs::write(
            tmp_dir.path().join("valid-check.yaml"),
            valid_yaml_check("VALID-001"),
        )
        .unwrap();
        std::fs::write(tmp_dir.path().join("readme.txt"), "not a check").unwrap();
        std::fs::write(tmp_dir.path().join("data.json"), r#"{"key": "value"}"#).unwrap();

        let registry = load_checks_from_dir(tmp_dir.path()).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("VALID-001").is_some());
    }

    #[test]
    fn test_load_handles_malformed_yaml() {
        let tmp_dir = TempDir::new().unwrap();

        std::fs::write(
            tmp_dir.path().join("good-check.yaml"),
            valid_yaml_check("GOOD-001"),
        )
        .unwrap();
        std::fs::write(
            tmp_dir.path().join("bad-check.yaml"),
            "this is not valid yaml: [[[",
        )
        .unwrap();

        let registry = load_checks_from_dir(tmp_dir.path()).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("GOOD-001").is_some());
    }

    #[test]
    fn test_load_nonexistent_dir() {
        let result = load_checks_from_dir("/tmp/nonexistent_forgescan_test_dir_12345");
        assert!(
            result.is_err(),
            "Loading from nonexistent dir should return an error"
        );
    }

    #[test]
    fn test_load_yml_extension() {
        let tmp_dir = TempDir::new().unwrap();

        std::fs::write(
            tmp_dir.path().join("check.yml"),
            valid_yaml_check("YML-001"),
        )
        .unwrap();

        let registry = load_checks_from_dir(tmp_dir.path()).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("YML-001").is_some());
    }
}
