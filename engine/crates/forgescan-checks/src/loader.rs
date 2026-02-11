//! Check loader - loads check definitions from files

use crate::{CheckRegistry, YamlCheck};
use forgescan_core::{Error, Result};
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
    for entry in std::fs::read_dir(dir).map_err(|e| Error::Io(e))? {
        let entry = entry.map_err(|e| Error::Io(e))?;
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
    let content = std::fs::read_to_string(path).map_err(|e| Error::Io(e))?;

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
}
