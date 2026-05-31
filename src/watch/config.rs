//! Configuration parser for bitvex-watch.toml.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

/// Top-level watch configuration.
#[derive(Debug, Deserialize)]
pub struct WatchConfig {
    /// Debounce interval in seconds.
    pub debounce_secs: Option<u64>,
    /// Directory for generated reports.
    pub output_dir: Option<PathBuf>,
    /// Path to SQLite database.
    pub db_path: Option<PathBuf>,
    /// Projects to monitor.
    pub projects: Vec<ProjectConfig>,
}

/// Configuration for a single project.
#[derive(Debug, Deserialize, Clone)]
pub struct ProjectConfig {
    /// Human-readable project name.
    pub name: String,
    /// Path to the SBOM (SPDX JSON).
    pub sbom: PathBuf,
    /// Kernel/U-Boot config files.
    #[serde(default)]
    pub configs: Vec<ConfigEntry>,
    /// Device tree files.
    #[serde(default)]
    pub device_trees: Vec<DtsEntry>,
    /// Optional rules file.
    pub rules: Option<PathBuf>,
    /// Optional author override.
    pub author: Option<String>,
}

/// A config file entry (kernel or U-Boot).
#[derive(Debug, Deserialize, Clone)]
pub struct ConfigEntry {
    /// Config type: "kernel" or "uboot".
    #[serde(rename = "type")]
    pub config_type: String,
    /// Path to the config file.
    pub path: PathBuf,
}

/// A device tree entry.
#[derive(Debug, Deserialize, Clone)]
pub struct DtsEntry {
    /// Path to the .dts or .dtb file.
    pub path: PathBuf,
}

impl ProjectConfig {
    /// Collect all file paths that should be watched for this project.
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.sbom.clone()];
        for cfg in &self.configs {
            paths.push(cfg.path.clone());
        }
        for dts in &self.device_trees {
            paths.push(dts.path.clone());
        }
        if let Some(ref rules) = self.rules {
            paths.push(rules.clone());
        }
        paths
    }
}

/// Load watch configuration from a TOML file.
pub fn load_watch_config(path: &PathBuf) -> Result<WatchConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read watch config: {}", path.display()))?;

    let config: WatchConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse watch config: {}", path.display()))?;

    info!(
        "Loaded {} projects from {}",
        config.projects.len(),
        path.display()
    );

    for project in &config.projects {
        info!(
            "  Project '{}': {} configs, {} device trees",
            project.name,
            project.configs.len(),
            project.device_trees.len()
        );
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_watch_config() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
debounce_secs = 10
output_dir = "./reports"
db_path = "/tmp/test.db"

[[projects]]
name = "Test Project"
sbom = "build/spdx.json"

[[projects.configs]]
type = "kernel"
path = "build/.config"

[[projects.configs]]
type = "uboot"
path = "build/u-boot/.config"

[[projects.device_trees]]
path = "build/board.dts"

[[projects]]
name = "Second Project"
sbom = "build/spdx2.json"

[[projects.configs]]
type = "kernel"
path = "build/.config2"
"#
        )
        .unwrap();

        let config = load_watch_config(&file.path().to_path_buf()).unwrap();
        assert_eq!(config.debounce_secs, Some(10));
        assert_eq!(config.projects.len(), 2);
        assert_eq!(config.projects[0].name, "Test Project");
        assert_eq!(config.projects[0].configs.len(), 2);
        assert_eq!(config.projects[0].device_trees.len(), 1);
        assert_eq!(config.projects[1].name, "Second Project");
    }

    #[test]
    fn test_watched_paths() {
        let project = ProjectConfig {
            name: "test".into(),
            sbom: "sbom.json".into(),
            configs: vec![
                ConfigEntry {
                    config_type: "kernel".into(),
                    path: ".config".into(),
                },
                ConfigEntry {
                    config_type: "uboot".into(),
                    path: "uboot.config".into(),
                },
            ],
            device_trees: vec![DtsEntry {
                path: "board.dts".into(),
            }],
            rules: Some("bitvex.toml".into()),
            author: None,
        };

        let paths = project.watched_paths();
        assert_eq!(paths.len(), 5); // sbom + 2 configs + dts + rules
    }
}
