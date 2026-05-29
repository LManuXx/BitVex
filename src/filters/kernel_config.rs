use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::osv::{OsvResult, OsvVuln};
use crate::vex::{VexStatement, VexStatus};

const JUSTIFICATION: &str = "vulnerable_code_not_present";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    BuiltIn,
    Module,
    Disabled,
    NotSet,
}

pub fn parse_kernel_config(path: &Path) -> Result<HashMap<String, ConfigValue>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read kernel config: {}", path.display()))?;

    let mut config = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("CONFIG_") {
            if let Some(rest) = line.strip_prefix("CONFIG_")
                && let Some((key, value)) = rest.split_once('=')
            {
                let val = match value {
                    "y" => ConfigValue::BuiltIn,
                    "m" => ConfigValue::Module,
                    "n" => ConfigValue::Disabled,
                    _ => continue,
                };
                config.insert(key.to_string(), val);
            }
        } else if line.starts_with("# CONFIG_")
            && line.ends_with("is not set")
            && let Some(key_part) = line.strip_prefix("# CONFIG_")
            && let Some(key) = key_part.strip_suffix(" is not set")
        {
            config.insert(key.to_string(), ConfigValue::NotSet);
        }
    }

    info!("Parsed {} kernel config entries", config.len());
    Ok(config)
}

fn package_name_to_config_key(name: &str) -> String {
    name.to_uppercase().replace('-', "_")
}

fn extract_config_keys_from_package(pkg_name: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let base = package_name_to_config_key(pkg_name);
    keys.push(base.clone());
    keys.push(format!("{}_DRIVER", base));
    keys.push(format!("{}_MODULE", base));
    keys
}

pub fn filter_by_kernel_config(
    results: &[OsvResult],
    config: &HashMap<String, ConfigValue>,
) -> (Vec<VexStatement>, Vec<usize>) {
    let mut statements = Vec::new();
    let mut filtered_indices = Vec::new();

    for (i, result) in results.iter().enumerate() {
        let config_keys = extract_config_keys_from_package(&result.package.name);

        // Only filter if at least one config key actually exists and is disabled
        let has_existing_disabled = config_keys.iter().any(|key| {
            matches!(
                config.get(key),
                Some(ConfigValue::Disabled) | Some(ConfigValue::NotSet)
            )
        });

        // Also filter if all existing keys are disabled/missing AND at least one key exists
        let existing_keys: Vec<_> = config_keys
            .iter()
            .filter(|key| config.contains_key(*key))
            .collect();

        let all_existing_disabled = !existing_keys.is_empty()
            && existing_keys.iter().all(|key| {
                matches!(
                    config.get(*key),
                    Some(ConfigValue::Disabled) | Some(ConfigValue::NotSet)
                )
            });

        if has_existing_disabled || all_existing_disabled {
            filtered_indices.push(i);
            for vuln in &result.vulns {
                statements.push(build_statement(vuln, result));
            }
            debug!(
                "Filtered package '{}' (not active in kernel config)",
                result.package.name
            );
        }
    }

    (statements, filtered_indices)
}

fn build_statement(vuln: &OsvVuln, result: &OsvResult) -> VexStatement {
    let purl = result
        .package
        .purl
        .clone()
        .unwrap_or_else(|| format!("pkg:generic/{}", result.package.name));

    VexStatement {
        vulnerability_name: vuln.id.clone(),
        product_purl: purl,
        status: VexStatus::NotAffected,
        justification: Some(JUSTIFICATION.to_string()),
        impact_statement: Some(format!(
            "The driver '{}' is not enabled in the kernel configuration (.config).",
            result.package.name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_kernel_config() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "CONFIG_USB_STORAGE=y").unwrap();
        writeln!(file, "CONFIG_EXT4_FS=m").unwrap();
        writeln!(file, "# CONFIG_BT is not set").unwrap();
        writeln!(file, "# CONFIG_NFS_FS is not set").unwrap();
        writeln!(file, "CONFIG_NET=y").unwrap();

        let config = parse_kernel_config(file.path()).unwrap();
        assert_eq!(config.get("USB_STORAGE"), Some(&ConfigValue::BuiltIn));
        assert_eq!(config.get("EXT4_FS"), Some(&ConfigValue::Module));
        assert_eq!(config.get("BT"), Some(&ConfigValue::NotSet));
        assert_eq!(config.get("NFS_FS"), Some(&ConfigValue::NotSet));
        assert_eq!(config.get("NET"), Some(&ConfigValue::BuiltIn));
        assert!(config.get("NONEXISTENT").is_none());
    }
}
