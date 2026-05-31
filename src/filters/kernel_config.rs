//! Kernel configuration filter.
//!
//! Filters CVEs based on Linux kernel `.config` file. If a driver or feature
//! is not enabled (`CONFIG_XXX` is not `=y` or `=m`), vulnerabilities in that
//! component are marked as `not_affected`.
//!
//! Includes known mappings for common embedded packages (bluez5→BT, etc.)
//! and automatically skips userspace packages (glibc, bash, python, etc.).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info};

use crate::osv::{OsvResult, OsvVuln};
use crate::vex::{VexStatement, VexStatus};

const JUSTIFICATION: &str = "vulnerable_code_not_present";

/// Kernel configuration value for a CONFIG_ option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    /// `CONFIG_XXX=y` — compiled into the kernel image.
    BuiltIn,
    /// `CONFIG_XXX=m` — compiled as a loadable module.
    Module,
    /// `CONFIG_XXX=n` — explicitly disabled.
    Disabled,
    /// `# CONFIG_XXX is not set` — not enabled.
    NotSet,
}

/// Known package-to-kernel-config mappings for common embedded packages.
/// These are packages where the heuristic name→CONFIG mapping fails.
fn known_config_mappings() -> HashMap<&'static str, Vec<&'static str>> {
    HashMap::from([
        ("bluez5", vec!["BT", "BLUETOOTH"]),
        ("wpa-supplicant", vec!["CFG80211", "WLAN", "MAC80211"]),
        ("openssh", vec!["CRYPTO", "ASYMMETRIC_KEY_TYPE"]),
        ("openssl", vec!["CRYPTO", "TLS"]),
        ("iptables", vec!["NETFILTER", "IP_NF_IPTABLES"]),
        ("systemd", vec!["CGROUPS", "FANOTIFY"]),
        ("mesa", vec!["DRM"]),
        ("imx-gpu-viv", vec!["DRM", "MXC_GPU_VIV"]),
        ("linux-imx", vec!["ARCH_MXC"]),
        ("u-boot-imx", vec![]),
    ])
}

/// Packages that are purely userspace and should never be filtered by kernel config.
fn is_userspace_package(name: &str) -> bool {
    let prefixes = [
        "glibc",
        "bash",
        "coreutils",
        "dbus",
        "systemd",
        "python",
        "ruby",
        "perl",
        "php",
        "node",
        "npm",
        "vim",
        "nano",
        "gcc",
        "binutils",
        "make",
        "cmake",
        "autoconf",
        "busybox",
        "shadow",
        "util-linux",
        "curl",
        "wget",
        "openssl",
        "openssh",
        "zlib",
        "libpng",
        "libxml2",
        "sqlite",
        "icu",
        "mesa",
        "wayland",
        "gstreamer",
        "opkg",
        "dnsmasq",
        "avahi",
        "networkmanager",
        "bluez",
        "wpa-supplicant",
        "iptables",
    ];
    let lower = name.to_lowercase();
    prefixes.iter().any(|p| lower.starts_with(p))
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

fn extract_config_keys_from_package(pkg_name: &str) -> Vec<String> {
    // Check known mappings first (these override userspace check)
    let known = known_config_mappings();
    if let Some(keys) = known.get(pkg_name) {
        return keys.iter().map(|k| k.to_string()).collect();
    }

    // Skip obvious userspace packages (that aren't in known mappings)
    if is_userspace_package(pkg_name) {
        return vec![];
    }

    // Fallback to heuristic
    let base = pkg_name.to_uppercase().replace('-', "_");
    vec![
        base.clone(),
        format!("{}_DRIVER", base),
        format!("{}_MODULE", base),
    ]
}

pub fn filter_by_kernel_config(
    results: &[OsvResult],
    config: &HashMap<String, ConfigValue>,
) -> (Vec<VexStatement>, Vec<usize>) {
    let mut statements = Vec::new();
    let mut filtered_indices = Vec::new();

    for (i, result) in results.iter().enumerate() {
        let config_keys = extract_config_keys_from_package(&result.package.name);

        // Skip if no config keys (userspace package)
        if config_keys.is_empty() {
            continue;
        }

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

    #[test]
    fn test_known_mappings() {
        let keys = extract_config_keys_from_package("bluez5");
        assert!(keys.contains(&"BT".to_string()));
        assert!(keys.contains(&"BLUETOOTH".to_string()));

        // openssl has known mapping (CRYPTO, TLS)
        let keys = extract_config_keys_from_package("openssl");
        assert!(keys.contains(&"CRYPTO".to_string()));
    }

    #[test]
    fn test_userspace_packages_skipped() {
        // Packages not in known mappings are skipped
        let keys = extract_config_keys_from_package("glibc");
        assert!(keys.is_empty());

        let keys = extract_config_keys_from_package("bash");
        assert!(keys.is_empty());

        let keys = extract_config_keys_from_package("python3");
        assert!(keys.is_empty());
    }

    #[test]
    fn test_config_string_values_ignored() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut file,
            b"CONFIG_CMDLINE=\"console=ttyAMA0\"\nCONFIG_VALUE=\"\"\nCONFIG_NORMAL=y\n",
        )
        .unwrap();

        let config = parse_kernel_config(file.path()).unwrap();
        assert_eq!(config.get("NORMAL"), Some(&ConfigValue::BuiltIn));
        assert!(config.get("CMDLINE").is_none());
        assert!(config.get("VALUE").is_none());
    }

    #[test]
    fn test_config_explicit_n() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"CONFIG_DISABLED=n\n").unwrap();

        let config = parse_kernel_config(file.path()).unwrap();
        assert_eq!(config.get("DISABLED"), Some(&ConfigValue::Disabled));
    }

    #[test]
    fn test_filter_with_disabled_config() {
        let mut config = std::collections::HashMap::new();
        config.insert("BT".to_string(), ConfigValue::NotSet);
        config.insert("USB_STORAGE".to_string(), ConfigValue::BuiltIn);

        let results = vec![OsvResult {
            package: crate::sbom::SbomPackage {
                _spdx_id: "SPDXRef-1".into(),
                name: "bluez5".into(),
                version: Some("5.68".into()),
                purl: Some("pkg:generic/bluez5@5.68".into()),
            },
            vulns: vec![OsvVuln {
                id: "CVE-2024-0001".into(),
                _modified: "2024-01-01T00:00:00Z".into(),
                aliases: vec![],
            }],
        }];

        let (statements, indices) = filter_by_kernel_config(&results, &config);
        assert_eq!(indices.len(), 1);
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].status, VexStatus::NotAffected);
    }
}
