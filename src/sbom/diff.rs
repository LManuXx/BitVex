use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use tabled::{Table, Tabled};

use crate::sbom::{SbomPackage, parse_spdx_sbom};

#[derive(Debug, Clone, Serialize)]
pub struct SbomDiff {
    pub added: Vec<SbomPackage>,
    pub removed: Vec<SbomPackage>,
    pub updated: Vec<PackageUpdate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageUpdate {
    pub name: String,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
}

#[derive(Tabled)]
struct DiffRow {
    #[tabled(rename = "Change")]
    change: String,
    #[tabled(rename = "Package")]
    package: String,
    #[tabled(rename = "Old Version")]
    old_version: String,
    #[tabled(rename = "New Version")]
    new_version: String,
}

pub fn diff_sboms(old_sbom_path: &Path, new_sbom_path: &Path) -> Result<SbomDiff> {
    let old_data = std::fs::read(old_sbom_path)
        .with_context(|| format!("Failed to read old SBOM: {}", old_sbom_path.display()))?;
    let new_data = std::fs::read(new_sbom_path)
        .with_context(|| format!("Failed to read new SBOM: {}", new_sbom_path.display()))?;

    let old_packages = parse_spdx_sbom(&old_data)?;
    let new_packages = parse_spdx_sbom(&new_data)?;

    diff_packages(&old_packages, &new_packages)
}

pub fn diff_packages(
    old_packages: &[SbomPackage],
    new_packages: &[SbomPackage],
) -> Result<SbomDiff> {
    let old_map: HashMap<&str, &SbomPackage> =
        old_packages.iter().map(|p| (p.name.as_str(), p)).collect();

    let new_map: HashMap<&str, &SbomPackage> =
        new_packages.iter().map(|p| (p.name.as_str(), p)).collect();

    let old_names: HashSet<&str> = old_map.keys().copied().collect();
    let new_names: HashSet<&str> = new_map.keys().copied().collect();

    let mut added: Vec<SbomPackage> = new_names
        .difference(&old_names)
        .filter_map(|name| new_map.get(name).map(|p| (*p).clone()))
        .collect();

    let mut removed: Vec<SbomPackage> = old_names
        .difference(&new_names)
        .filter_map(|name| old_map.get(name).map(|p| (*p).clone()))
        .collect();

    let mut updated = Vec::new();
    for name in old_names.intersection(&new_names) {
        let old_pkg = old_map[name];
        let new_pkg = new_map[name];

        let old_ver = old_pkg.version.clone();
        let new_ver = new_pkg.version.clone();

        if old_ver != new_ver {
            updated.push(PackageUpdate {
                name: name.to_string(),
                old_version: old_ver,
                new_version: new_ver,
            });
        }
    }

    added.sort_by(|a, b| a.name.cmp(&b.name));
    removed.sort_by(|a, b| a.name.cmp(&b.name));
    updated.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(SbomDiff {
        added,
        removed,
        updated,
    })
}

pub fn print_diff_summary(diff: &SbomDiff) {
    let mut rows = Vec::new();

    for pkg in &diff.added {
        rows.push(DiffRow {
            change: "+".to_string(),
            package: pkg.name.clone(),
            old_version: "-".to_string(),
            new_version: pkg.version.clone().unwrap_or_else(|| "?".to_string()),
        });
    }

    for pkg in &diff.removed {
        rows.push(DiffRow {
            change: "-".to_string(),
            package: pkg.name.clone(),
            old_version: pkg.version.clone().unwrap_or_else(|| "?".to_string()),
            new_version: "-".to_string(),
        });
    }

    for update in &diff.updated {
        rows.push(DiffRow {
            change: "~".to_string(),
            package: update.name.clone(),
            old_version: update
                .old_version
                .clone()
                .unwrap_or_else(|| "?".to_string()),
            new_version: update
                .new_version
                .clone()
                .unwrap_or_else(|| "?".to_string()),
        });
    }

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          BitVex - SBOM Diff Report                  ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!(
        "║  Packages added:       {:<5}                         ║",
        diff.added.len()
    );
    println!(
        "║  Packages removed:     {:<5}                         ║",
        diff.removed.len()
    );
    println!(
        "║  Packages updated:     {:<5}                         ║",
        diff.updated.len()
    );
    println!("╚══════════════════════════════════════════════════════╝");

    if !rows.is_empty() {
        println!();
        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pkg(name: &str, version: &str) -> SbomPackage {
        SbomPackage {
            _spdx_id: format!("SPDXRef-{}", name),
            name: name.into(),
            version: Some(version.into()),
            purl: Some(format!("pkg:generic/{}@{}", name, version)),
        }
    }

    #[test]
    fn test_diff_added_packages() {
        let old = vec![make_pkg("openssl", "3.0.13")];
        let new = vec![make_pkg("openssl", "3.0.13"), make_pkg("curl", "8.5.0")];

        let diff = diff_packages(&old, &new).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "curl");
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.updated.len(), 0);
    }

    #[test]
    fn test_diff_removed_packages() {
        let old = vec![make_pkg("openssl", "3.0.13"), make_pkg("curl", "8.5.0")];
        let new = vec![make_pkg("openssl", "3.0.13")];

        let diff = diff_packages(&old, &new).unwrap();
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].name, "curl");
    }

    #[test]
    fn test_diff_updated_packages() {
        let old = vec![make_pkg("openssl", "3.0.12")];
        let new = vec![make_pkg("openssl", "3.0.13")];

        let diff = diff_packages(&old, &new).unwrap();
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.updated.len(), 1);
        assert_eq!(diff.updated[0].name, "openssl");
        assert_eq!(diff.updated[0].old_version, Some("3.0.12".into()));
        assert_eq!(diff.updated[0].new_version, Some("3.0.13".into()));
    }

    #[test]
    fn test_diff_no_changes() {
        let old = vec![make_pkg("openssl", "3.0.13")];
        let new = vec![make_pkg("openssl", "3.0.13")];

        let diff = diff_packages(&old, &new).unwrap();
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.updated.len(), 0);
    }

    #[test]
    fn test_diff_mixed_changes() {
        let old = vec![
            make_pkg("openssl", "3.0.12"),
            make_pkg("curl", "8.1.2"),
            make_pkg("glibc", "2.37"),
        ];
        let new = vec![
            make_pkg("openssl", "3.0.13"),
            make_pkg("bash", "5.2.15"),
            make_pkg("glibc", "2.37"),
        ];

        let diff = diff_packages(&old, &new).unwrap();
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "bash");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].name, "curl");
        assert_eq!(diff.updated.len(), 1);
        assert_eq!(diff.updated[0].name, "openssl");
    }
}
