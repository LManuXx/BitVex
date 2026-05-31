//! Scan execution wrapper for watch mode.

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::filters;
use crate::osv;
use crate::rules;
use crate::sbom;
use crate::vex;
use crate::vex::{VexStatus, generate_openvex};
use crate::watch::config::ProjectConfig;
use crate::watch::state::WatchState;

use filters::device_tree::parse_device_tree;
use filters::kernel_config::parse_kernel_config;
use filters::native::filter_native_packages;
use sbom::parse_spdx_sbom;

/// Result of a scan execution.
pub struct ScanResult {
    pub scan_id: i64,
    pub total_packages: usize,
    pub affected: usize,
    pub not_affected: usize,
    pub statements: Vec<vex::VexStatement>,
}

/// Execute a scan for a single project.
pub async fn scan_project(
    project: &ProjectConfig,
    state: &WatchState,
    author: &str,
    output_dir: Option<&std::path::Path>,
) -> Result<ScanResult> {
    info!("Scanning project '{}'", project.name);

    // 1. Parse SBOM
    let sbom_data = std::fs::read(&project.sbom)
        .with_context(|| format!("Failed to read SBOM: {}", project.sbom.display()))?;
    let packages = parse_spdx_sbom(&sbom_data)?;
    info!("  {} packages in SBOM", packages.len());

    if packages.is_empty() {
        warn!("  No packages found, skipping");
        return Ok(ScanResult {
            scan_id: 0,
            total_packages: 0,
            affected: 0,
            not_affected: 0,
            statements: vec![],
        });
    }

    // 2. Parse configs
    let mut kernel_configs = Vec::new();
    let mut uboot_config = None;

    for cfg_entry in &project.configs {
        let config = parse_kernel_config(&cfg_entry.path)?;
        match cfg_entry.config_type.as_str() {
            "kernel" => kernel_configs.push(config),
            "uboot" => uboot_config = Some(config),
            _ => warn!("Unknown config type: {}", cfg_entry.config_type),
        }
    }

    // 3. Parse device trees
    let mut dts_nodes_all = Vec::new();
    for dts_entry in &project.device_trees {
        let nodes = parse_device_tree(&dts_entry.path)?;
        dts_nodes_all.extend(nodes);
    }

    // 4. Load rules
    let rules_config = if let Some(ref rules_path) = project.rules {
        Some(rules::load_rules(rules_path)?)
    } else {
        None
    };

    // 5. Filter native packages
    let native_indices: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, p)| filters::native::is_native_package(&p.name))
        .map(|(i, _)| i)
        .collect();

    let non_native_packages: Vec<_> = packages
        .iter()
        .enumerate()
        .filter(|(i, _)| !native_indices.contains(i))
        .map(|(_, p)| p.clone())
        .collect();

    // 6. Query OSV
    let osv_client = osv::OsvClient::new()?;
    let osv_results = osv_client.query_batch(&non_native_packages).await?;

    // 7. Apply rules
    let (rules_statements, rules_filtered) = if let Some(ref config) = rules_config {
        filters::rules::apply_rules(&osv_results, config)
    } else {
        (Vec::new(), Vec::new())
    };

    // 8. Apply hardware filters
    let remaining_after_rules: Vec<_> = osv_results
        .iter()
        .enumerate()
        .filter(|(i, _)| !rules_filtered.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (kernel_statements, kernel_filtered) = if !kernel_configs.is_empty() {
        let merged = merge_configs(&kernel_configs);
        filters::kernel_config::filter_by_kernel_config(&remaining_after_rules, &merged)
    } else {
        (Vec::new(), Vec::new())
    };

    let remaining_after_kernel: Vec<_> = remaining_after_rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !kernel_filtered.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (uboot_statements, uboot_filtered) = if let Some(ref cfg) = uboot_config {
        filters::kernel_config::filter_by_kernel_config(&remaining_after_kernel, cfg)
    } else {
        (Vec::new(), Vec::new())
    };

    let remaining_after_uboot: Vec<_> = remaining_after_kernel
        .iter()
        .enumerate()
        .filter(|(i, _)| !uboot_filtered.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (dts_statements, _) =
        filters::device_tree::filter_by_device_tree(&remaining_after_uboot, &dts_nodes_all);

    // 9. Build native statements
    let native_osv: Vec<_> = packages
        .iter()
        .enumerate()
        .filter(|(i, _)| native_indices.contains(i))
        .map(|(_, p)| osv::OsvResult {
            package: p.clone(),
            vulns: vec![],
        })
        .collect();
    let (native_statements, _) = filter_native_packages(&native_osv);

    // 10. Remaining get affected status
    let remaining_indices: Vec<usize> = remaining_after_uboot
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            let pkg_lower = r.package.name.to_lowercase();
            let disabled: Vec<String> = dts_nodes_all
                .iter()
                .filter(|n| n.status == filters::device_tree::NodeStatus::Disabled)
                .filter_map(|n| n.compatible.clone())
                .collect();
            !disabled.iter().any(|c| {
                let cl = c.to_lowercase();
                pkg_lower.contains(&cl) || cl.contains(&pkg_lower)
            })
        })
        .map(|(i, _)| i)
        .collect();

    let mut all_statements = Vec::new();
    all_statements.extend(native_statements);
    all_statements.extend(rules_statements);
    all_statements.extend(kernel_statements);
    all_statements.extend(uboot_statements);
    all_statements.extend(dts_statements);

    for &i in &remaining_indices {
        let result = &remaining_after_uboot[i];
        for vuln in &result.vulns {
            let purl = result
                .package
                .purl
                .clone()
                .unwrap_or_else(|| format!("pkg:generic/{}", result.package.name));
            all_statements.push(vex::VexStatement {
                vulnerability_name: vuln.id.clone(),
                product_purl: purl,
                status: VexStatus::Affected,
                justification: None,
                impact_statement: Some(format!(
                    "Vulnerability {} affects {} version {}.",
                    vuln.id,
                    result.package.name,
                    result.package.version.as_deref().unwrap_or("unknown")
                )),
            });
        }
    }

    let affected = all_statements
        .iter()
        .filter(|s| s.status == VexStatus::Affected)
        .count();
    let not_affected = all_statements
        .iter()
        .filter(|s| s.status == VexStatus::NotAffected)
        .count();

    // 11. Save to SQLite
    let scan_id = state.insert_scan(&project.name, packages.len(), affected, not_affected)?;

    for stmt in &all_statements {
        state.insert_cve(
            scan_id,
            &stmt.vulnerability_name,
            &stmt.product_purl,
            None,
            stmt.status.as_str(),
            None,
        )?;
    }

    // 12. Detect new CVEs
    let new_cves = state.detect_new_cves(&project.name, scan_id)?;
    if !new_cves.is_empty() {
        warn!(
            "  ⚠ {} NEW CVEs detected in '{}':",
            new_cves.len(),
            project.name
        );
        for cve in &new_cves {
            warn!("    - {} affects {}", cve.vuln_id, cve.package);
        }
    } else {
        info!("  ✓ No new CVEs detected");
    }

    // 13. Generate report if output dir specified
    if let Some(out_dir) = output_dir {
        std::fs::create_dir_all(out_dir)?;
        let filename = format!(
            "{}-{}.vex.json",
            project.name.replace(' ', "-").to_lowercase(),
            chrono::Utc::now().format("%Y%m%dT%H%M%S")
        );
        let out_path = out_dir.join(&filename);

        let author_str = project.author.as_deref().unwrap_or(author);
        let vex_doc = generate_openvex(&all_statements, author_str);
        let json = serde_json::to_string_pretty(&vex_doc)?;
        std::fs::write(&out_path, &json)?;
        info!("  Report saved: {}", out_path.display());
    }

    info!(
        "  Scan complete: {} affected, {} not affected, {} total packages",
        affected,
        not_affected,
        packages.len()
    );

    Ok(ScanResult {
        scan_id,
        total_packages: packages.len(),
        affected,
        not_affected,
        statements: all_statements,
    })
}

fn merge_configs(
    configs: &[std::collections::HashMap<String, filters::kernel_config::ConfigValue>],
) -> std::collections::HashMap<String, filters::kernel_config::ConfigValue> {
    let mut merged = std::collections::HashMap::new();
    for config in configs {
        for (key, value) in config {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}
