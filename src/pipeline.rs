//! Scan pipeline orchestration.
//!
//! Contains the main scanning logic that coordinates SBOM parsing,
//! OSV querying, hardware filtering, EPSS scoring, and report generation.

use std::collections::HashMap;

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::cli::Args;
use crate::epss;
use crate::filters;
use crate::osv;
use crate::output;
use crate::rules;
use crate::sbom;
use crate::vex;

use filters::device_tree::parse_device_tree;
use filters::kernel_config::parse_kernel_config;
use filters::native::filter_native_packages;
use sbom::parse_spdx_sbom;
use vex::{VexStatus, generate_openvex};

/// Run the main BitVex scan pipeline.
///
/// Orchestrates the complete vulnerability analysis workflow:
/// 1. Parse SBOM (SPDX JSON)
/// 2. Parse optional hardware configs (kernel, U-Boot, device tree)
/// 3. Load optional rules file
/// 4. Filter native build packages
/// 5. Query OSV for vulnerabilities
/// 6. Resolve GHSA/OSV aliases to CVE IDs
/// 7. Query EPSS for exploitability scores (if enabled)
/// 8. Apply hardware-aware filters
/// 9. Generate OpenVEX or SARIF report
/// 10. Print console summary
/// 11. Apply CI/CD exit codes
///
/// # Arguments
///
/// * `args` - Parsed CLI arguments
///
/// # Errors
///
/// Returns an error if required inputs are missing or parsing fails.
pub async fn run_scan(args: &Args) -> Result<()> {
    info!("BitVex v{} starting", env!("CARGO_PKG_VERSION"));

    // 1. Parse SBOM (required)
    let sbom_path = args
        .sbom
        .as_ref()
        .context("--sbom is required for scan mode")?;

    info!("Parsing SBOM: {}", sbom_path.display());
    let sbom_data = std::fs::read(sbom_path)
        .with_context(|| format!("Failed to read SBOM: {}", sbom_path.display()))?;

    // SPDX version detection
    if let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&sbom_data) {
        if let Some(version) = doc.get("spdxVersion").and_then(|v| v.as_str()) {
            if version.starts_with("SPDX-3") {
                warn!(
                    "SPDX 3.0 detected ({}) - limited support. Only basic package extraction.",
                    version
                );
            }
        }
    }

    let packages = parse_spdx_sbom(&sbom_data)?;
    info!("Found {} packages in SBOM", packages.len());

    if packages.is_empty() {
        warn!("No packages found in SBOM, nothing to do");
        return Ok(());
    }

    // 2. Parse kernel config (optional)
    let kernel_configs: Vec<_> = args
        .kernel_config
        .iter()
        .map(|path| {
            info!("Parsing kernel config: {}", path.display());
            parse_kernel_config(path)
        })
        .collect::<Result<Vec<_>>>()?;

    // 3. Parse U-Boot config (optional)
    let uboot_config = if let Some(ref uboot_path) = args.uboot_config {
        info!("Parsing U-Boot config: {}", uboot_path.display());
        Some(parse_kernel_config(uboot_path)?)
    } else {
        None
    };

    // 4. Parse device tree (optional)
    let dts_nodes = if let Some(ref dt_path) = args.device_tree {
        info!("Parsing device tree: {}", dt_path.display());
        Some(parse_device_tree(dt_path)?)
    } else {
        None
    };

    // 5. Load rules if provided
    let rules_config = if let Some(ref rules_path) = args.rules {
        Some(rules::load_rules(rules_path)?)
    } else {
        None
    };

    // 6. Pre-OSV filter: native packages
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

    info!(
        "Querying OSV for {} non-native packages (skipping {} native)",
        non_native_packages.len(),
        native_indices.len()
    );

    // 7. Download DB if requested and using offline mode
    if args.offline && args.download_db {
        let db_path = args
            .db_path
            .clone()
            .unwrap_or_else(osv::db::default_db_path);
        let eco_list = osv::db::resolve_ecosystems(None, args.profile.as_ref());
        osv::db::download_databases(&db_path, &eco_list, args.yes).await?;
    }

    // 8. Query OSV (online or offline)
    let osv_results = if args.offline {
        let db_path = args
            .db_path
            .clone()
            .unwrap_or_else(osv::db::default_db_path);
        let provider = osv::offline::OfflineOsvProvider::new(&db_path)?;
        provider.query_batch(&non_native_packages)?
    } else {
        let client = osv::OsvClient::new()?;
        client.query_batch(&non_native_packages).await?
    };

    // 9. Query EPSS if enabled
    let epss_scores = if args.epss {
        let mut all_cve_ids: Vec<String> = Vec::new();
        for result in &osv_results {
            for vuln in &result.vulns {
                if vuln.id.starts_with("CVE-") {
                    all_cve_ids.push(vuln.id.clone());
                }
                for alias in &vuln.aliases {
                    if alias.starts_with("CVE-") && !all_cve_ids.contains(alias) {
                        all_cve_ids.push(alias.clone());
                    }
                }
            }
        }
        all_cve_ids.sort();
        all_cve_ids.dedup();

        info!("Found {} unique CVE IDs for EPSS lookup", all_cve_ids.len());

        if all_cve_ids.is_empty() {
            Vec::new()
        } else if args.epss_offline {
            let epss_path = args
                .epss_db_path
                .clone()
                .unwrap_or_else(epss::offline::default_epss_db_path);
            let provider = epss::OfflineEpssProvider::new(&epss_path)?;
            provider.query_batch(&all_cve_ids)
        } else {
            let client = epss::EpssClient::new()?;
            client.query_batch(&all_cve_ids).await?
        }
    } else {
        Vec::new()
    };

    // 10. Apply rules engine first (if provided)
    let (rules_statements, rules_filtered_indices) = if let Some(ref config) = rules_config {
        filters::rules::apply_rules(&osv_results, config)
    } else {
        (Vec::new(), Vec::new())
    };

    // 11. Apply hardware filters on remaining
    let remaining_after_rules: Vec<_> = osv_results
        .iter()
        .enumerate()
        .filter(|(i, _)| !rules_filtered_indices.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (kernel_statements, kernel_filtered_local) = if !kernel_configs.is_empty() {
        let merged = merge_kernel_configs(&kernel_configs);
        let (stmts, filtered) =
            filters::kernel_config::filter_by_kernel_config(&remaining_after_rules, &merged);
        (stmts, filtered)
    } else {
        (Vec::new(), Vec::new())
    };

    let remaining_after_kernel: Vec<_> = remaining_after_rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !kernel_filtered_local.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (uboot_statements, uboot_filtered_local) = if let Some(ref uboot_cfg) = uboot_config {
        filters::kernel_config::filter_by_kernel_config(&remaining_after_kernel, uboot_cfg)
    } else {
        (Vec::new(), Vec::new())
    };

    let remaining_after_uboot: Vec<_> = remaining_after_kernel
        .iter()
        .enumerate()
        .filter(|(i, _)| !uboot_filtered_local.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (dts_statements, dts_filtered_local) = if let Some(ref dts) = dts_nodes {
        filters::device_tree::filter_by_device_tree(&remaining_after_uboot, dts)
    } else {
        (Vec::new(), Vec::new())
    };

    // 12. Build native statements
    let native_osv_results: Vec<_> = packages
        .iter()
        .enumerate()
        .filter(|(i, _)| native_indices.contains(i))
        .map(|(_, p)| osv::OsvResult {
            package: p.clone(),
            vulns: vec![],
        })
        .collect();

    let (native_statements, _) = filter_native_packages(&native_osv_results);

    // 13. Remaining packages get affected status (with EPSS if available)
    let remaining_indices: Vec<usize> = remaining_after_uboot
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            if let Some(ref dts) = dts_nodes {
                let pkg_lower = r.package.name.to_lowercase();
                let disabled_names: Vec<String> = dts
                    .iter()
                    .filter(|n| n.status == filters::device_tree::NodeStatus::Disabled)
                    .filter_map(|n| n.compatible.clone())
                    .collect();
                !disabled_names.iter().any(|compat| {
                    let cl = compat.to_lowercase();
                    pkg_lower.contains(&cl) || cl.contains(&pkg_lower)
                })
            } else {
                true
            }
        })
        .map(|(i, _)| i)
        .collect();

    let mut all_statements = Vec::new();
    all_statements.extend(native_statements);
    all_statements.extend(rules_statements);
    all_statements.extend(kernel_statements);
    all_statements.extend(uboot_statements);
    all_statements.extend(dts_statements);

    let mut _low_priority_count = 0usize;

    for &i in &remaining_indices {
        let result = &remaining_after_uboot[i];
        for vuln in &result.vulns {
            let purl = result
                .package
                .purl
                .clone()
                .unwrap_or_else(|| format!("pkg:generic/{}", result.package.name));

            let epss_score = epss_scores.iter().find(|e| e.cve == vuln.id).or_else(|| {
                vuln.aliases
                    .iter()
                    .find(|a| a.starts_with("CVE-"))
                    .and_then(|cve| epss_scores.iter().find(|e| &e.cve == cve))
            });
            let is_low_priority = epss_score
                .map(|e| e.epss < args.epss_threshold)
                .unwrap_or(false);

            if is_low_priority {
                _low_priority_count += 1;
            }

            let epss_note = epss_score
                .map(|e| {
                    format!(
                        " [EPSS: {:.1}%, Pctl: {:.1}%]",
                        e.epss * 100.0,
                        e.percentile * 100.0
                    )
                })
                .unwrap_or_default();

            all_statements.push(vex::VexStatement {
                vulnerability_name: vuln.id.clone(),
                product_purl: purl,
                status: VexStatus::Affected,
                justification: None,
                impact_statement: Some(format!(
                    "Vulnerability {} affects package {} version {}.{}",
                    vuln.id,
                    result.package.name,
                    result.package.version.as_deref().unwrap_or("unknown"),
                    epss_note,
                )),
            });
        }
    }

    info!("Total VEX statements: {}", all_statements.len());

    // 14. Build vuln_cve_map for EPSS lookup
    let mut vuln_cve_map: HashMap<String, String> = HashMap::new();
    for result in &osv_results {
        for vuln in &result.vulns {
            if !vuln.id.starts_with("CVE-") {
                for alias in &vuln.aliases {
                    if alias.starts_with("CVE-") {
                        vuln_cve_map.insert(vuln.id.clone(), alias.clone());
                        break;
                    }
                }
            }
        }
    }

    // 15. Generate output in requested format
    let author = rules_config
        .as_ref()
        .and_then(|c| c.author.as_ref().map(|a| a.name.as_str()))
        .unwrap_or(&args.author);

    let output_json = match args.format {
        crate::cli::OutputFormat::Openvex => {
            let vex_doc = generate_openvex(&all_statements, author);
            serde_json::to_string_pretty(&vex_doc)?
        }
        crate::cli::OutputFormat::Sarif => {
            let sarif_val =
                output::sarif::generate_sarif(&all_statements, &epss_scores, &vuln_cve_map);
            serde_json::to_string_pretty(&sarif_val)?
        }
    };

    std::fs::write(&args.output, &output_json)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;
    info!("Report written to: {}", args.output.display());

    // 16. Print console summary
    let kernel_filtered_total = kernel_filtered_local.len() + uboot_filtered_local.len();
    let dts_filtered_total = dts_filtered_local.len();

    output::print_summary(&output::SummaryData {
        total_packages: packages.len(),
        native_filtered: native_indices.len(),
        kernel_filtered: kernel_filtered_total,
        dts_filtered: dts_filtered_total,
        statements: &all_statements,
        epss_scores: &epss_scores,
        epss_enabled: args.epss,
        vuln_cve_map: &vuln_cve_map,
    });

    // 16. CI/CD exit codes
    let affected_count = all_statements
        .iter()
        .filter(|s| s.status == VexStatus::Affected)
        .count();

    if args.fail_on_any && affected_count > 0 {
        eprintln!("FAIL: {} CVEs require attention", affected_count);
        std::process::exit(1);
    }

    if args.fail_on_critical {
        let critical = epss_scores.iter().any(|e| e.epss > 0.9);
        if critical {
            eprintln!("FAIL: Critical CVEs detected (EPSS > 0.9)");
            std::process::exit(1);
        }
    }

    if args.fail_on_high {
        let high = epss_scores.iter().any(|e| e.epss > 0.7);
        if high {
            eprintln!("FAIL: High-risk CVEs detected (EPSS > 0.7)");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn merge_kernel_configs(
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
