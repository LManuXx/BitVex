use bitvex::cli::{Args, Command};
use bitvex::filters;
use bitvex::osv;
use bitvex::output;
use bitvex::rules;
use bitvex::sbom;
use bitvex::vex;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

use filters::device_tree::parse_device_tree;
use filters::kernel_config::parse_kernel_config;
use filters::native::filter_native_packages;
use sbom::parse_spdx_sbom;
use vex::{VexStatus, generate_openvex};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

    match args.command {
        Some(Command::Diff { old, new, output }) => {
            return cmd_diff(&old, &new, output.as_deref());
        }
        Some(Command::DownloadDb {
            db_path,
            ecosystems,
            profile,
            yes,
        }) => {
            return cmd_download_db(
                db_path.as_deref(),
                ecosystems.as_deref(),
                profile.as_ref(),
                yes,
            )
            .await;
        }
        None => {}
    }

    cmd_scan(&args).await
}

fn cmd_diff(
    old: &std::path::Path,
    new: &std::path::Path,
    output: Option<&std::path::Path>,
) -> Result<()> {
    info!("Comparing SBOMs");
    let diff = sbom::diff::diff_sboms(old, new)?;

    sbom::diff::print_diff_summary(&diff);

    if let Some(out_path) = output {
        let json = serde_json::to_string_pretty(&diff)?;
        std::fs::write(out_path, &json)
            .with_context(|| format!("Failed to write diff: {}", out_path.display()))?;
        info!("Diff written to {}", out_path.display());
    }

    Ok(())
}

async fn cmd_download_db(
    db_path: Option<&std::path::Path>,
    ecosystems: Option<&[String]>,
    profile: Option<&bitvex::cli::DownloadProfile>,
    yes: bool,
) -> Result<()> {
    let path = db_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(osv::db::default_db_path);

    let eco_list = osv::db::resolve_ecosystems(ecosystems, profile);

    osv::db::download_databases(&path, &eco_list, yes).await
}

async fn cmd_scan(args: &Args) -> Result<()> {
    info!("BitVex starting");

    let sbom_path = args
        .sbom
        .as_ref()
        .context("--sbom is required for scan mode")?;
    let kernel_config_path = args
        .kernel_config
        .as_ref()
        .context("--kernel-config is required for scan mode")?;
    let device_tree_path = args
        .device_tree
        .as_ref()
        .context("--device-tree is required for scan mode")?;

    // 1. Parse SBOM
    info!("Parsing SBOM: {}", sbom_path.display());
    let sbom_data = std::fs::read(sbom_path)
        .with_context(|| format!("Failed to read SBOM: {}", sbom_path.display()))?;
    let packages = parse_spdx_sbom(&sbom_data)?;
    info!("Found {} packages in SBOM", packages.len());

    if packages.is_empty() {
        warn!("No packages found in SBOM, nothing to do");
        return Ok(());
    }

    // 2. Parse kernel config
    info!("Parsing kernel config: {}", kernel_config_path.display());
    let kernel_config = parse_kernel_config(kernel_config_path)?;

    // 3. Parse device tree
    info!("Parsing device tree: {}", device_tree_path.display());
    let dts_nodes = parse_device_tree(device_tree_path)?;

    // 4. Load rules if provided
    let rules_config = if let Some(ref rules_path) = args.rules {
        Some(rules::load_rules(rules_path)?)
    } else {
        None
    };

    // 5. Pre-OSV filter: native packages
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

    // 6. Download DB if requested and using offline mode
    if args.offline && args.download_db {
        let db_path = args
            .db_path
            .clone()
            .unwrap_or_else(osv::db::default_db_path);

        let eco_list = osv::db::resolve_ecosystems(None, args.profile.as_ref());

        osv::db::download_databases(&db_path, &eco_list, args.yes).await?;
    }

    // 7. Query OSV (online or offline)
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

    // 8. Apply rules engine first (if provided)
    let (rules_statements, rules_filtered_indices) = if let Some(ref config) = rules_config {
        filters::rules::apply_rules(&osv_results, config)
    } else {
        (Vec::new(), Vec::new())
    };

    // 9. Apply hardware filters on remaining
    let remaining_after_rules: Vec<_> = osv_results
        .iter()
        .enumerate()
        .filter(|(i, _)| !rules_filtered_indices.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (kernel_statements, kernel_filtered_local) =
        filters::kernel_config::filter_by_kernel_config(&remaining_after_rules, &kernel_config);

    let remaining_after_kernel: Vec<_> = remaining_after_rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !kernel_filtered_local.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (dts_statements, dts_filtered_local) =
        filters::device_tree::filter_by_device_tree(&remaining_after_kernel, &dts_nodes);

    // 10. Build native statements
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

    // 11. Remaining packages get affected status
    let remaining_indices: Vec<usize> = remaining_after_rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !kernel_filtered_local.contains(i))
        .filter(|(_, r)| {
            let pkg_lower = r.package.name.to_lowercase();
            let disabled_names: Vec<String> = dts_nodes
                .iter()
                .filter(|n| n.status == filters::device_tree::NodeStatus::Disabled)
                .filter_map(|n| n.compatible.clone())
                .collect();
            !disabled_names.iter().any(|compat| {
                let cl = compat.to_lowercase();
                pkg_lower.contains(&cl) || cl.contains(&pkg_lower)
            })
        })
        .map(|(i, _)| i)
        .collect();

    let mut all_statements = Vec::new();
    all_statements.extend(native_statements);
    all_statements.extend(rules_statements);
    all_statements.extend(kernel_statements);
    all_statements.extend(dts_statements);

    for &i in &remaining_indices {
        let result = &remaining_after_rules[i];
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
                    "Vulnerability {} affects package {} version {}.",
                    vuln.id,
                    result.package.name,
                    result.package.version.as_deref().unwrap_or("unknown")
                )),
            });
        }
    }

    info!("Total VEX statements: {}", all_statements.len());

    // 12. Generate OpenVEX document
    let author = rules_config
        .as_ref()
        .and_then(|c| c.author.as_ref().map(|a| a.name.as_str()))
        .unwrap_or(&args.author);

    let vex_doc = generate_openvex(&all_statements, author);
    let vex_json = serde_json::to_string_pretty(&vex_doc)?;

    std::fs::write(&args.output, &vex_json)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;
    info!("OpenVEX report written to: {}", args.output.display());

    // 13. Print console summary
    output::print_summary(
        packages.len(),
        native_indices.len(),
        kernel_filtered_local.len(),
        dts_filtered_local.len(),
        &all_statements,
    );

    Ok(())
}
