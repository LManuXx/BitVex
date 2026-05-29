use bitvex::cli;
use bitvex::filters;
use bitvex::osv;
use bitvex::output;
use bitvex::sbom;
use bitvex::vex;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

use cli::Args;
use filters::device_tree::parse_device_tree;
use filters::kernel_config::parse_kernel_config;
use filters::native::filter_native_packages;
use osv::OsvClient;
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

    info!("BitVex starting");

    // 1. Parse SBOM
    info!("Parsing SBOM: {}", args.sbom.display());
    let sbom_data = std::fs::read(&args.sbom)
        .with_context(|| format!("Failed to read SBOM: {}", args.sbom.display()))?;
    let packages = parse_spdx_sbom(&sbom_data)?;
    info!("Found {} packages in SBOM", packages.len());

    if packages.is_empty() {
        warn!("No packages found in SBOM, nothing to do");
        return Ok(());
    }

    // 2. Parse kernel config
    info!("Parsing kernel config: {}", args.kernel_config.display());
    let kernel_config = parse_kernel_config(&args.kernel_config)?;

    // 3. Parse device tree
    info!("Parsing device tree: {}", args.device_tree.display());
    let dts_nodes = parse_device_tree(&args.device_tree)?;

    // 4. Pre-OSV filter: native packages
    let osv_client = OsvClient::new()?;

    // First, query all non-native packages against OSV
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

    let osv_results = osv_client.query_batch(&non_native_packages).await?;

    // 5. Apply hardware filters
    let (kernel_statements, kernel_filtered_local) =
        filters::kernel_config::filter_by_kernel_config(&osv_results, &kernel_config);

    let remaining_after_kernel: Vec<_> = osv_results
        .iter()
        .enumerate()
        .filter(|(i, _)| !kernel_filtered_local.contains(i))
        .map(|(_, r)| r.clone())
        .collect();

    let (dts_statements, dts_filtered_local) =
        filters::device_tree::filter_by_device_tree(&remaining_after_kernel, &dts_nodes);

    // Build native statements (from native packages)
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

    // Remaining packages (not filtered by any rule) get status based on OSV results
    let remaining_indices: Vec<usize> = osv_results
        .iter()
        .enumerate()
        .filter(|(i, _)| !kernel_filtered_local.contains(i))
        .filter(|(i, _)| {
            let pkg = &osv_results[*i].package;
            let pkg_lower = pkg.name.to_lowercase();
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
    all_statements.extend(kernel_statements);
    all_statements.extend(dts_statements);

    // Add remaining as affected or under_investigation
    for &i in &remaining_indices {
        let result = &osv_results[i];
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

    // 6. Generate OpenVEX document
    let vex_doc = generate_openvex(&all_statements, &args.author);
    let vex_json = serde_json::to_string_pretty(&vex_doc)?;

    std::fs::write(&args.output, &vex_json)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;
    info!("OpenVEX report written to: {}", args.output.display());

    // 7. Print console summary
    let kernel_filtered_total = kernel_filtered_local.len();
    let dts_filtered_total = dts_filtered_local.len();

    output::print_summary(
        packages.len(),
        native_indices.len(),
        kernel_filtered_total,
        dts_filtered_total,
        &all_statements,
    );

    Ok(())
}
