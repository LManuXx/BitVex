use bitvex::cli::{Args, Command};
use bitvex::epss;
use bitvex::osv;
use bitvex::sbom;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

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
        Some(Command::DownloadEpssDb { db_path, yes }) => {
            return cmd_download_epss_db(db_path.as_deref(), yes).await;
        }
        Some(Command::Delta { old, new, output }) => {
            return cmd_delta(&old, &new, output.as_deref());
        }
        None => {}
    }

    bitvex::pipeline::run_scan(&args).await
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

fn cmd_delta(
    old: &std::path::Path,
    new: &std::path::Path,
    output: Option<&std::path::Path>,
) -> Result<()> {
    info!("Comparing VEX documents");
    let delta = bitvex::vex::delta::compare_vex(old, new)?;

    bitvex::vex::delta::print_delta_summary(&delta);

    if let Some(out_path) = output {
        let json = serde_json::to_string_pretty(&delta)?;
        std::fs::write(out_path, &json)
            .with_context(|| format!("Failed to write delta: {}", out_path.display()))?;
        info!("Delta written to {}", out_path.display());
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

async fn cmd_download_epss_db(db_path: Option<&std::path::Path>, yes: bool) -> Result<()> {
    let path = db_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(epss::offline::default_epss_db_path);

    epss::offline::download_epss_db(&path, yes).await
}
