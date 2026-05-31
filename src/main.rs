use bitvex::cli::{Args, Command};
use bitvex::epss;
use bitvex::osv;
use bitvex::sbom;
use bitvex::watch;

use anyhow::{Context, Result};
use clap::Parser;
use tabled::{Table, Tabled};
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
        Some(Command::Watch { config }) => {
            return cmd_watch(&config).await;
        }
        Some(Command::Status { project, db_path }) => {
            return cmd_status(project.as_deref(), db_path.as_deref());
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

async fn cmd_watch(config_path: &std::path::Path) -> Result<()> {
    let config = watch::config::load_watch_config(&config_path.to_path_buf())?;

    let db_path = config.db_path.clone().unwrap_or_else(|| {
        dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("bitvex")
            .join("watch-state.db")
    });

    let state = watch::WatchState::new(&db_path)?;

    watch::watcher::run_watch(&config, &state, "BitVex <bitvex@automated>").await
}

fn cmd_status(project: Option<&str>, db_path: Option<&std::path::Path>) -> Result<()> {
    let path = db_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("bitvex")
            .join("watch-state.db")
    });

    if !path.exists() {
        println!("No watch database found at {}", path.display());
        println!("Run 'bitvex watch --config <path>' first to start monitoring.");
        return Ok(());
    }

    let state = watch::WatchState::new(&path)?;

    #[derive(Tabled)]
    struct StatusRow {
        #[tabled(rename = "Project")]
        project: String,
        #[tabled(rename = "Last Scan")]
        last_scan: String,
        #[tabled(rename = "Packages")]
        packages: String,
        #[tabled(rename = "Affected")]
        affected: String,
        #[tabled(rename = "Status")]
        status: String,
    }

    if let Some(proj_name) = project {
        // Show details for a specific project
        let scan = state.get_last_scan(proj_name)?;
        match scan {
            Some(s) => {
                println!();
                println!("Project: {}", s.project);
                println!("Last scan: {}", s.timestamp);
                println!("Packages: {}", s.total_packages);
                println!("Affected: {}", s.affected);
                println!("Not affected: {}", s.not_affected);

                let cves = state.get_cves_for_scan(s.id)?;
                if !cves.is_empty() {
                    println!();
                    println!("CVEs:");
                    for cve in &cves {
                        println!(
                            "  {} | {} | {} | first: {}",
                            cve.vuln_id, cve.package, cve.status, cve.first_seen
                        );
                    }
                }
                println!();
            }
            None => {
                println!("No scan found for project '{}'", proj_name);
            }
        }
    } else {
        // Show all projects
        let projects = state.get_all_project_status()?;

        if projects.is_empty() {
            println!("No projects found in watch database.");
            println!("Run 'bitvex watch --config <path>' first to start monitoring.");
            return Ok(());
        }

        let rows: Vec<StatusRow> = projects
            .iter()
            .map(|s| {
                let status = if s.affected > 0 {
                    "⚠ warning"
                } else {
                    "✓ clean"
                };
                StatusRow {
                    project: s.project.clone(),
                    last_scan: s.timestamp.clone(),
                    packages: s.total_packages.to_string(),
                    affected: s.affected.to_string(),
                    status: status.to_string(),
                }
            })
            .collect();

        println!();
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║          BitVex - Project Status                        ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  Monitored projects: {:<36} ║", projects.len());
        println!("╚══════════════════════════════════════════════════════════╝");
        println!();
        let table = Table::new(rows).to_string();
        println!("{}", table);
        println!();
    }

    Ok(())
}
