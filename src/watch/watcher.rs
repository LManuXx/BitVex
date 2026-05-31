//! File watcher with debouncing for watch mode.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::RecursiveMode;
use notify_debouncer_mini::new_debouncer;
use tracing::{debug, info, warn};

use crate::watch::config::WatchConfig;
use crate::watch::scanner;
use crate::watch::state::{WatchState, compute_file_hash};

/// Start the watch loop.
pub async fn run_watch(config: &WatchConfig, state: &WatchState, author: &str) -> Result<()> {
    let debounce_duration = Duration::from_secs(config.debounce_secs.unwrap_or(5));
    let output_dir = config.output_dir.clone();

    // Build a map of file path -> project index
    let mut file_to_project: Vec<(PathBuf, usize)> = Vec::new();
    for (idx, project) in config.projects.iter().enumerate() {
        for path in project.watched_paths() {
            file_to_project.push((path, idx));
        }
    }

    // Compute initial hashes for all files
    for (path, _) in &file_to_project {
        if path.exists() {
            if let Ok(hash) = compute_file_hash(path) {
                state.set_file_hash(&path.to_string_lossy(), &hash)?;
            }
        }
    }

    // Do initial scan for all projects
    info!(
        "Running initial scan for {} projects...",
        config.projects.len()
    );
    for project in &config.projects {
        let result = scanner::scan_project(project, state, author, output_dir.as_deref()).await;

        match result {
            Ok(r) => {
                if r.affected > 0 {
                    warn!(
                        "⚠  '{}': {} CVEs require attention",
                        project.name, r.affected
                    );
                } else {
                    info!("✓  '{}': clean", project.name);
                }
            }
            Err(e) => {
                warn!("Failed to scan '{}': {}", project.name, e);
            }
        }
    }

    // Set up file watcher
    let (tx, rx) = mpsc::channel();
    let mut debouncer =
        new_debouncer(debounce_duration, tx).context("Failed to create file watcher")?;

    // Watch all files
    let mut watched_paths = HashSet::new();
    for (path, _) in &file_to_project {
        if path.exists() {
            if let Some(parent) = path.parent() {
                let parent_str = parent.to_string_lossy().to_string();
                if !watched_paths.contains(&parent_str) {
                    debouncer
                        .watcher()
                        .watch(parent, RecursiveMode::NonRecursive)
                        .with_context(|| {
                            format!("Failed to watch directory: {}", parent.display())
                        })?;
                    watched_paths.insert(parent_str);
                    debug!("Watching directory: {}", parent.display());
                }
            }
        }
    }

    info!(
        "Watching {} projects for changes (debounce: {}s)...",
        config.projects.len(),
        config.debounce_secs.unwrap_or(5)
    );
    println!();
    println!("Press Ctrl+C to stop watching.");
    println!();

    // Event loop
    loop {
        match rx.recv() {
            Ok(Ok(events)) => {
                let changed_files: Vec<PathBuf> = events.iter().map(|e| e.path.clone()).collect();

                if changed_files.is_empty() {
                    continue;
                }

                // Determine which projects are affected
                let mut affected_projects: HashSet<usize> = HashSet::new();

                for changed in &changed_files {
                    let changed_str = changed.to_string_lossy();
                    for (path, idx) in &file_to_project {
                        if path.to_string_lossy() == changed_str {
                            // Verify hash actually changed
                            if let Ok(new_hash) = compute_file_hash(changed) {
                                let old_hash = state.get_file_hash(&changed_str);
                                if old_hash.as_deref() == Some(&new_hash) {
                                    debug!("File hash unchanged, skipping: {}", changed.display());
                                    continue;
                                }
                                state.set_file_hash(&changed_str, &new_hash)?;
                                affected_projects.insert(*idx);
                                info!("Change detected: {}", changed.display());
                            }
                        }
                    }
                }

                // Re-scan affected projects
                for idx in affected_projects {
                    let project = &config.projects[idx];
                    info!("Re-scanning '{}'...", project.name);

                    let result =
                        scanner::scan_project(project, state, author, output_dir.as_deref()).await;

                    match result {
                        Ok(r) => {
                            let new_cves = state
                                .detect_new_cves(&project.name, r.scan_id)
                                .unwrap_or_default();

                            if !new_cves.is_empty() {
                                println!();
                                println!("⚠  NEW CVEs in '{}':", project.name);
                                for cve in &new_cves {
                                    println!("   {} affects {}", cve.vuln_id, cve.package);
                                }
                                println!();
                            } else if r.affected > 0 {
                                println!("⚠  '{}': {} CVEs (no new)", project.name, r.affected);
                            } else {
                                println!("✓  '{}': clean", project.name);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to scan '{}': {}", project.name, e);
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("Watch error: {:?}", e);
            }
            Err(e) => {
                // Channel closed
                warn!("Watch channel closed: {}", e);
                break;
            }
        }
    }

    Ok(())
}
