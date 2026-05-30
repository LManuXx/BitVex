use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use tracing::{info, warn};

const OSV_BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";

const ECOSYSTEM_SIZES: &[(&str, u64)] = &[
    ("Alpine", 4_918_205),
    ("Debian", 58_055_286),
    ("Ubuntu", 515_463_105),
    ("Linux", 30_094_473),
    ("crates.io", 2_971_880),
    ("Go", 8_812_651),
    ("npm", 205_905_447),
    ("PyPI", 24_194_212),
    ("Maven", 9_367_361),
    ("NuGet", 2_204_922),
];

pub fn default_db_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("bitvex")
        .join("osv-db")
}

pub fn resolve_ecosystems<'a>(
    ecosystems: Option<&'a [String]>,
    profile: Option<&'a crate::cli::DownloadProfile>,
) -> Vec<&'a str> {
    if let Some(eco) = ecosystems {
        eco.iter().map(|s| s.as_str()).collect()
    } else if let Some(p) = profile {
        p.ecosystems().to_vec()
    } else {
        crate::cli::DownloadProfile::Medium.ecosystems().to_vec()
    }
}

fn ecosystem_size(name: &str) -> u64 {
    ECOSYSTEM_SIZES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, s)| *s)
        .unwrap_or(0)
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.0} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn check_existing_db(db_path: &Path) -> Option<u64> {
    if !db_path.exists() {
        return None;
    }

    let meta = std::fs::metadata(db_path).ok()?;
    let modified = meta.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    let age_secs = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs()
        .saturating_sub(duration.as_secs());

    Some(age_secs)
}

fn print_download_plan(db_path: &Path, ecosystems: &[&str], already_exists: bool, age_days: u64) {
    let total: u64 = ecosystems.iter().map(|e| ecosystem_size(e)).sum();

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          BitVex - Download OSV Database                 ║");
    println!("╠══════════════════════════════════════════════════════════╣");

    if already_exists {
        println!(
            "║  ⚠  Database already exists ({} days old)             ║",
            age_days
        );
        println!("╠══════════════════════════════════════════════════════════╣");
    }

    println!("║  Destination: {:<42} ║", truncate_path(db_path, 42));
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Ecosystem         Size         Status                   ║");
    println!("║  ──────────────────────────────────────────────────      ║");

    for eco in ecosystems {
        let size = ecosystem_size(eco);
        let json_path = db_path.join(eco).join("all.json");
        let status = if json_path.exists() {
            "✓ Cached"
        } else {
            "⏳ Pending"
        };
        println!("║  {:<18} {:<12} {:<24} ║", eco, format_size(size), status);
    }

    println!("║  ──────────────────────────────────────────────────      ║");
    println!("║  TOTAL              {:<38} ║", format_size(total));
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
}

fn truncate_path(path: &Path, max: usize) -> String {
    let s = path.display().to_string();
    if s.len() <= max {
        s
    } else {
        format!("...{}", &s[s.len() - max + 3..])
    }
}

fn prompt_confirm(message: &str) -> Result<bool> {
    print!("{} [Y/n]: ", message);
    io::stdout().flush().context("Failed to flush stdout")?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;

    let trimmed = input.trim().to_lowercase();
    Ok(trimmed.is_empty() || trimmed == "y" || trimmed == "yes")
}

pub async fn download_databases(db_path: &Path, ecosystems: &[&str], yes: bool) -> Result<()> {
    let already_exists = db_path.exists();
    let age_days = check_existing_db(db_path)
        .map(|secs| secs / 86400)
        .unwrap_or(0);

    print_download_plan(db_path, ecosystems, already_exists, age_days);

    if !yes {
        let message = if already_exists {
            "Update database?"
        } else {
            "Download database?"
        };

        if !prompt_confirm(message)? {
            println!("Cancelled.");
            return Ok(());
        }
    }

    std::fs::create_dir_all(db_path)
        .with_context(|| format!("Failed to create DB directory: {}", db_path.display()))?;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .context("Failed to build HTTP client")?;

    for ecosystem in ecosystems {
        let eco_dir = db_path.join(ecosystem);
        std::fs::create_dir_all(&eco_dir)
            .with_context(|| format!("Failed to create directory: {}", eco_dir.display()))?;

        let json_path = eco_dir.join("all.json");

        if json_path.exists() {
            info!("Skipping {} (already downloaded)", ecosystem);
            println!("  ✓ {} — already cached", ecosystem);
            continue;
        }

        let zip_url = format!("{}/{}/all.zip", OSV_BASE_URL, ecosystem);
        let total_size = ecosystem_size(ecosystem);

        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(&format!(
                    "  Downloading {:<14} [{{bar:30}}] {{percent}}%  {{bytes}}/{{total_bytes}}  {{bytes_per_sec}}"
                , ecosystem))
                .unwrap()
                .progress_chars("█░"),
        );

        let resp = http
            .get(&zip_url)
            .send()
            .await
            .with_context(|| format!("Failed to download {}", zip_url))?;

        if !resp.status().is_success() {
            warn!("Failed to download {}: HTTP {}", ecosystem, resp.status());
            pb.finish_with_message("failed");
            continue;
        }

        let zip_bytes = resp.bytes().await.context("Failed to read response body")?;

        pb.finish_with_message("done");

        let zip_path = eco_dir.join("all.zip");
        std::fs::write(&zip_path, &zip_bytes)
            .with_context(|| format!("Failed to write {}", zip_path.display()))?;

        extract_zip(&zip_path, &eco_dir)?;

        if zip_path.exists() {
            std::fs::remove_file(&zip_path).ok();
        }

        info!("Downloaded {} to {}", ecosystem, eco_dir.display());
    }

    println!();
    println!("✓ Database downloaded to {}", db_path.display());
    println!();

    Ok(())
}

fn extract_zip(zip_path: &Path, target_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(zip_path)
        .with_context(|| format!("Failed to open ZIP: {}", zip_path.display()))?;

    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("Failed to read ZIP archive: {}", zip_path.display()))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("Failed to read ZIP entry {}", i))?;

        let outpath = target_dir.join(entry.mangled_name());

        if entry.is_dir() {
            std::fs::create_dir_all(&outpath).ok();
        } else {
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent).ok();
            }

            let mut outfile = std::fs::File::create(&outpath)
                .with_context(|| format!("Failed to create {}", outpath.display()))?;

            std::io::copy(&mut entry, &mut outfile)
                .with_context(|| format!("Failed to extract {}", outpath.display()))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1024), "1 KB");
        assert_eq!(format_size(1_048_576), "1 MB");
        assert_eq!(format_size(4_918_205), "5 MB");
        assert_eq!(format_size(30_094_473), "29 MB");
        assert_eq!(format_size(515_463_105), "492 MB");
    }

    #[test]
    fn test_ecosystem_size() {
        assert_eq!(ecosystem_size("Linux"), 30_094_473);
        assert_eq!(ecosystem_size("Alpine"), 4_918_205);
        assert_eq!(ecosystem_size("Unknown"), 0);
    }

    #[test]
    fn test_resolve_ecosystems_default() {
        let result = resolve_ecosystems(None, None);
        assert_eq!(result, vec!["Linux", "Alpine", "crates.io"]);
    }

    #[test]
    fn test_resolve_ecosystems_from_list() {
        let list = vec!["Linux".to_string(), "Debian".to_string()];
        let result = resolve_ecosystems(Some(&list), None);
        assert_eq!(result, vec!["Linux", "Debian"]);
    }

    #[test]
    fn test_truncate_path_short() {
        let path = PathBuf::from("/tmp/db");
        assert_eq!(truncate_path(&path, 20), "/tmp/db");
    }

    #[test]
    fn test_truncate_path_long() {
        let path = PathBuf::from("/home/user/.cache/bitvex/osv-db");
        let result = truncate_path(&path, 20);
        assert!(result.starts_with("..."));
        assert!(result.len() <= 20);
    }
}
