use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tracing::{info, warn};

use super::EpssScore;

const EPSS_CSV_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

pub fn default_epss_db_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("bitvex")
        .join("epss-db")
}

pub struct OfflineEpssProvider {
    scores: HashMap<String, EpssScore>,
}

impl OfflineEpssProvider {
    pub fn new(db_path: &Path) -> Result<Self> {
        info!("Loading offline EPSS database from {}", db_path.display());
        let scores = load_csv(db_path)?;

        info!("Loaded {} EPSS scores from offline DB", scores.len());

        Ok(Self { scores })
    }

    pub fn get_score(&self, cve_id: &str) -> Option<&EpssScore> {
        self.scores.get(cve_id)
    }

    pub fn query_batch(&self, cve_ids: &[String]) -> Vec<EpssScore> {
        cve_ids
            .iter()
            .filter_map(|id| self.scores.get(id).cloned())
            .collect()
    }
}

pub async fn download_epss_db(db_path: &Path, yes: bool) -> Result<()> {
    std::fs::create_dir_all(db_path)
        .with_context(|| format!("Failed to create EPSS DB directory: {}", db_path.display()))?;

    let gz_path = db_path.join("epss_scores.csv.gz");
    let csv_path = db_path.join("epss_scores.csv");

    if csv_path.exists() {
        let meta = std::fs::metadata(&csv_path)?;
        let size_mb = meta.len() as f64 / 1_048_576.0;
        println!();
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║          BitVex - Download EPSS Database                ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!(
            "║  EPSS database already exists ({:.0} MB)              ║",
            size_mb
        );
        println!("║  Destination: {:<42} ║", db_path.display());
        println!("╚══════════════════════════════════════════════════════════╝");
        println!();

        if !yes {
            print!("Update? [Y/n]: ");
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().is_empty() && !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }
    } else {
        println!();
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║          BitVex - Download EPSS Database                ║");
        println!("╠══════════════════════════════════════════════════════════╣");
        println!("║  Source: EPSS CSV (~250 MB compressed)                  ║");
        println!("║  Destination: {:<42} ║", db_path.display());
        println!("╚══════════════════════════════════════════════════════════╝");
        println!();

        if !yes {
            print!("Download? [Y/n]: ");
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().is_empty() && !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled.");
                return Ok(());
            }
        }
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .context("Failed to build HTTP client")?;

    println!("Downloading EPSS database...");

    let resp = http
        .get(EPSS_CSV_URL)
        .send()
        .await
        .context("Failed to download EPSS CSV")?;

    if !resp.status().is_success() {
        anyhow::bail!("EPSS download failed: HTTP {}", resp.status());
    }

    let gz_bytes = resp.bytes().await.context("Failed to read EPSS response")?;

    std::fs::write(&gz_path, &gz_bytes)
        .with_context(|| format!("Failed to write {}", gz_path.display()))?;

    // Decompress
    let gz_file = std::fs::File::open(&gz_path)
        .with_context(|| format!("Failed to open {}", gz_path.display()))?;
    let mut decoder = GzDecoder::new(gz_file);
    let mut csv_content = String::new();
    decoder.read_to_string(&mut csv_content)?;

    std::fs::write(&csv_path, &csv_content)
        .with_context(|| format!("Failed to write {}", csv_path.display()))?;

    // Clean up gz
    std::fs::remove_file(&gz_path).ok();

    let size_mb = csv_content.len() as f64 / 1_048_576.0;
    println!(
        "✓ EPSS database downloaded ({:.0} MB) to {}",
        size_mb,
        db_path.display()
    );
    println!();

    Ok(())
}

fn load_csv(db_path: &Path) -> Result<HashMap<String, EpssScore>> {
    let csv_path = db_path.join("epss_scores.csv");

    if !csv_path.exists() {
        warn!("EPSS CSV not found at {}", csv_path.display());
        return Ok(HashMap::new());
    }

    let content = std::fs::read_to_string(&csv_path)
        .with_context(|| format!("Failed to read {}", csv_path.display()))?;

    let mut scores = HashMap::new();
    let mut reader = csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .from_reader(content.as_bytes());

    for result in reader.records() {
        let record = result.context("Failed to parse EPSS CSV record")?;
        if record.len() >= 3 {
            let cve = record[0].to_string();
            let epss: f64 = record[1].parse().unwrap_or(0.0);
            let percentile: f64 = record[2].parse().unwrap_or(0.0);

            if cve.starts_with("CVE-") {
                scores.insert(
                    cve.clone(),
                    EpssScore {
                        cve,
                        epss,
                        percentile,
                    },
                );
            }
        }
    }

    Ok(scores)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_csv_from_string() {
        let csv_data = "# date: 2026-05-30\ncve_id,epss,percentile\nCVE-2024-1234,0.95,0.99\nCVE-2024-5678,0.03,0.12\n";
        let tmpdir = tempfile::tempdir().unwrap();
        let csv_path = tmpdir.path().join("epss_scores.csv");
        std::fs::write(&csv_path, csv_data).unwrap();

        let scores = load_csv(tmpdir.path()).unwrap();
        assert_eq!(scores.len(), 2);
        assert!(scores.contains_key("CVE-2024-1234"));
        assert!(scores.contains_key("CVE-2024-5678"));

        let s = scores.get("CVE-2024-1234").unwrap();
        assert!((s.epss - 0.95).abs() < 0.001);
        assert!((s.percentile - 0.99).abs() < 0.001);
    }

    #[test]
    fn test_load_csv_empty() {
        let tmpdir = tempfile::tempdir().unwrap();
        let scores = load_csv(tmpdir.path()).unwrap();
        assert!(scores.is_empty());
    }

    #[test]
    fn test_offline_query() {
        let csv_data = "cve_id,epss,percentile\nCVE-2024-0001,0.50,0.75\nCVE-2024-0002,0.10,0.30\n";
        let tmpdir = tempfile::tempdir().unwrap();
        std::fs::write(tmpdir.path().join("epss_scores.csv"), csv_data).unwrap();

        let provider = OfflineEpssProvider::new(tmpdir.path()).unwrap();

        let scores = provider.query_batch(&[
            "CVE-2024-0001".to_string(),
            "CVE-2024-0002".to_string(),
            "CVE-2024-9999".to_string(),
        ]);

        assert_eq!(scores.len(), 2);
        assert!(scores.iter().any(|s| s.cve == "CVE-2024-0001"));
        assert!(!scores.iter().any(|s| s.cve == "CVE-2024-9999"));
    }
}
