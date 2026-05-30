use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, info};

use super::EpssScore;

const EPSS_API_URL: &str = "https://api.first.org/data/v1/epss";
const BATCH_SIZE: usize = 100;

fn is_cve_id(id: &str) -> bool {
    id.starts_with("CVE-")
}

#[derive(Deserialize)]
struct EpssResponse {
    data: Vec<EpssEntry>,
}

#[derive(Deserialize)]
struct EpssEntry {
    cve: String,
    epss: String,
    percentile: String,
}

pub struct EpssClient {
    http: Client,
}

impl EpssClient {
    pub fn new() -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to build EPSS HTTP client")?;
        Ok(Self { http })
    }

    pub async fn query_batch(&self, vuln_ids: &[String]) -> Result<Vec<EpssScore>> {
        let cve_ids: Vec<String> = vuln_ids
            .iter()
            .filter(|id| is_cve_id(id))
            .cloned()
            .collect();

        if cve_ids.is_empty() {
            debug!("No CVE IDs to query EPSS (all were GHSA/OSV/other)");
            return Ok(Vec::new());
        }

        info!(
            "Querying EPSS for {} CVEs (skipped {} non-CVE IDs)",
            cve_ids.len(),
            vuln_ids.len() - cve_ids.len()
        );

        let mut all_scores = Vec::with_capacity(cve_ids.len());

        for chunk in cve_ids.chunks(BATCH_SIZE) {
            let scores = self.query_chunk(chunk).await?;
            all_scores.extend(scores);
        }

        Ok(all_scores)
    }

    async fn query_chunk(&self, cve_ids: &[String]) -> Result<Vec<EpssScore>> {
        let cve_list = cve_ids.join(",");
        let url = format!("{}?cve={}", EPSS_API_URL, cve_list);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .context("Failed to send EPSS query")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("EPSS API returned {status}: {body}");
        }

        let epss_resp: EpssResponse = resp.json().await.context("Failed to parse EPSS response")?;

        let scores: Vec<EpssScore> = epss_resp
            .data
            .into_iter()
            .map(|e| {
                let epss: f64 = e.epss.parse().unwrap_or(0.0);
                let percentile: f64 = e.percentile.parse().unwrap_or(0.0);
                debug!(
                    "EPSS: {} -> epss={}, percentile={}",
                    e.cve, epss, percentile
                );
                EpssScore {
                    cve: e.cve,
                    epss,
                    percentile,
                }
            })
            .collect();

        Ok(scores)
    }
}
