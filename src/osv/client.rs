use std::collections::HashMap;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::sbom::SbomPackage;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
const BATCH_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub struct OsvVuln {
    pub id: String,
    pub _modified: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OsvResult {
    pub package: SbomPackage,
    pub vulns: Vec<OsvVuln>,
}

#[derive(Serialize)]
struct QueryBatchRequest {
    queries: Vec<QueryItem>,
}

#[derive(Serialize)]
struct QueryItem {
    package: QueryPackage,
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Serialize)]
struct QueryPackage {
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
}

#[derive(Deserialize)]
struct QueryBatchResponse {
    results: Vec<QueryResult>,
}

#[derive(Deserialize)]
struct QueryResult {
    vulns: Option<Vec<VulnEntry>>,
    #[serde(rename = "nextPageToken")]
    _next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct VulnEntry {
    id: String,
    modified: String,
}

#[derive(Deserialize)]
struct VulnDetail {
    aliases: Option<Vec<String>>,
}

pub struct OsvClient {
    http: Client,
}

impl OsvClient {
    pub fn new() -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("Failed to build HTTP client")?;
        Ok(Self { http })
    }

    pub async fn query_batch(&self, packages: &[SbomPackage]) -> Result<Vec<OsvResult>> {
        let mut all_results = Vec::with_capacity(packages.len());

        for chunk in packages.chunks(BATCH_SIZE) {
            let results = self.query_chunk(chunk).await?;
            all_results.extend(results);
        }

        // Enrich vulnerabilities with aliases (CVE IDs)
        self.enrich_aliases(&mut all_results).await?;

        Ok(all_results)
    }

    async fn enrich_aliases(&self, results: &mut [OsvResult]) -> Result<()> {
        // Collect unique vuln IDs that don't start with CVE-
        let non_cve_ids: Vec<String> = results
            .iter()
            .flat_map(|r| r.vulns.iter())
            .filter(|v| !v.id.starts_with("CVE-"))
            .map(|v| v.id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if non_cve_ids.is_empty() {
            return Ok(());
        }

        info!(
            "Fetching aliases for {} non-CVE vulnerabilities",
            non_cve_ids.len()
        );

        // Fetch aliases for each unique non-CVE vulnerability
        let mut alias_map: HashMap<String, Vec<String>> = HashMap::new();

        for vuln_id in &non_cve_ids {
            if let Ok(aliases) = self.fetch_aliases(vuln_id).await {
                if !aliases.is_empty() {
                    alias_map.insert(vuln_id.clone(), aliases);
                }
            }
        }

        // Enrich results with aliases
        for result in results.iter_mut() {
            for vuln in result.vulns.iter_mut() {
                if let Some(aliases) = alias_map.get(&vuln.id) {
                    vuln.aliases = aliases.clone();
                }
            }
        }

        Ok(())
    }

    async fn fetch_aliases(&self, vuln_id: &str) -> Result<Vec<String>> {
        let url = format!("{}/{}", OSV_VULN_URL, vuln_id);

        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch aliases for {}", vuln_id))?;

        if !resp.status().is_success() {
            debug!(
                "Failed to fetch aliases for {}: HTTP {}",
                vuln_id,
                resp.status()
            );
            return Ok(Vec::new());
        }

        let detail: VulnDetail = resp
            .json()
            .await
            .with_context(|| format!("Failed to parse vuln detail for {}", vuln_id))?;

        Ok(detail.aliases.unwrap_or_default())
    }

    async fn query_chunk(&self, packages: &[SbomPackage]) -> Result<Vec<OsvResult>> {
        let mut queryable: Vec<&SbomPackage> = Vec::new();
        let mut queries: Vec<QueryItem> = Vec::new();

        for pkg in packages {
            if pkg.purl.is_none() {
                continue;
            }
            let has_purl_with_version = pkg.purl.as_ref().is_some_and(|p| p.contains('@'));
            queryable.push(pkg);
            queries.push(QueryItem {
                package: QueryPackage {
                    purl: pkg.purl.clone(),
                    name: None,
                    ecosystem: None,
                },
                version: if has_purl_with_version {
                    None
                } else {
                    pkg.version.clone()
                },
                page_token: None,
            });
        }

        if queries.is_empty() {
            return Ok(packages
                .iter()
                .map(|pkg| OsvResult {
                    package: pkg.clone(),
                    vulns: vec![],
                })
                .collect());
        }

        info!("Querying OSV for {} packages", queries.len());
        let req_body = QueryBatchRequest { queries };

        let resp = self
            .http
            .post(OSV_BATCH_URL)
            .json(&req_body)
            .send()
            .await
            .context("Failed to send OSV batch query")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("OSV API returned {status}: {body}");
        }

        let batch_resp: QueryBatchResponse = resp
            .json()
            .await
            .context("Failed to parse OSV batch response")?;

        let mut results: Vec<OsvResult> = packages
            .iter()
            .map(|pkg| OsvResult {
                package: pkg.clone(),
                vulns: vec![],
            })
            .collect();

        for (qi, pkg) in queryable.iter().enumerate() {
            if let Some(qr) = batch_resp.results.get(qi) {
                let vulns: Vec<OsvVuln> = qr
                    .vulns
                    .as_ref()
                    .map(|v| {
                        v.iter()
                            .map(|e| OsvVuln {
                                id: e.id.clone(),
                                _modified: e.modified.clone(),
                                aliases: Vec::new(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                debug!(
                    "Package {} {} -> {} vulns",
                    pkg.name,
                    pkg.version.as_deref().unwrap_or("?"),
                    vulns.len()
                );

                // Find original index
                if let Some(orig) = results.iter_mut().find(|r| r.package.name == pkg.name) {
                    orig.vulns = vulns;
                }
            }
        }

        Ok(results)
    }
}
