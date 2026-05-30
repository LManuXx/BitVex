use std::collections::HashMap;

use anyhow::{Context, Result};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::sbom::SbomPackage;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns";
const BATCH_SIZE: usize = 100;

/// A vulnerability entry from the OSV database.
///
/// Contains the vulnerability ID, modification timestamp, and aliases
/// (e.g., GHSA-xxx → CVE-xxxx mapping).
#[derive(Debug, Clone)]
pub struct OsvVuln {
    /// Vulnerability identifier (e.g., "CVE-2024-12345" or "GHSA-xxx").
    pub id: String,
    /// Last modification timestamp from OSV.
    pub _modified: String,
    /// Aliases for this vulnerability (e.g., CVE IDs for GHSA entries).
    pub aliases: Vec<String>,
}

/// Result of querying OSV for a single package.
///
/// Links a package from the SBOM to its known vulnerabilities.
#[derive(Debug, Clone)]
pub struct OsvResult {
    /// The package that was queried.
    pub package: SbomPackage,
    /// List of vulnerabilities affecting this package.
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

/// Async client for the OSV vulnerability database API.
///
/// Queries the [OSV API](https://osv.dev/) to find known vulnerabilities
/// for software packages. Supports batch queries and concurrent alias
/// resolution for GHSA/OSV vulnerability IDs.
///
/// # Examples
///
/// ```rust,no_run
/// use bitvex::osv::OsvClient;
/// use bitvex::sbom::SbomPackage;
///
/// # async fn example() -> anyhow::Result<()> {
/// let client = OsvClient::new()?;
/// let packages = vec![SbomPackage {
///     _spdx_id: "SPDXRef-1".into(),
///     name: "openssl".into(),
///     version: Some("3.0.13".into()),
///     purl: Some("pkg:generic/openssl@3.0.13".into()),
/// }];
///
/// let results = client.query_batch(&packages).await?;
/// for result in &results {
///     println!("{}: {} vulns", result.package.name, result.vulns.len());
/// }
/// # Ok(())
/// # }
/// ```
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
        let pb = ProgressBar::new(packages.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  Querying OSV   [{bar:30}] {pos}/{len} packages")
                .unwrap()
                .progress_chars("█░"),
        );

        let mut all_results = Vec::with_capacity(packages.len());

        for chunk in packages.chunks(BATCH_SIZE) {
            let results = self.query_chunk(chunk).await?;
            pb.inc(chunk.len() as u64);
            all_results.extend(results);
        }

        pb.finish_with_message("done");

        // Enrich vulnerabilities with aliases (CVE IDs)
        self.enrich_aliases(&mut all_results).await?;

        Ok(all_results)
    }

    async fn enrich_aliases(&self, results: &mut [OsvResult]) -> Result<()> {
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
            "Fetching aliases for {} non-CVE vulnerabilities (concurrent)",
            non_cve_ids.len()
        );

        let pb = ProgressBar::new(non_cve_ids.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("  Fetching CVEs  [{bar:30}] {pos}/{len} aliases")
                .unwrap()
                .progress_chars("█░"),
        );

        // Concurrent alias fetching
        let futures: Vec<_> = non_cve_ids
            .iter()
            .map(|id| self.fetch_aliases(id))
            .collect();

        let results_vec = join_all(futures).await;

        let mut alias_map: HashMap<String, Vec<String>> = HashMap::new();
        for (vuln_id, result) in non_cve_ids.iter().zip(results_vec) {
            if let Ok(aliases) = result {
                if !aliases.is_empty() {
                    alias_map.insert(vuln_id.clone(), aliases);
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("done");

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

                if let Some(orig) = results.iter_mut().find(|r| r.package.name == pkg.name) {
                    orig.vulns = vulns;
                }
            }
        }

        Ok(results)
    }
}
