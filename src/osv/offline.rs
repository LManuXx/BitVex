use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, info, warn};

use super::OsvVuln;
use crate::sbom::SbomPackage;

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    modified: String,
    affected: Option<Vec<Affected>>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: OsvPackage,
    ranges: Option<Vec<Range>>,
    versions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    name: String,
    ecosystem: Option<String>,
    purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(rename = "type")]
    range_type: String,
    events: Option<Vec<Event>>,
}

#[derive(Debug, Deserialize)]
struct Event {
    introduced: Option<String>,
    fixed: Option<String>,
}

pub struct OfflineOsvProvider {
    _db_path: PathBuf,
    vulns_by_name: HashMap<String, Vec<OsvVulnerability>>,
}

impl OfflineOsvProvider {
    pub fn new(db_path: &Path) -> Result<Self> {
        info!("Loading offline OSV database from {}", db_path.display());
        let vulns_by_name = load_database(db_path)?;

        let total_vulns: usize = vulns_by_name.values().map(|v| v.len()).sum();
        info!(
            "Loaded {} vulnerabilities for {} packages from offline DB",
            total_vulns,
            vulns_by_name.len()
        );

        Ok(Self {
            _db_path: db_path.to_path_buf(),
            vulns_by_name,
        })
    }

    pub fn query_batch(&self, packages: &[SbomPackage]) -> Result<Vec<super::OsvResult>> {
        let mut results = Vec::with_capacity(packages.len());

        for pkg in packages {
            let vulns = self.query_package(pkg);
            debug!(
                "Offline: {} {} -> {} vulns",
                pkg.name,
                pkg.version.as_deref().unwrap_or("?"),
                vulns.len()
            );
            results.push(super::OsvResult {
                package: pkg.clone(),
                vulns,
            });
        }

        Ok(results)
    }

    fn query_package(&self, pkg: &SbomPackage) -> Vec<OsvVuln> {
        let mut found = Vec::new();

        if let Some(ref purl) = pkg.purl {
            for vuln in self.vulns_by_name.values().flatten() {
                if vuln_affected_by_purl(vuln, purl, pkg.version.as_deref()) {
                    found.push(OsvVuln {
                        id: vuln.id.clone(),
                        _modified: vuln.modified.clone(),
                        aliases: vec![],
                    });
                }
            }
        }

        if found.is_empty() {
            if let Some(vulns) = self.vulns_by_name.get(&pkg.name) {
                for vuln in vulns {
                    if vuln_affected_by_name(vuln, &pkg.name, pkg.version.as_deref()) {
                        found.push(OsvVuln {
                            id: vuln.id.clone(),
                            _modified: vuln.modified.clone(),
                            aliases: vec![],
                        });
                    }
                }
            }
        }

        found.sort_by(|a, b| a.id.cmp(&b.id));
        found.dedup_by(|a, b| a.id == b.id);
        found
    }
}

fn vuln_affected_by_purl(vuln: &OsvVulnerability, purl: &str, version: Option<&str>) -> bool {
    let Some(affected) = &vuln.affected else {
        return false;
    };

    for a in affected {
        if let Some(ref pkg_purl) = a.package.purl {
            let vuln_purl_base = pkg_purl.split('@').next().unwrap_or(pkg_purl);
            let query_purl_base = purl.split('@').next().unwrap_or(purl);

            if vuln_purl_base == query_purl_base {
                if let Some(v) = version {
                    if version_in_ranges(v, &a.ranges) || version_in_list(v, &a.versions) {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
    }

    false
}

fn vuln_affected_by_name(vuln: &OsvVulnerability, name: &str, version: Option<&str>) -> bool {
    let Some(affected) = &vuln.affected else {
        return false;
    };

    for a in affected {
        if a.package.name == name {
            if let Some(v) = version {
                if version_in_ranges(v, &a.ranges) || version_in_list(v, &a.versions) {
                    return true;
                }
            } else {
                return true;
            }
        }
    }

    false
}

fn version_in_ranges(version: &str, ranges: &Option<Vec<Range>>) -> bool {
    let Some(ranges) = ranges else {
        return false;
    };

    for range in ranges {
        if range.range_type != "ECOSYSTEM" && range.range_type != "SEMVER" {
            continue;
        }

        let Some(events) = &range.events else {
            continue;
        };

        let mut introduced = None;
        let mut fixed = None;

        for event in events {
            if let Some(ref v) = event.introduced {
                introduced = Some(v.as_str());
            }
            if let Some(ref v) = event.fixed {
                fixed = Some(v.as_str());
            }
        }

        let after_intro = introduced.map(|i| version >= i).unwrap_or(true);

        let before_fixed = fixed.map(|f| version < f).unwrap_or(true);

        if after_intro && before_fixed {
            return true;
        }
    }

    false
}

fn version_in_list(version: &str, versions: &Option<Vec<String>>) -> bool {
    let Some(versions) = versions else {
        return false;
    };

    versions.iter().any(|v| v == version)
}

fn load_database(db_path: &Path) -> Result<HashMap<String, Vec<OsvVulnerability>>> {
    let mut all_vulns: HashMap<String, Vec<OsvVulnerability>> = HashMap::new();

    if !db_path.exists() {
        warn!(
            "Offline database directory not found: {}",
            db_path.display()
        );
        return Ok(all_vulns);
    }

    for entry in std::fs::read_dir(db_path)
        .with_context(|| format!("Failed to read DB directory: {}", db_path.display()))?
    {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            let json_path = path.join("all.json");
            if json_path.exists() {
                let data = std::fs::read(&json_path)
                    .with_context(|| format!("Failed to read {}", json_path.display()))?;

                let vulns: Vec<OsvVulnerability> = serde_json::from_slice(&data)
                    .with_context(|| format!("Failed to parse {}", json_path.display()))?;

                for vuln in vulns {
                    if let Some(affected) = &vuln.affected {
                        for a in affected {
                            all_vulns.entry(a.package.name.clone()).or_default().push(
                                OsvVulnerability {
                                    id: vuln.id.clone(),
                                    modified: vuln.modified.clone(),
                                    affected: Some(vec![Affected {
                                        package: a.package.clone(),
                                        ranges: a.ranges.clone(),
                                        versions: a.versions.clone(),
                                    }]),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(all_vulns)
}

impl Clone for OsvPackage {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            ecosystem: self.ecosystem.clone(),
            purl: self.purl.clone(),
        }
    }
}

impl Clone for Affected {
    fn clone(&self) -> Self {
        Self {
            package: self.package.clone(),
            ranges: self.ranges.clone(),
            versions: self.versions.clone(),
        }
    }
}

impl Clone for Range {
    fn clone(&self) -> Self {
        Self {
            range_type: self.range_type.clone(),
            events: self.events.clone(),
        }
    }
}

impl Clone for Event {
    fn clone(&self) -> Self {
        Self {
            introduced: self.introduced.clone(),
            fixed: self.fixed.clone(),
        }
    }
}
