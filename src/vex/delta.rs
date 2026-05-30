use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};
use tracing::info;

use super::{VexStatement, VexStatus};

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexDocument {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    timestamp: String,
    version: u32,
    statements: Vec<OpenVexStatement>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexStatement {
    vulnerability: OpenVexVulnerability,
    products: Vec<OpenVexProduct>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact_statement: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexVulnerability {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenVexProduct {
    #[serde(rename = "@id")]
    id: String,
}

#[derive(Debug, Serialize)]
pub struct VexDelta {
    pub new_cves: Vec<VexStatement>,
    pub resolved_cves: Vec<VexStatement>,
    pub changed_status: Vec<StatusChange>,
}

#[derive(Debug, Serialize)]
pub struct StatusChange {
    pub vuln: String,
    pub product: String,
    pub old_status: String,
    pub new_status: String,
}

#[derive(Tabled)]
struct DeltaRow {
    #[tabled(rename = "Change")]
    change: String,
    #[tabled(rename = "CVE")]
    cve: String,
    #[tabled(rename = "Product")]
    product: String,
    #[tabled(rename = "Old Status")]
    old_status: String,
    #[tabled(rename = "New Status")]
    new_status: String,
}

fn vuln_key(vuln: &str, product: &str) -> String {
    format!("{}@{}", vuln, product)
}

pub fn compare_vex(old_path: &Path, new_path: &Path) -> Result<VexDelta> {
    let old_data = std::fs::read(old_path)
        .with_context(|| format!("Failed to read old VEX: {}", old_path.display()))?;
    let new_data = std::fs::read(new_path)
        .with_context(|| format!("Failed to read new VEX: {}", new_path.display()))?;

    let old_doc: OpenVexDocument =
        serde_json::from_slice(&old_data).context("Failed to parse old VEX document")?;
    let new_doc: OpenVexDocument =
        serde_json::from_slice(&new_data).context("Failed to parse new VEX document")?;

    // Build maps: (vuln, product) -> status
    let mut old_map: HashMap<String, String> = HashMap::new();
    for stmt in &old_doc.statements {
        for prod in &stmt.products {
            let key = vuln_key(&stmt.vulnerability.name, &prod.id);
            old_map.insert(key, stmt.status.clone());
        }
    }

    let mut new_map: HashMap<String, String> = HashMap::new();
    for stmt in &new_doc.statements {
        for prod in &stmt.products {
            let key = vuln_key(&stmt.vulnerability.name, &prod.id);
            new_map.insert(key, stmt.status.clone());
        }
    }

    let mut new_cves = Vec::new();
    let mut resolved_cves = Vec::new();
    let mut changed_status = Vec::new();

    // Find new CVEs (in new but not in old)
    for stmt in &new_doc.statements {
        for prod in &stmt.products {
            let key = vuln_key(&stmt.vulnerability.name, &prod.id);
            if !old_map.contains_key(&key) {
                new_cves.push(VexStatement {
                    vulnerability_name: stmt.vulnerability.name.clone(),
                    product_purl: prod.id.clone(),
                    status: parse_status(&stmt.status),
                    justification: stmt.justification.clone(),
                    impact_statement: stmt.impact_statement.clone(),
                });
            }
        }
    }

    // Find resolved CVEs (in old but not in new)
    for stmt in &old_doc.statements {
        for prod in &stmt.products {
            let key = vuln_key(&stmt.vulnerability.name, &prod.id);
            if !new_map.contains_key(&key) {
                resolved_cves.push(VexStatement {
                    vulnerability_name: stmt.vulnerability.name.clone(),
                    product_purl: prod.id.clone(),
                    status: parse_status(&stmt.status),
                    justification: stmt.justification.clone(),
                    impact_statement: stmt.impact_statement.clone(),
                });
            }
        }
    }

    // Find status changes
    for (key, new_status) in &new_map {
        if let Some(old_status) = old_map.get(key) {
            if old_status != new_status {
                let parts: Vec<&str> = key.splitn(2, '@').collect();
                changed_status.push(StatusChange {
                    vuln: parts.first().unwrap_or(&"").to_string(),
                    product: parts.get(1).unwrap_or(&"").to_string(),
                    old_status: old_status.clone(),
                    new_status: new_status.clone(),
                });
            }
        }
    }

    info!(
        "Delta: {} new, {} resolved, {} changed",
        new_cves.len(),
        resolved_cves.len(),
        changed_status.len()
    );

    Ok(VexDelta {
        new_cves,
        resolved_cves,
        changed_status,
    })
}

fn parse_status(s: &str) -> VexStatus {
    match s {
        "not_affected" => VexStatus::NotAffected,
        "affected" => VexStatus::Affected,
        "fixed" => VexStatus::Fixed,
        "under_investigation" => VexStatus::UnderInvestigation,
        _ => VexStatus::Affected,
    }
}

pub fn print_delta_summary(delta: &VexDelta) {
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          BitVex - VEX Delta Report                  ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!(
        "║  New CVEs:             {:<5}                         ║",
        delta.new_cves.len()
    );
    println!(
        "║  Resolved CVEs:        {:<5}                         ║",
        delta.resolved_cves.len()
    );
    println!(
        "║  Status changes:       {:<5}                         ║",
        delta.changed_status.len()
    );
    println!("╚══════════════════════════════════════════════════════╝");

    let mut rows = Vec::new();

    for stmt in &delta.new_cves {
        rows.push(DeltaRow {
            change: "+".to_string(),
            cve: stmt.vulnerability_name.clone(),
            product: truncate_str(&stmt.product_purl, 35),
            old_status: "-".to_string(),
            new_status: stmt.status.as_str().to_string(),
        });
    }

    for stmt in &delta.resolved_cves {
        rows.push(DeltaRow {
            change: "-".to_string(),
            cve: stmt.vulnerability_name.clone(),
            product: truncate_str(&stmt.product_purl, 35),
            old_status: stmt.status.as_str().to_string(),
            new_status: "-".to_string(),
        });
    }

    for change in &delta.changed_status {
        rows.push(DeltaRow {
            change: "~".to_string(),
            cve: change.vuln.clone(),
            product: truncate_str(&change.product, 35),
            old_status: change.old_status.clone(),
            new_status: change.new_status.clone(),
        });
    }

    if !rows.is_empty() {
        println!();
        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    println!();
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_vex(path: &Path, statements: &str) {
        let content = format!(
            r#"{{
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://test",
            "author": "test",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": 1,
            "statements": [{}]
        }}"#,
            statements
        );
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn test_delta_new_cves() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.vex.json");
        let new = dir.path().join("new.vex.json");

        write_vex(&old, r#"{"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"}"#);
        write_vex(
            &new,
            r#"{"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"},{"vulnerability":{"name":"CVE-2024-0002"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"}"#,
        );

        let delta = compare_vex(&old, &new).unwrap();
        assert_eq!(delta.new_cves.len(), 1);
        assert_eq!(delta.new_cves[0].vulnerability_name, "CVE-2024-0002");
        assert_eq!(delta.resolved_cves.len(), 0);
    }

    #[test]
    fn test_delta_resolved_cves() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.vex.json");
        let new = dir.path().join("new.vex.json");

        write_vex(
            &old,
            r#"{"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"},{"vulnerability":{"name":"CVE-2024-0002"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"}"#,
        );
        write_vex(&new, r#"{"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"}"#);

        let delta = compare_vex(&old, &new).unwrap();
        assert_eq!(delta.new_cves.len(), 0);
        assert_eq!(delta.resolved_cves.len(), 1);
        assert_eq!(delta.resolved_cves[0].vulnerability_name, "CVE-2024-0002");
    }

    #[test]
    fn test_delta_status_change() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("old.vex.json");
        let new = dir.path().join("new.vex.json");

        write_vex(&old, r#"{"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:a@1.0"}],"status":"affected"}"#);
        write_vex(&new, r#"{"vulnerability":{"name":"CVE-2024-0001"},"products":[{"@id":"pkg:a@1.0"}],"status":"fixed"}"#);

        let delta = compare_vex(&old, &new).unwrap();
        assert_eq!(delta.changed_status.len(), 1);
        assert_eq!(delta.changed_status[0].old_status, "affected");
        assert_eq!(delta.changed_status[0].new_status, "fixed");
    }
}
