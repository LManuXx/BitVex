use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl VexStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VexStatement {
    pub vulnerability_name: String,
    pub product_purl: String,
    pub status: VexStatus,
    pub justification: Option<String>,
    pub impact_statement: Option<String>,
}

#[derive(Debug, Serialize)]
struct OpenVexProduct {
    #[serde(rename = "@id")]
    id: String,
}

#[derive(Debug, Serialize)]
struct OpenVexVulnerability {
    name: String,
}

#[derive(Debug, Serialize)]
struct OpenVexStatement {
    vulnerability: OpenVexVulnerability,
    products: Vec<OpenVexProduct>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact_statement: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VexDocument {
    #[serde(rename = "@context")]
    context: String,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    role: String,
    timestamp: String,
    version: u32,
    tooling: String,
    statements: Vec<OpenVexStatement>,
}

pub fn generate_openvex(
    statements: &[VexStatement],
    author: &str,
) -> VexDocument {
    let uuid = Uuid::new_v4();
    let doc_id = format!(
        "https://openvex.dev/docs/bitvex/vex-{}",
        uuid.as_simple()
    );

    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

    let openvex_statements: Vec<OpenVexStatement> = statements
        .iter()
        .map(|s| OpenVexStatement {
            vulnerability: OpenVexVulnerability {
                name: s.vulnerability_name.clone(),
            },
            products: vec![OpenVexProduct {
                id: s.product_purl.clone(),
            }],
            status: s.status.as_str().to_string(),
            justification: s.justification.clone(),
            impact_statement: s.impact_statement.clone(),
        })
        .collect();

    VexDocument {
        context: "https://openvex.dev/ns/v0.2.0".to_string(),
        id: doc_id,
        author: author.to_string(),
        role: "Document Creator".to_string(),
        timestamp,
        version: 1,
        tooling: format!("BitVex {}", env!("CARGO_PKG_VERSION")),
        statements: openvex_statements,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_openvex_document() {
        let statements = vec![VexStatement {
            vulnerability_name: "CVE-2024-1234".into(),
            product_purl: "pkg:generic/openssl@3.0.13".into(),
            status: VexStatus::NotAffected,
            justification: Some("component_not_present".into()),
            impact_statement: Some("Host-only dependency".into()),
        }];

        let doc = generate_openvex(&statements, "Test Author <test@example.com>");
        let json = serde_json::to_string_pretty(&doc).unwrap();

        assert!(json.contains("https://openvex.dev/ns/v0.2.0"));
        assert!(json.contains("CVE-2024-1234"));
        assert!(json.contains("not_affected"));
        assert!(json.contains("component_not_present"));
    }

    #[test]
    fn test_empty_statements() {
        let doc = generate_openvex(&[], "Test");
        assert!(doc.statements.is_empty());
        assert_eq!(doc.version, 1);
    }
}
