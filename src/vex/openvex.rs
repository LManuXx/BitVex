//! OpenVEX v0.2.0 document generator.
//!
//! Generates spec-compliant OpenVEX JSON-LD documents from vulnerability
//! assessment results.

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use uuid::Uuid;

/// VEX status labels as defined by the VEX Working Group.
///
/// These labels indicate the relationship between a vulnerability and a
/// software product.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    /// The product is not affected by the vulnerability.
    /// Requires a `justification` or `impact_statement`.
    NotAffected,
    /// The product is affected by the vulnerability.
    /// Requires an `action_statement`.
    Affected,
    /// The product contains a fix for the vulnerability.
    Fixed,
    /// It is not yet known whether the product is affected.
    UnderInvestigation,
}

impl VexStatus {
    /// Returns the string representation of the status label.
    pub fn as_str(&self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }
}

/// A single VEX statement linking a vulnerability to a product.
///
/// Each statement asserts the impact status of one vulnerability on one
/// product, with optional justification.
#[derive(Debug, Clone, Serialize)]
pub struct VexStatement {
    /// Vulnerability identifier (e.g., "CVE-2024-12345").
    pub vulnerability_name: String,
    /// Product identifier as a Package URL (e.g., "pkg:generic/openssl@3.0.13").
    pub product_purl: String,
    /// Impact status of the vulnerability on this product.
    pub status: VexStatus,
    /// Machine-readable justification for `not_affected` status.
    /// Valid values: `component_not_present`, `vulnerable_code_not_present`,
    /// `vulnerable_code_not_in_execute_path`, etc.
    pub justification: Option<String>,
    /// Human-readable explanation of why the product is not affected,
    /// or what action should be taken.
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

/// OpenVEX v0.2.0 document structure.
///
/// Conforms to the [OpenVEX specification](https://github.com/openvex/spec).
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

/// Generate an OpenVEX v0.2.0 document from a list of statements.
///
/// Creates a complete, spec-compliant OpenVEX document with a unique
/// identifier and current timestamp.
///
/// # Arguments
///
/// * `statements` - List of VEX statements to include
/// * `author` - Author identifier (e.g., "Company <email@example.com>")
///
/// # Examples
///
/// ```rust
/// use bitvex::vex::{VexStatement, VexStatus, generate_openvex};
///
/// let statements = vec![VexStatement {
///     vulnerability_name: "CVE-2024-12345".into(),
///     product_purl: "pkg:generic/openssl@3.0.13".into(),
///     status: VexStatus::NotAffected,
///     justification: Some("component_not_present".into()),
///     impact_statement: Some("Not deployed on target".into()),
/// }];
///
/// let doc = generate_openvex(&statements, "My Company <sec@company.com>");
/// let json = serde_json::to_string_pretty(&doc).unwrap();
/// assert!(json.contains("CVE-2024-12345"));
/// ```
pub fn generate_openvex(statements: &[VexStatement], author: &str) -> VexDocument {
    let uuid = Uuid::new_v4();
    let doc_id = format!("https://openvex.dev/docs/bitvex/vex-{}", uuid.as_simple());

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
