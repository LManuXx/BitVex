//! SPDX 3.0 JSON-LD SBOM parser.
//!
//! Parses Software Bill of Materials (SBOM) documents in SPDX 3.0 format
//! and extracts package information for vulnerability analysis.
//!
//! SPDX 3.0 uses JSON-LD and has a different structure than 2.x:
//! - `element[]` instead of `packages[]`
//! - `type: "Package"` to identify packages
//! - `packageVersion` instead of `versionInfo`
//! - `externalIdentifier[]` instead of `externalRefs[]`

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{debug, info, warn};

/// SPDX 3.0 document structure (JSON-LD).
#[derive(Debug, Deserialize)]
struct Spdx3Document {
    #[serde(rename = "specVersion")]
    spec_version: Option<String>,
    #[serde(rename = "spdxId")]
    _spdx_id: Option<String>,
    _name: Option<String>,
    element: Option<Vec<Spdx3Element>>,
}

/// An element in an SPDX 3.0 document.
#[derive(Debug, Deserialize)]
struct Spdx3Element {
    #[serde(rename = "type")]
    element_type: String,
    #[serde(rename = "spdxId")]
    spdx_id: Option<String>,
    name: Option<String>,
    #[serde(rename = "packageVersion")]
    package_version: Option<String>,
    #[serde(rename = "downloadLocation")]
    _download_location: Option<String>,
    #[serde(rename = "externalIdentifier")]
    external_identifier: Option<Vec<ExternalIdentifier>>,
}

/// An external identifier in SPDX 3.0.
#[derive(Debug, Deserialize)]
struct ExternalIdentifier {
    #[serde(rename = "type")]
    id_type: String,
    identifier: String,
}

/// Parse an SPDX 3.0 JSON-LD document and extract packages.
///
/// Reads an SPDX 3.0 document and extracts all Package elements
/// with their names, versions, and Package URLs (if available).
///
/// # Arguments
///
/// * `data` - Raw bytes of the SPDX 3.0 JSON-LD document
///
/// # Returns
///
/// A vector of [`SbomPackage`] structs, one for each Package element.
///
/// # Errors
///
/// Returns an error if the JSON is malformed.
pub fn parse_spdx3(data: &[u8]) -> Result<Vec<crate::sbom::SbomPackage>> {
    let doc: Spdx3Document =
        serde_json::from_slice(data).context("Failed to parse SPDX 3.0 JSON document")?;

    if let Some(ref version) = doc.spec_version {
        info!("Parsing SPDX 3.0 document (specVersion: {})", version);
    }

    let elements = doc.element.unwrap_or_default();
    let mut result = Vec::new();

    for elem in &elements {
        if elem.element_type != "Package" {
            continue;
        }

        let name = match &elem.name {
            Some(n) => n.clone(),
            None => {
                warn!("Package element without name, skipping");
                continue;
            }
        };

        let purl = elem.external_identifier.as_ref().and_then(|ids| {
            ids.iter()
                .find(|id| id.id_type == "purl")
                .map(|id| id.identifier.clone())
        });

        let sbom_pkg = crate::sbom::SbomPackage {
            _spdx_id: elem.spdx_id.clone().unwrap_or_default(),
            name: name.clone(),
            version: elem.package_version.clone(),
            purl,
        };

        debug!(
            "Parsed SPDX 3.0 package: {} {:?}",
            sbom_pkg.name, sbom_pkg.version
        );
        result.push(sbom_pkg);
    }

    info!("Extracted {} packages from SPDX 3.0 document", result.len());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_spdx3_basic() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "name": "test-sbom",
            "element": [
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-openssl",
                    "name": "openssl",
                    "packageVersion": "3.0.13",
                    "externalIdentifier": [
                        {
                            "type": "purl",
                            "identifier": "pkg:generic/openssl@3.0.13"
                        }
                    ]
                }
            ]
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[0].version.as_deref(), Some("3.0.13"));
        assert_eq!(pkgs[0].purl.as_deref(), Some("pkg:generic/openssl@3.0.13"));
    }

    #[test]
    fn test_parse_spdx3_multiple_packages() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": [
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-openssl",
                    "name": "openssl",
                    "packageVersion": "3.0.13"
                },
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-curl",
                    "name": "curl",
                    "packageVersion": "8.5.0"
                },
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-glibc",
                    "name": "glibc",
                    "packageVersion": "2.37"
                }
            ]
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[1].name, "curl");
        assert_eq!(pkgs[2].name, "glibc");
    }

    #[test]
    fn test_parse_spdx3_no_packages() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": []
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_parse_spdx3_empty_document() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1"
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_parse_spdx3_non_package_elements() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": [
                {
                    "type": "File",
                    "spdxId": "SPDXRef-File-test",
                    "name": "test.txt"
                },
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-openssl",
                    "name": "openssl",
                    "packageVersion": "3.0.13"
                }
            ]
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "openssl");
    }

    #[test]
    fn test_parse_spdx3_package_without_name() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": [
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-noname",
                    "packageVersion": "1.0.0"
                },
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-openssl",
                    "name": "openssl",
                    "packageVersion": "3.0.13"
                }
            ]
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "openssl");
    }

    #[test]
    fn test_parse_spdx3_with_npm_purl() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": [
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-axios",
                    "name": "axios",
                    "packageVersion": "0.21.0",
                    "externalIdentifier": [
                        {
                            "type": "purl",
                            "identifier": "pkg:npm/axios@0.21.0"
                        }
                    ]
                }
            ]
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl.as_deref(), Some("pkg:npm/axios@0.21.0"));
    }

    #[test]
    fn test_parse_spdx3_without_version() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": [
                {
                    "type": "Package",
                    "spdxId": "SPDXRef-Package-test",
                    "name": "test-pkg"
                }
            ]
        }"#;

        let pkgs = parse_spdx3(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "test-pkg");
        assert!(pkgs[0].version.is_none());
        assert!(pkgs[0].purl.is_none());
    }
}
