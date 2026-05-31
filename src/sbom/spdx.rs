//! SPDX JSON SBOM parser.
//!
//! Parses Software Bill of Materials (SBOM) documents in SPDX JSON format
//! (v2.2 and v2.3) and extracts package information for vulnerability analysis.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// A package extracted from an SPDX SBOM document.
///
/// Represents a single software package with its identifying information.
/// The `purl` (Package URL) is optional because not all SPDX documents
/// include external references.
#[derive(Debug, Clone, Serialize)]
pub struct SbomPackage {
    /// SPDX identifier (e.g., "SPDXRef-Package-openssl").
    pub _spdx_id: String,
    /// Package name (e.g., "openssl", "curl", "glibc").
    pub name: String,
    /// Package version (e.g., "3.0.13"). May be absent.
    pub version: Option<String>,
    /// Package URL (e.g., "pkg:generic/openssl@3.0.13"). May be absent.
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SpdxDocument {
    #[serde(rename = "SPDXID")]
    _spdx_id: String,
    packages: Option<Vec<SpdxPackage>>,
}

#[derive(Debug, Deserialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: Option<String>,
    #[serde(rename = "downloadLocation")]
    _download_location: Option<String>,
    #[serde(rename = "externalRefs")]
    external_refs: Option<Vec<ExternalRef>>,
}

#[derive(Debug, Deserialize)]
struct ExternalRef {
    #[serde(rename = "referenceCategory")]
    reference_category: String,
    #[serde(rename = "referenceType")]
    reference_type: String,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

/// Parse an SPDX JSON document and extract packages.
///
/// Reads an SPDX JSON document (v2.2 or v2.3) and extracts all packages
/// with their names, versions, and Package URLs (if available).
///
/// # Arguments
///
/// * `data` - Raw bytes of the SPDX JSON document
///
/// # Returns
///
/// A vector of [`SbomPackage`] structs, one for each package in the document.
///
/// # Errors
///
/// Returns an error if the JSON is malformed or required fields are missing.
///
/// # Examples
///
/// ```rust
/// use bitvex::sbom::parse_spdx_sbom;
///
/// let json = r#"{
///     "SPDXID": "SPDXRef-DOCUMENT",
///     "packages": [{
///         "SPDXID": "SPDXRef-Package-openssl",
///         "name": "openssl",
///         "versionInfo": "3.0.13"
///     }]
/// }"#;
///
/// let packages = parse_spdx_sbom(json.as_bytes()).unwrap();
/// assert_eq!(packages[0].name, "openssl");
/// assert_eq!(packages[0].version.as_deref(), Some("3.0.13"));
/// ```
pub fn parse_spdx_sbom(data: &[u8]) -> Result<Vec<SbomPackage>> {
    let doc: SpdxDocument =
        serde_json::from_slice(data).context("Failed to parse SPDX JSON document")?;

    let packages = doc.packages.unwrap_or_default();
    let mut result = Vec::with_capacity(packages.len());

    for pkg in packages {
        let purl = pkg
            .external_refs
            .as_ref()
            .and_then(|refs| {
                refs.iter().find(|r| {
                    r.reference_category == "PACKAGE-MANAGER" && r.reference_type == "purl"
                })
            })
            .map(|r| r.reference_locator.clone());

        let sbom_pkg = SbomPackage {
            _spdx_id: pkg.spdx_id,
            name: pkg.name,
            version: pkg.version_info,
            purl,
        };
        debug!("Parsed package: {} {:?}", sbom_pkg.name, sbom_pkg.version);
        result.push(sbom_pkg);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_spdx() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-openssl",
                    "name": "openssl",
                    "versionInfo": "3.0.13",
                    "downloadLocation": "https://example.com/openssl",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:generic/openssl@3.0.13"
                        }
                    ]
                },
                {
                    "SPDXID": "SPDXRef-Package-curl",
                    "name": "curl",
                    "versionInfo": "8.5.0",
                    "downloadLocation": "NONE"
                }
            ]
        }"#;

        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 2);

        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[0].version.as_deref(), Some("3.0.13"));
        assert_eq!(pkgs[0].purl.as_deref(), Some("pkg:generic/openssl@3.0.13"));

        assert_eq!(pkgs[1].name, "curl");
        assert_eq!(pkgs[1].version.as_deref(), Some("8.5.0"));
        assert!(pkgs[1].purl.is_none());
    }

    #[test]
    fn test_parse_no_packages() {
        let json = r#"{"SPDXID": "SPDXRef-DOCUMENT"}"#;
        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert!(pkgs.is_empty());
    }

    #[test]
    fn test_parse_spdx_version_22() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.2",
            "packages": [{
                "SPDXID": "SPDXRef-Package-test",
                "name": "test-pkg",
                "versionInfo": "1.0.0"
            }]
        }"#;

        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "test-pkg");
    }

    #[test]
    fn test_parse_multiple_packages() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"SPDXID": "SPDXRef-1", "name": "pkg-a", "versionInfo": "1.0"},
                {"SPDXID": "SPDXRef-2", "name": "pkg-b", "versionInfo": "2.0"},
                {"SPDXID": "SPDXRef-3", "name": "pkg-c", "versionInfo": "3.0"},
                {"SPDXID": "SPDXRef-4", "name": "pkg-d", "versionInfo": "4.0"},
                {"SPDXID": "SPDXRef-5", "name": "pkg-e", "versionInfo": "5.0"}
            ]
        }"#;

        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 5);
        assert_eq!(pkgs[0].name, "pkg-a");
        assert_eq!(pkgs[4].name, "pkg-e");
    }

    #[test]
    fn test_parse_package_with_npm_purl() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{
                "SPDXID": "SPDXRef-Package-axios",
                "name": "axios",
                "versionInfo": "0.21.0",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/axios@0.21.0"
                }]
            }]
        }"#;

        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs[0].purl.as_deref(), Some("pkg:npm/axios@0.21.0"));
    }

    #[test]
    fn test_parse_package_without_version() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{
                "SPDXID": "SPDXRef-Package-test",
                "name": "test-pkg"
            }]
        }"#;

        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs[0].name, "test-pkg");
        assert!(pkgs[0].version.is_none());
        assert!(pkgs[0].purl.is_none());
    }
}
