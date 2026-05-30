use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize)]
pub struct SbomPackage {
    pub _spdx_id: String,
    pub name: String,
    pub version: Option<String>,
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
}
