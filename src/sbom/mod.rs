//! SPDX SBOM parser with automatic version detection.
//!
//! Supports SPDX 2.2, 2.3, and 3.0 formats. Detects the version from the
//! document and delegates to the appropriate parser.

pub mod diff;
pub mod spdx2;
pub mod spdx3;

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{debug, info, warn};

/// A package extracted from an SPDX SBOM document.
///
/// Represents a single software package with its identifying information.
/// This is the unified representation across all SPDX versions.
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

/// Parse an SPDX JSON document and extract packages.
///
/// Automatically detects the SPDX version (2.2, 2.3, or 3.0) and delegates
/// to the appropriate parser.
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
/// Returns an error if the JSON is malformed or the version cannot be determined.
///
/// # Examples
///
/// ```rust
/// use bitvex::sbom::parse_spdx_sbom;
///
/// // SPDX 2.3
/// let json = r#"{
///     "SPDXID": "SPDXRef-DOCUMENT",
///     "spdxVersion": "SPDX-2.3",
///     "packages": [{
///         "SPDXID": "SPDXRef-Package-openssl",
///         "name": "openssl",
///         "versionInfo": "3.0.13"
///     }]
/// }"#;
/// let packages = parse_spdx_sbom(json.as_bytes()).unwrap();
/// assert_eq!(packages[0].name, "openssl");
/// ```
pub fn parse_spdx_sbom(data: &[u8]) -> Result<Vec<SbomPackage>> {
    // First, detect version from raw JSON
    let doc: serde_json::Value =
        serde_json::from_slice(data).context("Failed to parse SBOM as JSON")?;

    // Check for SPDX 3.0 via specVersion
    if let Some(spec_version) = doc.get("specVersion").and_then(|v| v.as_str()) {
        if spec_version.starts_with("3.") {
            info!("Detected SPDX 3.0 document (specVersion: {})", spec_version);
            return spdx3::parse_spdx3(data);
        }
    }

    // Check for SPDX 3.0 via spdxVersion (some tools use this)
    if let Some(spdx_version) = doc.get("spdxVersion").and_then(|v| v.as_str()) {
        if spdx_version.starts_with("SPDX-3") {
            info!("Detected SPDX 3.0 document (spdxVersion: {})", spdx_version);
            return spdx3::parse_spdx3(data);
        }
    }

    // Check for SPDX 2.x
    if let Some(spdx_version) = doc.get("spdxVersion").and_then(|v| v.as_str()) {
        if spdx_version.starts_with("SPDX-2") {
            debug!("Detected SPDX 2.x document (spdxVersion: {})", spdx_version);
            return spdx2::parse_spdx2(data);
        }
    }

    // Fallback: try SPDX 2.x parser (most common)
    warn!("Could not detect SPDX version from document, trying SPDX 2.x parser");
    spdx2::parse_spdx2(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_spdx23() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "packages": [{"SPDXID": "SPDXRef-1", "name": "test", "versionInfo": "1.0"}]
        }"#;
        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "test");
    }

    #[test]
    fn test_detect_spdx30() {
        let json = r#"{
            "type": "SpdxDocument",
            "spdxId": "SPDXRef-DOCUMENT",
            "specVersion": "3.0.1",
            "element": [{"type": "Package", "spdxId": "SPDXRef-1", "name": "test", "packageVersion": "1.0"}]
        }"#;
        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "test");
    }

    #[test]
    fn test_detect_spdx30_via_spdxversion() {
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-3.0",
            "element": [{"type": "Package", "spdxId": "SPDXRef-1", "name": "test", "packageVersion": "1.0"}]
        }"#;
        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn test_fallback_to_spdx2() {
        // No version field, should fallback to SPDX 2.x
        let json = r#"{
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{"SPDXID": "SPDXRef-1", "name": "test", "versionInfo": "1.0"}]
        }"#;
        let pkgs = parse_spdx_sbom(json.as_bytes()).unwrap();
        assert_eq!(pkgs.len(), 1);
    }
}
