use crate::osv::{OsvResult, OsvVuln};
use crate::vex::{VexStatement, VexStatus};

const JUSTIFICATION: &str = "component_not_present";

pub fn is_native_package(name: &str) -> bool {
    name.ends_with("-native") || name.contains("-native-")
}

pub fn filter_native_packages(results: &[OsvResult]) -> (Vec<VexStatement>, Vec<usize>) {
    let mut statements = Vec::new();
    let mut filtered_indices = Vec::new();

    for (i, result) in results.iter().enumerate() {
        if is_native_package(&result.package.name) {
            filtered_indices.push(i);
            for vuln in &result.vulns {
                statements.push(build_statement(vuln, result));
            }
        }
    }

    (statements, filtered_indices)
}

fn build_statement(vuln: &OsvVuln, result: &OsvResult) -> VexStatement {
    let purl = result
        .package
        .purl
        .clone()
        .unwrap_or_else(|| format!("pkg:generic/{}", result.package.name));

    VexStatement {
        vulnerability_name: vuln.id.clone(),
        product_purl: purl,
        status: VexStatus::NotAffected,
        justification: Some(JUSTIFICATION.to_string()),
        impact_statement: Some(format!(
            "Package '{}' is a host-only build dependency (native recipe) and is not present in the target image.",
            result.package.name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::OsvVuln;

    #[test]
    fn test_native_detection() {
        assert!(is_native_package("gcc-runtime-native"));
        assert!(is_native_package("qemu-native"));
        assert!(is_native_package("cmake-native"));
        assert!(!is_native_package("openssl"));
        assert!(!is_native_package("glibc"));
    }

    #[test]
    fn test_filter_marks_native() {
        let results = vec![
            OsvResult {
                package: crate::sbom::SbomPackage {
                    _spdx_id: "SPDXRef-1".into(),
                    name: "gcc-runtime-native".into(),
                    version: Some("12.3.0".into()),
                    purl: Some("pkg:generic/gcc-runtime-native@12.3.0".into()),
                },
                vulns: vec![OsvVuln {
                    id: "CVE-2024-1234".into(),
                    _modified: "2024-01-01T00:00:00Z".into(),
                }],
            },
            OsvResult {
                package: crate::sbom::SbomPackage {
                    _spdx_id: "SPDXRef-2".into(),
                    name: "openssl".into(),
                    version: Some("3.0.13".into()),
                    purl: Some("pkg:generic/openssl@3.0.13".into()),
                },
                vulns: vec![OsvVuln {
                    id: "CVE-2024-5678".into(),
                    _modified: "2024-01-01T00:00:00Z".into(),
                }],
            },
        ];

        let (statements, indices) = filter_native_packages(&results);
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0], 0);
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].vulnerability_name, "CVE-2024-1234");
        assert_eq!(
            statements[0].justification.as_deref(),
            Some("component_not_present")
        );
    }
}
