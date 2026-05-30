use tracing::debug;

use crate::osv::OsvResult;
use crate::rules::{Rule, RulesConfig, rule_matches};
use crate::vex::VexStatement;

pub fn apply_rules(results: &[OsvResult], config: &RulesConfig) -> (Vec<VexStatement>, Vec<usize>) {
    let mut statements = Vec::new();
    let mut filtered_indices = Vec::new();

    for (i, result) in results.iter().enumerate() {
        for vuln in &result.vulns {
            for rule in &config.rules {
                if rule_matches(
                    rule,
                    &vuln.id,
                    &result.package.name,
                    result.package.version.as_deref(),
                ) {
                    let statement = build_statement_from_rule(vuln, result, rule);
                    debug!(
                        "Rule '{}' matched: {} on {} -> {}",
                        rule.name,
                        vuln.id,
                        result.package.name,
                        rule.status.as_str()
                    );
                    statements.push(statement);

                    if rule.status == RuleStatus::NotAffected {
                        filtered_indices.push(i);
                    }

                    break;
                }
            }
        }
    }

    (statements, filtered_indices)
}

use crate::rules::RuleStatus;

fn build_statement_from_rule(
    vuln: &crate::osv::OsvVuln,
    result: &OsvResult,
    rule: &Rule,
) -> VexStatement {
    let purl = result
        .package
        .purl
        .clone()
        .unwrap_or_else(|| format!("pkg:generic/{}", result.package.name));

    VexStatement {
        vulnerability_name: vuln.id.clone(),
        product_purl: purl,
        status: rule.status.to_vex_status(),
        justification: rule.justification.clone(),
        impact_statement: rule.impact_statement.clone().or_else(|| {
            Some(format!(
                "Rule '{}': vulnerability {} on package {}.",
                rule.name, vuln.id, result.package.name
            ))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::OsvVuln;
    use crate::rules::RuleStatus;
    use crate::sbom::SbomPackage;
    use crate::vex::VexStatus;

    fn make_result(name: &str, version: &str, vuln_id: &str) -> OsvResult {
        OsvResult {
            package: SbomPackage {
                _spdx_id: format!("SPDXRef-{}", name),
                name: name.into(),
                version: Some(version.into()),
                purl: Some(format!("pkg:generic/{}@{}", name, version)),
            },
            vulns: vec![OsvVuln {
                id: vuln_id.into(),
                _modified: "2024-01-01T00:00:00Z".into(),
            }],
        }
    }

    #[test]
    fn test_rules_filter_specific_cve() {
        let results = vec![make_result("openssl", "3.0.13", "CVE-2024-1234")];
        let config = RulesConfig {
            author: None,
            rules: vec![Rule {
                name: "ignore CVE".into(),
                cve: Some("CVE-2024-1234".into()),
                cve_pattern: None,
                package: Some("openssl".into()),
                version: None,
                status: RuleStatus::NotAffected,
                justification: Some("vulnerable_code_not_present".into()),
                impact_statement: Some("Parcheado".into()),
            }],
        };

        let (statements, filtered) = apply_rules(&results, &config);
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].status, VexStatus::NotAffected);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_rules_does_not_match_wrong_cve() {
        let results = vec![make_result("openssl", "3.0.13", "CVE-2024-9999")];
        let config = RulesConfig {
            author: None,
            rules: vec![Rule {
                name: "ignore CVE".into(),
                cve: Some("CVE-2024-1234".into()),
                cve_pattern: None,
                package: None,
                version: None,
                status: RuleStatus::NotAffected,
                justification: None,
                impact_statement: None,
            }],
        };

        let (statements, _) = apply_rules(&results, &config);
        assert_eq!(statements.len(), 0);
    }

    #[test]
    fn test_rules_glob_pattern() {
        let results = vec![make_result("glibc", "2.37", "CVE-2024-5678")];
        let config = RulesConfig {
            author: None,
            rules: vec![Rule {
                name: "all 2024 CVEs".into(),
                cve: None,
                cve_pattern: Some("CVE-2024-*".into()),
                package: None,
                version: None,
                status: RuleStatus::UnderInvestigation,
                justification: None,
                impact_statement: None,
            }],
        };

        let (statements, _) = apply_rules(&results, &config);
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].status, VexStatus::UnderInvestigation);
    }
}
