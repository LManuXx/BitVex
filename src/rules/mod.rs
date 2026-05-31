//! Custom filtering rules engine.
//!
//! Parses `bitvex.toml` configuration files and evaluates rules against
//! vulnerability results. Rules can match by CVE ID, glob pattern,
//! package name, and version.
//!
//! # Rule File Format
//!
//! ```toml
//! [author]
//! name = "Company <security@company.com>"
//!
//! [[rules]]
//! name = "Ignore specific CVE"
//! cve = "CVE-2024-12345"
//! package = "openssl"
//! status = "not_affected"
//! justification = "vulnerable_code_not_present"
//! impact_statement = "Patched in our build"
//!
//! [[rules]]
//! name = "All glibc CVEs under investigation"
//! package = "glibc"
//! status = "under_investigation"
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use tracing::info;

use crate::vex::VexStatus;

/// Configuration loaded from a `bitvex.toml` rules file.
#[derive(Debug, Deserialize)]
pub struct RulesConfig {
    /// Optional author override for the VEX document.
    pub author: Option<AuthorConfig>,
    /// List of filtering rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Author configuration in a rules file.
#[derive(Debug, Deserialize)]
pub struct AuthorConfig {
    /// Author name and contact (e.g., "Company <email@example.com>").
    pub name: String,
}

/// A single filtering rule.
///
/// Rules match vulnerabilities based on CVE ID, glob pattern, package name,
/// and/or version. The first matching rule determines the VEX status.
#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    /// Human-readable name for this rule.
    pub name: String,
    /// Match a specific CVE ID (e.g., "CVE-2024-12345").
    pub cve: Option<String>,
    /// Match CVE IDs by glob pattern (e.g., "CVE-2024-*").
    pub cve_pattern: Option<String>,
    /// Match a specific package name (e.g., "openssl").
    pub package: Option<String>,
    /// Match a specific package version (e.g., "3.0.13").
    pub version: Option<String>,
    /// VEX status to assign when this rule matches.
    pub status: RuleStatus,
    /// Justification for `not_affected` status.
    pub justification: Option<String>,
    /// Human-readable impact statement.
    pub impact_statement: Option<String>,
}

/// VEX status values for rules.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    /// Product is not affected by the vulnerability.
    NotAffected,
    /// Product is affected by the vulnerability.
    Affected,
    /// Product contains a fix for the vulnerability.
    Fixed,
    /// It is not yet known whether the product is affected.
    UnderInvestigation,
}

impl RuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleStatus::NotAffected => "not_affected",
            RuleStatus::Affected => "affected",
            RuleStatus::Fixed => "fixed",
            RuleStatus::UnderInvestigation => "under_investigation",
        }
    }

    pub fn to_vex_status(&self) -> VexStatus {
        match self {
            RuleStatus::NotAffected => VexStatus::NotAffected,
            RuleStatus::Affected => VexStatus::Affected,
            RuleStatus::Fixed => VexStatus::Fixed,
            RuleStatus::UnderInvestigation => VexStatus::UnderInvestigation,
        }
    }
}

pub fn load_rules(path: &Path) -> Result<RulesConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rules file: {}", path.display()))?;

    let config: RulesConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse rules file: {}", path.display()))?;

    info!(
        "Loaded {} rules from {}",
        config.rules.len(),
        path.display()
    );
    Ok(config)
}

pub fn rule_matches(
    rule: &Rule,
    cve_id: &str,
    package_name: &str,
    package_version: Option<&str>,
) -> bool {
    if let Some(ref expected_cve) = rule.cve {
        if cve_id != expected_cve {
            return false;
        }
    }

    if let Some(ref pattern) = rule.cve_pattern {
        if !matches_glob(pattern, cve_id) {
            return false;
        }
    }

    if let Some(ref expected_pkg) = rule.package {
        if package_name != expected_pkg {
            return false;
        }
    }

    if let Some(ref expected_ver) = rule.version {
        match package_version {
            Some(v) if v == expected_ver => {}
            _ => return false,
        }
    }

    true
}

fn matches_glob(pattern: &str, value: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(value))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_rules_from_toml() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[author]
name = "Test Author"

[[rules]]
name = "Ignore specific CVE"
cve = "CVE-2024-1234"
package = "openssl"
status = "not_affected"
justification = "vulnerable_code_not_present"
impact_statement = "Parcheado manualmente"

[[rules]]
name = "Ignore all glibc CVEs"
package = "glibc"
status = "under_investigation"
"#
        )
        .unwrap();

        let config = load_rules(file.path()).unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].name, "Ignore specific CVE");
        assert_eq!(config.rules[0].cve, Some("CVE-2024-1234".to_string()));
        assert_eq!(config.rules[1].name, "Ignore all glibc CVEs");
        assert_eq!(config.rules[1].status, RuleStatus::UnderInvestigation);
    }

    #[test]
    fn test_rule_matches_exact_cve() {
        let rule = Rule {
            name: "test".into(),
            cve: Some("CVE-2024-1234".into()),
            cve_pattern: None,
            package: None,
            version: None,
            status: RuleStatus::NotAffected,
            justification: None,
            impact_statement: None,
        };

        assert!(rule_matches(
            &rule,
            "CVE-2024-1234",
            "openssl",
            Some("3.0.13")
        ));
        assert!(!rule_matches(
            &rule,
            "CVE-2024-5678",
            "openssl",
            Some("3.0.13")
        ));
    }

    #[test]
    fn test_rule_matches_glob_pattern() {
        let rule = Rule {
            name: "test".into(),
            cve: None,
            cve_pattern: Some("CVE-2024-*".into()),
            package: None,
            version: None,
            status: RuleStatus::NotAffected,
            justification: None,
            impact_statement: None,
        };

        assert!(rule_matches(&rule, "CVE-2024-1234", "any", None));
        assert!(rule_matches(&rule, "CVE-2024-9999", "any", None));
        assert!(!rule_matches(&rule, "CVE-2023-1234", "any", None));
    }

    #[test]
    fn test_rule_matches_package_and_version() {
        let rule = Rule {
            name: "test".into(),
            cve: None,
            cve_pattern: None,
            package: Some("openssl".into()),
            version: Some("3.0.13".into()),
            status: RuleStatus::Affected,
            justification: None,
            impact_statement: None,
        };

        assert!(rule_matches(
            &rule,
            "CVE-2024-0001",
            "openssl",
            Some("3.0.13")
        ));
        assert!(!rule_matches(
            &rule,
            "CVE-2024-0001",
            "openssl",
            Some("3.0.14")
        ));
        assert!(!rule_matches(
            &rule,
            "CVE-2024-0001",
            "curl",
            Some("3.0.13")
        ));
    }

    #[test]
    fn test_rule_matches_any_package() {
        let rule = Rule {
            name: "test".into(),
            cve: None,
            cve_pattern: None,
            package: None,
            version: None,
            status: RuleStatus::UnderInvestigation,
            justification: None,
            impact_statement: None,
        };

        assert!(rule_matches(
            &rule,
            "CVE-2024-0001",
            "openssl",
            Some("3.0.13")
        ));
        assert!(rule_matches(&rule, "CVE-2024-0001", "curl", Some("8.1.2")));
    }

    #[test]
    fn test_load_empty_rules() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[author]
name = "Test Author"
"#
        )
        .unwrap();

        let config = load_rules(file.path()).unwrap();
        assert_eq!(config.rules.len(), 0);
        assert_eq!(config.author.as_ref().unwrap().name, "Test Author");
    }

    #[test]
    fn test_rule_combined_cve_and_package() {
        let rule = Rule {
            name: "test".into(),
            cve: Some("CVE-2024-1234".into()),
            cve_pattern: None,
            package: Some("openssl".into()),
            version: Some("3.0.13".into()),
            status: RuleStatus::NotAffected,
            justification: Some("vulnerable_code_not_present".into()),
            impact_statement: None,
        };

        // All conditions match
        assert!(rule_matches(
            &rule,
            "CVE-2024-1234",
            "openssl",
            Some("3.0.13")
        ));

        // Wrong version
        assert!(!rule_matches(
            &rule,
            "CVE-2024-1234",
            "openssl",
            Some("3.0.14")
        ));

        // Wrong package
        assert!(!rule_matches(
            &rule,
            "CVE-2024-1234",
            "curl",
            Some("3.0.13")
        ));

        // Wrong CVE
        assert!(!rule_matches(
            &rule,
            "CVE-2024-9999",
            "openssl",
            Some("3.0.13")
        ));
    }
}
