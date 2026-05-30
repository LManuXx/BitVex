use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use tracing::info;

use crate::vex::VexStatus;

#[derive(Debug, Deserialize)]
pub struct RulesConfig {
    pub author: Option<AuthorConfig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorConfig {
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Rule {
    pub name: String,
    pub cve: Option<String>,
    pub cve_pattern: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
    pub status: RuleStatus,
    pub justification: Option<String>,
    pub impact_statement: Option<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    NotAffected,
    Affected,
    Fixed,
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
}
