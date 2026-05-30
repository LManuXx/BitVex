use serde::Serialize;

use crate::epss::EpssScore;
use crate::vex::{VexStatement, VexStatus};

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
}

#[derive(Serialize)]
struct SarResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

fn status_to_level(status: &VexStatus, epss: Option<f64>) -> String {
    match status {
        VexStatus::Affected => {
            if let Some(score) = epss {
                if score > 0.9 {
                    "error".to_string()
                } else if score > 0.7 {
                    "warning".to_string()
                } else {
                    "note".to_string()
                }
            } else {
                "warning".to_string()
            }
        }
        VexStatus::UnderInvestigation => "note".to_string(),
        VexStatus::NotAffected | VexStatus::Fixed => "none".to_string(),
    }
}

pub fn generate_sarif(
    statements: &[VexStatement],
    epss_scores: &[EpssScore],
    vuln_cve_map: &std::collections::HashMap<String, String>,
) -> serde_json::Value {
    let results: Vec<SarResult> = statements
        .iter()
        .filter(|s| s.status == VexStatus::Affected || s.status == VexStatus::UnderInvestigation)
        .map(|s| {
            let epss = epss_scores
                .iter()
                .find(|e| e.cve == s.vulnerability_name)
                .or_else(|| {
                    vuln_cve_map
                        .get(&s.vulnerability_name)
                        .and_then(|cve| epss_scores.iter().find(|e| &e.cve == cve))
                })
                .map(|e| e.epss);

            let level = status_to_level(&s.status, epss);

            let epss_note = epss
                .map(|e| format!(" [EPSS: {:.1}%]", e * 100.0))
                .unwrap_or_default();

            SarResult {
                rule_id: s.vulnerability_name.clone(),
                level,
                message: SarifMessage {
                    text: format!(
                        "{} affects {}{}",
                        s.vulnerability_name, s.product_purl, epss_note
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: s.product_purl.clone(),
                        },
                    },
                }],
            }
        })
        .collect();

    let sarif = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "BitVex".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/LManuXx/BitVex".to_string(),
                },
            },
            results,
        }],
    };

    serde_json::to_value(&sarif).unwrap()
}
