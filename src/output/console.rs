//! Console output formatting.
//!
//! Generates human-readable summaries of the BitVex scan results,
//! including vulnerability tables with EPSS scores.

use std::collections::HashMap;

use tabled::{Table, Tabled};

use crate::epss::EpssScore;
use crate::vex::{VexStatement, VexStatus};

#[derive(Tabled)]
struct VulnRow {
    #[tabled(rename = "CVE")]
    cve: String,
    #[tabled(rename = "Package (purl)")]
    purl: String,
    #[tabled(rename = "EPSS")]
    epss: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Justification")]
    justification: String,
}

/// Data for generating the console summary.
///
/// Contains all the information needed to display the scan results,
/// including package counts, filter statistics, and vulnerability details.
pub struct SummaryData<'a> {
    /// Total number of packages in the SBOM.
    pub total_packages: usize,
    /// Number of native (host-only) packages filtered out.
    pub native_filtered: usize,
    /// Number of packages filtered by kernel/U-Boot config.
    pub kernel_filtered: usize,
    /// Number of packages filtered by device tree.
    pub dts_filtered: usize,
    /// All VEX statements generated during the scan.
    pub statements: &'a [VexStatement],
    /// EPSS scores for CVEs (if EPSS was enabled).
    pub epss_scores: &'a [EpssScore],
    /// Whether EPSS scoring was enabled.
    pub epss_enabled: bool,
    /// Map from vulnerability ID to CVE alias (for GHSA→CVE resolution).
    pub vuln_cve_map: &'a HashMap<String, String>,
}

/// Print the scan summary to stdout.
///
/// Displays a formatted table with scan statistics and a detailed
/// table of vulnerabilities requiring attention.
pub fn print_summary(data: &SummaryData) {
    let real_cve_count = data
        .statements
        .iter()
        .filter(|s| s.status == VexStatus::Affected || s.status == VexStatus::UnderInvestigation)
        .count();

    let not_affected_count = data
        .statements
        .iter()
        .filter(|s| s.status == VexStatus::NotAffected)
        .count();

    let fixed_count = data
        .statements
        .iter()
        .filter(|s| s.status == VexStatus::Fixed)
        .count();

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          BitVex - CRA Compliance Report             ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!(
        "║  Total packages analyzed:     {:<5}                  ║",
        data.total_packages
    );
    println!(
        "║  Native packages filtered:    {:<5}                  ║",
        data.native_filtered
    );
    println!(
        "║  Kernel/U-Boot filtered:      {:<5}                  ║",
        data.kernel_filtered
    );
    println!(
        "║  DTS disabled filtered:       {:<5}                  ║",
        data.dts_filtered
    );
    println!("║  ─────────────────────────────────────              ║");
    println!(
        "║  CVEs marked not_affected:    {:<5}                  ║",
        not_affected_count
    );
    println!(
        "║  CVEs marked fixed:           {:<5}                  ║",
        fixed_count
    );
    println!(
        "║  Real CVEs to address:        {:<5}                  ║",
        real_cve_count
    );
    if data.epss_enabled {
        let high_epss = data.epss_scores.iter().filter(|e| e.epss > 0.7).count();
        let critical_epss = data.epss_scores.iter().filter(|e| e.epss > 0.9).count();
        println!("║  ─────────────────────────────────────              ║");
        println!(
            "║  EPSS high risk (>0.7):       {:<5}                  ║",
            high_epss
        );
        println!(
            "║  EPSS critical (>0.9):        {:<5}                  ║",
            critical_epss
        );
    }
    println!("╚══════════════════════════════════════════════════════╝");

    let affected: Vec<&VexStatement> = data
        .statements
        .iter()
        .filter(|s| s.status != VexStatus::NotAffected)
        .collect();

    if !affected.is_empty() {
        println!();
        println!("Vulnerabilities requiring attention:");
        println!();

        let rows: Vec<VulnRow> = affected
            .iter()
            .map(|s| {
                let epss_str = data
                    .epss_scores
                    .iter()
                    .find(|e| e.cve == s.vulnerability_name)
                    .or_else(|| {
                        data.vuln_cve_map
                            .get(&s.vulnerability_name)
                            .and_then(|cve| data.epss_scores.iter().find(|e| &e.cve == cve))
                    })
                    .map(|e| format!("{:.1}%", e.epss * 100.0))
                    .unwrap_or_else(|| "-".to_string());

                let display_id = if s.vulnerability_name.starts_with("CVE-") {
                    s.vulnerability_name.clone()
                } else {
                    data.vuln_cve_map
                        .get(&s.vulnerability_name)
                        .map(|cve| format!("{} ({})", s.vulnerability_name, cve))
                        .unwrap_or_else(|| s.vulnerability_name.clone())
                };

                VulnRow {
                    cve: display_id,
                    purl: truncate_str(&s.product_purl, 40),
                    epss: epss_str,
                    status: s.status.as_str().to_string(),
                    justification: s
                        .justification
                        .clone()
                        .or_else(|| s.impact_statement.clone())
                        .unwrap_or_default(),
                }
            })
            .collect();

        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    println!();
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}
