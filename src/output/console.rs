use tabled::{Table, Tabled};

use crate::vex::{VexStatement, VexStatus};

#[derive(Tabled)]
struct VulnRow {
    #[tabled(rename = "CVE")]
    cve: String,
    #[tabled(rename = "Package (purl)")]
    purl: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Justification")]
    justification: String,
}

pub fn print_summary(
    total_packages: usize,
    native_filtered: usize,
    kernel_filtered: usize,
    dts_filtered: usize,
    statements: &[VexStatement],
) {
    let real_cve_count = statements
        .iter()
        .filter(|s| s.status == VexStatus::Affected || s.status == VexStatus::UnderInvestigation)
        .count();

    let not_affected_count = statements
        .iter()
        .filter(|s| s.status == VexStatus::NotAffected)
        .count();

    let fixed_count = statements
        .iter()
        .filter(|s| s.status == VexStatus::Fixed)
        .count();

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║          BitVex - CRA Compliance Report             ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Total packages analyzed:     {:<5}                  ║", total_packages);
    println!("║  Native packages filtered:    {:<5}                  ║", native_filtered);
    println!("║  Kernel drivers filtered:     {:<5}                  ║", kernel_filtered);
    println!("║  DTS disabled filtered:       {:<5}                  ║", dts_filtered);
    println!("║  ─────────────────────────────────────              ║");
    println!("║  CVEs marked not_affected:    {:<5}                  ║", not_affected_count);
    println!("║  CVEs marked fixed:           {:<5}                  ║", fixed_count);
    println!("║  Real CVEs to address:        {:<5}                  ║", real_cve_count);
    println!("╚══════════════════════════════════════════════════════╝");

    let affected: Vec<&VexStatement> = statements
        .iter()
        .filter(|s| s.status != VexStatus::NotAffected)
        .collect();

    if !affected.is_empty() {
        println!();
        println!("Vulnerabilities requiring attention:");
        println!();

        let rows: Vec<VulnRow> = affected
            .iter()
            .map(|s| VulnRow {
                cve: s.vulnerability_name.clone(),
                purl: truncate_str(&s.product_purl, 40),
                status: s.status.as_str().to_string(),
                justification: s
                    .justification
                    .clone()
                    .or_else(|| s.impact_statement.clone())
                    .unwrap_or_default(),
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
