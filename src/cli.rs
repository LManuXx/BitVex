//! CLI argument definitions for BitVex.
//!
//! Defines the command-line interface using `clap` with derive macros.
//! Supports scan mode (default), diff, delta, and database download commands.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// BitVex CLI arguments.
///
/// The main entry point for the BitVex command-line tool. Supports multiple
/// subcommands for different operations, or direct scan mode via flags.
///
/// # Examples
///
/// ```bash
/// # Scan mode (default)
/// bitvex --sbom path/to/spdx.json --epss --output report.vex.json
///
/// # Diff mode
/// bitvex diff --old v1.spdx.json --new v2.spdx.json
///
/// # Delta VEX
/// bitvex delta --old report-v1.vex.json --new report-v2.vex.json
/// ```
#[derive(Parser, Debug)]
#[command(
    name = "bitvex",
    version,
    about = "CRA compliance tool: generates OpenVEX reports from Yocto build artifacts"
)]
pub struct Args {
    /// Subcommand to execute (diff, delta, download-db, download-epss-db).
    /// If omitted, runs in scan mode.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to the SBOM in SPDX JSON format.
    /// Required for scan mode. Supports SPDX v2.2 and v2.3.
    #[arg(long, value_name = "PATH")]
    pub sbom: Option<PathBuf>,

    /// Path to the Linux kernel .config file.
    /// Optional. Can be specified multiple times for config fragments.
    #[arg(long = "kernel-config", value_name = "PATH")]
    pub kernel_config: Vec<PathBuf>,

    /// Path to the U-Boot .config file.
    /// Optional. Uses the same format as kernel .config.
    #[arg(long = "uboot-config", value_name = "PATH")]
    pub uboot_config: Option<PathBuf>,

    /// Path to the Device Tree file (.dts or .dtb).
    /// Optional. Binary .dtb files are automatically decompiled using dtc.
    #[arg(long = "device-tree", value_name = "PATH")]
    pub device_tree: Option<PathBuf>,

    /// Output path for the generated report.
    #[arg(
        long,
        short,
        value_name = "PATH",
        default_value = "bitvex-report.vex.json"
    )]
    pub output: PathBuf,

    /// Output format for the generated report.
    ///
    /// - `openvex`: OpenVEX v0.2.0 JSON-LD format (default)
    /// - `sarif`: SARIF 2.1.0 format for GitHub Security tab
    #[arg(long, value_enum, default_value = "openvex")]
    pub format: OutputFormat,

    /// Author identifier for the VEX document.
    /// Used in the `author` field of the generated OpenVEX document.
    #[arg(long, default_value = "BitVex <bitvex@automated>")]
    pub author: String,

    /// Path to a `bitvex.toml` rules file for custom filtering rules.
    #[arg(long, value_name = "PATH")]
    pub rules: Option<PathBuf>,

    /// Use offline OSV database instead of querying the API.
    /// Requires a previously downloaded database (see `download-db`).
    #[arg(long)]
    pub offline: bool,

    /// Download or update the offline OSV database before scanning.
    /// Can be combined with `--offline` for a single-command workflow.
    #[arg(long)]
    pub download_db: bool,

    /// Custom path for the offline OSV database directory.
    /// Defaults to `~/.cache/bitvex/osv-db/`.
    #[arg(long = "db-path", value_name = "PATH")]
    pub db_path: Option<PathBuf>,

    /// Download profile for the OSV database.
    /// Determines which ecosystems to download and the total size.
    #[arg(long)]
    pub profile: Option<DownloadProfile>,

    /// Enable EPSS (Exploit Prediction Scoring System) integration.
    /// Queries FIRST.org API to score CVE exploitability.
    #[arg(long)]
    pub epss: bool,

    /// Use offline EPSS database instead of querying the API.
    #[arg(long)]
    pub epss_offline: bool,

    /// Download or update the offline EPSS database.
    #[arg(long)]
    pub download_epss_db: bool,

    /// Custom path for the offline EPSS database directory.
    /// Defaults to `~/.cache/bitvex/epss-db/`.
    #[arg(long = "epss-db-path", value_name = "PATH")]
    pub epss_db_path: Option<PathBuf>,

    /// EPSS threshold for marking CVEs as low priority.
    /// CVEs with EPSS score below this value are marked as low_priority.
    /// Range: 0.0 to 1.0.
    #[arg(long, value_name = "FLOAT", default_value = "0.0")]
    pub epss_threshold: f64,

    /// Exit with code 1 if any CVE is affected (not mitigated).
    /// Useful for CI/CD pipeline gating.
    #[arg(long)]
    pub fail_on_any: bool,

    /// Exit with code 1 if any CVE has EPSS score > 0.7.
    /// Indicates high exploitability risk.
    #[arg(long)]
    pub fail_on_high: bool,

    /// Exit with code 1 if any CVE has EPSS score > 0.9.
    /// Indicates critical exploitability risk.
    #[arg(long)]
    pub fail_on_critical: bool,

    /// Skip all confirmation prompts (accept all).
    /// Useful for automated/CI environments.
    #[arg(long, short)]
    pub yes: bool,

    /// Enable verbose (debug) logging output.
    #[arg(long, short)]
    pub verbose: bool,
}

/// BitVex subcommands for non-scan operations.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Compare two SBOMs and report differences.
    ///
    /// Analyzes two SPDX JSON SBOMs and reports packages that were
    /// added, removed, or updated between them.
    Diff {
        /// Path to the old (baseline) SBOM in SPDX JSON format.
        #[arg(long)]
        old: PathBuf,

        /// Path to the new SBOM in SPDX JSON format.
        #[arg(long)]
        new: PathBuf,

        /// Output path for the diff report in JSON format.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Compare two VEX documents and report changes (Delta VEX).
    ///
    /// Tracks how vulnerability assessments have changed between two
    /// points in time: new CVEs, resolved CVEs, and status changes.
    Delta {
        /// Path to the old VEX document.
        #[arg(long)]
        old: PathBuf,

        /// Path to the new VEX document.
        #[arg(long)]
        new: PathBuf,

        /// Output path for the delta report in JSON format.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Download or update the offline OSV vulnerability database.
    ///
    /// Downloads vulnerability data from OSV.dev for use in offline mode.
    /// Supports multiple ecosystems and download profiles.
    DownloadDb {
        /// Custom path to store the database.
        #[arg(long = "db-path", value_name = "PATH")]
        db_path: Option<PathBuf>,

        /// Comma-separated list of ecosystems to download.
        /// Overrides the profile setting.
        #[arg(long, value_delimiter = ',')]
        ecosystems: Option<Vec<String>>,

        /// Download profile: small (29MB), medium (35MB), big (116MB), complete (822MB).
        #[arg(long)]
        profile: Option<DownloadProfile>,

        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },

    /// Download or update the offline EPSS database.
    ///
    /// Downloads the EPSS CSV database from FIRST.org for offline use.
    /// The database is approximately 250 MB.
    DownloadEpssDb {
        /// Custom path to store the database.
        #[arg(long = "db-path", value_name = "PATH")]
        db_path: Option<PathBuf>,

        /// Skip the confirmation prompt.
        #[arg(long, short)]
        yes: bool,
    },
}

/// Download profile for OSV database.
///
/// Determines which ecosystems to download and the approximate total size.
#[derive(Debug, Clone, ValueEnum)]
pub enum DownloadProfile {
    /// Linux kernel only (~29 MB).
    /// Suitable for kernel-only devices.
    Small,
    /// Linux + Alpine + crates.io (~35 MB).
    /// Recommended for typical embedded Linux builds.
    Medium,
    /// Linux + Alpine + Debian + PyPI + crates.io (~116 MB).
    /// Full coverage for most embedded projects.
    Big,
    /// All 10 ecosystems (~822 MB).
    /// Maximum audit coverage.
    Complete,
}

/// Output format for generated reports.
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    /// OpenVEX v0.2.0 JSON-LD format (default).
    /// Spec-compliant format for VEX interoperability.
    Openvex,
    /// SARIF 2.1.0 format.
    /// Compatible with GitHub Security tab and other SARIF consumers.
    Sarif,
}

impl DownloadProfile {
    /// Returns the list of ecosystem names for this profile.
    pub fn ecosystems(&self) -> &[&str] {
        match self {
            DownloadProfile::Small => &["Linux"],
            DownloadProfile::Medium => &["Linux", "Alpine", "crates.io"],
            DownloadProfile::Big => &["Linux", "Alpine", "Debian", "PyPI", "crates.io"],
            DownloadProfile::Complete => &[
                "Alpine",
                "Debian",
                "Ubuntu",
                "Linux",
                "crates.io",
                "Go",
                "npm",
                "PyPI",
                "Maven",
                "NuGet",
            ],
        }
    }

    /// Returns the human-readable name of this profile.
    pub fn name(&self) -> &str {
        match self {
            DownloadProfile::Small => "small",
            DownloadProfile::Medium => "medium",
            DownloadProfile::Big => "big",
            DownloadProfile::Complete => "complete",
        }
    }
}
