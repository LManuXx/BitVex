use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "bitvex",
    version,
    about = "CRA compliance tool: generates OpenVEX reports from Yocto build artifacts"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to the SBOM in SPDX JSON format
    #[arg(long, value_name = "PATH")]
    pub sbom: Option<PathBuf>,

    /// Path to the Linux kernel .config file (optional, can specify multiple)
    #[arg(long = "kernel-config", value_name = "PATH")]
    pub kernel_config: Vec<PathBuf>,

    /// Path to the U-Boot .config file (optional)
    #[arg(long = "uboot-config", value_name = "PATH")]
    pub uboot_config: Option<PathBuf>,

    /// Path to the Device Tree file (.dts or .dtb, optional)
    #[arg(long = "device-tree", value_name = "PATH")]
    pub device_tree: Option<PathBuf>,

    /// Output path for the OpenVEX JSON report
    #[arg(
        long,
        short,
        value_name = "PATH",
        default_value = "bitvex-report.vex.json"
    )]
    pub output: PathBuf,

    /// Author identifier for the VEX document
    #[arg(long, default_value = "BitVex <bitvex@automated>")]
    pub author: String,

    /// Path to bitvex.toml rules file
    #[arg(long, value_name = "PATH")]
    pub rules: Option<PathBuf>,

    /// Use offline OSV database (no network required)
    #[arg(long)]
    pub offline: bool,

    /// Download/update offline OSV database
    #[arg(long)]
    pub download_db: bool,

    /// Path to offline OSV database directory
    #[arg(long = "db-path", value_name = "PATH")]
    pub db_path: Option<PathBuf>,

    /// Database download profile (small/medium/big/complete)
    #[arg(long)]
    pub profile: Option<DownloadProfile>,

    /// Enable EPSS scoring for CVEs
    #[arg(long)]
    pub epss: bool,

    /// Use offline EPSS database
    #[arg(long)]
    pub epss_offline: bool,

    /// Download/update offline EPSS database
    #[arg(long)]
    pub download_epss_db: bool,

    /// Path to offline EPSS database directory
    #[arg(long = "epss-db-path", value_name = "PATH")]
    pub epss_db_path: Option<PathBuf>,

    /// Mark CVEs below this EPSS threshold as low_priority (0.0-1.0)
    #[arg(long, value_name = "FLOAT", default_value = "0.0")]
    pub epss_threshold: f64,

    /// Exit with code 1 if any CVE is affected (not mitigated)
    #[arg(long)]
    pub fail_on_any: bool,

    /// Exit with code 1 if any CVE has EPSS > 0.7
    #[arg(long)]
    pub fail_on_high: bool,

    /// Exit with code 1 if any CVE has EPSS > 0.9
    #[arg(long)]
    pub fail_on_critical: bool,

    /// Skip confirmation prompts (accept all)
    #[arg(long, short)]
    pub yes: bool,

    /// Enable verbose logging
    #[arg(long, short)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Compare two SBOMs and report differences
    Diff {
        /// Path to the old SBOM (SPDX JSON)
        #[arg(long)]
        old: PathBuf,

        /// Path to the new SBOM (SPDX JSON)
        #[arg(long)]
        new: PathBuf,

        /// Output path for the diff report (JSON)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Download/update the offline OSV vulnerability database
    DownloadDb {
        /// Path to store the database
        #[arg(long = "db-path", value_name = "PATH")]
        db_path: Option<PathBuf>,

        /// Comma-separated list of ecosystems to download
        #[arg(long, value_delimiter = ',')]
        ecosystems: Option<Vec<String>>,

        /// Download profile: small (29MB), medium (35MB), big (116MB), complete (822MB)
        #[arg(long)]
        profile: Option<DownloadProfile>,

        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },

    /// Download/update the offline EPSS database
    DownloadEpssDb {
        /// Path to store the database
        #[arg(long = "db-path", value_name = "PATH")]
        db_path: Option<PathBuf>,

        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Debug, Clone, ValueEnum)]
pub enum DownloadProfile {
    /// Linux kernel only (~29 MB)
    Small,
    /// Linux + Alpine + crates.io (~35 MB) - Recommended
    Medium,
    /// Linux + Alpine + Debian + PyPI + crates.io (~116 MB)
    Big,
    /// All ecosystems (~822 MB)
    Complete,
}

impl DownloadProfile {
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

    pub fn name(&self) -> &str {
        match self {
            DownloadProfile::Small => "small",
            DownloadProfile::Medium => "medium",
            DownloadProfile::Big => "big",
            DownloadProfile::Complete => "complete",
        }
    }
}
