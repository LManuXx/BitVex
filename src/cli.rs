use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "bitvex", version, about = "CRA compliance tool: generates OpenVEX reports from Yocto build artifacts")]
pub struct Args {
    /// Path to the SBOM in SPDX JSON format
    #[arg(long, value_name = "PATH")]
    pub sbom: PathBuf,

    /// Path to the Linux kernel .config file
    #[arg(long = "kernel-config", value_name = "PATH")]
    pub kernel_config: PathBuf,

    /// Path to the Device Tree source file (.dts)
    #[arg(long = "device-tree", value_name = "PATH")]
    pub device_tree: PathBuf,

    /// Output path for the OpenVEX JSON report
    #[arg(long, short, value_name = "PATH", default_value = "bitvex-report.vex.json")]
    pub output: PathBuf,

    /// Author identifier for the VEX document
    #[arg(long, default_value = "BitVex <bitvex@automated>")]
    pub author: String,

    /// Enable verbose logging
    #[arg(long, short)]
    pub verbose: bool,
}
