//! # BitVex
//!
//! Automated CRA (Cyber Resilience Act) compliance tool for embedded Linux.
//!
//! BitVex generates spec-compliant OpenVEX reports from Yocto build artifacts
//! by filtering CVEs against actual hardware configuration.
//!
//! ## Features
//!
//! - **Hardware-aware CVE filtering** — kernel config, device tree, U-Boot filters
//! - **EPSS integration** — exploit prediction scoring from FIRST.org
//! - **Rules engine** — custom filtering via `bitvex.toml`
//! - **Offline mode** — scan without internet using local databases
//! - **Multi-format output** — OpenVEX JSON-LD and SARIF 2.1.0
//! - **Watch mode** — continuous monitoring with file change detection
//!
//! ## Quick Start
//!
//! The primary way to use BitVex is as a CLI tool:
//!
//! ```bash
//! # One-time scan
//! bitvex --sbom path/to/spdx.json --kernel-config path/to/.config \
//!        --device-tree path/to/board.dts --output report.vex.json
//!
//! # Continuous monitoring
//! bitvex watch --config bitvex-watch.toml
//! ```
//!
//! For programmatic use, the library exposes the core parsing and filtering
//! functions:
//!
//! ```rust,no_run
//! use bitvex::sbom::parse_spdx_sbom;
//! use bitvex::filters::kernel_config::parse_kernel_config;
//!
//! // Parse SBOM
//! let sbom_data = std::fs::read("path/to/spdx.json").unwrap();
//! let packages = parse_spdx_sbom(&sbom_data).unwrap();
//! println!("Found {} packages", packages.len());
//!
//! // Parse kernel config
//! let config = parse_kernel_config(std::path::Path::new("path/to/.config")).unwrap();
//! println!("Loaded {} config entries", config.len());
//! ```

pub mod cli;
pub mod epss;
pub mod filters;
pub mod osv;
pub mod output;
pub mod pipeline;
pub mod rules;
pub mod sbom;
pub mod vex;
pub mod watch;
