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
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use bitvex::sbom::parse_spdx_sbom;
//!
//! let data = std::fs::read("path/to/spdx.json").unwrap();
//! let packages = parse_spdx_sbom(&data).unwrap();
//! println!("Found {} packages", packages.len());
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
