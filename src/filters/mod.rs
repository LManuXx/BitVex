//! Hardware-aware CVE filtering.
//!
//! Filters CVEs based on actual hardware configuration to eliminate
//! false positives from the vulnerability scan.

pub mod device_tree;
pub mod kernel_config;
pub mod native;
pub mod rules;
