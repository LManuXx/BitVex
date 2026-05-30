//! VEX document generation and comparison.
//!
//! Provides OpenVEX v0.2.0 document generation and Delta VEX comparison
//! for tracking vulnerability status changes over time.

pub mod delta;
pub mod openvex;

pub use openvex::{VexStatement, VexStatus, generate_openvex};
