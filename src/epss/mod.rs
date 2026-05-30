//! EPSS (Exploit Prediction Scoring System) integration.
//!
//! Provides clients for querying the [EPSS API](https://www.first.org/epss/)
//! to score CVE exploitability, with both online and offline support.

pub mod client;
pub mod offline;

pub use client::EpssClient;
pub use offline::OfflineEpssProvider;

/// EPSS score for a CVE vulnerability.
///
/// EPSS estimates the probability (0.0-1.0) that a vulnerability will be
/// exploited in the wild within the next 30 days. The percentile indicates
/// how this CVE compares to all other CVEs.
#[derive(Debug, Clone)]
pub struct EpssScore {
    /// CVE identifier (e.g., "CVE-2024-12345").
    pub cve: String,
    /// Exploit probability (0.0 to 1.0). Higher = more likely to be exploited.
    pub epss: f64,
    /// Percentile (0.0 to 1.0). 0.99 = top 1% most likely to be exploited.
    pub percentile: f64,
}
