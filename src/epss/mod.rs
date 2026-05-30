pub mod client;
pub mod offline;

pub use client::EpssClient;
pub use offline::OfflineEpssProvider;

#[derive(Debug, Clone)]
pub struct EpssScore {
    pub cve: String,
    pub epss: f64,
    pub percentile: f64,
}
