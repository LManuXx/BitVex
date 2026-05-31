//! Watch mode for continuous vulnerability monitoring.
//!
//! Monitors multiple Yocto projects for file changes and automatically
//! re-scans when SBOMs, kernel configs, or device trees are modified.

pub mod config;
pub mod scanner;
pub mod state;
pub mod watcher;

pub use config::WatchConfig;
pub use state::WatchState;
