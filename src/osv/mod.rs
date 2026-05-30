//! OSV (Open Source Vulnerabilities) API client.
//!
//! Provides an async client for querying the [OSV API](https://osv.dev/)
//! with support for batch queries and concurrent alias resolution.

pub mod client;
pub mod db;
pub mod offline;

pub use client::{OsvClient, OsvResult, OsvVuln};
