//! SQLite state management for watch mode.
//!
//! Persists scan results and tracks CVE lifecycle across builds.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};
use tracing::{debug, info};

/// A scan record from the database.
#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub id: i64,
    pub project: String,
    pub timestamp: String,
    pub total_packages: usize,
    pub affected: usize,
    pub not_affected: usize,
}

/// A CVE record from a scan.
#[derive(Debug, Clone)]
pub struct CveRecord {
    pub vuln_id: String,
    pub package: String,
    pub purl: Option<String>,
    pub status: String,
    pub epss: Option<f64>,
    pub first_seen: String,
    pub last_seen: String,
}

/// SQLite state manager for watch mode.
pub struct WatchState {
    conn: Connection,
}

impl WatchState {
    /// Open or create the SQLite database.
    pub fn new(db_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create DB directory: {}", parent.display()))?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("Failed to open SQLite DB: {}", db_path.display()))?;

        let state = Self { conn };
        state.init_tables()?;

        info!("SQLite state DB opened at {}", db_path.display());
        Ok(state)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_packages INTEGER NOT NULL,
                affected INTEGER NOT NULL,
                not_affected INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                vuln_id TEXT NOT NULL,
                package TEXT NOT NULL,
                purl TEXT,
                status TEXT NOT NULL,
                epss REAL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_hashes (
                path TEXT PRIMARY KEY,
                hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cves_scan ON scan_cves(scan_id);
            CREATE INDEX IF NOT EXISTS idx_cves_vuln ON scan_cves(vuln_id);
            CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project);",
            )
            .context("Failed to create SQLite tables")?;

        Ok(())
    }

    /// Insert a new scan record and return its ID.
    pub fn insert_scan(
        &self,
        project: &str,
        total_packages: usize,
        affected: usize,
        not_affected: usize,
    ) -> Result<i64> {
        let timestamp = Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO scans (project, timestamp, total_packages, affected, not_affected) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![project, timestamp, total_packages as i64, affected as i64, not_affected as i64],
            )
            .context("Failed to insert scan")?;

        let scan_id = self.conn.last_insert_rowid();
        debug!("Inserted scan {} for project '{}'", scan_id, project);
        Ok(scan_id)
    }

    /// Insert a CVE record for a scan.
    pub fn insert_cve(
        &self,
        scan_id: i64,
        vuln_id: &str,
        package: &str,
        purl: Option<&str>,
        status: &str,
        epss: Option<f64>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Check if this CVE already exists for this project
        let existing_first_seen = self.get_first_seen(vuln_id, package);

        let first_seen = existing_first_seen.unwrap_or_else(|| now.clone());

        self.conn.execute(
            "INSERT INTO scan_cves (scan_id, vuln_id, package, purl, status, epss, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![scan_id, vuln_id, package, purl, status, epss, first_seen, now],
        ).context("Failed to insert CVE")?;

        Ok(())
    }

    /// Get the first_seen timestamp for a CVE on a package.
    fn get_first_seen(&self, vuln_id: &str, package: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT first_seen FROM scan_cves WHERE vuln_id = ?1 AND package = ?2 ORDER BY first_seen ASC LIMIT 1",
                params![vuln_id, package],
                |row| row.get(0),
            )
            .ok()
    }

    /// Get the latest scan for a project.
    pub fn get_last_scan(&self, project: &str) -> Result<Option<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, project, timestamp, total_packages, affected, not_affected FROM scans WHERE project = ?1 ORDER BY id DESC LIMIT 1",
        )?;

        let result = stmt
            .query_row(params![project], |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    project: row.get(1)?,
                    timestamp: row.get(2)?,
                    total_packages: row.get::<_, i64>(3)? as usize,
                    affected: row.get::<_, i64>(4)? as usize,
                    not_affected: row.get::<_, i64>(5)? as usize,
                })
            })
            .ok();

        Ok(result)
    }

    /// Get all CVEs for a specific scan.
    pub fn get_cves_for_scan(&self, scan_id: i64) -> Result<Vec<CveRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT vuln_id, package, purl, status, epss, first_seen, last_seen FROM scan_cves WHERE scan_id = ?1",
        )?;

        let cves = stmt
            .query_map(params![scan_id], |row| {
                Ok(CveRecord {
                    vuln_id: row.get(0)?,
                    package: row.get(1)?,
                    purl: row.get(2)?,
                    status: row.get(3)?,
                    epss: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(cves)
    }

    /// Get the last scan summary for all projects.
    pub fn get_all_project_status(&self) -> Result<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.project, s.timestamp, s.total_packages, s.affected, s.not_affected
             FROM scans s
             INNER JOIN (
                 SELECT project, MAX(id) as max_id FROM scans GROUP BY project
             ) latest ON s.id = latest.max_id
             ORDER BY s.project",
        )?;

        let records = stmt
            .query_map([], |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    project: row.get(1)?,
                    timestamp: row.get(2)?,
                    total_packages: row.get::<_, i64>(3)? as usize,
                    affected: row.get::<_, i64>(4)? as usize,
                    not_affected: row.get::<_, i64>(5)? as usize,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Get the stored hash for a file path.
    pub fn get_file_hash(&self, path: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT hash FROM file_hashes WHERE path = ?1",
                params![path],
                |row| row.get(0),
            )
            .ok()
    }

    /// Store or update a file hash.
    pub fn set_file_hash(&self, path: &str, hash: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO file_hashes (path, hash) VALUES (?1, ?2)",
            params![path, hash],
        )?;
        Ok(())
    }

    /// Detect new CVEs by comparing current scan with the previous one.
    pub fn detect_new_cves(&self, project: &str, current_scan_id: i64) -> Result<Vec<CveRecord>> {
        // Get the previous scan (before current)
        let prev_scan = self
            .conn
            .query_row(
                "SELECT id FROM scans WHERE project = ?1 AND id < ?2 ORDER BY id DESC LIMIT 1",
                params![project, current_scan_id],
                |row| row.get::<_, i64>(0),
            )
            .ok();

        let Some(prev_id) = prev_scan else {
            // First scan, all CVEs are "new"
            return self.get_cves_for_scan(current_scan_id);
        };

        // Get CVEs from previous scan (for future use)
        let _prev_cves: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT vuln_id FROM scan_cves WHERE scan_id = ?1 AND status = 'affected'",
            )?;
            stmt.query_map(params![prev_id], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?
        };

        // Get current affected CVEs that were not in previous scan
        let mut stmt = self.conn.prepare(
            "SELECT vuln_id, package, purl, status, epss, first_seen, last_seen
             FROM scan_cves
             WHERE scan_id = ?1 AND status = 'affected' AND vuln_id NOT IN (
                 SELECT vuln_id FROM scan_cves WHERE scan_id = ?2
             )",
        )?;

        let new_cves = stmt
            .query_map(params![current_scan_id, prev_id], |row| {
                Ok(CveRecord {
                    vuln_id: row.get(0)?,
                    package: row.get(1)?,
                    purl: row.get(2)?,
                    status: row.get(3)?,
                    epss: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(new_cves)
    }
}

/// Compute a simple hash of file contents for change detection.
pub fn compute_file_hash(path: &Path) -> Result<String> {
    let content = std::fs::read(path)
        .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;

    // Simple hash using std::hash
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    Ok(format!("{:016x}", hasher.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_init() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let state = WatchState::new(&db_path).unwrap();

        // Verify tables exist
        let count: i64 = state
            .conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_insert_and_retrieve_scan() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let state = WatchState::new(&db_path).unwrap();

        let scan_id = state.insert_scan("test-project", 100, 5, 95).unwrap();
        assert!(scan_id > 0);

        let scan = state.get_last_scan("test-project").unwrap().unwrap();
        assert_eq!(scan.project, "test-project");
        assert_eq!(scan.total_packages, 100);
        assert_eq!(scan.affected, 5);
    }

    #[test]
    fn test_insert_and_retrieve_cves() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let state = WatchState::new(&db_path).unwrap();

        let scan_id = state.insert_scan("proj", 10, 2, 8).unwrap();
        state
            .insert_cve(
                scan_id,
                "CVE-2024-0001",
                "openssl",
                Some("pkg:generic/openssl@3.0.13"),
                "affected",
                Some(0.05),
            )
            .unwrap();
        state
            .insert_cve(scan_id, "CVE-2024-0002", "curl", None, "not_affected", None)
            .unwrap();

        let cves = state.get_cves_for_scan(scan_id).unwrap();
        assert_eq!(cves.len(), 2);
        assert_eq!(cves[0].vuln_id, "CVE-2024-0001");
        assert_eq!(cves[1].vuln_id, "CVE-2024-0002");
    }

    #[test]
    fn test_detect_new_cves() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let state = WatchState::new(&db_path).unwrap();

        // First scan
        let scan1 = state.insert_scan("proj", 10, 1, 9).unwrap();
        state
            .insert_cve(scan1, "CVE-2024-0001", "openssl", None, "affected", None)
            .unwrap();

        // Second scan with new CVE
        let scan2 = state.insert_scan("proj", 10, 2, 8).unwrap();
        state
            .insert_cve(scan2, "CVE-2024-0001", "openssl", None, "affected", None)
            .unwrap();
        state
            .insert_cve(scan2, "CVE-2024-0002", "curl", None, "affected", None)
            .unwrap();

        let new_cves = state.detect_new_cves("proj", scan2).unwrap();
        assert_eq!(new_cves.len(), 1);
        assert_eq!(new_cves[0].vuln_id, "CVE-2024-0002");
    }

    #[test]
    fn test_file_hash() {
        let tmpdir = tempfile::tempdir().unwrap();
        let file_path = tmpdir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let hash1 = compute_file_hash(&file_path).unwrap();
        std::fs::write(&file_path, "hello world!").unwrap();
        let hash2 = compute_file_hash(&file_path).unwrap();

        assert_ne!(hash1, hash2);
    }
}
