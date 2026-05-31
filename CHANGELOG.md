# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Watch mode with SQLite state tracking (`bitvex watch`)
- Project status command (`bitvex status`)
- bitvex-watch.toml multi-project configuration
- File watcher with inotify + debouncing
- New CVE detection by comparing with previous scan
- CI workflow: caching, multi-OS matrix (Linux/macOS/Windows), doc tests
- 12 new unit tests for EPSS, kernel config, DTS, SPDX, rules modules

### Fixed

- Code formatting across all source files (cargo fmt)

## [0.2.7] - 2026-05-30

### Added

- Concurrent alias fetching with `futures::join_all` for OSV API
- Progress bars for OSV and EPSS queries using `indicatif`
- Delta VEX subcommand: compare two VEX documents and track changes
- SARIF 2.1.0 output format (`--format sarif`) for GitHub Security tab
- Improved kernel config filter with known package-to-CONFIG mappings
- Automatic userspace package detection (glibc, bash, python skipped)
- Pipeline refactor: extracted scan logic to `src/pipeline.rs`
- Comprehensive rustdoc documentation on all public APIs

### Changed

- Version bumped to 0.2.7
- README updated with all v0.2.6 and v0.2.7 features

## [0.2.6] - 2026-05-30

### Added

- EPSS integration with online API and offline CSV download
- Alias resolution: GHSA/OSV IDs mapped to CVE-xxxx via OSV API
- U-Boot config support for bootloader CVE filtering
- CI/CD exit codes: --fail-on-any, --fail-on-high, --fail-on-critical
- DTB auto-decompile (detects binary DTB, runs dtc automatically)
- SPDX 3.0 version detection with warning
- /omit-if-no-ref/ DTS syntax support
- Multiple kernel config fragment support (--kernel-config accepts multiple paths)
- EPSS column in console output with CVE alias display
- download-epss-db subcommand for offline EPSS database
- Real iMX8MP test fixtures with EPSS-enabled integration tests

### Changed

- --kernel-config, --device-tree, --uboot-config are now optional
- EPSS client filters non-CVE IDs before querying API
- OSV client fetches vulnerability aliases for CVE resolution

## [0.2.5] - 2026-05-30

### Added

- **Rules Engine** — Custom filtering rules via `bitvex.toml` file
  - Match by CVE ID, glob pattern, package name, version
  - Define custom status, justification, and impact statement
  - Author override from rules file
- **Offline Mode** — Scan without internet using local OSV database
  - `--offline` flag to use local database
  - `--download-db` command to download/update database
  - Download profiles: `small` (29MB), `medium` (35MB), `big` (116MB), `complete` (822MB)
  - Interactive confirmation with size estimation
  - Progress bars during download
  - `--yes` / `-y` flag to skip confirmation prompts
- **SBOM Diff** — Compare two SBOMs and report changes
  - `bitvex diff --old <path> --new <path>` subcommand
  - Reports added, removed, and updated packages
  - Optional JSON output
- **Combined offline + download** — `--offline --download-db` in single command
- 11 new integration tests with real iMX8MP fixtures

### Changed

- Version bump to 2.5.0
- CLI now uses subcommands (`diff`, `download-db`) for non-scan operations
- OSV client refactored to support online/offline providers

## [0.1.0] - 2024-06-15

### Added

- Initial release by Manuel Neto Romero
- SPDX JSON SBOM parsing
- OSV API batch query integration (async, 100 packages per request)
- Native recipe filter (`-native` packages marked `not_affected`)
- Kernel `.config` cross-reference filter
- Device Tree (`.dts`) disabled peripheral filter
- OpenVEX v0.2.0 JSON-LD output generation
- Console summary with tabulated results
- CLI interface with `clap` (6 configurable flags)
- Full test suite (unit + integration with real iMX8MP fixtures)
- SSPL-1.0 license
