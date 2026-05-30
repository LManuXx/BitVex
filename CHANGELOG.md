# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
