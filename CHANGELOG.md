# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-05-30

### Added

- **SPDX 3.0 support** — full parsing of SPDX 3.0 JSON-LD SBOMs
- **SPDX version auto-detection** — automatically detects SPDX 2.2/2.3/3.0
- **Watch mode** — `bitvex watch` for continuous vulnerability monitoring
- **Project status** — `bitvex status` to view monitored projects
- **SQLite state tracking** — CVE lifecycle tracking across builds
- **bitvex-watch.toml** — multi-project configuration format
- **File watcher** — inotify-based with debouncing (Linux)
- **New CVE detection** — compares with previous scan in SQLite
- CI workflow: multi-OS matrix (Linux/macOS/Windows), cargo caching, doc tests
- 14 new unit tests + 5 new integration tests for SPDX 3.0

### Changed

- SPDX parser split into `spdx2.rs` and `spdx3.rs` modules
- Version bumped to 0.3.0

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
- README updated with all v0.2.6 and v0.2.7 features documented

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

- Rules engine with `bitvex.toml` custom filtering
- Offline mode with downloadable OSV database
- Download profiles: small (29MB), medium (35MB), big (116MB), complete (822MB)
- SBOM diff: compare two builds
- Progress bars during downloads
- Interactive confirmation prompts
- SSPL-1.0 license

## [0.1.0] - 2026-05-30

### Added

- Initial release
- SPDX JSON SBOM parsing (v2.2/v2.3)
- OSV API batch query integration (async, 100 packages per request)
- Native recipe filter (`-native` packages marked `not_affected`)
- Kernel `.config` cross-reference filter
- Device Tree (`.dts`) disabled peripheral filter
- OpenVEX v0.2.0 JSON-LD output generation
- Console summary with tabulated results
- CLI interface with `clap` (6 configurable flags)
- Full test suite (unit + integration with real iMX8MP fixtures)
