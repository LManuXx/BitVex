# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
