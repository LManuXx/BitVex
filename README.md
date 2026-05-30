<div align="center">

# BitVex

**Automated CRA Compliance for Embedded Linux**

Generate spec-compliant OpenVEX reports from Yocto builds by filtering CVEs against your actual hardware configuration.

[![License: SSPL-1.0](https://img.shields.io/badge/License-SSPL--1.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](#)
[![OpenVEX](https://img.shields.io/badge/OpenVEX-v0.2.0-purple.svg)](https://openvex.dev/)
[![SPDX](https://img.shields.io/badge/SPDX-2.3-blue.svg)](https://spdx.dev/)
[![EPSS](https://img.shields.io/badge/EPSS-Integrated-yellow.svg)](https://www.first.org/epss/)

[Getting Started](#getting-started) ·
[Features](#features) ·
[CLI Reference](#cli-reference) ·
[Integration](#integration) ·
[Architecture](#architecture)

</div>

---

## The Problem

The EU Cyber Resilience Act (CRA) mandates vulnerability disclosure for connected devices. If you build embedded Linux products with Yocto, you face a critical challenge:

> **Your SBOM lists 200+ packages. A scanner flags 500 CVEs. How many actually affect your device?**

Most are false positives:

| False Positive Source | Why It Doesn't Apply |
|---|---|
| `gcc-native`, `cmake-native` | Host-only build tools, never deployed on target |
| `CONFIG_BT` drivers | Kernel compiled without Bluetooth support |
| WiFi chipset firmware | `status = "disabled"` in your Device Tree |

Manual triage of hundreds of CVEs per build is unsustainable. **BitVex automates it.**

## What BitVex Does

BitVex takes inputs from your Yocto build and produces an auditable VEX document:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  SBOM       │     │  Kernel      │     │  Device     │
│  (SPDX)     │     │  .config     │     │  Tree       │
└──────┬──────┘     └──────┬───────┘     └──────┬──────┘
       │                   │                    │
       └───────────────────┼────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   BitVex    │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │  OpenVEX /  │
                    │  SARIF      │
                    └─────────────┘
```

**Result:** A machine-readable document that tells scanners exactly which CVEs are real, which are mitigated by your hardware config, and why.

---

## Features

### Core Filters

| Filter | Input | Rule | OpenVEX Justification |
|---|---|---|---|
| **Native Recipes** | SBOM package names | Packages ending in `-native` are build host tools | `component_not_present` |
| **Kernel Config** | `.config` file | Drivers with `CONFIG_XXX` not set to `=y` or `=m` | `vulnerable_code_not_present` |
| **Device Tree** | `.dts` / `.dtb` | Peripherals with `status = "disabled"` | `vulnerable_code_not_in_execute_path` |
| **U-Boot Config** | U-Boot `.config` | Bootloader drivers not compiled | `vulnerable_code_not_present` |

### EPSS Integration

BitVex integrates FIRST.org's [Exploit Prediction Scoring System](https://www.first.org/epss/) to prioritize CVEs by real-world exploitability:

```
| CVE          | Package     | EPSS  | Percentile | Status   |
|--------------|-------------|-------|------------|----------|
| CVE-2021-3749| axios@0.21.0| 8.9%  | 92.7%      | affected |
| CVE-2021-23337| lodash@4.17| 4.3%  | 89.1%      | affected |
| CVE-2020-8203 | lodash@4.17| 2.5%  | 85.7%      | affected |
```

- Online mode: queries EPSS API in real-time
- Offline mode: download CSV database for air-gapped environments
- CI gating: `--fail-on-high` / `--fail-on-critical` exit codes
- Alias resolution: GHSA/OSV vulnerability IDs are automatically mapped to CVE-xxxx via OSV API for EPSS lookup

### Rules Engine

Define custom filtering rules in `bitvex.toml`:

```toml
[author]
name = "Mi Empresa <security@empresa.com>"

[[rules]]
name = "OpenSSL parcheado"
cve = "CVE-2024-12345"
package = "openssl"
status = "not_affected"
justification = "vulnerable_code_not_present"
impact_statement = "Parcheado manualmente en nuestra build"

[[rules]]
name = "WiFi deshabilitado"
cve_pattern = "CVE-2024-*"
package = "linux-firmware"
status = "not_affected"
justification = "component_not_present"
```

### Offline Mode

Download vulnerability databases and scan without internet — perfect for air-gapped environments:

```bash
# Download OSV database (~35 MB for Linux + Alpine + crates.io)
bitvex download-db --profile medium

# Download EPSS database (~250 MB)
bitvex download-epss-db

# Scan offline (no internet needed)
bitvex --offline --epss-offline --sbom ... --kernel-config ... --device-tree ...
```

### SBOM Diff

Compare two builds and see what changed:

```bash
bitvex diff --old v1.spdx.json --new v2.spdx.json
```

```
╔══════════════════════════════════════════════════════╗
║          BitVex - SBOM Diff Report                  ║
╠══════════════════════════════════════════════════════╣
║  Packages added:       5                            ║
║  Packages removed:     2                            ║
║  Packages updated:     12                           ║
╚══════════════════════════════════════════════════════╝
```

### Delta VEX

Compare two VEX documents to track changes over time:

```bash
bitvex delta --old report-v1.vex.json --new report-v2.vex.json
```

```
╔══════════════════════════════════════════════════════╗
║          BitVex - VEX Delta Report                  ║
╠══════════════════════════════════════════════════════╣
║  New CVEs:             3                            ║
║  Resolved CVEs:        1                            ║
║  Status changes:       2                            ║
╚══════════════════════════════════════════════════════╝
```

### Multi-Format Output

Export to OpenVEX (default) or SARIF for GitHub Security tab:

```bash
# OpenVEX (default)
bitvex --sbom ... --output report.vex.json

# SARIF for GitHub Security
bitvex --sbom ... --format sarif --output report.sarif.json
```

### Download Profiles

Choose your database size based on your needs:

| Profile | Ecosystems | Size | Use case |
|---|---|---|---|
| `small` | Linux | ~29 MB | Kernel-only devices |
| `medium` | Linux, Alpine, crates.io | ~35 MB | Typical embedded |
| `big` | + Debian, PyPI | ~116 MB | Full coverage |
| `complete` | All 10 ecosystems | ~822 MB | Maximum audit |

### CI/CD Integration

Exit codes for pipeline gating:

```bash
# Fail if any CVE is not mitigated
bitvex --sbom ... --fail-on-any

# Fail if any CVE has EPSS > 0.7 (high exploitability)
bitvex --sbom ... --epss --fail-on-high

# Fail if any CVE has EPSS > 0.9 (critical)
bitvex --sbom ... --epss --fail-on-critical
```

### DTB Auto-Decompile

BitVex automatically detects compiled Device Tree binaries and decompiles them:

```bash
# Works with both .dts and .dtb
bitvex --sbom ... --device-tree board.dtb
```

---

## Getting Started

### Prerequisites

- Rust 1.85+ (install via [rustup](https://rustup.rs/))
- Files from your Yocto build:
  - **Required:** SBOM in SPDX JSON format
  - **Optional:** Kernel `.config`, Device Tree (`.dts`/`.dtb`), U-Boot `.config`

### Install

```bash
git clone https://github.com/LManuXx/BitVex.git
cd BitVex
cargo install --path .
```

### Quick Start

```bash
# 1. Download vulnerability database (one time, ~35 MB)
bitvex download-db --profile medium

# 2. Scan your build
bitvex \
  --sbom build/tmp/deploy/images/rpi4/image-spdx.json \
  --kernel-config build/tmp/work/rpi4-linux/linux-raspberrypi/6.1/.config \
  --device-tree build/tmp/work/rpi4-linux/linux-raspberrypi/6.1/arch/arm64/boot/dts/broadcom/bcm2711-rpi-4-b.dts \
  --output rpi4-cra-report.vex.json \
  --author "Acme Devices <security@acme.com>"

# 3. With EPSS scoring
bitvex \
  --sbom build/image-spdx.json \
  --epss \
  --output report.vex.json

# 4. Scan offline (no internet needed)
bitvex \
  --offline \
  --sbom build/image-spdx.json \
  --kernel-config build/.config \
  --device-tree build/board.dts \
  --rules bitvex.toml

# 5. All inputs optional (scan SBOM only)
bitvex --sbom build/image-spdx.json --epss --output report.vex.json
```

### Output

```
╔══════════════════════════════════════════════════════╗
║          BitVex - CRA Compliance Report             ║
╠══════════════════════════════════════════════════════╣
║  Total packages analyzed:     142                    ║
║  Native packages filtered:     23                    ║
║  Kernel/U-Boot filtered:      12                    ║
║  DTS disabled filtered:         5                    ║
║  ─────────────────────────────────────              ║
║  CVEs marked not_affected:     40                    ║
║  CVEs marked fixed:             0                    ║
║  Real CVEs to address:         12                    ║
║  ─────────────────────────────────────              ║
║  EPSS high risk (>0.7):        2                    ║
║  EPSS critical (>0.9):         0                    ║
╚══════════════════════════════════════════════════════╝
```

---

## CLI Reference

### Scan Mode (default)

```
bitvex [OPTIONS] --sbom <PATH>

Options:
      --sbom <PATH>              SBOM in SPDX JSON format (required)
      --kernel-config <PATH>     Linux kernel .config (optional, multiple)
      --uboot-config <PATH>      U-Boot .config (optional)
      --device-tree <PATH>       Device Tree .dts/.dtb (optional)
  -o, --output <PATH>            Output file [default: bitvex-report.vex.json]
      --format <FORMAT>          Output format: openvex | sarif
      --author <STRING>          VEX document author
      --rules <PATH>             bitvex.toml rules file
      --offline                  Use offline OSV database
      --download-db              Download DB before scanning
      --profile <PROFILE>        Download profile (small/medium/big/complete)
      --epss                     Enable EPSS scoring
      --epss-offline             Use offline EPSS database
      --download-epss-db         Download EPSS database
      --epss-threshold <FLOAT>   EPSS low_priority threshold [default: 0.0]
      --fail-on-any              Exit 1 if any CVE affected
      --fail-on-high             Exit 1 if EPSS > 0.7
      --fail-on-critical         Exit 1 if EPSS > 0.9
  -y, --yes                      Skip confirmation prompts
  -v, --verbose                  Debug logging
```

### Diff Mode

```bash
bitvex diff --old <PATH> --new <PATH> [--output <PATH>]
```

### Delta VEX

```bash
bitvex delta --old <PATH> --new <PATH> [--output <PATH>]
```

### Download Database

```bash
bitvex download-db [--profile <PROFILE>] [--ecosystems <LIST>] [-y]
bitvex download-epss-db [--db-path <PATH>] [-y]
```

---

## Integration

### CI/CD Pipeline (GitHub Actions)

```yaml
- name: Download OSV Database
  run: bitvex download-db --profile medium -y

- name: Generate VEX Report
  run: |
    bitvex \
      --offline \
      --sbom build/image-spdx.json \
      --kernel-config build/.config \
      --device-tree build/board.dts \
      --format sarif \
      --output results.sarif.json \
      --author "${{ github.repository_owner }} <ci@${{ github.repository_owner }}.com>"

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif.json

- name: Upload VEX Artifact
  uses: actions/upload-artifact@v4
  with:
    name: vex-report
    path: results.sarif.json
```

### Yocto Integration

Add BitVex to your Yocto build as a post-build step in `local.conf`:

```bitbake
# Generate VEX report after image build
IMAGE_POSTPROCESS_COMMAND += "generate_vex_report; "

generate_vex_report() {
    bitvex \
        --offline \
        --sbom ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.spdx.json \
        --kernel-config ${STAGING_KERNEL_BUILDDIR}/.config \
        --device-tree ${STAGING_KERNEL_BUILDDIR}/arch/${ARCH}/boot/dts/*.dts \
        --output ${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.vex.json
}
```

### Input Format Requirements

<details>
<summary><strong>SBOM (SPDX 2.2 / 2.3 JSON)</strong></summary>

Produced by Yocto's `meta-spdxscanner` or tools like [syft](https://github.com/anchore/syft). Required fields per package:
- `name` — package identifier
- `versionInfo` — version string
- `externalRefs` — optional `purl` (Package URL)

SPDX 3.0 is detected with a warning (full support planned).

</details>

<details>
<summary><strong>Kernel .config</strong></summary>

Standard Linux kernel configuration. Located at `${STAGING_KERNEL_BUILDDIR}/.config` in a Yocto build. Supports multiple config fragments via `--kernel-config`.

</details>

<details>
<summary><strong>Device Tree (.dts / .dtb)</strong></summary>

Source format (`.dts`) or compiled binary (`.dtb`). BitVex auto-detects DTB and decompiles using `dtc`. Supports modern DTS syntax including `/omit-if-no-ref/` blocks. To manually decompile:

```bash
dtc -I dtb -O dts -o board.dts board.dtb
```

In Yocto, the preprocessed DTS is typically in `${STAGING_KERNEL_BUILDDIR}/arch/${ARCH}/boot/dts/`.

</details>

<details>
<summary><strong>U-Boot .config</strong></summary>

Same format as kernel `.config`. Located in the U-Boot build directory.

</details>

---

## Architecture

```
src/
├── main.rs              CLI dispatch
├── lib.rs               Public API exports
├── pipeline.rs          Scan pipeline orchestration
├── cli.rs               CLI args + subcommands (clap)
├── sbom/
│   ├── spdx.rs          SPDX JSON parser (v2.2/v2.3)
│   └── diff.rs          SBOM diff engine
├── osv/
│   ├── client.rs        Async OSV API client (concurrent alias fetching)
│   ├── offline.rs       Offline OSV provider
│   └── db.rs            DB download with profiles + progress
├── epss/
│   ├── client.rs        EPSS API client (online)
│   └── offline.rs       EPSS CSV parser (offline)
├── filters/
│   ├── native.rs        Host-only recipe filter
│   ├── kernel_config.rs .config cross-reference (known mappings + heuristics)
│   ├── device_tree.rs   DTS/DTB status cross-reference
│   └── rules.rs         Custom rules engine
├── rules/
│   └── mod.rs           bitvex.toml parser + rule matching
├── vex/
│   ├── openvex.rs       OpenVEX v0.2.0 generator
│   └── delta.rs         VEX delta comparison
└── output/
    ├── console.rs       Console summary formatter (with progress bars)
    └── sarif.rs         SARIF 2.1.0 generator
```

---

## Development

```bash
cargo build              # Compile
cargo test               # Run 48 tests (37 unit + 11 integration)
cargo clippy             # Lint (0 warnings)
cargo fmt                # Format
```

---

## Security Model

BitVex follows the principle of least privilege:

- **No credentials required** — OSV and EPSS APIs are free and anonymous
- **Minimal data sent** — only package names/versions transmitted to OSV/EPSS
- **Offline mode** — download DBs once, scan without internet
- **Local processing** — all filtering happens on your machine
- **Deterministic output** — same inputs produce the same VEX document

---

## License

This project is licensed under the [Server Side Public License (SSPL-1.0)](LICENSE).

**What this means:**
- You can use, modify, and distribute BitVex freely for internal/non-commercial purposes
- If you offer BitVex as a service (SaaS), you must make your entire service stack open source under SSPL-1.0
- For commercial licensing or OEM integration, contact the author

**Author:** Manuel Neto Romero

---

## Acknowledgments

- [OpenVEX](https://openvex.dev/) — VEX specification
- [OSV](https://osv.dev/) — vulnerability database
- [EPSS](https://www.first.org/epss/) — exploit prediction scoring
- [CISA](https://www.cisa.gov/) — VEX minimum requirements
- [Yocto Project](https://www.yoctoproject.org/) — embedded Linux build system
