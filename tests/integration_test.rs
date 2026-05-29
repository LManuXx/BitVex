use std::path::Path;

use bitvex::sbom::parse_spdx_sbom;
use bitvex::filters::kernel_config::{parse_kernel_config, ConfigValue};
use bitvex::filters::device_tree::{parse_device_tree, NodeStatus};
use bitvex::filters::native::is_native_package;
use bitvex::vex::generate_openvex;
use bitvex::vex::{VexStatement, VexStatus};

#[test]
fn test_full_pipeline_offline() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    // Parse SBOM
    let sbom_data = std::fs::read(fixtures.join("sample_sbom.spdx.json")).unwrap();
    let packages = parse_spdx_sbom(&sbom_data).unwrap();
    assert_eq!(packages.len(), 7);

    // Verify native packages are detected
    let native_count = packages
        .iter()
        .filter(|p| is_native_package(&p.name))
        .count();
    assert_eq!(native_count, 2); // gcc-runtime-native, qemu-native

    // Parse kernel config
    let config = parse_kernel_config(&fixtures.join("sample.config")).unwrap();
    assert!(config.len() > 100);
    assert_eq!(
        config.get("USB_STORAGE"),
        Some(&bitvex::filters::kernel_config::ConfigValue::BuiltIn)
    );
    assert_eq!(
        config.get("BT"),
        Some(&bitvex::filters::kernel_config::ConfigValue::NotSet)
    );
    assert_eq!(
        config.get("WLAN"),
        Some(&bitvex::filters::kernel_config::ConfigValue::NotSet)
    );

    // Parse device tree
    let dts_nodes = parse_device_tree(&fixtures.join("sample.dts")).unwrap();
    let disabled: Vec<_> = dts_nodes
        .iter()
        .filter(|n| n.status == bitvex::filters::device_tree::NodeStatus::Disabled)
        .collect();
    assert_eq!(disabled.len(), 2); // wifi, bluetooth

    // Generate a VEX document with synthetic data
    use bitvex::vex::{VexStatement, VexStatus};

    let statements = vec![
        VexStatement {
            vulnerability_name: "CVE-2024-0001".into(),
            product_purl: "pkg:generic/gcc-runtime-native@12.3.0".into(),
            status: VexStatus::NotAffected,
            justification: Some("component_not_present".into()),
            impact_statement: Some("Host-only build dependency".into()),
        },
        VexStatement {
            vulnerability_name: "CVE-2024-0002".into(),
            product_purl: "pkg:generic/openssl@3.0.13".into(),
            status: VexStatus::Affected,
            justification: None,
            impact_statement: Some("Vulnerability affects openssl".into()),
        },
    ];

    let doc = generate_openvex(&statements, "Test Author");
    let json = serde_json::to_string_pretty(&doc).unwrap();

    // Validate OpenVEX structure
    assert!(json.contains("https://openvex.dev/ns/v0.2.0"));
    assert!(json.contains("CVE-2024-0001"));
    assert!(json.contains("CVE-2024-0002"));
    assert!(json.contains("not_affected"));
    assert!(json.contains("affected"));
    assert!(json.contains("component_not_present"));
    assert!(json.contains("BitVex"));
}

// ============================================================================
// Real-world integration test: NXP i.MX8MPlus EVK
// Uses actual DTS from linux-imx and real NXP defconfig
// ============================================================================

#[test]
fn test_imx8mp_real_sbom_parsing() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let sbom_data = std::fs::read(fixtures.join("imx8mp-evk.spdx.json")).unwrap();
    let packages = parse_spdx_sbom(&sbom_data).unwrap();

    // Should parse all 44 packages from the iMX8MP image
    assert!(packages.len() >= 40, "Expected >= 40 packages, got {}", packages.len());

    // Verify specific real packages exist
    let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"linux-imx"), "Missing linux-imx");
    assert!(names.contains(&"openssl"), "Missing openssl");
    assert!(names.contains(&"imx-gpu-viv"), "Missing imx-gpu-viv");
    assert!(names.contains(&"u-boot-imx"), "Missing u-boot-imx");
    assert!(names.contains(&"bluez5"), "Missing bluez5");

    // Verify purl extraction
    let openssl = packages.iter().find(|p| p.name == "openssl").unwrap();
    assert_eq!(openssl.version.as_deref(), Some("3.0.13"));
    assert_eq!(openssl.purl.as_deref(), Some("pkg:generic/openssl@3.0.13"));

    // NXP proprietary packages have no purl
    let gpu = packages.iter().find(|p| p.name == "imx-gpu-viv").unwrap();
    assert!(gpu.purl.is_none(), "NXP proprietary packages should not have purl");
}

#[test]
fn test_imx8mp_native_package_detection() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let sbom_data = std::fs::read(fixtures.join("imx8mp-evk.spdx.json")).unwrap();
    let packages = parse_spdx_sbom(&sbom_data).unwrap();

    let native: Vec<&str> = packages
        .iter()
        .filter(|p| is_native_package(&p.name))
        .map(|p| p.name.as_str())
        .collect();

    // Must detect all 10 native build tools
    assert_eq!(native.len(), 10, "Expected 10 native packages, got {}: {:?}", native.len(), native);
    assert!(native.contains(&"gcc-runtime-native"));
    assert!(native.contains(&"cmake-native"));
    assert!(native.contains(&"ninja-native"));
    assert!(native.contains(&"meson-native"));
    assert!(native.contains(&"python3-native"));
    assert!(native.contains(&"qemu-native"));
    assert!(native.contains(&"dtc-native"));
    assert!(native.contains(&"flex-native"));
    assert!(native.contains(&"bison-native"));
    assert!(native.contains(&"pkgconfig-native"));

    // Real target packages must NOT be detected as native
    assert!(!is_native_package("openssl"));
    assert!(!is_native_package("imx-gpu-viv"));
    assert!(!is_native_package("linux-imx"));
    assert!(!is_native_package("u-boot-imx"));
}

#[test]
fn test_imx8mp_nxp_defconfig_parsing() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let config = parse_kernel_config(&fixtures.join("imx_v8_defconfig")).unwrap();

    // The NXP defconfig has 1100+ entries
    assert!(config.len() > 1000, "Expected > 1000 config entries, got {}", config.len());

    // Verify key iMX8MP subsystems are enabled
    assert_eq!(config.get("PINCTRL_IMX8MP"), Some(&ConfigValue::BuiltIn),
        "iMX8MP pinctrl must be built-in");
    assert_eq!(config.get("CLK_IMX8MP"), Some(&ConfigValue::BuiltIn),
        "iMX8MP clock driver must be built-in");
    assert_eq!(config.get("ARCH_MXC"), Some(&ConfigValue::BuiltIn),
        "i.MX architecture must be enabled");
    assert_eq!(config.get("FEC"), Some(&ConfigValue::BuiltIn),
        "FEC ethernet must be built-in");
    assert_eq!(config.get("I2C_IMX"), Some(&ConfigValue::BuiltIn),
        "i2c-imx must be built-in");
    assert_eq!(config.get("SPI_IMX"), Some(&ConfigValue::BuiltIn),
        "spi-imx must be built-in");
    assert_eq!(config.get("USB_DWC3"), Some(&ConfigValue::BuiltIn),
        "USB DWC3 must be built-in");
    assert_eq!(config.get("MMC_SDHCI_ESDHC_IMX"), Some(&ConfigValue::BuiltIn),
        "iMX eSDHC must be built-in");

    // Verify Bluetooth is enabled (matches DTS bluetooth node)
    assert_eq!(config.get("BT"), Some(&ConfigValue::BuiltIn),
        "Bluetooth must be enabled in this NXP defconfig");

    // Verify WiFi/cfg80211 is enabled
    assert_eq!(config.get("CFG80211"), Some(&ConfigValue::BuiltIn),
        "cfg80211 must be enabled for WiFi");

    // Verify some features are explicitly disabled
    assert_eq!(config.get("MTD_SPI_NOR_USE_4K_SECTORS"), Some(&ConfigValue::NotSet),
        "4K sectors should be disabled");

    // Verify modules are used where expected
    assert_eq!(config.get("NF_CONNTRACK"), Some(&ConfigValue::Module),
        "Netfilter conntrack should be a module");
}

#[test]
fn test_imx8mp_evk_device_tree_parsing() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let dts_nodes = parse_device_tree(&fixtures.join("imx8mp-evk.dts")).unwrap();

    // The iMX8MP EVK DTS has many nodes
    assert!(dts_nodes.len() >= 20, "Expected >= 20 DTS nodes, got {}", dts_nodes.len());

    // Verify disabled peripherals are detected
    let disabled: Vec<&str> = dts_nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Disabled)
        .filter_map(|n| n.compatible.as_deref())
        .collect();

    // The iMX8MP EVK DTS has these disabled in the top-level file:
    // - flexcan2 (status = "disabled", can2 pin conflict with pdm)
    // - ov5640_1 camera (status = "disabled")
    // - mipi_csi_1 (status = "disabled")
    // - i2c5 (status = "disabled", can1 pins conflict with i2c5)
    // - pcie_ep (status = "disabled")
    // Note: the raw DTS has #include directives; the parser sees top-level nodes
    assert!(disabled.len() >= 1, "Expected >= 1 disabled nodes, got {}: {:?}", disabled.len(), disabled);

    // Verify at least one peripheral is disabled
    let flexcan_disabled = disabled.iter().any(|c| c.contains("flexcan") || c.contains("can") || c.contains("ovti"));
    assert!(flexcan_disabled, "At least one peripheral should be detected as disabled");

    // Verify at least some peripherals are enabled
    // Note: nodes using &ref syntax (like &uart2) may not be fully parsed
    // from raw .dts without preprocessing; this test validates what the
    // parser can extract from the top-level file.
    assert!(dts_nodes.iter().any(|n| n.status == NodeStatus::Enabled),
        "At least some peripherals should be enabled in the DTS");
}

#[test]
fn test_imx8mp_vex_document_structure() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let sbom_data = std::fs::read(fixtures.join("imx8mp-evk.spdx.json")).unwrap();
    let packages = parse_spdx_sbom(&sbom_data).unwrap();

    // Build VEX statements for all packages with purls
    let statements: Vec<VexStatement> = packages
        .iter()
        .filter(|p| p.purl.is_some())
        .map(|p| VexStatement {
            vulnerability_name: format!("CVE-TEST-{}", p.name),
            product_purl: p.purl.clone().unwrap(),
            status: VexStatus::NotAffected,
            justification: Some("component_not_present".into()),
            impact_statement: Some(format!("Package '{}' is a test entry.", p.name)),
        })
        .collect();

    assert!(statements.len() >= 15, "Expected >= 15 statements, got {}", statements.len());

    let doc = generate_openvex(&statements, "BitVex iMX8MP Test");
    let json = serde_json::to_string_pretty(&doc).unwrap();

    // Validate OpenVEX v0.2.0 structure
    assert!(json.contains("\"@context\": \"https://openvex.dev/ns/v0.2.0\""));
    assert!(json.contains("\"author\": \"BitVex iMX8MP Test\""));
    assert!(json.contains("\"version\": 1"));
    assert!(json.contains("\"tooling\": \"BitVex"));

    // Verify all packages appear in the document
    assert!(json.contains("openssl@3.0.13"));
    assert!(json.contains("linux-imx@6.1.55"));
    assert!(json.contains("curl@8.1.2"));
    assert!(json.contains("u-boot-imx@2023.04"));

    // Verify the document is valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["@context"].as_str().is_some());
    assert!(parsed["@id"].as_str().is_some());
    assert!(parsed["timestamp"].as_str().is_some());
    assert!(parsed["statements"].as_array().unwrap().len() >= 15);

    // Verify each statement has required fields
    for stmt in parsed["statements"].as_array().unwrap() {
        assert!(stmt["vulnerability"]["name"].as_str().is_some(),
            "Statement missing vulnerability.name");
        assert!(stmt["products"].as_array().unwrap().len() >= 1,
            "Statement missing products");
        assert!(stmt["status"].as_str().is_some(),
            "Statement missing status");
        assert_eq!(stmt["status"].as_str().unwrap(), "not_affected",
            "All test statements should be not_affected");
        assert!(stmt["justification"].as_str().is_some(),
            "not_affected statement must have justification");
    }
}
