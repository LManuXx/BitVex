use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use tracing::{debug, info};

use crate::osv::{OsvResult, OsvVuln};
use crate::vex::{VexStatement, VexStatus};

const JUSTIFICATION: &str = "vulnerable_code_not_in_execute_path";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeStatus {
    Enabled,
    Disabled,
    Other(String),
}

#[derive(Debug, Clone)]
pub struct DtsNode {
    pub _path: String,
    pub status: NodeStatus,
    pub compatible: Option<String>,
}

const DTB_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];

pub fn parse_device_tree(path: &Path) -> Result<Vec<DtsNode>> {
    let content = if is_dtb_file(path)? {
        info!("Detected DTB binary, decompiling with dtc...");
        decompile_dtb(path)?
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read device tree: {}", path.display()))?
    };

    parse_device_tree_content(&content)
}

fn is_dtb_file(path: &Path) -> Result<bool> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file: {}", path.display()))?;
    let mut magic = [0u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic == DTB_MAGIC),
        Err(_) => Ok(false),
    }
}

fn decompile_dtb(path: &Path) -> Result<String> {
    let output = std::process::Command::new("dtc")
        .args(["-I", "dtb", "-O", "dts", "-q"])
        .arg(path)
        .output()
        .context(
            "Failed to run 'dtc'. Install device-tree-compiler: \
             apt install device-tree-compiler (Debian/Ubuntu) or \
             apk add dtc (Alpine)",
        )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("dtc failed to decompile DTB: {}", stderr);
    }

    String::from_utf8(output.stdout).context("dtc output is not valid UTF-8")
}

fn parse_device_tree_content(content: &str) -> Result<Vec<DtsNode>> {
    let mut nodes = Vec::new();
    let mut current_path: Vec<String> = Vec::new();
    let mut brace_depth: usize = 0;
    let mut current_status: Option<NodeStatus> = None;
    let mut current_compatible: Option<String> = None;
    let mut in_omit_block: bool = false;

    let node_re = Regex::new(r"^(\s*)([\w,@.+-]+)\s*\{").unwrap();
    let status_re = Regex::new(r#"status\s*=\s*"([^"]+)""#).unwrap();
    let compatible_re = Regex::new(r#"compatible\s*=\s*"([^"]+)""#).unwrap();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with("/dts-v1/")
            || trimmed.is_empty()
        {
            continue;
        }

        if trimmed.starts_with("/omit-if-no-ref/") {
            in_omit_block = true;
            continue;
        }

        if trimmed.contains('{') && !trimmed.starts_with('#') {
            let opens = trimmed.matches('{').count();
            let closes = trimmed.matches('}').count();

            if in_omit_block {
                brace_depth += opens;
                brace_depth = brace_depth.saturating_sub(closes);
                if brace_depth == 0 {
                    in_omit_block = false;
                }
                continue;
            }

            if let Some(caps) = node_re.captures(trimmed) {
                let node_name = caps[2].to_string();
                if brace_depth <= current_path.len() {
                    current_path.push(node_name);
                    current_status = None;
                    current_compatible = None;
                }
            }

            brace_depth += opens;
            brace_depth = brace_depth.saturating_sub(closes);

            if let Some(caps) = status_re.captures(trimmed) {
                let status_str = &caps[1];
                current_status = Some(match status_str {
                    "okay" | "ok" => NodeStatus::Enabled,
                    "disabled" => NodeStatus::Disabled,
                    other => NodeStatus::Other(other.to_string()),
                });
            }

            if let Some(caps) = compatible_re.captures(trimmed) {
                current_compatible = Some(caps[1].to_string());
            }
        } else {
            if in_omit_block {
                if trimmed.contains('}') {
                    let closes = trimmed.matches('}').count();
                    brace_depth = brace_depth.saturating_sub(closes);
                    if brace_depth == 0 {
                        in_omit_block = false;
                    }
                }
                continue;
            }

            if let Some(caps) = status_re.captures(trimmed) {
                let status_str = &caps[1];
                current_status = Some(match status_str {
                    "okay" | "ok" => NodeStatus::Enabled,
                    "disabled" => NodeStatus::Disabled,
                    other => NodeStatus::Other(other.to_string()),
                });
            }

            if let Some(caps) = compatible_re.captures(trimmed) {
                current_compatible = Some(caps[1].to_string());
            }
        }

        if trimmed.contains('}') {
            let closes = trimmed.matches('}').count();
            for _ in 0..closes {
                if let Some(status) = current_status.take() {
                    let path_str = format!("/{}", current_path.join("/"));
                    nodes.push(DtsNode {
                        _path: path_str,
                        status,
                        compatible: current_compatible.take(),
                    });
                }

                if brace_depth > 0 {
                    brace_depth = brace_depth.saturating_sub(1);
                }
                if !current_path.is_empty() && brace_depth < current_path.len() {
                    current_path.pop();
                    current_status = None;
                    current_compatible = None;
                }
            }
        }
    }

    let disabled_count = nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Disabled)
        .count();
    info!(
        "Parsed {} DTS nodes ({} disabled)",
        nodes.len(),
        disabled_count
    );

    Ok(nodes)
}

pub fn filter_by_device_tree(
    results: &[OsvResult],
    dts_nodes: &[DtsNode],
) -> (Vec<VexStatement>, Vec<usize>) {
    let disabled_names: Vec<&str> = dts_nodes
        .iter()
        .filter(|n| n.status == NodeStatus::Disabled)
        .filter_map(|n| n.compatible.as_deref())
        .collect();

    let mut statements = Vec::new();
    let mut filtered_indices = Vec::new();

    for (i, result) in results.iter().enumerate() {
        let pkg_lower = result.package.name.to_lowercase();

        let is_disabled = disabled_names.iter().any(|compat| {
            let compat_lower = compat.to_lowercase();
            pkg_lower.contains(&compat_lower) || compat_lower.contains(&pkg_lower)
        });

        if is_disabled {
            filtered_indices.push(i);
            for vuln in &result.vulns {
                statements.push(build_statement(vuln, result));
            }
            debug!(
                "Filtered package '{}' (peripheral disabled in DTS)",
                result.package.name
            );
        }
    }

    (statements, filtered_indices)
}

fn build_statement(vuln: &OsvVuln, result: &OsvResult) -> VexStatement {
    let purl = result
        .package
        .purl
        .clone()
        .unwrap_or_else(|| format!("pkg:generic/{}", result.package.name));

    VexStatement {
        vulnerability_name: vuln.id.clone(),
        product_purl: purl,
        status: VexStatus::NotAffected,
        justification: Some(JUSTIFICATION.to_string()),
        impact_statement: Some(format!(
            "The peripheral associated with '{}' has status=disabled in the Device Tree.",
            result.package.name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dts_nodes() {
        let dts = r#"
/ {
    model = "Test Board";
    compatible = "test,board";

    chosen {};

    serial@1000 {
        compatible = "ns16550a";
        status = "okay";
    };

    wifi@2000 {
        compatible = "brcm,bcm4329-wifi";
        status = "disabled";
    };

    bluetooth@3000 {
        compatible = "brcm,bcm4329-bt";
        status = "disabled";
    };
};
"#;
        let nodes = parse_device_tree_content(dts).unwrap();
        let disabled: Vec<_> = nodes
            .iter()
            .filter(|n| n.status == NodeStatus::Disabled)
            .collect();
        assert_eq!(disabled.len(), 2);
    }

    #[test]
    fn test_dtb_magic_detection() {
        // DTB files start with magic bytes 0xd00dfeed
        let dtb_bytes = vec![0xd0, 0x0d, 0xfe, 0xed, 0x00, 0x00, 0x00, 0x00];
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmpfile.path(), &dtb_bytes).unwrap();
        assert!(is_dtb_file(tmpfile.path()).unwrap());

        // DTS files are text
        let dts_bytes = b"/dts-v1/;\n/ { model = \"test\"; };";
        let tmpfile2 = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmpfile2.path(), dts_bytes).unwrap();
        assert!(!is_dtb_file(tmpfile2.path()).unwrap());
    }

    #[test]
    fn test_parse_dts_with_omit_if_no_ref() {
        let dts = r#"
/ {
    /omit-if-no-ref/ {
        compatible = "some,device";
        status = "disabled";
    };

    uart@1000 {
        compatible = "ns16550a";
        status = "okay";
    };
};
"#;
        let nodes = parse_device_tree_content(dts).unwrap();
        // omit-if-no-ref should be skipped
        assert!(
            nodes
                .iter()
                .all(|n| n.compatible.as_deref() != Some("some,device"))
        );
    }
}
