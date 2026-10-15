//! Resolve an AMI to the build that produced it.

use crate::error::Result;
use aws_sdk_ec2::types::ArchitectureValues;
use aws_sdk_ec2::Client as Ec2Client;
use regex::Regex;
use serde::{Deserialize, Serialize};
use snafu::{ensure_whatever, whatever, OptionExt, ResultExt};
use std::sync::LazyLock;

const ROOT_DEVICE: &str = "/dev/xvda";
const DATA_DEVICE: &str = "/dev/xvdb";

/// Architectures supported by Bottlerocket builds, using their artifact names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

impl Architecture {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "x86_64" => Some(Self::X86_64),
            "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    fn from_ec2(arch: &ArchitectureValues) -> Result<Self> {
        match arch {
            ArchitectureValues::X8664 => Ok(Self::X86_64),
            ArchitectureValues::Arm64 => Ok(Self::Aarch64),
            _ => {
                whatever!("unsupported EC2 architecture '{}'", arch.as_str());
            }
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        })
    }
}

/// Matches the default AMI name `<name>-<variant>-<arch>-v<version>-<build_id>` and the
/// snapshot description `<name>-<variant>-<arch>-<version>-<build_id>.img`.
static NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<name>[A-Za-z0-9_]+)-(?P<variant>[A-Za-z0-9_.-]+)-(?P<arch>x86_64|aarch64)-v?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)-(?P<build_id>[0-9a-f]{8,40}(?:-dirty)?)(?:\.img)?$",
    )
    .expect("valid regex")
});

/// Build identity encoded in an AMI or snapshot name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildName {
    pub name: String,
    pub variant: String,
    pub arch: Architecture,
    pub version: String,
    pub build_id: String,
}

impl BuildName {
    /// Parse a name produced by the default Bottlerocket naming scheme.
    pub fn parse(s: &str) -> Option<Self> {
        let caps = NAME_RE.captures(s.trim())?;
        Some(Self {
            name: caps["name"].to_string(),
            variant: caps["variant"].to_string(),
            arch: Architecture::parse(&caps["arch"])?,
            version: caps["version"].to_string(),
            build_id: caps["build_id"].to_string(),
        })
    }

    pub fn is_dirty(&self) -> bool {
        self.build_id.ends_with("-dirty")
    }

    /// File name prefix used for the build's image artifacts.
    pub fn filename_prefix(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}",
            self.name, self.variant, self.arch, self.version, self.build_id
        )
    }
}

/// Everything known about an AMI that is needed to reproduce it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmiInfo {
    pub ami_id: String,
    pub ami_name: String,
    pub name: String,
    pub variant: String,
    pub arch: Architecture,
    pub version: String,
    pub build_id: String,
    pub filename_prefix: String,
    pub root_snapshot: String,
    pub data_snapshot: Option<String>,
    pub owner: String,
    pub owned_by_caller: bool,
}

/// Find the snapshot backing `device` in the image's block device mappings.
fn snapshot_for(image: &aws_sdk_ec2::types::Image, device: &str) -> Option<String> {
    image
        .block_device_mappings()
        .iter()
        .find(|bdm| bdm.device_name() == Some(device))
        .and_then(|bdm| bdm.ebs())
        .and_then(|ebs| ebs.snapshot_id())
        .map(String::from)
}

/// The root and optional data snapshots of the standard Bottlerocket device layout.
fn snapshots(image: &aws_sdk_ec2::types::Image) -> Result<(String, Option<String>)> {
    let devices: Vec<_> = image
        .block_device_mappings()
        .iter()
        .map(|bdm| bdm.device_name().unwrap_or("<missing>"))
        .collect();
    ensure_whatever!(
        image.root_device_name() == Some(ROOT_DEVICE),
        "unsupported AMI root device '{}'; expected {ROOT_DEVICE} (optional data device \
         {DATA_DEVICE}); observed devices: {}",
        image.root_device_name().unwrap_or("<missing>"),
        devices.join(", ")
    );
    for (i, bdm) in image.block_device_mappings().iter().enumerate() {
        let device = bdm.device_name().unwrap_or("<missing>");
        ensure_whatever!(
            !devices[..i].contains(&device),
            "AMI has duplicate mappings for {device}"
        );
        if bdm.ebs().is_some() {
            ensure_whatever!(
                matches!(device, ROOT_DEVICE | DATA_DEVICE),
                "unsupported AMI EBS device '{device}'; expected {ROOT_DEVICE} and optional \
                 {DATA_DEVICE}; observed devices: {}",
                devices.join(", ")
            );
        }
        if matches!(device, ROOT_DEVICE | DATA_DEVICE) {
            ensure_whatever!(
                bdm.ebs().and_then(|ebs| ebs.snapshot_id()).is_some(),
                "AMI device {device} has no snapshot"
            );
        }
    }
    let root = snapshot_for(image, ROOT_DEVICE)
        .whatever_context(format!("AMI has no root snapshot at {ROOT_DEVICE}"))?;
    Ok((root, snapshot_for(image, DATA_DEVICE)))
}

/// Return the description of a snapshot.
async fn snapshot_description(ec2: &Ec2Client, snapshot_id: &str) -> Result<Option<String>> {
    let response = ec2
        .describe_snapshots()
        .snapshot_ids(snapshot_id)
        .send()
        .await
        .whatever_context(format!("failed to describe snapshot {snapshot_id}"))?;
    Ok(response
        .snapshots()
        .first()
        .and_then(|s| s.description())
        .map(String::from))
}

/// Match the build identity and explain why it cannot be used for reproduction.
fn resolve_build_name(
    ami_id: &str,
    ami_name: &str,
    description: Option<&str>,
    arch: Architecture,
) -> Result<BuildName> {
    let (parsed, source, matched_name) = match BuildName::parse(ami_name) {
        Some(parsed) => (parsed, "AMI name", ami_name),
        None => {
            match description.and_then(|name| BuildName::parse(name).map(|parsed| (parsed, name))) {
                Some((parsed, name)) => (parsed, "root snapshot description", name),
                None => {
                    whatever!(
                        "could not determine the build for AMI {ami_id}: neither AMI name \
                     '{ami_name}' nor root snapshot description '{}' matches the expected format \
                     '<name>-<variant>-<arch>-v<version>-<build_id>' (AMI) or \
                     '<name>-<variant>-<arch>-<version>-<build_id>.img' (snapshot). \
                     Architecture must be x86_64 or aarch64; version must be major.minor.patch \
                     with an optional prerelease; build ID must be 8-40 lowercase hexadecimal \
                     characters, optionally followed by '-dirty'",
                        description.unwrap_or("<missing>")
                    );
                }
            }
        }
    };

    ensure_whatever!(
        !parsed.is_dirty(),
        "cannot reproduce AMI {ami_id}: matched {source} '{matched_name}', but build ID '{}' \
         ends with '-dirty', indicating uncommitted source changes. Checking out commit '{}' \
         alone cannot reproduce those changes; use an AMI built from a clean working tree",
        parsed.build_id,
        parsed.build_id.trim_end_matches("-dirty")
    );
    ensure_whatever!(
        parsed.arch == arch,
        "cannot reproduce AMI {ami_id}: EC2 architecture '{arch}' does not match architecture \
         '{}' parsed from {source} '{matched_name}'",
        parsed.arch
    );
    Ok(parsed)
}

/// Look up the AMI and work out which build produced it.
pub async fn resolve(ec2: &Ec2Client, caller_account: &str, ami_id: &str) -> Result<AmiInfo> {
    let response = ec2
        .describe_images()
        .image_ids(ami_id)
        .send()
        .await
        .whatever_context(format!("failed to describe AMI {ami_id}"))?;
    let image = response
        .images()
        .first()
        .whatever_context(format!("AMI {ami_id} not found in this region"))?;

    let ami_name = image.name().unwrap_or_default().to_string();
    let owner = image.owner_id().unwrap_or_default().to_string();
    let ec2_arch = image
        .architecture()
        .whatever_context("AMI has no architecture")?;
    let arch = Architecture::from_ec2(ec2_arch)?;

    let (root_snapshot, data_snapshot) = snapshots(image)?;

    let description = if BuildName::parse(&ami_name).is_none() {
        snapshot_description(ec2, &root_snapshot).await?
    } else {
        None
    };
    let parsed = resolve_build_name(ami_id, &ami_name, description.as_deref(), arch)?;

    Ok(AmiInfo {
        ami_id: ami_id.to_string(),
        ami_name,
        filename_prefix: parsed.filename_prefix(),
        name: parsed.name,
        variant: parsed.variant,
        arch,
        version: parsed.version,
        build_id: parsed.build_id,
        root_snapshot,
        data_snapshot,
        owned_by_caller: owner == caller_account,
        owner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ami_name() {
        let n =
            BuildName::parse("bottlerocket-aws-k8s-1.32-nvidia-x86_64-v1.40.0-a1b2c3d4").unwrap();
        assert_eq!(n.name, "bottlerocket");
        assert_eq!(n.variant, "aws-k8s-1.32-nvidia");
        assert_eq!(n.arch, Architecture::X86_64);
        assert_eq!(n.version, "1.40.0");
        assert_eq!(n.build_id, "a1b2c3d4");
        assert!(!n.is_dirty());
        assert_eq!(
            n.filename_prefix(),
            "bottlerocket-aws-k8s-1.32-nvidia-x86_64-1.40.0-a1b2c3d4"
        );
    }

    #[test]
    fn parses_snapshot_description() {
        let n = BuildName::parse("bottlerocket-aws-dev-aarch64-1.2.3-0123abcd.img").unwrap();
        assert_eq!(n.variant, "aws-dev");
        assert_eq!(n.arch, Architecture::Aarch64);
        assert_eq!(n.version, "1.2.3");
        assert_eq!(n.build_id, "0123abcd");
    }

    #[test]
    fn parses_dirty_name() {
        let n = BuildName::parse("bottlerocket-aws-ecs-2-x86_64-v1.2.3-0123abcd-dirty").unwrap();
        assert_eq!(n.variant, "aws-ecs-2");
        assert_eq!(n.build_id, "0123abcd-dirty");
        assert!(n.is_dirty());
    }

    #[test]
    fn parses_prerelease_version() {
        let n = BuildName::parse("bottlerocket-aws-dev-x86_64-v1.2.3-rc.1-0123abcd").unwrap();
        assert_eq!(n.version, "1.2.3-rc.1");
        assert_eq!(n.build_id, "0123abcd");
    }

    #[test]
    fn rejects_custom_names() {
        assert!(BuildName::parse("my-custom-ami").is_none());
        assert!(BuildName::parse("bottlerocket-aws-dev-riscv64-v1.2.3-0123abcd").is_none());
        assert!(BuildName::parse("bottlerocket-aws-dev-x86_64-v1.2.3-XYZ").is_none());
        assert!(BuildName::parse("").is_none());
    }

    #[test]
    fn maps_arch() {
        assert_eq!(
            Architecture::from_ec2(&ArchitectureValues::Arm64).unwrap(),
            Architecture::Aarch64
        );
        assert_eq!(
            Architecture::from_ec2(&ArchitectureValues::X8664).unwrap(),
            Architecture::X86_64
        );
        for name in ["i386", "x86_64_mac", "arm64_mac", "unknown"] {
            assert!(Architecture::from_ec2(&ArchitectureValues::from(name)).is_err());
        }
    }

    #[test]
    fn architecture_preserves_artifact_and_json_names() {
        for (arch, name) in [
            (Architecture::X86_64, "x86_64"),
            (Architecture::Aarch64, "aarch64"),
        ] {
            assert_eq!(arch.to_string(), name);
            assert_eq!(Architecture::parse(name), Some(arch));
            let json = serde_json::to_string(&arch).unwrap();
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(serde_json::from_str::<Architecture>(&json).unwrap(), arch);
        }
        assert!(serde_json::from_str::<Architecture>("\"arm64\"").is_err());
    }

    fn image(root: Option<&str>, mappings: &[(&str, Option<&str>)]) -> aws_sdk_ec2::types::Image {
        use aws_sdk_ec2::types::{BlockDeviceMapping, EbsBlockDevice};
        aws_sdk_ec2::types::Image::builder()
            .set_root_device_name(root.map(String::from))
            .set_block_device_mappings(Some(
                mappings
                    .iter()
                    .map(|(device, snapshot)| {
                        BlockDeviceMapping::builder()
                            .device_name(*device)
                            .ebs(
                                EbsBlockDevice::builder()
                                    .set_snapshot_id(snapshot.map(String::from))
                                    .build(),
                            )
                            .build()
                    })
                    .collect(),
            ))
            .build()
    }

    #[test]
    fn resolves_standard_snapshot_layouts() {
        let root_only = image(Some(ROOT_DEVICE), &[(ROOT_DEVICE, Some("snap-root"))]);
        assert_eq!(snapshots(&root_only).unwrap(), ("snap-root".into(), None));
        let both = image(
            Some(ROOT_DEVICE),
            &[
                (DATA_DEVICE, Some("snap-data")),
                (ROOT_DEVICE, Some("snap-root")),
            ],
        );
        assert_eq!(
            snapshots(&both).unwrap(),
            ("snap-root".into(), Some("snap-data".into()))
        );
    }

    #[test]
    fn rejects_unsupported_snapshot_layouts() {
        for root in [None, Some("/dev/sda")] {
            let error = snapshots(&image(root, &[(ROOT_DEVICE, Some("snap-root"))])).unwrap_err();
            assert!(error.to_string().contains("unsupported AMI root device"));
        }
        let renamed_data = image(
            Some(ROOT_DEVICE),
            &[
                (ROOT_DEVICE, Some("snap-root")),
                ("/dev/sdb", Some("snap-data")),
            ],
        );
        let error = snapshots(&renamed_data).unwrap_err().to_string();
        assert!(error.contains("unsupported AMI EBS device '/dev/sdb'"));
        assert!(error.contains("observed devices: /dev/xvda, /dev/sdb"));
        assert!(snapshots(&image(Some(ROOT_DEVICE), &[])).is_err());
        for device in [ROOT_DEVICE, DATA_DEVICE] {
            let missing = image(Some(ROOT_DEVICE), &[(device, None)]);
            assert!(snapshots(&missing)
                .unwrap_err()
                .to_string()
                .contains(&format!("AMI device {device} has no snapshot")));
        }
        let duplicate = image(
            Some(ROOT_DEVICE),
            &[(ROOT_DEVICE, Some("snap-1")), (ROOT_DEVICE, Some("snap-2"))],
        );
        assert!(snapshots(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate mappings"));
    }

    #[test]
    fn dirty_build_error_explains_matched_name_and_remedy() {
        let name = "bottlerocket-aws-dev-x86_64-v1.2.3-0123abcd-dirty";
        let error = resolve_build_name("ami-test", name, None, Architecture::X86_64).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&format!("matched AMI name '{name}'")));
        assert!(message.contains("build ID '0123abcd-dirty'"));
        assert!(message.contains("uncommitted source changes"));
        assert!(message.contains("Checking out commit '0123abcd' alone"));
        assert!(message.contains("use an AMI built from a clean working tree"));
    }

    #[test]
    fn architecture_error_identifies_snapshot_match() {
        let description = "bottlerocket-aws-dev-aarch64-1.2.3-0123abcd.img";
        let error = resolve_build_name(
            "ami-test",
            "custom-ami",
            Some(description),
            Architecture::X86_64,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("AMI ami-test"));
        assert!(message.contains("EC2 architecture 'x86_64'"));
        assert!(message.contains("architecture 'aarch64'"));
        assert!(message.contains(&format!("root snapshot description '{description}'")));
    }

    #[test]
    fn unmatched_names_error_explains_expected_format() {
        let error = resolve_build_name(
            "ami-test",
            "custom-ami",
            Some("custom-snapshot"),
            Architecture::X86_64,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("AMI ami-test"));
        assert!(message.contains("AMI name 'custom-ami'"));
        assert!(message.contains("root snapshot description 'custom-snapshot'"));
        assert!(message.contains("<name>-<variant>-<arch>-v<version>-<build_id>"));
        assert!(message.contains("8-40 lowercase hexadecimal characters"));
    }

    #[test]
    fn missing_snapshot_description_is_explicit() {
        let error =
            resolve_build_name("ami-test", "custom-ami", None, Architecture::X86_64).unwrap_err();
        assert!(error
            .to_string()
            .contains("root snapshot description '<missing>'"));
    }
}
