//! Resolve an AMI to the build that produced it.

use crate::error::Result;
use aws_sdk_ec2::Client as Ec2Client;
use regex::Regex;
use serde::{Deserialize, Serialize};
use snafu::{ensure_whatever, whatever, OptionExt, ResultExt};
use std::sync::LazyLock;

const ROOT_DEVICE: &str = "/dev/xvda";
const DATA_DEVICE: &str = "/dev/xvdb";

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
    pub arch: String,
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
            arch: caps["arch"].to_string(),
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

/// Map an EC2 architecture name to a Bottlerocket architecture name.
fn bottlerocket_arch(ec2_arch: &str) -> &str {
    match ec2_arch {
        "arm64" => "aarch64",
        other => other,
    }
}

/// Everything known about an AMI that is needed to reproduce it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmiInfo {
    pub ami_id: String,
    pub ami_name: String,
    pub name: String,
    pub variant: String,
    pub arch: String,
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
    arch: &str,
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
        .map(|a| a.as_str().to_string())
        .whatever_context("AMI has no architecture")?;
    let arch = bottlerocket_arch(&ec2_arch).to_string();

    let root_device = image.root_device_name().unwrap_or(ROOT_DEVICE);
    let root_snapshot =
        snapshot_for(image, root_device).whatever_context("AMI has no root snapshot")?;
    let data_snapshot = snapshot_for(image, DATA_DEVICE);

    let description = if BuildName::parse(&ami_name).is_none() {
        snapshot_description(ec2, &root_snapshot).await?
    } else {
        None
    };
    let parsed = resolve_build_name(ami_id, &ami_name, description.as_deref(), &arch)?;

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
        assert_eq!(n.arch, "x86_64");
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
        assert_eq!(n.arch, "aarch64");
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
        assert_eq!(bottlerocket_arch("arm64"), "aarch64");
        assert_eq!(bottlerocket_arch("x86_64"), "x86_64");
    }

    #[test]
    fn dirty_build_error_explains_matched_name_and_remedy() {
        let name = "bottlerocket-aws-dev-x86_64-v1.2.3-0123abcd-dirty";
        let error = resolve_build_name("ami-test", name, None, "x86_64").unwrap_err();
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
        let error =
            resolve_build_name("ami-test", "custom-ami", Some(description), "x86_64").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("AMI ami-test"));
        assert!(message.contains("EC2 architecture 'x86_64'"));
        assert!(message.contains("architecture 'aarch64'"));
        assert!(message.contains(&format!("root snapshot description '{description}'")));
    }

    #[test]
    fn unmatched_names_error_explains_expected_format() {
        let error = resolve_build_name("ami-test", "custom-ami", Some("custom-snapshot"), "x86_64")
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
        let error = resolve_build_name("ami-test", "custom-ami", None, "x86_64").unwrap_err();
        assert!(error
            .to_string()
            .contains("root snapshot description '<missing>'"));
    }
}
