//! Runs build scripts inside SDK containers.
//!
//! This module provides functions that execute shell scripts within containerized SDK environments
//! to build packages, kits, and variant images. Unlike `DockerBuild` which builds container images,
//! `script_builder` orchestrates the actual compilation and assembly of Bottlerocket artifacts.

pub(crate) mod error;

use crate::args::{BuildKitArgs, BuildPackageArgs, BuildVariantArgs, RepackVariantArgs};
use buildsys::manifest::Manifest;
use buildsys::runtime::{ContainerRuntime, ScriptBuildArgs, VolumeMount};
use error::Result;
use snafu::ResultExt;
use std::collections::HashMap;
use std::sync::Arc;

/// Returns the UID of the current process for ownership management.
///
/// Used to ensure build artifacts have correct ownership after container execution.
fn get_builder_uid() -> String {
    std::fs::metadata("/proc/self/comm")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m).to_string())
        // UID 1000 is the conventional first non-system user on most Linux distributions,
        // making it a safe fallback when /proc is unavailable (e.g., in some containers).
        .unwrap_or_else(|_| "1000".into())
}

pub(crate) struct ScriptBuilder;

impl ScriptBuilder {
    fn mount(host: &str, container: &str, readonly: bool) -> VolumeMount {
        VolumeMount { host: host.into(), container: container.into(), readonly }
    }

    /// Builds a package RPM by running package-build.sh in the SDK container.
    ///
    /// Mounts source code, tools, and dependencies into the container, sets up environment
    /// variables (PACKAGE, ARCH, BUILD_ID, etc.), and executes the build script. Output
    /// RPMs are written to the packages directory with ownership corrected post-build.
    ///
    /// Use this for compiling source packages into RPMs, not for building container images.
    pub(crate) fn build_package(args: BuildPackageArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<()> {
        runtime.check_version().context(error::RuntimeSnafu)?;

        let package = manifest.info().package_name();
        let root = &args.common.root_dir;
        let output_dir = args.packages_dir.join(package);
        std::fs::create_dir_all(&output_dir).context(error::DirectoryCreateSnafu { path: &output_dir })?;

        let mut env = HashMap::new();
        env.insert("PACKAGE".into(), package.to_string());
        env.insert("ARCH".into(), args.common.arch.to_string());
        env.insert("BUILD_ID".into(), args.version_build);
        env.insert("BUILD_ID_TIMESTAMP".into(), args.version_build_timestamp);
        env.insert("BUILDER_UID".into(), get_builder_uid());

        if let Ok(deps) = manifest.package_dependencies() {
            env.insert("PACKAGE_DEPENDENCIES".into(), deps.join(" "));
        }
        if let Ok(deps) = manifest.kit_dependencies() {
            env.insert("KIT_DEPENDENCIES".into(), deps.join(" "));
        }
        if let Ok(ext_kits) = buildsys::manifest::ExternalKitMetadataView::load(&root) {
            env.insert("EXTERNAL_KIT_DEPENDENCIES".into(), ext_kits.list().join(" "));
        }

        let cargo_vendor = root.join(".cargo/vendor");
        let cargo_config = root.join(".cargo/twoliter_cargo_config.toml");
        let sources_dir = root.join("sources");
        let external_kits = root.join("build/external-kits");
        let kits_dir = root.join("build/kits");

        let mut mounts = vec![
            Self::mount(&root.display().to_string(), "/src", true),
            Self::mount(&args.common.tools_dir.display().to_string(), "/tools", true),
            Self::mount(&output_dir.display().to_string(), "/output", false),
            Self::mount(&args.packages_dir.display().to_string(), "/rpms", false),
            Self::mount(&args.common.state_dir.display().to_string(), "/cache", false),
        ];

        if cargo_vendor.exists() {
            mounts.push(Self::mount(&cargo_vendor.display().to_string(), "/cargo-vendor", true));
        }
        if cargo_config.exists() {
            mounts.push(Self::mount(&cargo_config.display().to_string(), "/cargo-config", true));
        }
        if sources_dir.exists() {
            mounts.push(Self::mount(&sources_dir.display().to_string(), "/sources", true));
        }
        if external_kits.exists() {
            mounts.push(Self::mount(&external_kits.display().to_string(), "/external-kits", true));
        }
        if kits_dir.exists() {
            mounts.push(Self::mount(&kits_dir.display().to_string(), "/kits", true));
        }

        let script_args = ScriptBuildArgs {
            image: args.common.sdk_image,
            script: "bash /tools/scripts/package-build.sh".into(),
            env,
            mounts,
            user: Some("0".into()),
            workdir: Some("/".into()),
        };

        runtime.run_script(&script_args).context(error::RuntimeSnafu)?;
        Self::fix_output_ownership(&output_dir, &runtime);
        Ok(())
    }

    /// Builds a kit by running kit-build.sh in the SDK container.
    ///
    /// Assembles a kit from built packages and dependencies. Mounts packages, kits, and
    /// external kits directories, configures environment (KIT, ARCH, VERSION_ID, etc.),
    /// and generates kit metadata. Output is written to the kits directory.
    ///
    /// Use this for creating kit artifacts from RPMs, not for building container images.
    pub(crate) fn build_kit(args: BuildKitArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<()> {
        runtime.check_version().context(error::RuntimeSnafu)?;

        let kit = manifest.info().kit_name();
        let root = &args.common.root_dir;
        let output_dir = args.kits_dir.join(kit);
        std::fs::create_dir_all(&output_dir).context(error::DirectoryCreateSnafu { path: &output_dir })?;

        let mut env = HashMap::new();
        env.insert("KIT".into(), kit.to_string());
        env.insert("ARCH".into(), args.common.arch.to_string());
        env.insert("BUILD_ID".into(), args.version_build);
        env.insert("VERSION_ID".into(), args.version_image);
        env.insert("VENDOR".into(), "bottlerocket".into());
        env.insert("EXTERNAL_KIT_METADATA".into(), "external-kit-metadata.json".into());
        env.insert("BUILDER_UID".into(), get_builder_uid());

        if let Ok(deps) = manifest.package_dependencies() {
            env.insert("PACKAGE_DEPENDENCIES".into(), deps.join(" "));
        }
        if let Ok(deps) = manifest.kit_dependencies() {
            env.insert("LOCAL_KIT_DEPENDENCIES".into(), deps.join(" "));
        }

        let mounts = vec![
            Self::mount(&root.display().to_string(), "/src", true),
            Self::mount(&args.common.tools_dir.display().to_string(), "/tools", true),
            Self::mount(&output_dir.display().to_string(), "/output", false),
            Self::mount(&args.packages_dir.display().to_string(), "/rpms", true),
            Self::mount(&args.kits_dir.display().to_string(), "/kits", true),
            Self::mount(&args.external_kits_dir.display().to_string(), "/bypass", true),
            Self::mount(&args.common.state_dir.display().to_string(), "/cache", false),
        ];

        let script_args = ScriptBuildArgs {
            image: args.common.sdk_image,
            script: "bash /tools/scripts/kit-build.sh".into(),
            env,
            mounts,
            user: Some("0".into()),
            workdir: Some("/".into()),
        };

        runtime.run_script(&script_args).context(error::RuntimeSnafu)?;
        Self::fix_output_ownership(&output_dir, &runtime);
        Ok(())
    }

    /// Builds a variant image by running variant-build.sh in the SDK container.
    ///
    /// Creates a bootable Bottlerocket image from packages and kits. Configures variant-specific
    /// settings (platform, runtime, family, flavor), image layout (partition plan, sizes),
    /// kernel parameters, and image format (raw/qcow2/vmdk). Optionally mounts signing keys
    /// and TUF metadata for secure boot and update infrastructure.
    ///
    /// Use this for assembling final OS images, not for building container images.
    pub(crate) fn build_variant(args: BuildVariantArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<()> {
        runtime.check_version().context(error::RuntimeSnafu)?;

        let variant = args.common.cargo_manifest_dir.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let root = &args.common.root_dir;
        let output_dir = args.image_dir.join(format!("{}-{}", args.common.arch, &variant));
        std::fs::create_dir_all(&output_dir).context(error::DirectoryCreateSnafu { path: &output_dir })?;

        let v = bottlerocket_variant::Variant::new(&variant).ok();

        let mut env = HashMap::new();
        env.insert("VARIANT".into(), variant);
        env.insert("ARCH".into(), args.common.arch.to_string());
        env.insert("BUILD_ID".into(), args.version_build);
        env.insert("VERSION_ID".into(), args.version_image);
        env.insert("IMAGE_NAME".into(), args.name);
        env.insert("PRETTY_NAME".into(), args.pretty_name);
        env.insert("BUILDER_UID".into(), get_builder_uid());
        if let Some(ref v) = v {
            env.insert("VARIANT_PLATFORM".into(), v.platform().into());
            env.insert("VARIANT_RUNTIME".into(), v.runtime().into());
            env.insert("VARIANT_FAMILY".into(), v.family().into());
            env.insert("VARIANT_FLAVOR".into(), v.variant_flavor().unwrap_or("").into());
        }
        for feature in manifest.info().image_features().unwrap_or_default() {
            env.insert(feature.to_string(), "1".into());
        }
        if let Some(layout) = manifest.info().image_layout() {
            env.insert("OS_IMAGE_SIZE_GIB".into(), layout.os_image_size_gib.to_string());
            env.insert("DATA_IMAGE_SIZE_GIB".into(), layout.data_image_size_gib.to_string());
            env.insert("PARTITION_PLAN".into(), match layout.partition_plan {
                buildsys::manifest::PartitionPlan::Split => "split",
                buildsys::manifest::PartitionPlan::Unified => "unified",
            }.into());
            let (os_pub, data_pub) = layout.publish_image_sizes_gib();
            env.insert("OS_IMAGE_PUBLISH_SIZE_GIB".into(), os_pub.to_string());
            env.insert("DATA_IMAGE_PUBLISH_SIZE_GIB".into(), data_pub.to_string());
        }
        env.insert("IMAGE_FORMAT".into(), match manifest.info().image_format() {
            Some(buildsys::manifest::ImageFormat::Raw) | None => "raw",
            Some(buildsys::manifest::ImageFormat::Qcow2) => "qcow2",
            Some(buildsys::manifest::ImageFormat::Vmdk) => "vmdk",
        }.into());
        if let Some(params) = manifest.info().kernel_parameters() {
            env.insert("KERNEL_PARAMETERS".into(), params.join(" "));
        }

        if let Some(pkgs) = manifest.info().included_packages() {
            env.insert("PACKAGES".into(), pkgs.join(" "));
        }
        if let Ok(deps) = manifest.package_dependencies() {
            env.insert("PACKAGE_DEPENDENCIES".into(), deps.join(" "));
        }
        if let Ok(deps) = manifest.kit_dependencies() {
            env.insert("KIT_DEPENDENCIES".into(), deps.join(" "));
        }
        if let Ok(ext_kits) = buildsys::manifest::ExternalKitMetadataView::load(&root) {
            env.insert("EXTERNAL_KIT_DEPENDENCIES".into(), ext_kits.list().join(" "));
            env.insert("PROJECT_VENDOR".into(), ext_kits.get_project_vendor().into());
        }

        let mut mounts = vec![
            Self::mount(&root.display().to_string(), "/src", true),
            Self::mount(&args.common.tools_dir.display().to_string(), "/tools", true),
            Self::mount(&output_dir.display().to_string(), "/output", false),
            Self::mount(&args.packages_dir.display().to_string(), "/rpms", true),
            Self::mount(&args.kits_dir.display().to_string(), "/kits", true),
            Self::mount(&args.external_kits_dir.display().to_string(), "/external-kits", true),
            Self::mount(&args.common.state_dir.display().to_string(), "/cache", false),
        ];
        if let Ok(root_json) = std::env::var("PUBLISH_REPO_ROOT_JSON") {
            if !root_json.is_empty() && std::path::Path::new(&root_json).exists() {
                mounts.push(Self::mount(&root_json, "/root/roles/root.json", true));
            }
        }
        if let Ok(sbkeys_dir) = std::env::var("BUILDSYS_SBKEYS_PROFILE_DIR") {
            if !sbkeys_dir.is_empty() && std::path::Path::new(&sbkeys_dir).exists() {
                mounts.push(Self::mount(&sbkeys_dir, "/root/sbkeys", true));
            }
        }
        if let Ok(ca_bundle) = std::env::var("BUILDSYS_CACERTS_BUNDLE_OVERRIDE") {
            if !ca_bundle.is_empty() && std::path::Path::new(&ca_bundle).exists() {
                mounts.push(Self::mount(&ca_bundle, "/etc/pki/tls/certs/ca-bundle.crt", true));
            }
        }

        let script_args = ScriptBuildArgs {
            image: args.common.sdk_image,
            script: "bash /tools/scripts/variant-build.sh".into(),
            env,
            mounts,
            user: Some("0".into()),
            workdir: Some("/".into()),
        };

        runtime.run_script(&script_args).context(error::RuntimeSnafu)?;
        Self::fix_output_ownership(&output_dir, &runtime);
        Ok(())
    }

    /// Repacks a variant image by running repack-build.sh in the SDK container.
    ///
    /// Converts an existing variant image to a different format or applies post-processing.
    /// Mounts the input image directory and writes the repacked output to the same location.
    /// Preserves variant configuration and image layout settings from the manifest.
    ///
    /// Use this for format conversion or image post-processing, not for building container images.
    pub(crate) fn repack_variant(args: RepackVariantArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<()> {
        runtime.check_version().context(error::RuntimeSnafu)?;

        let variant = args.common.cargo_manifest_dir.file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let root = &args.common.root_dir;
        let variant_dir = args.image_dir.join(format!("{}-{}", args.common.arch, &variant));
        let input_dir = variant_dir.join(format!("{}-{}", &args.version_image, &args.version_build));
        let output_dir = variant_dir.clone();
        std::fs::create_dir_all(&output_dir).context(error::DirectoryCreateSnafu { path: &output_dir })?;

        let mut env = HashMap::new();
        env.insert("VARIANT".into(), variant);
        env.insert("ARCH".into(), args.common.arch.to_string());
        env.insert("BUILD_ID".into(), args.version_build);
        env.insert("VERSION_ID".into(), args.version_image);
        env.insert("IMAGE_NAME".into(), args.name);
        env.insert("BUILDER_UID".into(), get_builder_uid());

        for feature in manifest.info().image_features().unwrap_or_default() {
            env.insert(feature.to_string(), "1".into());
        }
        if let Some(layout) = manifest.info().image_layout() {
            env.insert("OS_IMAGE_SIZE_GIB".into(), layout.os_image_size_gib.to_string());
            env.insert("DATA_IMAGE_SIZE_GIB".into(), layout.data_image_size_gib.to_string());
            env.insert("PARTITION_PLAN".into(), match layout.partition_plan {
                buildsys::manifest::PartitionPlan::Split => "split",
                buildsys::manifest::PartitionPlan::Unified => "unified",
            }.into());
            let (os_pub, data_pub) = layout.publish_image_sizes_gib();
            env.insert("OS_IMAGE_PUBLISH_SIZE_GIB".into(), os_pub.to_string());
            env.insert("DATA_IMAGE_PUBLISH_SIZE_GIB".into(), data_pub.to_string());
        }
        env.insert("IMAGE_FORMAT".into(), match manifest.info().image_format() {
            Some(buildsys::manifest::ImageFormat::Raw) | None => "raw",
            Some(buildsys::manifest::ImageFormat::Qcow2) => "qcow2",
            Some(buildsys::manifest::ImageFormat::Vmdk) => "vmdk",
        }.into());

        let mut mounts = vec![
            Self::mount(&root.display().to_string(), "/src", true),
            Self::mount(&args.common.tools_dir.display().to_string(), "/tools", true),
            Self::mount(&input_dir.display().to_string(), "/input", true),
            Self::mount(&output_dir.display().to_string(), "/output", false),
        ];
        if let Ok(root_json) = std::env::var("PUBLISH_REPO_ROOT_JSON") {
            if !root_json.is_empty() && std::path::Path::new(&root_json).exists() {
                mounts.push(Self::mount(&root_json, "/root/roles/root.json", true));
            }
        }
        if let Ok(sbkeys_dir) = std::env::var("BUILDSYS_SBKEYS_PROFILE_DIR") {
            if !sbkeys_dir.is_empty() && std::path::Path::new(&sbkeys_dir).exists() {
                mounts.push(Self::mount(&sbkeys_dir, "/root/sbkeys", true));
            }
        }

        let script_args = ScriptBuildArgs {
            image: args.common.sdk_image,
            script: "bash /tools/scripts/repack-build.sh".into(),
            env,
            mounts,
            user: Some("0".into()),
            workdir: Some("/".into()),
        };

        runtime.run_script(&script_args).context(error::RuntimeSnafu)?;
        Self::fix_output_ownership(&output_dir, &runtime);
        Ok(())
    }

    /// Attempts to fix output file ownership after container builds.
    ///
    /// Failures are intentionally ignored because:
    /// - The in-container chown (via BUILDER_UID) may have already succeeded
    /// - Permission errors are expected in some rootless/restricted environments
    /// - Build artifacts are still usable even with suboptimal ownership
    fn fix_output_ownership(path: &std::path::Path, runtime: &Arc<dyn ContainerRuntime>) {
        let path_str = path.display().to_string();
        match runtime.name() {
            "podman" => {
                let _ = std::process::Command::new("podman")
                    .args(["unshare", "chown", "-R", "0:0", &path_str])
                    .status();
            }
            "finch" => {
                let _ = std::process::Command::new("rootlesskit")
                    .args(["chown", "-R", "0:0", &path_str])
                    .status();
            }
            _ => {
                if let Ok(uid) = std::fs::metadata("/proc/self/comm").map(|m| std::os::unix::fs::MetadataExt::uid(&m)) {
                    let _ = std::process::Command::new("chown")
                        .args(["-R", &format!("{}:{}", uid, uid), &path_str])
                        .status();
                }
            }
        }
    }
}
