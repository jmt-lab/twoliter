/*!
This module handles the calls to Docker needed to execute package and variant
builds. The actual build steps and the expected parameters are defined in
the repository's top-level Dockerfile.

*/
pub(crate) mod error;

use crate::args::{BuildKitArgs, BuildPackageArgs, BuildVariantArgs, RepackVariantArgs};
use buildsys::runtime::{ContainerRuntime, BuildArgs as RuntimeBuildArgs, RunArgs, VolumeMount};
use bottlerocket_variant::Variant;
use buildsys::manifest::{
    ExternalKitMetadataView, ImageFeature, ImageFormat, ImageLayout, Manifest, PartitionPlan,
    SupportedArch,
};
use buildsys::BuildType;
use buildsys_config::EXTERNAL_KIT_METADATA;
use error::Result;
use lazy_static::lazy_static;
use pipesys::server::Server as PipesysServer;

use sha2::{Digest, Sha512};
use snafu::{OptionExt, ResultExt};
use std::collections::HashSet;
use std::env;
use std::fs::{self, read_dir, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::{DirEntry, WalkDir};

// Expected UID for privileged and unprivileged processes inside the build container.
const ROOT_UID: u32 = 0;
lazy_static! {
    static ref BUILDER_UID: u32 = std::fs::metadata("/proc/self/comm")
        .map(|m| m.uid())
        .expect("Failed to obtain current UID");
}

enum OutputCleanup {
    BeforeBuild,
    None,
}

struct CommonBuildArgs {
    arch: SupportedArch,
    sdk: String,
    nocache: String,
    token: String,
    cleanup: OutputCleanup,
    output_socket: String,
}

impl CommonBuildArgs {
    fn new(
        root: impl AsRef<Path>,
        sdk: String,
        arch: SupportedArch,
        cleanup: OutputCleanup,
    ) -> Result<Self> {
        let token = token(&root);

        // Avoid using a cached layer from a previous build.
        let nocache = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context(error::SystemTimeBeforeEpochSnafu)?
            .as_nanos()
            .to_string();

        // Generate a unique address for the socket that sends the output directory file
        // descriptor.
        let output_socket = format!("buildsys-output-{token}-{nocache}");

        Ok(Self {
            arch,
            sdk,
            nocache,
            token,
            cleanup,
            output_socket,
        })
    }
}

struct PackageBuildArgs {
    package: String,
    package_dependencies: Vec<String>,
    kit_dependencies: Vec<String>,
    external_kit_dependencies: Vec<String>,
    version_build: String,
    version_build_timestamp: String,
}

impl KitBuildArgs {
    fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.build_arg("KIT", &self.kit);
        args.build_arg("PACKAGE_DEPENDENCIES", self.package_dependencies.join(" "));
        args.build_arg("BUILD_ID", &self.version_build);
        args.build_arg("VERSION_ID", &self.version_id);
        args.build_arg("EXTERNAL_KIT_METADATA", &self.external_kit_metadata);
        args.build_arg("VENDOR", &self.vendor);
        args.build_arg("LOCAL_KIT_DEPENDENCIES", self.local_kits.join(" "));
        args
    }
}

struct KitBuildArgs {
    kit: String,
    package_dependencies: Vec<String>,
    external_kit_metadata: String,
    local_kits: Vec<String>,
    vendor: String,
    version_build: String,
    version_id: String,
}

impl crate::builder::PackageBuildArgs {
    fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.build_arg("KIT_DEPENDENCIES", self.kit_dependencies.join(" "));
        args.build_arg(
            "EXTERNAL_KIT_DEPENDENCIES",
            self.external_kit_dependencies.join(" "),
        );
        args.build_arg("PACKAGE", &self.package);
        args.build_arg("PACKAGE_DEPENDENCIES", self.package_dependencies.join(" "));
        args.build_arg("BUILD_ID", &self.version_build);
        args.build_arg("BUILD_ID_TIMESTAMP", &self.version_build_timestamp);
        args
    }
}

struct VariantBuildArgs {
    package_dependencies: Vec<String>,
    kit_dependencies: Vec<String>,
    external_kit_dependencies: Vec<String>,
    project_vendor: String,
    data_image_publish_size_gib: i32,
    data_image_size_gib: String,
    image_features: HashSet<ImageFeature>,
    image_format: String,
    kernel_parameters: String,
    name: String,
    os_image_publish_size_gib: String,
    os_image_size_gib: String,
    packages: String,
    partition_plan: String,
    pretty_name: String,
    variant: String,
    variant_family: String,
    variant_flavor: String,
    variant_platform: String,
    variant_runtime: String,
    version_build: String,
    version_image: String,
}

impl VariantBuildArgs {
    fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.build_arg(
            "DATA_IMAGE_PUBLISH_SIZE_GIB",
            self.data_image_publish_size_gib.to_string(),
        );
        args.build_arg("BUILD_ID", &self.version_build);
        args.build_arg("DATA_IMAGE_SIZE_GIB", &self.data_image_size_gib);
        args.build_arg("IMAGE_FORMAT", &self.image_format);
        args.build_arg("IMAGE_NAME", &self.name);
        args.build_arg("KERNEL_PARAMETERS", &self.kernel_parameters);
        args.build_arg("KIT_DEPENDENCIES", self.kit_dependencies.join(" "));
        args.build_arg(
            "EXTERNAL_KIT_DEPENDENCIES",
            self.external_kit_dependencies.join(" "),
        );
        args.build_arg("PROJECT_VENDOR", &self.project_vendor);
        args.build_arg("OS_IMAGE_PUBLISH_SIZE_GIB", &self.os_image_publish_size_gib);
        args.build_arg("OS_IMAGE_SIZE_GIB", &self.os_image_size_gib);
        args.build_arg("PACKAGES", &self.packages);
        args.build_arg("PACKAGE_DEPENDENCIES", self.package_dependencies.join(" "));
        args.build_arg("PARTITION_PLAN", &self.partition_plan);
        args.build_arg("PRETTY_NAME", &self.pretty_name);
        args.build_arg("VARIANT", &self.variant);
        args.build_arg("VARIANT_FAMILY", &self.variant_family);
        args.build_arg("VARIANT_FLAVOR", &self.variant_flavor);
        args.build_arg("VARIANT_PLATFORM", &self.variant_platform);
        args.build_arg("VARIANT_RUNTIME", &self.variant_runtime);
        args.build_arg("VERSION_ID", &self.version_image);

        for image_feature in self.image_features.iter() {
            args.build_arg(format!("{image_feature}"), "1");
        }

        args
    }
}

struct RepackVariantBuildArgs {
    data_image_publish_size_gib: i32,
    data_image_size_gib: String,
    image_features: HashSet<ImageFeature>,
    image_format: String,
    name: String,
    os_image_publish_size_gib: String,
    os_image_size_gib: String,
    partition_plan: String,
    variant: String,
    version_build: String,
    version_image: String,
}

impl RepackVariantBuildArgs {
    fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.push("--network".into());
        args.push("host".into());
        args.build_arg(
            "DATA_IMAGE_PUBLISH_SIZE_GIB",
            self.data_image_publish_size_gib.to_string(),
        );
        args.build_arg("DATA_IMAGE_SIZE_GIB", &self.data_image_size_gib);
        args.build_arg("IMAGE_FORMAT", &self.image_format);
        args.build_arg("IMAGE_NAME", &self.name);
        args.build_arg("OS_IMAGE_PUBLISH_SIZE_GIB", &self.os_image_publish_size_gib);
        args.build_arg("OS_IMAGE_SIZE_GIB", &self.os_image_size_gib);
        args.build_arg("PARTITION_PLAN", &self.partition_plan);
        args.build_arg("VARIANT", &self.variant);
        args.build_arg("BUILD_ID", &self.version_build);
        args.build_arg("VERSION_ID", &self.version_image);

        for image_feature in self.image_features.iter() {
            args.build_arg(format!("{image_feature}"), "1");
        }

        args
    }
}

#[allow(clippy::large_enum_variant)]
enum TargetBuildArgs {
    Package(PackageBuildArgs),
    Kit(KitBuildArgs),
    Variant(VariantBuildArgs),
    Repack(RepackVariantBuildArgs),
}

impl TargetBuildArgs {
    pub(crate) fn build_type(&self) -> BuildType {
        match self {
            TargetBuildArgs::Package(_) => BuildType::Package,
            TargetBuildArgs::Kit(_) => BuildType::Kit,
            TargetBuildArgs::Variant(_) => BuildType::Variant,
            TargetBuildArgs::Repack(_) => BuildType::Repack,
        }
    }
}

pub(crate) struct DockerBuild {
    dockerfile: PathBuf,
    context: PathBuf,
    target: String,
    tag: String,
    root_dir: PathBuf,
    artifacts_dirs: Vec<PathBuf>,
    state_dir: PathBuf,
    artifact_name: String,
    common_build_args: CommonBuildArgs,
    target_build_args: TargetBuildArgs,
    secrets_args: Vec<String>,
    runtime: Arc<dyn ContainerRuntime>,
}

impl DockerBuild {
    /// Create a new `DockerBuild` that can build a package.
    pub(crate) fn new_package(args: BuildPackageArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<Self> {
        let package = manifest.info().package_name();
        let per_package_dir = format!("{}/{}", args.packages_dir.display(), package).into();
        let old_package_dir = format!("{}", args.packages_dir.display()).into();

        Ok(Self {
            dockerfile: args.common.tools_dir.join("build.Dockerfile"),
            context: args.common.root_dir.clone(),
            target: "package".to_string(),
            tag: append_token(
                format!(
                    "buildsys-pkg-{package}-{arch}",
                    package = package,
                    arch = args.common.arch,
                ),
                &args.common.root_dir,
            ),
            root_dir: args.common.root_dir.clone(),
            artifacts_dirs: vec![per_package_dir, old_package_dir],
            state_dir: args.common.state_dir,
            artifact_name: package.to_string(),
            common_build_args: CommonBuildArgs::new(
                &args.common.root_dir,
                args.common.sdk_image,
                args.common.arch,
                OutputCleanup::BeforeBuild,
            )?,
            target_build_args: TargetBuildArgs::Package(PackageBuildArgs {
                package: package.to_string(),
                package_dependencies: manifest.package_dependencies().context(error::GraphSnafu)?,
                kit_dependencies: manifest.kit_dependencies().context(error::GraphSnafu)?,
                external_kit_dependencies: ExternalKitMetadataView::load(args.common.root_dir)
                    .context(error::GraphSnafu)?
                    .list(),
                version_build: args.version_build,
                version_build_timestamp: args.version_build_timestamp,
            }),
            secrets_args: Vec::new(),
            runtime,
        })
    }

    pub(crate) fn new_kit(args: BuildKitArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<Self> {
        let kit = manifest.info().kit_name();
        let per_kit_dir = args.kits_dir.join(kit);

        Ok(Self {
            dockerfile: args.common.tools_dir.join("build.Dockerfile"),
            context: args.common.root_dir.clone(),
            target: "kit".to_string(),
            tag: append_token(
                format!(
                    "buildsys-kit-{kit}-{arch}",
                    kit = kit,
                    arch = args.common.arch,
                ),
                &args.common.root_dir,
            ),
            root_dir: args.common.root_dir.clone(),
            artifacts_dirs: vec![per_kit_dir],
            state_dir: args.common.state_dir,
            artifact_name: kit.to_string(),
            common_build_args: CommonBuildArgs::new(
                &args.common.root_dir,
                args.common.sdk_image,
                args.common.arch,
                OutputCleanup::BeforeBuild,
            )?,
            target_build_args: TargetBuildArgs::Kit(KitBuildArgs {
                kit: kit.to_string(),
                vendor: manifest.info().kit_vendor().context(error::GraphSnafu)?,
                local_kits: manifest.kit_dependencies().context(error::GraphSnafu)?,
                external_kit_metadata: EXTERNAL_KIT_METADATA.into(),
                package_dependencies: manifest.package_dependencies().context(error::GraphSnafu)?,
                version_build: args.version_build,
                version_id: args.version_image,
            }),
            secrets_args: Vec::new(),
            runtime,
        })
    }

    /// Create a new `DockerBuild` that can build a variant image.
    pub(crate) fn new_variant(args: BuildVariantArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<Self> {
        let image_layout = manifest.info().image_layout().cloned().unwrap_or_default();
        let ImageLayout {
            os_image_size_gib,
            data_image_size_gib,
            partition_plan,
            ..
        } = image_layout;

        let (os_image_publish_size_gib, data_image_publish_size_gib) =
            image_layout.publish_image_sizes_gib();

        let variant = filename(args.common.cargo_manifest_dir);

        let v = Variant::new(&variant).context(error::VariantParseSnafu)?;
        let variant_platform = v.platform().into();
        let variant_runtime = v.runtime().into();
        let variant_family = v.family().into();
        let variant_flavor = v.variant_flavor().unwrap_or("").into();
        let external_kit_metadata_view =
            ExternalKitMetadataView::load(&args.common.root_dir).context(error::GraphSnafu)?;

        Ok(Self {
            dockerfile: args.common.tools_dir.join("build.Dockerfile"),
            context: args.common.root_dir.clone(),
            target: "variant".to_string(),
            tag: append_token(
                format!("buildsys-var-{variant}-{arch}", arch = args.common.arch),
                &args.common.root_dir,
            ),
            root_dir: args.common.root_dir.clone(),
            artifacts_dirs: vec![args
                .image_dir
                .join(format!("{}-{}", args.common.arch, variant))],
            state_dir: args.common.state_dir,
            artifact_name: variant.clone(),
            common_build_args: CommonBuildArgs::new(
                &args.common.root_dir,
                args.common.sdk_image,
                args.common.arch,
                OutputCleanup::BeforeBuild,
            )?,
            target_build_args: TargetBuildArgs::Variant(VariantBuildArgs {
                package_dependencies: manifest.package_dependencies().context(error::GraphSnafu)?,
                kit_dependencies: manifest.kit_dependencies().context(error::GraphSnafu)?,
                external_kit_dependencies: external_kit_metadata_view.list(),
                project_vendor: external_kit_metadata_view.get_project_vendor().to_owned(),
                data_image_publish_size_gib,
                data_image_size_gib: data_image_size_gib.to_string(),
                image_features: manifest.info().image_features().unwrap_or_default(),
                image_format: match manifest.info().image_format() {
                    Some(ImageFormat::Raw) | None => "raw",
                    Some(ImageFormat::Qcow2) => "qcow2",
                    Some(ImageFormat::Vmdk) => "vmdk",
                }
                .to_string(),
                kernel_parameters: manifest
                    .info()
                    .kernel_parameters()
                    .cloned()
                    .unwrap_or_default()
                    .join(" "),
                name: args.name,
                os_image_publish_size_gib: os_image_publish_size_gib.to_string(),
                os_image_size_gib: os_image_size_gib.to_string(),
                packages: manifest
                    .info()
                    .included_packages()
                    .cloned()
                    .unwrap_or_default()
                    .join(" "),
                partition_plan: match partition_plan {
                    PartitionPlan::Split => "split",
                    PartitionPlan::Unified => "unified",
                }
                .to_string(),
                pretty_name: args.pretty_name,
                variant,
                variant_family,
                variant_flavor,
                variant_platform,
                variant_runtime,
                version_build: args.version_build,
                version_image: args.version_image,
            }),
            secrets_args: secrets_args()?,
            runtime,
        })
    }

    /// Create a new `DockerBuild` that can repackage a variant image.
    pub(crate) fn repack_variant(args: RepackVariantArgs, manifest: &Manifest, runtime: Arc<dyn ContainerRuntime>) -> Result<Self> {
        let image_layout = manifest.info().image_layout().cloned().unwrap_or_default();
        let ImageLayout {
            os_image_size_gib,
            data_image_size_gib,
            partition_plan,
            ..
        } = image_layout;

        let (os_image_publish_size_gib, data_image_publish_size_gib) =
            image_layout.publish_image_sizes_gib();

        let variant = filename(args.common.cargo_manifest_dir);

        Ok(Self {
            dockerfile: args.common.tools_dir.join("build.Dockerfile"),
            context: args.common.root_dir.clone(),
            target: "repack".to_string(),
            tag: append_token(
                format!("buildsys-repack-{variant}-{arch}", arch = args.common.arch),
                &args.common.root_dir,
            ),
            root_dir: args.common.root_dir.clone(),
            artifacts_dirs: vec![args
                .image_dir
                .join(format!("{}-{}", args.common.arch, variant))],
            state_dir: args.common.state_dir,
            artifact_name: variant.clone(),
            common_build_args: CommonBuildArgs::new(
                &args.common.root_dir,
                args.common.sdk_image,
                args.common.arch,
                OutputCleanup::None,
            )?,
            target_build_args: TargetBuildArgs::Repack(RepackVariantBuildArgs {
                data_image_publish_size_gib,
                data_image_size_gib: data_image_size_gib.to_string(),
                image_features: manifest.info().image_features().unwrap_or_default(),
                image_format: match manifest.info().image_format() {
                    Some(ImageFormat::Raw) | None => "raw",
                    Some(ImageFormat::Qcow2) => "qcow2",
                    Some(ImageFormat::Vmdk) => "vmdk",
                }
                .to_string(),
                name: args.name,
                os_image_publish_size_gib: os_image_publish_size_gib.to_string(),
                os_image_size_gib: os_image_size_gib.to_string(),
                partition_plan: match partition_plan {
                    PartitionPlan::Split => "split",
                    PartitionPlan::Unified => "unified",
                }
                .to_string(),
                variant,
                version_build: args.version_build,
                version_image: args.version_image,
            }),
            secrets_args: secrets_args()?,
            runtime,
        })
    }

    pub(crate) fn build(&self) -> Result<()> {
        self.runtime.check_version().context(error::RuntimeSnafu)?;

        env::set_current_dir(&self.root_dir).context(error::DirectoryChangeSnafu {
            path: &self.root_dir,
        })?;

        // Create a directory for tracking outputs before we move them into position.
        let marker_dir = create_marker_dir(
            &self.target_build_args.build_type(),
            &self.artifact_name,
            &self.common_build_args.arch.to_string(),
            &self.state_dir,
        )?;

        // Clean up any previous outputs we have tracked.
        match self.common_build_args.cleanup {
            OutputCleanup::BeforeBuild => {
                clean_build_files(&marker_dir, &self.artifacts_dirs)?;
            }
            OutputCleanup::None => (),
        }

        let bypass_name = format!("{}-bypass", self.tag);

        // Clean up the previous image if it exists.
        let _ = self.runtime.remove_image(&self.tag);

        // Clean up the stopped bypass container if it exists.
        let _ = self.runtime.remove_container(&bypass_name);

        // Run a container with the project's root as a read-only volume mount, so that pipesys can
        // serve a read-only file descriptor that's safe to pass into builds.
        let bypass_args = RunArgs {
            image: self.common_build_args.sdk.clone(),
            name: bypass_name.clone(),
            volumes: vec![
                VolumeMount { host: self.root_dir.display().to_string(), container: "/bypass".into(), readonly: true },
                VolumeMount { host: format!("{}/build/tools/pipesys", self.root_dir.display()), container: "/usr/local/bin/pipesys".into(), readonly: true },
            ],
            user: Some(ROOT_UID.to_string()),
            detach: true,
            rm: true,
            init: true,
            net: Some("host".into()),
            pid: Some("host".into()),
            command: vec!["pipesys".into(), "serve".into(), "--socket".into(), bypass_name.clone(), "--client-uid".into(), ROOT_UID.to_string(), "--path".into(), "/bypass".into()],
        };

        // Start the bypass container that will serve the project root file
        // descriptor.
        self.runtime.run(&bypass_args).context(error::RuntimeSnafu)?;

        let tokio_runtime = tokio::runtime::Runtime::new().context(error::AsyncRuntimeSnafu)?;

        // Spawn a background task to share the file descriptors for the output directory.
        let output_socket = self.common_build_args.output_socket.clone();
        let output_dir = marker_dir.clone();
        tokio_runtime.spawn(async move {
            PipesysServer::for_path(output_socket, ROOT_UID, &output_dir)
                .serve()
                .await
        });

        // Build the image, which builds the artifacts we want.
        let mut build_args_vec = self.build_args();
        build_args_vec.push("--build-arg".into());
        build_args_vec.push(format!("BYPASS_SOCKET={}", bypass_name));
        build_args_vec.push("--build-arg".into());
        build_args_vec.push(format!("BUILDER_UID={}", *BUILDER_UID));

        let runtime_build_args = RuntimeBuildArgs {
            context: self.context.display().to_string(),
            dockerfile: self.dockerfile.display().to_string(),
            target: self.target.clone(),
            tag: self.tag.clone(),
            build_args: build_args_vec,
            secrets_args: self.secrets_args.clone(),
            no_cache_filter: vec!["rpmbuild".into(), "kitbuild".into(), "repobuild".into(), "imgbuild".into(), "migrationbuild".into(), "kmodkitbuild".into(), "imgrepack".into()],
            network: "host".into(),
        };

        let build_result = self.runtime.build(&runtime_build_args);

        // Clean up our bypass container.
        let _ = self.runtime.remove_container(&bypass_name);

        // Stop the runtime and the background threads.
        tokio_runtime.shutdown_background();

        // Check whether the build succeeded before continuing.
        build_result.context(error::RuntimeSnafu)?;

        // Clean up our image now that we're done.
        self.runtime.remove_image(&self.tag).context(error::RuntimeSnafu)?;

        // Copy artifacts to the expected directory and write markers to track them.
        copy_build_files(&marker_dir, &self.artifacts_dirs[0])?;

        Ok(())
    }

    fn build_args(&self) -> Vec<String> {
        let mut args = match &self.target_build_args {
            TargetBuildArgs::Package(p) => p.build_args(),
            TargetBuildArgs::Kit(k) => k.build_args(),
            TargetBuildArgs::Variant(v) => v.build_args(),
            TargetBuildArgs::Repack(r) => r.build_args(),
        };
        args.build_arg("ARCH", self.common_build_args.arch.to_string());
        args.build_arg("GOARCH", self.common_build_args.arch.goarch());
        args.build_arg("SDK", &self.common_build_args.sdk);
        args.build_arg("NOCACHE", &self.common_build_args.nocache);
        args.build_arg("TOKEN", &self.common_build_args.token);
        args.build_arg("OUTPUT_SOCKET", &self.common_build_args.output_socket);

        // Skip some build checks:
        // - InvalidDefaultArgInFrom warns about the SDK argument, which is always set
        // - SecretsUsedInArgOrEnv warns about the TOKEN argument, which is not a secret
        args.build_arg(
            "BUILDKIT_DOCKERFILE_CHECK",
            "skip=InvalidDefaultArgInFrom,SecretsUsedInArgOrEnv",
        );

        args
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Add secrets that might be needed for builds. Since most builds won't use
/// them, they are not automatically tracked for changes. If necessary, builds
/// can emit the relevant cargo directives for tracking in their build script.
fn secrets_args() -> Result<Vec<String>> {
    let mut args = Vec::new();
    let sbkeys_var = "BUILDSYS_SBKEYS_PROFILE_DIR";
    let sbkeys_dir = env::var(sbkeys_var).context(error::EnvironmentSnafu { var: sbkeys_var })?;

    let sbkeys = read_dir(&sbkeys_dir).context(error::DirectoryReadSnafu { path: &sbkeys_dir })?;
    for s in sbkeys {
        let s = s.context(error::DirectoryReadSnafu { path: &sbkeys_dir })?;
        args.build_secret(
            "file",
            &s.file_name().to_string_lossy(),
            &s.path().to_string_lossy(),
        );
    }

    let ca_bundle_var = "BUILDSYS_CACERTS_BUNDLE_OVERRIDE";
    let ca_bundle_value =
        env::var(ca_bundle_var).context(error::EnvironmentSnafu { var: ca_bundle_var })?;

    if !ca_bundle_value.is_empty() {
        let ca_bundle_path = PathBuf::from(&ca_bundle_value);
        if !ca_bundle_path.exists() {
            return error::BadCaBundleSnafu { ca_bundle_path }.fail();
        }
        args.build_secret("file", "ca-bundle.crt", &ca_bundle_path.to_string_lossy());
    }

    let root_json_var = "PUBLISH_REPO_ROOT_JSON";
    let root_json_value =
        env::var(root_json_var).context(error::EnvironmentSnafu { var: root_json_var })?;

    if !root_json_value.is_empty() {
        let root_json_path = PathBuf::from(&root_json_value);
        if !root_json_path.exists() {
            return error::BadRootJsonSnafu { root_json_path }.fail();
        }
        args.build_secret("file", "root.json", &root_json_path.to_string_lossy());
    }

    for var in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ] {
        let id = format!("{}.env", var.to_lowercase().replace('_', "-"));
        args.build_secret("env", &id, var);
    }

    Ok(args)
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Create a directory for build artifacts.
fn create_marker_dir(
    kind: &BuildType,
    name: &str,
    arch: &str,
    state_dir: &Path,
) -> Result<PathBuf> {
    let prefix = match kind {
        BuildType::Package => "packages",
        BuildType::Kit => "kits",
        BuildType::Variant => "variants",
        BuildType::Repack => "variants",
    };

    let path = [&state_dir.display().to_string(), arch, prefix, name]
        .iter()
        .collect();

    fs::create_dir_all(&path).context(error::DirectoryCreateSnafu { path: &path })?;

    Ok(path)
}

const MARKER_EXTENSION: &str = ".buildsys_marker";

/// Copy build artifacts to the output directory.
/// Before we copy each file, we create a corresponding marker file to record its existence.
fn copy_build_files<P>(build_dir: P, output_dir: P) -> Result<()>
where
    P: AsRef<Path>,
{
    fn has_artifacts(entry: &DirEntry) -> bool {
        let is_dir = entry.path().is_dir();
        let is_file = entry.file_type().is_file();
        let is_not_marker = is_file
            && entry
                .file_name()
                .to_str()
                .map(|s| !s.ends_with(MARKER_EXTENSION))
                .unwrap_or(false);
        let is_symlink = entry.file_type().is_symlink();
        is_dir || is_not_marker || is_symlink
    }

    for artifact_file in find_files(&build_dir, has_artifacts) {
        let mut marker_file = artifact_file.clone().into_os_string();
        marker_file.push(MARKER_EXTENSION);
        File::create(&marker_file).context(error::FileCreateSnafu { path: &marker_file })?;

        let mut output_file: PathBuf = output_dir.as_ref().into();
        output_file.push(artifact_file.strip_prefix(&build_dir).context(
            error::StripPathPrefixSnafu {
                path: &marker_file,
                prefix: build_dir.as_ref(),
            },
        )?);

        let parent_dir = output_file
            .parent()
            .context(error::BadDirectorySnafu { path: &output_file })?;
        fs::create_dir_all(parent_dir)
            .context(error::DirectoryCreateSnafu { path: &parent_dir })?;

        fs::rename(&artifact_file, &output_file).context(error::FileRenameSnafu {
            old_path: &artifact_file,
            new_path: &output_file,
        })?;
    }

    Ok(())
}

/// Remove build artifacts from any of the known output directories.
/// Any marker file we find could have a corresponding file that should be cleaned up.
/// We also clean up the marker files so they do not accumulate across builds.
/// For the same reason, if a directory is empty after build artifacts, marker files, and other
/// empty directories have been removed, then that directory will also be removed.
fn clean_build_files<P>(build_dir: P, output_dirs: &[PathBuf]) -> Result<()>
where
    P: AsRef<Path>,
{
    let build_dir = build_dir.as_ref();

    fn has_markers(entry: &DirEntry) -> bool {
        let is_dir = entry.path().is_dir();
        let is_file = entry.file_type().is_file();
        let is_marker = is_file
            && entry
                .file_name()
                .to_str()
                .map(|s| s.ends_with(MARKER_EXTENSION))
                .unwrap_or(false);
        is_dir || is_marker
    }

    fn cleanup(path: &Path, top: &Path, dirs: &mut HashSet<PathBuf>) -> Result<()> {
        if !path.exists() && !path.is_symlink() {
            return Ok(());
        }
        std::fs::remove_file(path).context(error::FileRemoveSnafu { path })?;
        let mut parent = path.parent();
        while let Some(p) = parent {
            if p == top || dirs.contains(p) {
                break;
            }
            dirs.insert(p.into());
            parent = p.parent()
        }
        Ok(())
    }

    fn is_empty_dir(path: &Path) -> Result<bool> {
        Ok(path.is_dir()
            && path
                .read_dir()
                .context(error::DirectoryReadSnafu { path })?
                .next()
                .is_none())
    }

    let mut clean_dirs: HashSet<PathBuf> = HashSet::new();

    for marker_file in find_files(&build_dir, has_markers) {
        for output_dir in output_dirs {
            let mut output_file: PathBuf = output_dir.into();
            output_file.push(marker_file.strip_prefix(build_dir).context(
                error::StripPathPrefixSnafu {
                    path: &marker_file,
                    prefix: build_dir,
                },
            )?);
            output_file.set_extension("");
            cleanup(&output_file, output_dir, &mut clean_dirs)?;
        }
        cleanup(&marker_file, build_dir, &mut clean_dirs)?;
    }

    // Clean up directories in reverse order, so that empty child directories don't stop an
    // otherwise empty parent directory from being removed.
    let mut clean_dirs = clean_dirs.into_iter().collect::<Vec<PathBuf>>();
    clean_dirs.sort_by(|a, b| b.cmp(a));

    for clean_dir in clean_dirs {
        if is_empty_dir(&clean_dir)? {
            std::fs::remove_dir(&clean_dir)
                .context(error::DirectoryRemoveSnafu { path: &clean_dir })?;
        }
    }

    Ok(())
}

/// Create an iterator over files matching the supplied filter.
fn find_files<P>(
    dir: P,
    filter: for<'r> fn(&'r walkdir::DirEntry) -> bool,
) -> impl Iterator<Item = PathBuf>
where
    P: AsRef<Path>,
{
    WalkDir::new(&dir)
        .follow_links(false)
        .same_file_system(true)
        .min_depth(1)
        .into_iter()
        .filter_entry(filter)
        .flat_map(|e| e.context(error::DirectoryWalkSnafu))
        .map(|e| e.into_path())
        .filter(|e| e.is_file() || e.is_symlink())
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Compute a per-checkout suffix for the tag to avoid collisions.
fn token(p: impl AsRef<Path>) -> String {
    let mut d = Sha512::new();
    d.update(p.as_ref().display().to_string());
    let digest = hex::encode(d.finalize());
    digest[..12].to_string()
}

/// Append the per-checkout suffix token to a Docker tag.
fn append_token(tag: impl AsRef<str>, p: impl AsRef<Path>) -> String {
    format!("{}-{}", tag.as_ref(), token(p))
}

/// Helper trait for constructing buildkit --build-arg arguments.
trait BuildArg {
    fn build_arg<S1, S2>(&mut self, key: S1, value: S2)
    where
        S1: AsRef<str>,
        S2: AsRef<str>;
}

impl BuildArg for Vec<String> {
    fn build_arg<S1, S2>(&mut self, key: S1, value: S2)
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        self.push("--build-arg".to_string());
        self.push(format!("{}={}", key.as_ref(), value.as_ref()));
    }
}

/// Helper trait for constructing buildkit --secret arguments.
trait BuildSecret {
    fn build_secret<S>(&mut self, typ: S, id: S, src: S)
    where
        S: AsRef<str>;
}

impl BuildSecret for Vec<String> {
    fn build_secret<S>(&mut self, typ: S, id: S, src: S)
    where
        S: AsRef<str>,
    {
        self.push("--secret".to_string());
        self.push(format!(
            "type={},id={},src={}",
            typ.as_ref(),
            id.as_ref(),
            src.as_ref()
        ));
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// Helper to extract the file name from a path.
fn filename(p: impl AsRef<Path>) -> String {
    let path = p.as_ref();
    path.file_name()
        .with_context(|| error::BadFilenameSnafu {
            path: PathBuf::from(path),
        })
        .unwrap()
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod test {
    use super::*;
    use semver::Version;

    #[test]
    fn test_docker_version_req_25_0_5_passes() {
        let version = Version::parse("25.0.5").unwrap();
        assert!(MINIMUM_DOCKER_VERSION.matches(&version))
    }

    #[test]
    fn test_docker_version_req_27_1_4_passes() {
        let version = Version::parse("27.1.4").unwrap();
        assert!(MINIMUM_DOCKER_VERSION.matches(&version))
    }

    #[test]
    fn test_docker_version_req_18_0_9_fails() {
        let version = Version::parse("18.0.9").unwrap();
        assert!(!MINIMUM_DOCKER_VERSION.matches(&version))
    }

    #[test]
    fn test_docker_version_req_20_10_27_fails() {
        let version = Version::parse("20.10.27").unwrap();
        assert!(!MINIMUM_DOCKER_VERSION.matches(&version))
    }
}
