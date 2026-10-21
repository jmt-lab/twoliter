use super::{
    check_twoliter_version, ensure_clean, fetch_source, git, read_release_version, run_build,
    shorten_hashes, wrap, REPROSYS_NOT_VERIFIED,
};
use crate::common::fs;
use crate::tools::install_tools;
use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use clap::Parser;
use oci_cli_wrapper::ImageTool;
use path_absolutize::Absolutize;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;
use tokio::process::Command;
use tracing::{info, warn};

const DEFAULT_REGISTRY: &str = "public.ecr.aws/bottlerocket";

/// Kits are cloned from `<DEFAULT_GITHUB_ORG>/<kit>` unless --repo is given.
const DEFAULT_GITHUB_ORG: &str = "https://github.com/bottlerocket-os";

/// Architectures kits are built for, with the name the OCI image index uses for each.
const ARCHES: &[(&str, &str)] = &[("x86_64", "amd64"), ("aarch64", "arm64")];

/// The architecture of the SDK Bottlerocket kits are built with, for every target architecture.
const DEFAULT_SDK_ARCH: &str = "x86_64";

/// The image config label prefix under which kits record their metadata; the metadata version is
/// appended to it.
const KIT_METADATA_LABEL_PREFIX: &str = "dev.bottlerocket.kit.";

/// Config fields not compared on their own. The layers they hash are compared individually.
const IGNORED_CONFIG_FIELDS: &[&str] = &["rootfs.diff_ids"];

/// The layer holding the kit's repository metadata.
const REPODATA: &str = "repodata";

/// The status of a comparison, most severe first. Only mismatches fail verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Status {
    Mismatch,
    Warning,
    ExpectedDifference,
    Match,
}

/// Rebuild a kit from source and compare it against the published kit image.
///
/// Needs Docker, git and make. The kit repository must build the kit with `make build`, as the
/// Bottlerocket kit repositories do, so that it is rebuilt with the twoliter version it pins.
#[derive(Debug, Parser)]
pub(crate) struct VerifyKit {
    /// The kit to verify, such as bottlerocket-core-kit. This is the image repository name the kit
    /// is published under.
    pub(crate) kit: String,

    /// The version of the kit to verify, such as 17.3.0.
    pub(crate) version: String,

    /// The container registry the kit is published to. The kit image is
    /// `<registry>/<kit>:v<version>`.
    #[clap(long, default_value = DEFAULT_REGISTRY)]
    pub(crate) registry: String,

    /// The git repository to clone the source from. Defaults to
    /// `https://github.com/bottlerocket-os/<kit>`. Conflicts with --source-dir.
    #[clap(long, conflicts_with = "source_dir")]
    pub(crate) repo: Option<String>,

    /// An existing clean clone of the source repository to build from. The kit's commit is
    /// checked out in it.
    #[clap(long = "source-dir")]
    pub(crate) source_dir: Option<PathBuf>,

    /// The commit the kit was built from. Defaults to the commit tagged `v<version>`.
    #[clap(long)]
    pub(crate) commit: Option<String>,

    /// An architecture to verify, x86_64 or aarch64. Can be given more than once. Defaults to
    /// every architecture the kit is published for.
    #[clap(long = "arch", value_parser = ["x86_64", "aarch64"])]
    pub(crate) arches: Vec<String>,

    /// The architecture of the SDK image to build with, x86_64 or aarch64. It must be the
    /// architecture of the host that built the published kit: the SDK image of each architecture
    /// holds its own build of the toolchains, which compile different code. Defaults to x86_64,
    /// which Bottlerocket kits are built on. On a host of another architecture, the SDK runs
    /// under emulation, which needs QEMU user-mode emulation registered with binfmt_misc and makes
    /// the build several times slower.
    #[clap(long = "sdk-arch", value_parser = ["x86_64", "aarch64"], default_value = DEFAULT_SDK_ARCH)]
    pub(crate) sdk_arch: String,

    /// Directory for the source checkout, kit images and report. Defaults to
    /// `./twoliter-verify-<kit>-v<version>`.
    #[clap(long = "work-dir")]
    pub(crate) work_dir: Option<PathBuf>,

    /// Keep the source checkout and kit images in the work directory when done. The report is
    /// always kept.
    #[clap(long)]
    pub(crate) keep: bool,

    /// Show the build output instead of writing it to `build-<arch>.log` in the work directory,
    /// and show full hashes in the summary.
    #[clap(long)]
    pub(crate) verbose: bool,
}

#[derive(Debug, Deserialize)]
struct Index {
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(deserialize_with = "deserialize_digest")]
    digest: String,
    platform: Option<Platform>,
}

/// Accept only SHA-256 digests, since digests name the blobs of an image layout.
fn deserialize_digest<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let digest = String::deserialize(deserializer)?;
    let valid = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    });
    if !valid {
        return Err(serde::de::Error::custom(format!(
            "'{digest}' is not a SHA-256 digest"
        )));
    }
    Ok(digest)
}

#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

/// The kit metadata recorded in the image config.
#[derive(Debug, Deserialize)]
struct KitMetadata {
    name: String,
    version: String,
}

/// The parts of Twoliter.lock that pin the SDK.
#[derive(Debug, Deserialize)]
struct Lock {
    sdk: LockedImage,
}

#[derive(Debug, Deserialize)]
struct LockedImage {
    source: String,
    /// The SHA-256 of the canonicalized image index, in base64.
    digest: String,
}

/// An OCI image layout on disk.
struct Layout {
    dir: PathBuf,
}

/// A published image to verify, and the image rebuilt from source.
struct ArchImages {
    arch: String,
    published: Layout,
    published_digest: String,
    rebuilt: Option<Layout>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Report {
    verdict: String,
    kit: String,
    version: String,
    image: String,
    commit: String,
    /// The architecture of the SDK image the kit was rebuilt with.
    sdk_arch: String,
    arches: Vec<ArchReport>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArchReport {
    arch: String,
    /// The digest of the published manifest.
    published: String,
    /// The digest of the rebuilt manifest.
    rebuilt: String,
    /// `match` when the manifests are identical, `expected-difference` when every difference is
    /// expected or a warning, and `mismatch` otherwise.
    status: Status,
    /// Layers identical in both images.
    identical_layers: usize,
    differences: Vec<Difference>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Difference {
    /// `config`, `manifest`, or the directory a layer holds, such as `Packages/glibc`.
    item: String,
    /// The most severe status of its files: `mismatch`, `warning` or `expected-difference`.
    status: Status,
    detail: String,
    #[serde(default)]
    files: Vec<FileDifference>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileDifference {
    path: String,
    status: Status,
    detail: String,
    /// For a package, how its header differs, apart from the tags derived from its payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    header: Vec<String>,
    /// For a package, the payload files that differ.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    payload: Vec<PayloadFile>,
    /// Whether the file is in both images, under the same name or renamed with its checksum, and
    /// differs only in its contents.
    #[serde(skip)]
    contents_only: bool,
}

/// The output of `reprosys compare-rpm`.
#[derive(Debug, Deserialize)]
struct PackageReport {
    status: Status,
    detail: String,
    #[serde(default)]
    header: Vec<String>,
    #[serde(default)]
    files: Vec<PayloadFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PayloadFile {
    path: String,
    status: Status,
    detail: String,
}

/// Compares a rebuilt package against the published one.
type ComparePackage<'a> = &'a dyn Fn(&Path, &Path) -> Result<PackageReport>;

/// The layers of an image keyed by the directory each holds, with each layer's digest and entries.
type Layers = BTreeMap<String, (String, BTreeMap<String, Entry>)>;

/// A tar entry in a layer.
#[derive(Debug, PartialEq)]
struct Entry {
    kind: String,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    size: u64,
    link: Option<String>,
    sha256: Option<String>,
}

impl VerifyKit {
    pub(super) async fn run(&self) -> Result<()> {
        for tool in ["git", "make", "docker"] {
            which::which(tool)
                .with_context(|| format!("'{tool}' is required but not found in PATH"))?;
        }
        let version = self.version.trim_start_matches('v');
        Version::parse(version)
            .with_context(|| format!("'{}' is not a valid kit version", self.version))?;

        let work_dir = match &self.work_dir {
            Some(dir) => dir.clone(),
            None => PathBuf::from(format!("twoliter-verify-{}-v{version}", self.kit)),
        };
        let work_dir = work_dir.absolutize()?.into_owned();
        fs::create_dir_all(&work_dir).await?;

        let tools = TempDir::new().context("Unable to create a directory for tools")?;
        install_tools(tools.path()).await?;
        let reprosys = tools.path().join("reprosys");

        let image_tool = ImageTool::from_builtin_krane();
        let repository = format!("{}/{}", self.registry, self.kit);
        let image = format!("{repository}:v{version}");
        let index: Index = serde_json::from_slice(
            &image_tool
                .get_manifest(&image)
                .await
                .with_context(|| format!("Unable to fetch the image index of '{image}'"))?,
        )
        .with_context(|| format!("'{image}' is not a multi-platform kit image"))?;
        let mut published = BTreeMap::new();
        for manifest in index.manifests {
            let Some(platform) = manifest.platform else {
                warn!(
                    "Ignoring manifest {} in '{image}', which has no platform",
                    manifest.digest
                );
                continue;
            };
            match ARCHES
                .iter()
                .find(|(_, docker)| *docker == platform.architecture)
            {
                Some((arch, _)) => {
                    // Consumers use the first manifest for an architecture, so verifying another
                    // one would not cover what they get.
                    ensure!(
                        published
                            .insert(arch.to_string(), manifest.digest)
                            .is_none(),
                        "'{image}' lists more than one manifest for {arch}"
                    );
                }
                None => warn!(
                    "Ignoring '{image}' for unknown architecture {}",
                    platform.architecture
                ),
            }
        }
        let arches: Vec<String> = if self.arches.is_empty() {
            published.keys().cloned().collect()
        } else {
            self.arches.clone()
        };
        ensure!(!arches.is_empty(), "'{image}' has no kit images");

        // Download the published images first: their metadata names the kit to build and dates
        // the commit, which catches a wrong commit before a long build.
        let images_dir = work_dir.join("images");
        let mut images = Vec::new();
        for arch in &arches {
            let digest = published.get(arch).with_context(|| {
                format!(
                    "'{image}' is not published for {arch}; it has {:?}",
                    published.keys()
                )
            })?;
            let layout = Layout {
                dir: images_dir.join(arch).join("published"),
            };
            info!("Downloading the published {arch} kit {repository}@{digest}");
            if layout.dir.exists() {
                fs::remove_dir_all(&layout.dir).await?;
            }
            fs::create_dir_all(&layout.dir).await?;
            image_tool
                .pull_oci_image(&layout.dir, &format!("{repository}@{digest}"))
                .await
                .with_context(|| format!("Unable to download the published {arch} kit"))?;
            let bytes = fs::read(layout.blob(digest)).await?;
            ensure!(
                sha256_digest(&bytes) == *digest,
                "The downloaded {arch} manifest does not match its digest {digest}"
            );
            images.push(ArchImages {
                arch: arch.clone(),
                published: layout,
                published_digest: digest.clone(),
                rebuilt: None,
            });
        }

        let config = images[0]
            .published
            .config(&images[0].published_digest)
            .await?;
        let metadata = kit_metadata(&config)?;
        ensure!(
            metadata.version == version,
            "'{image}' holds version {} of kit {}, not {version}",
            metadata.version,
            metadata.name
        );
        if metadata.name != self.kit {
            info!("'{image}' holds kit {}", metadata.name);
        }

        let (source_dir, cloned) = match &self.source_dir {
            Some(dir) => (dir.absolutize()?.into_owned(), false),
            None => (work_dir.join("source"), true),
        };
        let default_repo = format!("{DEFAULT_GITHUB_ORG}/{}", self.kit);
        let repo = self.repo.as_deref().unwrap_or(&default_repo);
        let commit = prepare_source(
            &source_dir,
            cloned.then_some(repo),
            self.commit.as_deref(),
            version,
        )
        .await?;
        ensure!(
            source_dir.join("Makefile").is_file(),
            "'{}' has no Makefile; kits are rebuilt with `make build`",
            source_dir.display()
        );
        ensure!(
            source_dir
                .join("kits")
                .join(&metadata.name)
                .join("Cargo.toml")
                .is_file(),
            "Kit {} is not in '{}'",
            metadata.name,
            source_dir.join("kits").display()
        );
        let reproducible = check_twoliter_version(&source_dir).await?;
        check_commit_time(&source_dir, &commit, &config, reproducible).await?;

        // The build ID buildsys names the kit archive with.
        let build_id = git(
            &source_dir,
            &[
                "describe",
                "--always",
                "--dirty",
                "--exclude",
                "*",
                "--abbrev=8",
            ],
        )
        .await?;
        let sdk = Sdk::load(&image_tool, &source_dir, &self.sdk_arch).await?;
        let mut build_logs = Vec::new();
        let build = async {
            for images in &mut images {
                let arch = &images.arch;
                let log = (!self.verbose).then(|| work_dir.join(format!("build-{arch}.log")));
                let mut cmd = Command::new("make");
                cmd.arg("build")
                    .arg(format!("KIT={}", metadata.name))
                    .arg(format!("ARCH={arch}"))
                    // The platform of the SDK images the build runs.
                    .env("DOCKER_DEFAULT_PLATFORM", &sdk.platform);
                run_build(
                    cmd,
                    &source_dir,
                    log.as_deref(),
                    &format!("{} {arch}", metadata.name),
                )
                .await?;
                build_logs.extend(log);

                let archive = source_dir
                    .join("build/kits")
                    .join(&metadata.name)
                    .join(format!(
                        "{}-v{version}-{build_id}-{arch}.tar",
                        metadata.name
                    ));
                ensure!(
                    archive.is_file(),
                    "The build did not produce '{}'",
                    archive.display()
                );
                let layout = Layout {
                    dir: images_dir.join(arch).join("rebuilt"),
                };
                layout.unpack(&archive).await?;
                images.rebuilt = Some(layout);
            }
            Ok::<_, anyhow::Error>(())
        };
        // Stop the build on Ctrl-C rather than exiting, so that the SDK tag is restored.
        let built = tokio::select! {
            built = build => built,
            _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("Interrupted")),
        };
        drop(sdk);
        built?;

        let mut arch_reports = Vec::new();
        let packages_dir = images_dir.join("packages");
        for images in images {
            let rebuilt = images.rebuilt.context("Kit was not rebuilt")?;
            let published = images.published;
            let published_digest = images.published_digest;
            let arch = images.arch;
            let (reprosys, packages_dir) = (reprosys.clone(), packages_dir.clone());
            arch_reports.push(
                tokio::task::spawn_blocking(move || {
                    std::fs::create_dir_all(&packages_dir).with_context(|| {
                        format!("Unable to create '{}'", packages_dir.display())
                    })?;
                    let compare_package = |rebuilt: &Path, published: &Path| {
                        compare_package(&reprosys, rebuilt, published, &packages_dir)
                    };
                    compare(
                        arch,
                        &published,
                        published_digest,
                        &rebuilt,
                        &compare_package,
                        &packages_dir,
                    )
                })
                .await
                .context("Unable to join the comparison task")??,
            );
        }
        let verified = arch_reports.iter().all(|r| r.status != Status::Mismatch);
        let report = Report {
            verdict: if verified { "verified" } else { "failed" }.to_string(),
            kit: metadata.name,
            version: version.to_string(),
            image: image.clone(),
            commit: commit.clone(),
            sdk_arch: self.sdk_arch.clone(),
            arches: arch_reports,
        };
        let report_path = work_dir.join("report.json");
        fs::write(&report_path, serde_json::to_string_pretty(&report)?).await?;
        print!("{}", summary(&report, self.verbose));
        println!("Report:    {}", report_path.display());
        for log in &build_logs {
            println!("Build log: {}", log.display());
        }

        if !self.keep {
            let mut cleanup = vec![&images_dir];
            if cloned {
                cleanup.push(&source_dir);
            }
            for dir in cleanup {
                if let Err(e) = fs::remove_dir_all(dir).await {
                    warn!("Unable to clean up '{}': {e:#}", dir.display());
                }
            }
        }

        ensure!(
            verified,
            "Kit '{image}' could not be verified as built from commit {commit}"
        );
        println!("Kit '{image}' was verified as built from commit {commit}");
        Ok(())
    }
}

/// Check out the commit the kit was built from, cloning `repo` first if given, and return it.
async fn prepare_source(
    dir: &Path,
    repo: Option<&str>,
    commit: Option<&str>,
    version: &str,
) -> Result<String> {
    if let Some(repo) = repo {
        fetch_source(dir, repo).await?;
    }
    ensure_clean(dir).await?;

    let tag = format!("v{version}");
    let rev_parse = |rev: String| async move {
        git(
            dir,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{rev}^{{commit}}"),
            ],
        )
        .await
    };
    let tagged = rev_parse(tag.clone()).await.ok();
    let commit = match commit {
        Some(commit) => {
            let resolved = rev_parse(commit.to_string()).await.with_context(|| {
                format!(
                    "Commit {commit} is not in '{}', or the abbreviation is ambiguous",
                    dir.display()
                )
            })?;
            match &tagged {
                Some(tagged) if *tagged == resolved => info!("Tag {tag} points at {resolved}"),
                Some(tagged) => warn!("Tag {tag} points at {tagged}, not at {resolved}"),
                None => warn!("Tag {tag} does not exist in the source repository"),
            }
            resolved
        }
        None => tagged.with_context(|| {
            format!(
                "Tag {tag} does not exist in '{}'; pass the commit the kit was built from with \
                 --commit",
                dir.display()
            )
        })?,
    };
    if repo.is_none() {
        warn!("Checking out commit {commit} in '{}'", dir.display());
    }
    git(dir, &["checkout", "--quiet", "--detach", &commit]).await?;
    info!("Checked out commit {commit}");

    let release_version = read_release_version(dir).await?;
    ensure!(
        release_version == version,
        "Commit {commit} has release version {release_version}, but the kit is version {version}"
    );
    Ok(commit)
}

/// Fail when the published kit was not created at the commit's time.
///
/// Reproducible kit builds set the image creation time to the time of the commit they build, so a
/// different time means the kit was built from another commit, and the rebuild cannot match.
/// Older builds used the build time, so for them a different time is only reported.
async fn check_commit_time(
    dir: &Path,
    commit: &str,
    config: &Value,
    reproducible: bool,
) -> Result<()> {
    let Some(created) = config.get("created").and_then(Value::as_str) else {
        warn!("The published kit has no creation time; unable to check its commit");
        return Ok(());
    };
    let seconds: i64 = git(dir, &["show", "-s", "--format=%ct", commit])
        .await?
        .parse()
        .context("Unable to parse the commit time")?;
    let committed = rfc3339(seconds);
    if !reproducible {
        if created != committed {
            warn!("The published kit was created at {created}, not at the time of commit {commit}");
        }
        return Ok(());
    }
    ensure!(
        created == committed,
        "The published kit was created at {created}, but commit {commit} is from {committed}, so \
         the kit was built from a different commit. Pass the commit it was built from with --commit."
    );
    info!("The published kit was created at the time of commit {commit}");
    Ok(())
}

/// The SDK image a kit is rebuilt with, loaded into Docker for one platform.
///
/// The build uses the SDK image Docker has under the name in Twoliter.lock, and only pulls one,
/// for the Docker host's platform, when there is none. Tagging that platform's image with the name
/// first, and setting `DOCKER_DEFAULT_PLATFORM` for the build, makes the build use it whatever
/// the host's architecture.
struct Sdk {
    /// The name the build uses, from Twoliter.lock.
    name: String,
    /// The Docker platform of the image, such as `linux/amd64`.
    platform: String,
    /// The ID of the image Docker had under `name` before, if any.
    previous: Option<String>,
}

impl Sdk {
    /// Pull the image of the SDK the checkout in `dir` pins for `sdk_arch`, and tag it with the
    /// name the build uses.
    async fn load(image_tool: &ImageTool, dir: &Path, sdk_arch: &str) -> Result<Self> {
        let path = dir.join("Twoliter.lock");
        let lock: Lock = toml::from_str(&fs::read_to_string(&path).await?)
            .with_context(|| format!("Unable to parse '{}'", path.display()))?;
        let locked = lock.sdk;
        let docker_arch = ARCHES
            .iter()
            .find(|(arch, _)| *arch == sdk_arch)
            .map(|(_, docker)| *docker)
            .with_context(|| format!("Unknown SDK architecture {sdk_arch}"))?;
        let platform = format!("linux/{docker_arch}");

        // Twoliter.lock records the digest of the image index as twoliter fetches it, which is
        // not the registry's digest. Fetch it the same way to check that the name still points
        // at the locked SDK, then pull the platform's image by the digest the index lists.
        let index_bytes = image_tool
            .get_manifest(&locked.source)
            .await
            .with_context(|| format!("Unable to fetch the image index of '{}'", locked.source))?;
        let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&index_bytes));
        ensure!(
            digest == locked.digest,
            "The SDK '{}' has digest {digest}, but Twoliter.lock pins {}",
            locked.source,
            locked.digest
        );
        let index: Index = serde_json::from_slice(&index_bytes)
            .with_context(|| format!("'{}' is not a multi-platform image", locked.source))?;
        let manifest = index
            .manifests
            .iter()
            .find(|m| {
                m.platform
                    .as_ref()
                    .is_some_and(|p| p.architecture == docker_arch)
            })
            .with_context(|| format!("The SDK '{}' has no {sdk_arch} image", locked.source))?;
        let pinned = format!("{}@{}", image_repository(&locked.source), manifest.digest);

        info!("Pulling the {sdk_arch} SDK {pinned}");
        docker(&["pull", "--quiet", "--platform", &platform, &pinned]).await?;
        let host_arch = docker(&["version", "--format", "{{.Server.Arch}}"]).await?;
        if host_arch != docker_arch {
            info!(
                "The Docker host is {host_arch}, so the {sdk_arch} SDK runs under emulation and \
                 the build takes several times longer"
            );
            docker(&[
                "run",
                "--rm",
                "--platform",
                &platform,
                "--entrypoint",
                "true",
                &pinned,
            ])
            .await
            .with_context(|| {
                format!(
                    "Unable to run the {sdk_arch} SDK on this {host_arch} host. It needs QEMU \
                     user-mode emulation registered with binfmt_misc, for example with `docker \
                     run --privileged --rm tonistiigi/binfmt --install {docker_arch}`. If the kit \
                     was built on a {host_arch} host, pass --sdk-arch instead."
                )
            })?;
        }

        let previous = image_id(&locked.source).await;
        docker(&["tag", &pinned, &locked.source]).await?;
        Ok(Self {
            name: locked.source,
            platform,
            previous,
        })
    }
}

impl Drop for Sdk {
    /// Give the name back to the image Docker had under it before, or remove it if there was none,
    /// so that later builds on this host use their own platform's SDK again.
    fn drop(&mut self) {
        let args = match &self.previous {
            Some(id) => vec!["tag", id, &self.name],
            None => vec!["rmi", &self.name],
        };
        let restored = std::process::Command::new("docker")
            .args(&args)
            .stdout(Stdio::null())
            .status();
        match restored {
            Ok(status) if status.success() => {}
            Ok(status) => warn!(
                "Unable to restore the SDK image '{}': 'docker {}' failed with {status}",
                self.name,
                args.join(" ")
            ),
            Err(e) => warn!("Unable to restore the SDK image '{}': {e}", self.name),
        }
    }
}

/// The ID of the image Docker has under `name`, if any.
async fn image_id(name: &str) -> Option<String> {
    let output = Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", name])
        .stderr(Stdio::null())
        .output()
        .await
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The repository of an image reference, without its tag or digest.
fn image_repository(image: &str) -> &str {
    let image = image
        .split_once('@')
        .map_or(image, |(repository, _)| repository);
    match image.rsplit_once(':') {
        // A colon followed by a slash separates a registry's port, not a tag.
        Some((repository, tag)) if !tag.contains('/') => repository,
        _ => image,
    }
}

async fn docker(args: &[&str]) -> Result<String> {
    let output = Command::new("docker")
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .await
        .context("Unable to run docker")?;
    ensure!(
        output.status.success(),
        "'docker {}' failed",
        args.join(" ")
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Read the kit metadata from the label of an image config.
fn kit_metadata(config: &Value) -> Result<KitMetadata> {
    let labels = config
        .pointer("/config/Labels")
        .and_then(Value::as_object)
        .context("The kit image config has no labels")?;
    let encoded = labels
        .iter()
        .find(|(label, _)| label.starts_with(KIT_METADATA_LABEL_PREFIX))
        .and_then(|(_, value)| value.as_str())
        .context("The image has no kit metadata label; it does not appear to be a kit")?;
    let metadata: KitMetadata =
        serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(encoded.trim())?)
            .context("Unable to parse the kit metadata")?;
    // The name is used in paths and make arguments.
    let name = &metadata.name;
    ensure!(
        name.starts_with(|c: char| c.is_ascii_alphanumeric())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
        "The kit metadata names kit '{name}', which is not a valid kit name"
    );
    Ok(metadata)
}

impl Layout {
    fn blob(&self, digest: &str) -> PathBuf {
        self.dir
            .join("blobs")
            .join(digest.replace(':', std::path::MAIN_SEPARATOR_STR))
    }

    async fn config(&self, manifest_digest: &str) -> Result<Value> {
        let manifest: Manifest = read_json(&self.blob(manifest_digest)).await?;
        read_json(&self.blob(&manifest.config.digest)).await
    }

    /// The digest of the single manifest in the layout's index.
    fn manifest_digest(&self) -> Result<String> {
        let index: Index = read_json_sync(&self.dir.join("index.json"))?;
        match index.manifests.as_slice() {
            [manifest] => Ok(manifest.digest.clone()),
            manifests => bail!(
                "Expected one manifest in '{}', found {}",
                self.dir.display(),
                manifests.len()
            ),
        }
    }

    async fn unpack(&self, archive: &Path) -> Result<()> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).await?;
        }
        fs::create_dir_all(&self.dir).await?;
        let (archive, dir) = (archive.to_path_buf(), self.dir.clone());
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(&archive)
                .with_context(|| format!("Unable to open '{}'", archive.display()))?;
            tar::Archive::new(file)
                .unpack(&dir)
                .with_context(|| format!("Unable to unpack '{}'", archive.display()))
        })
        .await
        .context("Unable to join the unpack task")?
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).await?)
        .with_context(|| format!("Unable to parse '{}'", path.display()))
}

fn read_json_sync<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Unable to read '{}'", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("Unable to parse '{}'", path.display()))
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Compare the rebuilt image of one architecture against the published one.
///
/// Identical manifest digests verify the image, since the manifest hashes the config and every
/// layer. Otherwise the config and layers are compared to explain the difference, and each package
/// whose bytes differ is compared by header and payload with `compare_package`, after extracting
/// both copies into `packages_dir`.
fn compare(
    arch: String,
    published: &Layout,
    published_digest: String,
    rebuilt: &Layout,
    compare_package: ComparePackage,
    packages_dir: &Path,
) -> Result<ArchReport> {
    let rebuilt_digest = rebuilt.manifest_digest()?;
    let published_manifest: Manifest = read_json_sync(&published.blob(&published_digest))?;
    let rebuilt_manifest: Manifest = read_json_sync(&rebuilt.blob(&rebuilt_digest))?;
    if rebuilt_digest == published_digest {
        return Ok(ArchReport {
            arch,
            published: published_digest,
            rebuilt: rebuilt_digest,
            status: Status::Match,
            identical_layers: published_manifest.layers.len(),
            differences: Vec::new(),
        });
    }

    let mut differences = Vec::new();
    let published_config: Value =
        read_json_sync(&published.blob(&published_manifest.config.digest))?;
    let rebuilt_config: Value = read_json_sync(&rebuilt.blob(&rebuilt_manifest.config.digest))?;
    let config_differences = compare_configs(&rebuilt_config, &published_config);
    if !config_differences.is_empty() {
        differences.push(Difference {
            item: "config".to_string(),
            status: Status::Mismatch,
            detail: config_differences.join("; "),
            files: Vec::new(),
        });
    }

    let published_layers = read_layers(published, &published_manifest)?;
    let rebuilt_layers = read_layers(rebuilt, &rebuilt_manifest)?;
    let names: BTreeSet<&String> = published_layers
        .keys()
        .chain(rebuilt_layers.keys())
        .collect();
    let mut identical_layers = 0;
    for name in names {
        let difference = |status, detail: String, files| Difference {
            item: name.clone(),
            status,
            detail,
            files,
        };
        match (rebuilt_layers.get(name), published_layers.get(name)) {
            (Some(rebuilt_layer), Some(published_layer))
                if rebuilt_layer.0 == published_layer.0 =>
            {
                identical_layers += 1
            }
            (Some(rebuilt_layer), Some(published_layer)) => {
                let extract_package = |path: &str| {
                    let rebuilt_package = packages_dir.join("rebuilt.rpm");
                    let published_package = packages_dir.join("published.rpm");
                    extract_entry(&rebuilt.blob(&rebuilt_layer.0), path, &rebuilt_package)?;
                    extract_entry(
                        &published.blob(&published_layer.0),
                        path,
                        &published_package,
                    )?;
                    let report = compare_package(&rebuilt_package, &published_package);
                    for package in [rebuilt_package, published_package] {
                        std::fs::remove_file(&package)
                            .with_context(|| format!("Unable to remove '{}'", package.display()))?;
                    }
                    report
                };
                let files = compare_entries(
                    &rebuilt_layer.1,
                    &published_layer.1,
                    name == REPODATA,
                    &extract_package,
                )?;
                let detail = format!("layer {} vs {}", rebuilt_layer.0, published_layer.0);
                // A layer can differ without any of its entries differing, such as in their order.
                let status = files
                    .iter()
                    .map(|f| f.status)
                    .min()
                    .unwrap_or(Status::Mismatch);
                differences.push(difference(status, detail, files));
            }
            (Some(_), None) => differences.push(difference(
                Status::Mismatch,
                "only in the rebuilt kit".to_string(),
                Vec::new(),
            )),
            (None, Some(_)) => differences.push(difference(
                Status::Mismatch,
                "only in the published kit".to_string(),
                Vec::new(),
            )),
            (None, None) => unreachable!("layer names come from either image"),
        }
    }
    expect_repodata(&mut differences);

    // Report a difference even when the config and layers match, so a failure is always explained.
    if differences.is_empty() {
        let digests = |manifest: &Manifest| {
            manifest
                .layers
                .iter()
                .map(|l| l.digest.clone())
                .collect::<Vec<_>>()
        };
        let detail = if digests(&rebuilt_manifest) != digests(&published_manifest) {
            "the layers are identical but in a different order"
        } else {
            "the manifests differ, but their config and layers are identical"
        };
        differences.push(Difference {
            item: "manifest".to_string(),
            status: Status::Mismatch,
            detail: detail.to_string(),
            files: Vec::new(),
        });
    }

    let status = if differences.iter().any(|d| d.status == Status::Mismatch) {
        Status::Mismatch
    } else {
        Status::ExpectedDifference
    };
    Ok(ArchReport {
        arch,
        published: published_digest,
        rebuilt: rebuilt_digest,
        status,
        identical_layers,
        differences,
    })
}

/// Treat the repository metadata as an expected difference when some package differs, and every
/// difference besides it is expected. It records the checksum of each package, and names its
/// files by their own checksums, so it changes whenever a package does. Its files may differ in
/// contents, and be renamed with their checksum; any other difference still fails.
fn expect_repodata(differences: &mut [Difference]) {
    let others: Vec<&Difference> = differences.iter().filter(|d| d.item != REPODATA).collect();
    let others_expected = others.iter().all(|d| d.status != Status::Mismatch);
    let no_others = others.is_empty();
    let Some(repodata) = differences.iter_mut().find(|d| d.item == REPODATA) else {
        return;
    };
    if no_others {
        repodata
            .detail
            .push_str("; no package differs, so the repository metadata should not either");
        return;
    }
    if !others_expected {
        repodata.detail.push_str(
            "; the repository metadata records the packages, which differ in ways not expected",
        );
        return;
    }
    for file in repodata.files.iter_mut().filter(|f| f.contents_only) {
        file.status = Status::ExpectedDifference;
    }
    repodata.status = repodata
        .files
        .iter()
        .map(|f| f.status)
        .min()
        .unwrap_or(Status::Mismatch);
    if repodata.status == Status::ExpectedDifference {
        repodata.detail.push_str(
            "; the repository metadata records the packages, which differ only in expected ways",
        );
    }
}

/// Compare two packages with `reprosys compare-rpm`, unpacking their payloads in `work_dir`.
fn compare_package(
    reprosys: &Path,
    rebuilt: &Path,
    published: &Path,
    work_dir: &Path,
) -> Result<PackageReport> {
    // Spawn explicitly so reprosys diagnostics remain visible.
    let output = std::process::Command::new(reprosys)
        .arg("compare-rpm")
        .arg("--expected")
        .arg(rebuilt)
        .arg("--actual")
        .arg(published)
        .arg("--work-dir")
        .arg(work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Unable to run reprosys")?
        .wait_with_output()
        .context("Unable to wait for reprosys")?;
    let code = output.status.code();
    ensure!(
        output.status.success() || code == Some(REPROSYS_NOT_VERIFIED),
        "reprosys compare-rpm failed with exit code {}",
        code.unwrap_or(-1)
    );
    serde_json::from_slice(&output.stdout).context("Unable to parse 'reprosys compare-rpm' output")
}

/// Extract the file `name` from a layer to `dest`.
fn extract_entry(layer: &Path, name: &str, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(layer)
        .with_context(|| format!("Unable to open '{}'", layer.display()))?;
    let mut archive = tar::Archive::new(file);
    for entry in archive
        .entries()
        .with_context(|| format!("Unable to read '{}'", layer.display()))?
    {
        let mut entry = entry.with_context(|| format!("Unable to read '{}'", layer.display()))?;
        if entry.path()?.to_string_lossy() != name {
            continue;
        }
        let mut out = std::fs::File::create(dest)
            .with_context(|| format!("Unable to create '{}'", dest.display()))?;
        std::io::copy(&mut entry, &mut out)
            .with_context(|| format!("Unable to extract '{name}' from '{}'", layer.display()))?;
        return Ok(());
    }
    bail!("'{name}' is not in '{}'", layer.display())
}

/// Describe each config field that differs, as `field: rebuilt <value>, published <value>`.
fn compare_configs(rebuilt: &Value, published: &Value) -> Vec<String> {
    let (mut rebuilt_fields, mut published_fields) = (BTreeMap::new(), BTreeMap::new());
    flatten("", &decode_metadata(rebuilt), &mut rebuilt_fields);
    flatten("", &decode_metadata(published), &mut published_fields);
    let fields: BTreeSet<&String> = rebuilt_fields
        .keys()
        .chain(published_fields.keys())
        .collect();
    let missing = "(none)".to_string();
    fields
        .into_iter()
        .filter(|field| {
            !IGNORED_CONFIG_FIELDS
                .iter()
                .any(|ignored| field.starts_with(ignored))
        })
        .filter_map(|field| {
            let rebuilt = rebuilt_fields.get(field).unwrap_or(&missing);
            let published = published_fields.get(field).unwrap_or(&missing);
            (rebuilt != published)
                .then(|| format!("{field}: rebuilt {rebuilt}, published {published}"))
        })
        .collect()
}

/// Replace the base64-encoded kit metadata label with the metadata it encodes, so that its
/// fields are compared individually.
fn decode_metadata(config: &Value) -> Value {
    let mut config = config.clone();
    if let Some(labels) = config
        .pointer_mut("/config/Labels")
        .and_then(Value::as_object_mut)
    {
        for (label, value) in labels.iter_mut() {
            if !label.starts_with(KIT_METADATA_LABEL_PREFIX) {
                continue;
            }
            let decoded = value
                .as_str()
                .and_then(|v| {
                    base64::engine::general_purpose::STANDARD
                        .decode(v.trim())
                        .ok()
                })
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
            if let Some(decoded) = decoded {
                *value = decoded;
            }
        }
    }
    config
}

fn flatten(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
    let key = |name: &str| {
        if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        }
    };
    match value {
        Value::Object(map) => {
            for (name, value) in map {
                flatten(&key(name), value, out);
            }
        }
        Value::Array(items) => {
            for (i, value) in items.iter().enumerate() {
                flatten(&key(&i.to_string()), value, out);
            }
        }
        value => {
            out.insert(prefix.to_string(), value.to_string());
        }
    }
}

/// Read each layer of an image, keyed by the directory it holds: `Packages/<package>` or
/// `repodata`. The value is the layer's digest and its entries.
fn read_layers(layout: &Layout, manifest: &Manifest) -> Result<Layers> {
    let mut layers = BTreeMap::new();
    for layer in &manifest.layers {
        let path = layout.blob(&layer.digest);
        let entries = read_entries(&path)?;
        // Every entry is under the layer's directory, which sorts first.
        let name = entries
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| layer.digest.clone());
        if layers.contains_key(&name) {
            layers.insert(layer.digest.clone(), (layer.digest.clone(), entries));
        } else {
            layers.insert(name, (layer.digest.clone(), entries));
        }
    }
    Ok(layers)
}

fn read_entries(path: &Path) -> Result<BTreeMap<String, Entry>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Unable to open '{}'", path.display()))?;
    let mut archive = tar::Archive::new(file);
    let mut entries = BTreeMap::new();
    for entry in archive
        .entries()
        .with_context(|| format!("Unable to read '{}'", path.display()))?
    {
        let mut entry = entry.with_context(|| format!("Unable to read '{}'", path.display()))?;
        let name = entry
            .path()?
            .to_string_lossy()
            .trim_end_matches('/')
            .to_string();
        let header = entry.header();
        let kind = header.entry_type();
        let mut info = Entry {
            kind: format!("{kind:?}"),
            mode: header.mode()?,
            uid: header.uid()?,
            gid: header.gid()?,
            mtime: header.mtime()?,
            size: header.size()?,
            link: entry
                .link_name()?
                .map(|link| link.to_string_lossy().into_owned()),
            sha256: None,
        };
        if kind.is_file() {
            let mut hasher = Sha256::new();
            std::io::copy(&mut entry, &mut hasher)
                .with_context(|| format!("Unable to read '{name}' in '{}'", path.display()))?;
            info.sha256 = Some(format!("{:x}", hasher.finalize()));
        }
        // Unpacking a layer keeps the last of several entries for a path, and extracting a
        // package from it takes the first.
        ensure!(
            !entries.contains_key(&name),
            "'{name}' appears more than once in '{}'",
            path.display()
        );
        entries.insert(name, info);
    }
    Ok(entries)
}

/// Compare the entries of two layers. Packages whose contents differ are compared by header and
/// payload with `compare_package`, given their path. With `checksum_named`, a file named by its
/// checksum that is renamed with it is compared against its renamed counterpart.
fn compare_entries(
    rebuilt: &BTreeMap<String, Entry>,
    published: &BTreeMap<String, Entry>,
    checksum_named: bool,
    compare_package: &dyn Fn(&str) -> Result<PackageReport>,
) -> Result<Vec<FileDifference>> {
    let renames = if checksum_named {
        checksum_renames(rebuilt, published)
    } else {
        BTreeMap::new()
    };
    let renamed: BTreeSet<&String> = renames.values().collect();
    let paths: BTreeSet<&String> = rebuilt.keys().chain(published.keys()).collect();
    let mut files = Vec::new();
    for path in paths {
        if renamed.contains(path) {
            continue;
        }
        let published_path = renames.get(path).unwrap_or(path);
        let mut file = FileDifference {
            path: path.clone(),
            status: Status::Mismatch,
            detail: String::new(),
            header: Vec::new(),
            payload: Vec::new(),
            contents_only: false,
        };
        let (rebuilt, published) = match (rebuilt.get(path), published.get(published_path)) {
            (Some(rebuilt), Some(published)) => (rebuilt, published),
            (rebuilt, _) => {
                file.detail = if rebuilt.is_some() {
                    "only in the rebuilt kit"
                } else {
                    "only in the published kit"
                }
                .to_string();
                files.push(file);
                continue;
            }
        };
        let mut differences = attribute_differences(rebuilt, published);
        file.contents_only = differences.is_empty();
        if published_path != path {
            differences.insert(0, format!("renamed to {published_path}"));
        }
        if rebuilt.sha256 != published.sha256 {
            let packages = rebuilt.sha256.is_some()
                && published.sha256.is_some()
                && published_path == path
                && path.ends_with(".rpm");
            if packages {
                let package = compare_package(path)?;
                if file.contents_only {
                    file.status = package.status;
                }
                differences.push(package.detail);
                file.header = package.header;
                file.payload = package.files;
            } else {
                let describe = |entry: &Entry| match &entry.sha256 {
                    Some(sha256) => format!("{} bytes, sha256 {sha256}", entry.size),
                    None => "no contents".to_string(),
                };
                differences.push(format!(
                    "contents differ ({} vs {})",
                    describe(rebuilt),
                    describe(published)
                ));
            }
        }
        if !differences.is_empty() {
            file.detail = differences.join("; ");
            files.push(file);
        }
    }
    Ok(files)
}

/// Pair the files named `<checksum>-<name>` that are in only one of the layers, when each layer
/// has exactly one such file of that name in the same directory. Returns the published path of
/// each paired rebuilt path.
fn checksum_renames(
    rebuilt: &BTreeMap<String, Entry>,
    published: &BTreeMap<String, Entry>,
) -> BTreeMap<String, String> {
    let by_name = |ours: &BTreeMap<String, Entry>, theirs: &BTreeMap<String, Entry>| {
        let mut names: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for path in ours.keys().filter(|path| !theirs.contains_key(*path)) {
            let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
            let Some((checksum, name)) = file.split_once('-') else {
                continue;
            };
            if !checksum.is_empty()
                && checksum
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                names
                    .entry((dir.to_string(), name.to_string()))
                    .or_default()
                    .push(path.clone());
            }
        }
        names
    };
    let published_names = by_name(published, rebuilt);
    by_name(rebuilt, published)
        .into_iter()
        .filter_map(|(name, rebuilt_paths)| {
            match (
                rebuilt_paths.as_slice(),
                published_names.get(&name)?.as_slice(),
            ) {
                ([rebuilt_path], [published_path]) => {
                    Some((rebuilt_path.clone(), published_path.clone()))
                }
                _ => None,
            }
        })
        .collect()
}

/// Describe how two tar entries differ apart from their contents, rebuilt first.
fn attribute_differences(rebuilt: &Entry, published: &Entry) -> Vec<String> {
    let mut differences = Vec::new();
    if rebuilt.kind != published.kind {
        differences.push(format!("type {} vs {}", rebuilt.kind, published.kind));
    }
    if rebuilt.mode != published.mode {
        differences.push(format!("mode {:o} vs {:o}", rebuilt.mode, published.mode));
    }
    if (rebuilt.uid, rebuilt.gid) != (published.uid, published.gid) {
        differences.push(format!(
            "owner {}:{} vs {}:{}",
            rebuilt.uid, rebuilt.gid, published.uid, published.gid
        ));
    }
    if rebuilt.mtime != published.mtime {
        differences.push(format!(
            "mtime {} vs {}",
            rfc3339(rebuilt.mtime as i64),
            rfc3339(published.mtime as i64)
        ));
    }
    if rebuilt.link != published.link {
        differences.push(format!(
            "link target {} vs {}",
            rebuilt.link.as_deref().unwrap_or("(none)"),
            published.link.as_deref().unwrap_or("(none)")
        ));
    }
    differences
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`, the form kit builds record times in.
fn rfc3339(seconds: i64) -> String {
    let (days, time) = (seconds.div_euclid(86400), seconds.rem_euclid(86400));
    // Civil date from days since 1970-01-01, after Howard Hinnant's `civil_from_days`.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

/// The summary's marker for a status.
fn marker(status: Status) -> &'static str {
    match status {
        Status::Match => "ok",
        Status::ExpectedDifference => "note",
        Status::Warning => "warn",
        Status::Mismatch => "FAIL",
    }
}

/// Render the comparison report for the terminal. Expected differences are counted rather than
/// listed unless `verbose` is set.
fn summary(report: &Report, verbose: bool) -> String {
    let shorten = |text: &str| {
        if verbose {
            text.to_string()
        } else {
            shorten_hashes(text)
        }
    };
    let hidden_line = |indent: usize, hidden: usize| {
        let s = if hidden == 1 { "" } else { "s" };
        format!(
            "{}+ {hidden} expected difference{s} (shown with --verbose)",
            " ".repeat(indent)
        )
    };
    let mut out = vec![
        String::new(),
        format!(
            "Verification of {} v{} ({}, commit {}, rebuilt with the {} SDK)",
            report.kit, report.version, report.image, report.commit, report.sdk_arch
        ),
    ];
    for arch in &report.arches {
        out.push(String::new());
        out.push(arch.arch.clone());
        if arch.status == Status::Match {
            out.push(format!(
                "  {:<5} {}",
                "ok",
                wrap(
                    &shorten(&format!(
                        "manifest {} identical, with {} layers",
                        arch.published, arch.identical_layers
                    )),
                    8
                )
            ));
            continue;
        }
        out.push(format!(
            "  {:<5} {}",
            marker(arch.status),
            wrap(
                &shorten(&format!(
                    "manifest {} vs published {}",
                    arch.rebuilt, arch.published
                )),
                8
            )
        ));
        // Failures first.
        let mut differences: Vec<&Difference> = arch.differences.iter().collect();
        differences.sort_by_key(|d| d.status);
        for difference in differences {
            out.push(format!(
                "  {:<5} {:<12} {}",
                marker(difference.status),
                difference.item,
                wrap(&shorten(&difference.detail), 21)
            ));
            let mut hidden = 0;
            for file in &difference.files {
                if file.status == Status::ExpectedDifference && !verbose {
                    hidden += 1;
                    continue;
                }
                out.push(format!("          {}", file.path));
                out.push(format!("            {}", wrap(&shorten(&file.detail), 12)));
                for line in &file.header {
                    out.push(format!("            header: {}", wrap(&shorten(line), 20)));
                }
                let mut hidden_payload = 0;
                for payload in &file.payload {
                    if payload.status == Status::ExpectedDifference && !verbose {
                        hidden_payload += 1;
                        continue;
                    }
                    out.push(format!("            {}", payload.path));
                    out.push(format!(
                        "              {:<5} {}",
                        marker(payload.status),
                        wrap(&shorten(&payload.detail), 20)
                    ));
                }
                if hidden_payload > 0 {
                    out.push(hidden_line(12, hidden_payload));
                }
            }
            if hidden > 0 {
                out.push(hidden_line(10, hidden));
            }
        }
        if arch.identical_layers > 0 {
            let s = if arch.identical_layers == 1 { "" } else { "s" };
            out.push(format!(
                "  {:<5} {} layer{s} identical",
                "ok", arch.identical_layers
            ));
        }
    }

    out.push(String::new());
    out.push(wrap(
        "Differences are shown as rebuilt vs published. A kit is verified when the manifest of \
         each architecture is identical to the published one, or when every difference is \
         expected. FAIL fails verification. note is an expected difference: a kernel module \
         that differs only in its signature, and the package and repository metadata that \
         record it. warn is a difference that the per-build module signing key can explain but \
         that is not checked: the kernel image and the signing certificate. Neither fails \
         verification.",
        0,
    ));
    out.push(String::new());
    let failed: Vec<&str> = report
        .arches
        .iter()
        .filter(|a| a.status == Status::Mismatch)
        .map(|a| a.arch.as_str())
        .collect();
    if report.verdict == "verified" {
        out.push("Result: VERIFIED".to_string());
    } else {
        out.push(format!(
            "Result: FAILED ({} differ{} from the rebuilt kit)",
            failed.join(", "),
            if failed.len() == 1 { "s" } else { "" }
        ));
    }
    out.push(String::new());
    out.join("\n")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A layer to write: the directory it holds, and the names and contents of its files.
    type LayerSpec<'a> = (&'a str, &'a [(&'a str, &'a [u8])]);

    const EPOCH: u64 = 1_792_536_015;

    /// Write an OCI layout like rpm2kit's, with one layer per directory in `layers`, each holding
    /// the given files and their contents.
    fn write_layout(dir: &Path, created: &str, layers: &[LayerSpec]) -> String {
        let blobs = dir.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        let write_blob = |bytes: &[u8]| {
            let digest = sha256_digest(bytes);
            std::fs::write(blobs.join(digest.trim_start_matches("sha256:")), bytes).unwrap();
            digest
        };
        let mut layer_digests = Vec::new();
        for (name, files) in layers {
            let mut builder = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(EPOCH);
            header.set_size(0);
            builder
                .append_data(&mut header, format!("{name}/"), std::io::empty())
                .unwrap();
            for (file, contents) in *files {
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o644);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(EPOCH);
                header.set_size(contents.len() as u64);
                builder
                    .append_data(&mut header, format!("{name}/{file}"), *contents)
                    .unwrap();
            }
            layer_digests.push(write_blob(&builder.into_inner().unwrap()));
        }
        let metadata = base64::engine::general_purpose::STANDARD
            .encode(r#"{"kit":[],"name":"test-kit","sdk":{},"version":"1.0.0"}"#);
        let config = serde_json::json!({
            "architecture": "amd64",
            "config": { "Labels": { "dev.bottlerocket.kit.v4": metadata } },
            "created": created,
            "rootfs": { "type": "layers", "diff_ids": layer_digests },
        });
        let config = write_blob(config.to_string().as_bytes());
        let layers: Vec<_> = layer_digests
            .iter()
            .map(|digest| serde_json::json!({ "digest": digest, "size": 0 }))
            .collect();
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": config, "size": 0 },
            "layers": layers,
        });
        let manifest = write_blob(manifest.to_string().as_bytes());
        let index = serde_json::json!({ "manifests": [{ "digest": manifest }] });
        std::fs::write(dir.join("index.json"), index.to_string()).unwrap();
        manifest
    }

    fn compare_layouts(
        rebuilt: &[LayerSpec],
        published: &[LayerSpec],
        published_created: &str,
    ) -> ArchReport {
        let dir = TempDir::new().unwrap();
        let rebuilt_layout = Layout {
            dir: dir.path().join("rebuilt"),
        };
        let published_layout = Layout {
            dir: dir.path().join("published"),
        };
        write_layout(&rebuilt_layout.dir, "2026-10-20T22:40:15Z", rebuilt);
        let digest = write_layout(&published_layout.dir, published_created, published);
        let packages_dir = dir.path().join("packages");
        std::fs::create_dir(&packages_dir).unwrap();
        compare(
            "x86_64".to_string(),
            &published_layout,
            digest,
            &rebuilt_layout,
            &fake_compare_package,
            &packages_dir,
        )
        .unwrap()
    }

    /// Stands in for `reprosys compare-rpm`: packages whose contents both start with `signed:`
    /// differ only in expected ways.
    fn fake_compare_package(rebuilt: &Path, published: &Path) -> Result<PackageReport> {
        let (rebuilt, published) = (std::fs::read(rebuilt)?, std::fs::read(published)?);
        let expected = rebuilt.starts_with(b"signed:") && published.starts_with(b"signed:");
        let status = if expected {
            Status::ExpectedDifference
        } else {
            Status::Mismatch
        };
        Ok(PackageReport {
            status,
            detail: format!(
                "{} vs {}",
                String::from_utf8_lossy(&rebuilt),
                String::from_utf8_lossy(&published)
            ),
            header: Vec::new(),
            files: vec![PayloadFile {
                path: "/lib/modules/xfs.ko".to_string(),
                status,
                detail: "payload file".to_string(),
            }],
        })
    }

    const CREATED: &str = "2026-10-20T22:40:15Z";

    #[test]
    fn identical_kits_match() {
        let layers: &[LayerSpec] = &[
            ("Packages/glibc", &[("glibc.rpm", b"glibc")]),
            ("repodata", &[("repomd.xml", b"repomd")]),
        ];
        let report = compare_layouts(layers, layers, CREATED);
        assert_eq!(report.status, Status::Match);
        assert_eq!(report.identical_layers, 2);
        assert!(report.differences.is_empty());
    }

    #[test]
    fn differing_kits_list_config_layers_and_files() {
        let report = compare_layouts(
            &[
                ("Packages/glibc", &[("glibc.rpm", b"glibc")]),
                ("Packages/bash", &[("bash.rpm", b"bash rebuilt")]),
                ("repodata", &[("repomd.xml", b"repomd rebuilt")]),
            ],
            &[
                ("Packages/glibc", &[("glibc.rpm", b"glibc")]),
                ("Packages/bash", &[("bash.rpm", b"bash")]),
                ("Packages/old", &[("old.rpm", b"old")]),
                ("repodata", &[("repomd.xml", b"repomd")]),
            ],
            "2026-10-21T00:00:00Z",
        );
        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(report.identical_layers, 1);
        let items: Vec<&str> = report.differences.iter().map(|d| d.item.as_str()).collect();
        assert_eq!(
            items,
            ["config", "Packages/bash", "Packages/old", "repodata"]
        );
        assert_eq!(
            report.differences[0].detail,
            "created: rebuilt \"2026-10-20T22:40:15Z\", published \"2026-10-21T00:00:00Z\""
        );
        let bash = &report.differences[1].files;
        assert_eq!(bash.len(), 1);
        assert_eq!(bash[0].path, "Packages/bash/bash.rpm");
        assert_eq!(bash[0].detail, "bash rebuilt vs bash");
        assert_eq!(report.differences[2].detail, "only in the published kit");
        let repodata = &report.differences[3];
        assert_eq!(repodata.status, Status::Mismatch);
        assert!(repodata.files[0]
            .detail
            .starts_with("contents differ (14 bytes, sha256 "));

        let text = summary(
            &Report {
                verdict: "failed".to_string(),
                kit: "test-kit".to_string(),
                version: "1.0.0".to_string(),
                image: "registry/test-kit:v1.0.0".to_string(),
                commit: "0123abcd".to_string(),
                sdk_arch: "x86_64".to_string(),
                arches: vec![report],
            },
            false,
        );
        assert!(text.contains("  FAIL  Packages/bash"));
        assert!(text.contains("          Packages/bash/bash.rpm\n"));
        assert!(
            text.contains("            /lib/modules/xfs.ko\n              FAIL  payload file\n")
        );
        assert!(text.contains("  ok    1 layer identical"));
        assert!(text.contains('…'));
        assert!(text.ends_with("Result: FAILED (x86_64 differs from the rebuilt kit)\n"));
    }

    #[test]
    fn expected_package_differences_verify() {
        let rebuilt: &[LayerSpec] = &[
            ("Packages/kernel", &[("kernel.rpm", b"signed:rebuilt")]),
            (
                "repodata",
                &[("abc-primary.xml.zst", b"a"), ("repomd.xml", b"x")],
            ),
        ];
        let published: &[LayerSpec] = &[
            ("Packages/kernel", &[("kernel.rpm", b"signed:published")]),
            (
                "repodata",
                &[("def-primary.xml.zst", b"d"), ("repomd.xml", b"y")],
            ),
        ];
        let report = compare_layouts(rebuilt, published, CREATED);
        assert_eq!(report.status, Status::ExpectedDifference, "{report:#?}");
        let statuses: Vec<(&str, Status)> = report
            .differences
            .iter()
            .map(|d| (d.item.as_str(), d.status))
            .collect();
        assert_eq!(
            statuses,
            [
                ("Packages/kernel", Status::ExpectedDifference),
                (REPODATA, Status::ExpectedDifference)
            ]
        );
        let repodata = &report.differences[1].files;
        assert_eq!(repodata.len(), 2);
        assert_eq!(repodata[0].path, "repodata/abc-primary.xml.zst");
        assert!(repodata[0]
            .detail
            .starts_with("renamed to repodata/def-primary.xml.zst; contents differ"));

        let text = summary(
            &Report {
                verdict: "verified".to_string(),
                kit: "test-kit".to_string(),
                version: "1.0.0".to_string(),
                image: "registry/test-kit:v1.0.0".to_string(),
                commit: "0123abcd".to_string(),
                sdk_arch: "x86_64".to_string(),
                arches: vec![report],
            },
            false,
        );
        assert!(text.contains("  note  Packages/kernel"));
        assert!(text.contains("          + 1 expected difference (shown with --verbose)"));
        assert!(text.contains("          + 2 expected differences (shown with --verbose)"));
        assert!(!text.contains("kernel.rpm"));
        assert!(text.ends_with("Result: VERIFIED\n"));
    }

    #[test]
    fn repodata_fails_with_the_packages_it_records() {
        let report = compare_layouts(
            &[
                ("Packages/kernel", &[("kernel.rpm", b"signed:rebuilt")]),
                ("Packages/tool", &[("tool.rpm", b"rebuilt")]),
                ("repodata", &[("repomd.xml", b"x")]),
            ],
            &[
                ("Packages/kernel", &[("kernel.rpm", b"signed:published")]),
                ("Packages/tool", &[("tool.rpm", b"published")]),
                ("repodata", &[("repomd.xml", b"y")]),
            ],
            CREATED,
        );
        assert_eq!(report.status, Status::Mismatch);
        let repodata = report.differences.last().unwrap();
        assert_eq!(
            (repodata.item.as_str(), repodata.status),
            (REPODATA, Status::Mismatch)
        );
        assert!(repodata
            .detail
            .ends_with("which differ in ways not expected"));
    }

    #[test]
    fn repodata_fails_when_no_package_differs() {
        let report = compare_layouts(
            &[
                ("Packages/kernel", &[("kernel.rpm", b"signed:same")]),
                ("repodata", &[("abc-primary.xml.zst", b"a")]),
            ],
            &[
                ("Packages/kernel", &[("kernel.rpm", b"signed:same")]),
                ("repodata", &[("def-primary.xml.zst", b"tampered")]),
            ],
            CREATED,
        );
        assert_eq!(report.status, Status::Mismatch);
        assert_eq!(report.differences.len(), 1);
        assert!(report.differences[0]
            .detail
            .ends_with("no package differs, so the repository metadata should not either"));
    }

    #[test]
    fn repodata_files_in_one_image_fail() {
        let report = compare_layouts(
            &[
                ("Packages/kernel", &[("kernel.rpm", b"signed:rebuilt")]),
                ("repodata", &[("repomd.xml", b"x")]),
            ],
            &[
                ("Packages/kernel", &[("kernel.rpm", b"signed:published")]),
                (
                    "repodata",
                    &[("repomd.xml", b"y"), ("0123-extra.xml", b"extra")],
                ),
            ],
            CREATED,
        );
        assert_eq!(report.status, Status::Mismatch);
        let repodata = report.differences.last().unwrap();
        let statuses: Vec<(&str, Status)> = repodata
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.status))
            .collect();
        assert_eq!(
            statuses,
            [
                ("repodata/0123-extra.xml", Status::Mismatch),
                ("repodata/repomd.xml", Status::ExpectedDifference)
            ]
        );
    }

    #[test]
    fn rejects_duplicate_layer_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("layer.tar");
        let mut builder = tar::Builder::new(std::fs::File::create(&path).unwrap());
        for contents in [&b"checked"[..], b"installed"] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(EPOCH);
            header.set_size(contents.len() as u64);
            builder
                .append_data(&mut header, "Packages/foo/foo.rpm", contents)
                .unwrap();
        }
        builder.finish().unwrap();
        let err = read_entries(&path).unwrap_err();
        assert!(err.to_string().contains("appears more than once"), "{err}");
    }

    #[test]
    fn rejects_unknown_statuses() {
        let parsed = serde_json::from_str::<PackageReport>(r#"{"status":"error","detail":""}"#);
        assert!(parsed.is_err());
        let parsed: PackageReport =
            serde_json::from_str(r#"{"status":"expected-difference","detail":""}"#).unwrap();
        assert_eq!(parsed.status, Status::ExpectedDifference);
    }

    #[test]
    fn rejects_invalid_names_and_digests() {
        let encode = |json: &str| base64::engine::general_purpose::STANDARD.encode(json);
        let config = |metadata: &str| serde_json::json!({ "config": { "Labels": { "dev.bottlerocket.kit.v4": encode(metadata) } } });
        for name in ["../kit", "kit;rm", "-kit", ""] {
            let metadata = format!(r#"{{"name":"{name}","version":"1.0.0"}}"#);
            assert!(kit_metadata(&config(&metadata)).is_err(), "{name}");
        }
        for digest in [
            "sha256:../../x",
            "sha512:abcd",
            &format!("sha256:{}", "A".repeat(64)),
        ] {
            let json = format!(r#"{{"digest":"{digest}"}}"#);
            assert!(
                serde_json::from_str::<Descriptor>(&json).is_err(),
                "{digest}"
            );
        }
        let digest = format!(r#"{{"digest":"sha256:{}"}}"#, "0a".repeat(32));
        assert!(serde_json::from_str::<Descriptor>(&digest).is_ok());
    }

    #[test]
    fn compares_decoded_kit_metadata() {
        let encode = |json: &str| base64::engine::general_purpose::STANDARD.encode(json);
        let config = |metadata: &str| serde_json::json!({ "config": { "Labels": { "dev.bottlerocket.kit.v4": encode(metadata) } } });
        let differences = compare_configs(
            &config(r#"{"name":"kit","sdk":{"digest":"a"}}"#),
            &config(r#"{"name":"kit","sdk":{"digest":"b"}}"#),
        );
        assert_eq!(
            differences,
            [r#"config.Labels.dev.bottlerocket.kit.v4.sdk.digest: rebuilt "a", published "b""#]
        );
        let metadata = kit_metadata(&config(r#"{"name":"kit","version":"1.0.0"}"#)).unwrap();
        assert_eq!(
            (metadata.name.as_str(), metadata.version.as_str()),
            ("kit", "1.0.0")
        );
    }

    #[test]
    fn strips_tag_and_digest_from_image() {
        for (image, repository) in [
            (
                "public.ecr.aws/bottlerocket/bottlerocket-sdk:v0.80.0",
                "public.ecr.aws/bottlerocket/bottlerocket-sdk",
            ),
            ("localhost:5000/sdk", "localhost:5000/sdk"),
            ("localhost:5000/sdk:v1", "localhost:5000/sdk"),
            ("registry/sdk@sha256:abcd", "registry/sdk"),
        ] {
            assert_eq!(image_repository(image), repository);
        }
    }

    #[test]
    fn formats_rfc3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(EPOCH as i64), CREATED);
    }

    #[tokio::test]
    async fn reads_pinned_twoliter_from_makefile() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Makefile"),
            "TOP := here\nTWOLITER_VERSION ?= \"0.26.0\" # pinned\nTWOLITER_SHA256_AARCH64 ?= \"abc\"\n",
        )
        .unwrap();
        assert_eq!(
            super::super::pinned_twoliter_version(dir.path())
                .await
                .unwrap(),
            "0.26.0"
        );
    }
}
