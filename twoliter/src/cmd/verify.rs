use crate::common::fs;
use crate::tools::install_tools;
use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use path_absolutize::Absolutize;
use semver::Version;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use tempfile::TempDir;
use tokio::process::Command;
use tracing::{info, warn};

const DEFAULT_REPO: &str = "https://github.com/bottlerocket-os/bottlerocket";

/// The first twoliter release whose builds are expected to be reproducible.
const MIN_REPRODUCIBLE_TWOLITER: Version = Version::new(0, 26, 0);

/// erofs-utils commands reprosys uses to compare an erofs ROOT-A.
const EROFS_TOOLS: &[&str] = &["fsck.erofs", "dump.erofs"];

/// Exit code of `reprosys compare` when the images were compared but did not verify.
const REPROSYS_NOT_VERIFIED: i32 = 2;

/// Lines of the build log shown when the build fails.
const BUILD_LOG_TAIL: usize = 40;

/// The TUF root role in ROOT-A, which rebuilds cannot reproduce and users check by hand.
const TUF_ROOT_ROLE: &str = "/usr/share/updog/root.json";

/// The fields describing the published TUF root role in its report detail.
const ROOT_ROLE_FIELDS: &[&str] = &["sha512", "version", "expires", "keys"];

/// Hex strings at least this long are shortened in the summary; the report has them in full.
const LONG_HASH: usize = 32;

/// Width the summary's prose is wrapped to.
const WRAP_WIDTH: usize = 100;

#[derive(Debug, Parser)]
pub(crate) enum VerifyCommand {
    Ami(VerifyAmi),
}

impl VerifyCommand {
    pub(crate) async fn run(self) -> Result<()> {
        match self {
            VerifyCommand::Ami(command) => command.run().await,
        }
    }
}

/// Rebuild the image behind an AMI from source and compare it against the AMI's snapshots.
///
/// Needs Docker, git, cargo-make, lz4, erofs-utils for variants with an erofs root filesystem, and
/// AWS credentials allowing ec2:DescribeImages,
/// ec2:DescribeSnapshots, ec2:CopySnapshot, ec2:DeleteSnapshot, ebs:ListSnapshotBlocks and
/// ebs:GetSnapshotBlock.
#[derive(Debug, Parser)]
pub(crate) struct VerifyAmi {
    /// The AMI to verify.
    #[clap(long = "ami-id")]
    pub(crate) ami_id: String,

    /// The AWS region of the AMI.
    #[clap(long)]
    pub(crate) region: Option<String>,

    /// The AWS profile to use.
    #[clap(long)]
    pub(crate) profile: Option<String>,

    /// An existing clean clone of the source repository to build from. The commit the AMI was
    /// built from is checked out in it. Conflicts with --repo.
    #[clap(long = "source-dir", conflicts_with = "repo")]
    pub(crate) source_dir: Option<PathBuf>,

    /// The git repository to clone the source from.
    #[clap(long, default_value = DEFAULT_REPO)]
    pub(crate) repo: String,

    /// Directory for the source checkout, downloaded images, report and log. Defaults to
    /// `./twoliter-verify-<ami-id>`.
    #[clap(long = "work-dir")]
    pub(crate) work_dir: Option<PathBuf>,

    /// Keep the source checkout and images in the work directory when done. The report and the
    /// log are always kept.
    #[clap(long)]
    pub(crate) keep: bool,

    /// Show the build output instead of writing it to `build.log` in the work directory, and list
    /// every differing file, full hashes and an explanation of each check in the summary.
    #[clap(long)]
    pub(crate) verbose: bool,
}

/// The build identity of an AMI, as printed by `reprosys resolve`.
#[derive(Debug, Deserialize)]
struct AmiInfo {
    ami_name: String,
    variant: String,
    arch: String,
    version: String,
    build_id: String,
    filename_prefix: String,
    owner: String,
    owned_by_caller: bool,
}

/// The output of `reprosys download`.
#[derive(Debug, Deserialize)]
struct Downloaded {
    root_image: PathBuf,
    data_image: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct Report {
    verdict: String,
    os: ImageReport,
    data: Option<ImageReport>,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ImageReport {
    regions: Vec<RegionReport>,
}

#[derive(Debug, Deserialize)]
struct RegionReport {
    name: String,
    status: String,
    fatal: bool,
    detail: String,
    #[serde(default)]
    files: Vec<FileReport>,
}

#[derive(Debug, Deserialize)]
struct FileReport {
    path: String,
    status: String,
    detail: String,
}

/// Images rebuilt from source.
struct Built {
    os_image: PathBuf,
    data_image: Option<PathBuf>,
}

impl VerifyAmi {
    pub(super) async fn run(&self) -> Result<()> {
        for tool in ["git", "cargo-make", "lz4", "docker"] {
            which::which(tool)
                .with_context(|| format!("'{tool}' is required but not found in PATH"))?;
        }

        let work_dir = match &self.work_dir {
            Some(dir) => dir.clone(),
            None => PathBuf::from(format!("twoliter-verify-{}", self.ami_id)),
        };
        let work_dir = work_dir.absolutize()?.into_owned();
        fs::create_dir_all(&work_dir).await?;

        let tools = TempDir::new().context("Unable to create a directory for tools")?;
        install_tools(tools.path()).await?;
        let reprosys = Reprosys {
            path: tools.path().join("reprosys"),
            aws_args: self.aws_args(),
        };

        let info: AmiInfo = serde_json::from_slice(
            &reprosys
                .run(&["resolve", "--ami-id", &self.ami_id])
                .await
                .context("Unable to determine the build that produced the AMI")?,
        )
        .context("Unable to parse 'reprosys resolve' output")?;
        info!(
            "AMI {} ('{}') is {} {} version {} built from commit {}",
            self.ami_id, info.ami_name, info.variant, info.arch, info.version, info.build_id
        );
        if !info.owned_by_caller {
            info!(
                "AMI is owned by account {}; its snapshots will be copied into this account to download them",
                info.owner
            );
        }

        let (source_dir, cloned) = match &self.source_dir {
            Some(dir) => (dir.absolutize()?.into_owned(), false),
            None => (work_dir.join("source"), true),
        };
        prepare_source(&source_dir, cloned.then_some(self.repo.as_str()), &info).await?;
        check_twoliter_version(&source_dir).await?;
        // Fail now rather than after the build if ROOT-A cannot be compared.
        if uses_erofs_root(&source_dir, &info.variant).await? {
            for tool in EROFS_TOOLS {
                which::which(tool).with_context(|| {
                    format!(
                        "Variant {} has an erofs root filesystem, which is compared using \
                         erofs-utils, but '{tool}' was not found in PATH. Install erofs-utils \
                         and run again.",
                        info.variant
                    )
                })?;
            }
        }

        let images_dir = work_dir.join("images");
        let download = async {
            let out = reprosys
                .run(&[
                    "download",
                    "--ami-id",
                    &self.ami_id,
                    "--out-dir",
                    &images_dir.display().to_string(),
                ])
                .await
                .context("Unable to download the AMI's snapshots")?;
            serde_json::from_slice::<Downloaded>(&out)
                .context("Unable to parse 'reprosys download' output")
        };
        // Let both finish even if one fails: stopping the download early would skip deleting
        // its snapshot copies, and stopping cargo make would leave its children building.
        let download = async {
            let result = download.await;
            if let Err(e) = &result {
                warn!("{e:#}; waiting for the build to finish (press Ctrl-C to stop it)");
            }
            result
        };
        let build_log = (!self.verbose).then(|| work_dir.join("build.log"));
        let build = async {
            let result = build(&source_dir, &images_dir, build_log.as_deref(), &info).await;
            if let Err(e) = &result {
                warn!("{e:#}; waiting for the snapshot download to finish");
            }
            result
        };
        let (downloaded, built) = tokio::join!(download, build);
        let (downloaded, built) = (downloaded?, built?);

        let report_path = work_dir.join("report.json");
        let log_path = work_dir.join("log.jsonl");
        // Start a new log with what was verified; reprosys appends each comparison step.
        let header = serde_json::json!({
            "time_ms": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            "event": "verify",
            "region": null,
            "twoliter_version": env!("CARGO_PKG_VERSION"),
            "ami_id": self.ami_id,
            "ami_name": info.ami_name,
            "variant": info.variant,
            "arch": info.arch,
            "version": info.version,
            "build_id": info.build_id,
            "owner": info.owner,
            "source_dir": source_dir,
            "rebuilt_image": built.os_image,
            "rebuilt_data_image": built.data_image,
            "published_image": downloaded.root_image,
            "published_data_image": downloaded.data_image,
        });
        fs::write(&log_path, format!("{header}\n")).await?;
        let mut compare_args = vec![
            "compare".to_string(),
            "--expected".to_string(),
            built.os_image.display().to_string(),
            "--actual".to_string(),
            downloaded.root_image.display().to_string(),
            "--report".to_string(),
            report_path.display().to_string(),
            "--log".to_string(),
            log_path.display().to_string(),
        ];
        // Pass whichever data images exist; reprosys fails verification when only one side has one.
        if let Some(expected) = &built.data_image {
            compare_args.extend([
                "--expected-data".to_string(),
                expected.display().to_string(),
            ]);
        }
        if let Some(actual) = &downloaded.data_image {
            compare_args.extend(["--actual-data".to_string(), actual.display().to_string()]);
        }
        let compare_args: Vec<&str> = compare_args.iter().map(String::as_str).collect();
        reprosys
            .run_allowing(&compare_args, &[REPROSYS_NOT_VERIFIED])
            .await
            .context("Unable to compare the rebuilt image against the AMI")?;
        let report: Report = serde_json::from_slice(&fs::read(&report_path).await?)
            .context("Unable to parse the comparison report")?;
        print!("{}", summary(&report, &self.ami_id, &info, self.verbose));
        println!("Report:    {}", report_path.display());
        println!("Log:       {}", log_path.display());
        if let Some(build_log) = &build_log {
            println!("Build log: {}", build_log.display());
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
            report.verdict == "verified",
            "AMI {} could not be verified as built from commit {}",
            self.ami_id,
            info.build_id
        );
        println!(
            "AMI {} was verified as built from commit {}",
            self.ami_id, info.build_id
        );
        Ok(())
    }

    fn aws_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(region) = &self.region {
            args.extend(["--region".to_string(), region.clone()]);
        }
        if let Some(profile) = &self.profile {
            args.extend(["--profile".to_string(), profile.clone()]);
        }
        args
    }
}

struct Reprosys {
    path: PathBuf,
    aws_args: Vec<String>,
}

impl Reprosys {
    async fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        self.run_allowing(args, &[]).await
    }

    /// Run reprosys and return its stdout; `ok_codes` are non-zero exit codes that are not errors.
    async fn run_allowing(&self, args: &[&str], ok_codes: &[i32]) -> Result<Vec<u8>> {
        let mut cmd = Command::new(&self.path);
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if args.first() != Some(&"compare") {
            cmd.args(&self.aws_args);
        }
        // `Command::output` pipes stderr even when it is configured to be inherited.
        // Spawn explicitly so reprosys diagnostics and progress remain visible.
        let output = cmd
            .spawn()
            .context("Unable to run reprosys")?
            .wait_with_output()
            .await
            .context("Unable to wait for reprosys")?;
        let code = output.status.code();
        ensure!(
            output.status.success() || code.is_some_and(|c| ok_codes.contains(&c)),
            "reprosys {} failed with exit code {}",
            args.first().unwrap_or(&""),
            code.unwrap_or(-1)
        );
        Ok(output.stdout)
    }
}

async fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .await
        .context("Unable to run git")?;
    ensure!(
        output.status.success(),
        "'git {}' failed in '{}'",
        args.join(" "),
        dir.display()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Check out the commit the AMI was built from, cloning `repo` first if given.
async fn prepare_source(dir: &Path, repo: Option<&str>, info: &AmiInfo) -> Result<()> {
    match repo {
        Some(repo) => {
            if dir.exists() {
                info!("Reusing existing checkout in '{}'", dir.display());
                git(dir, &["fetch", "--tags", "origin"]).await?;
            } else {
                info!("Cloning '{repo}' into '{}'", dir.display());
                let parent = dir.parent().context("Source directory has no parent")?;
                let name = dir.file_name().context("Source directory has no name")?;
                git(parent, &["clone", repo, &name.to_string_lossy()]).await?;
            }
        }
        None => warn!(
            "Checking out commit {} in '{}'",
            info.build_id,
            dir.display()
        ),
    }

    let status = git(dir, &["status", "--porcelain", "--untracked-files=no"]).await?;
    ensure!(
        status.is_empty(),
        "Source directory '{}' has uncommitted changes, which would change the build ID",
        dir.display()
    );

    let commit = git(
        dir,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{}^{{commit}}", info.build_id),
        ],
    )
    .await
    .with_context(|| {
        format!(
            "Commit {} is not in '{}', or the abbreviation is ambiguous",
            info.build_id,
            dir.display()
        )
    })?;
    git(dir, &["checkout", "--quiet", "--detach", &commit]).await?;
    info!("Checked out commit {commit}");

    let tag = format!("v{}", info.version);
    match git(
        dir,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{tag}^{{commit}}"),
        ],
    )
    .await
    {
        Ok(tagged) if tagged == commit => info!("Tag {tag} points at the AMI's commit"),
        Ok(tagged) => warn!("Tag {tag} points at {tagged}, not at the AMI's commit {commit}"),
        Err(_) => warn!("Tag {tag} does not exist in the source repository"),
    }

    let release_version = read_release_version(dir).await?;
    ensure!(
        release_version == info.version,
        "Commit {commit} has release version {release_version}, but the AMI is version {}",
        info.version
    );
    Ok(())
}

/// Read the release version from Twoliter.toml, or Release.toml in older checkouts.
async fn read_release_version(dir: &Path) -> Result<String> {
    for (file, key) in [
        ("Twoliter.toml", "release-version"),
        ("Release.toml", "version"),
    ] {
        let path = dir.join(file);
        if !path.exists() {
            continue;
        }
        let value: toml::Value = toml::from_str(&fs::read_to_string(&path).await?)
            .with_context(|| format!("Unable to parse '{}'", path.display()))?;
        if let Some(version) = value.get(key).and_then(|v| v.as_str()) {
            return Ok(version.to_string());
        }
    }
    bail!(
        "No release version found in Twoliter.toml or Release.toml in '{}'",
        dir.display()
    )
}

/// Warn when the checkout pins a twoliter that predates reproducible builds.
async fn check_twoliter_version(dir: &Path) -> Result<()> {
    let path = dir.join("Makefile.toml");
    let makefile: toml::Value = toml::from_str(&fs::read_to_string(&path).await?)
        .with_context(|| format!("Unable to parse '{}'", path.display()))?;
    let pinned = makefile
        .get("env")
        .and_then(|env| env.get("TWOLITER_VERSION"))
        .and_then(|v| v.as_str())
        .with_context(|| format!("No TWOLITER_VERSION found in '{}'", path.display()))?;
    match Version::parse(pinned.trim_start_matches('v')) {
        Ok(version) if version >= MIN_REPRODUCIBLE_TWOLITER => {
            info!("Source pins twoliter {version}");
        }
        _ => warn!(
            "\n\n!!! The source pins twoliter {pinned}, which predates reproducible builds \
             (twoliter {MIN_REPRODUCIBLE_TWOLITER}). The rebuilt image is expected to differ \
             from the AMI. !!!\n"
        ),
    }
    Ok(())
}

/// Whether the variant enables the `erofs-root-partition` image feature.
async fn uses_erofs_root(dir: &Path, variant: &str) -> Result<bool> {
    let path = dir.join("variants").join(variant).join("Cargo.toml");
    if !path.exists() {
        warn!(
            "'{}' does not exist; unable to tell whether the variant has an erofs root filesystem",
            path.display()
        );
        return Ok(false);
    }
    let manifest: toml::Value = toml::from_str(&fs::read_to_string(&path).await?)
        .with_context(|| format!("Unable to parse '{}'", path.display()))?;
    Ok(manifest
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("build-variant"))
        .and_then(|b| b.get("image-features"))
        .and_then(|f| f.get("erofs-root-partition"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// Build the variant with the checkout's own entry point and decompress the resulting images.
///
/// The build output is written to `log` if given, and shown otherwise.
async fn build(
    source_dir: &Path,
    images_dir: &Path,
    log: Option<&Path>,
    info: &AmiInfo,
) -> Result<Built> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(source_dir)
        .args(["make", "-e"])
        .arg(format!("BUILDSYS_VARIANT={}", info.variant))
        .arg("-e")
        .arg(format!("BUILDSYS_ARCH={}", info.arch))
        .kill_on_drop(true);
    match log {
        Some(log) => {
            info!(
                "Building {} {}; this takes a while. Build output is written to '{}'",
                info.variant,
                info.arch,
                log.display()
            );
            let file = std::fs::File::create(log)
                .with_context(|| format!("Unable to create '{}'", log.display()))?;
            cmd.stdin(Stdio::null())
                .stdout(file.try_clone()?)
                .stderr(file);
        }
        None => info!(
            "Building {} {} in '{}'",
            info.variant,
            info.arch,
            source_dir.display()
        ),
    }
    let started = Instant::now();
    let status = cmd.status().await.context("Unable to run cargo make")?;
    if !status.success() {
        if let Some(log) = log {
            print_log_tail(log).await;
        }
        bail!("Building the variant from source failed");
    }
    info!(
        "Built {} {} in {}m {:02}s",
        info.variant,
        info.arch,
        started.elapsed().as_secs() / 60,
        started.elapsed().as_secs() % 60
    );

    let variant_dir = source_dir
        .join("build/images")
        .join(format!("{}-{}", info.arch, info.variant))
        .join(format!("{}-{}", info.version, info.build_id));
    let os_lz4 = variant_dir.join(format!("{}.img.lz4", info.filename_prefix));
    ensure!(
        os_lz4.is_file(),
        "The build did not produce '{}'; the build ID may differ from the AMI's",
        os_lz4.display()
    );
    fs::create_dir_all(images_dir).await?;
    let os_image = images_dir.join("rebuilt.img");
    lz4_decompress(&os_lz4, &os_image).await?;

    let data_lz4 = variant_dir.join(format!("{}-data.img.lz4", info.filename_prefix));
    let data_image = if data_lz4.is_file() {
        let path = images_dir.join("rebuilt-data.img");
        lz4_decompress(&data_lz4, &path).await?;
        Some(path)
    } else {
        None
    };
    Ok(Built {
        os_image,
        data_image,
    })
}

/// Show the end of a failed build's log, where the error usually is.
async fn print_log_tail(log: &Path) {
    let Ok(contents) = fs::read_to_string(log).await else {
        return;
    };
    let lines: Vec<&str> = contents.lines().collect();
    let tail = &lines[lines.len().saturating_sub(BUILD_LOG_TAIL)..];
    eprintln!(
        "Last {} lines of '{}':\n{}",
        tail.len(),
        log.display(),
        tail.join("\n")
    );
}

async fn lz4_decompress(input: &Path, output: &Path) -> Result<()> {
    let status = Command::new("lz4")
        .args(["-d", "-f", "-q", "--sparse"])
        .arg(input)
        .arg(output)
        .status()
        .await
        .context("Unable to run lz4")?;
    ensure!(
        status.success(),
        "Unable to decompress '{}'",
        input.display()
    );
    Ok(())
}

impl RegionReport {
    fn failed(&self) -> bool {
        self.fatal && self.status == "mismatch"
    }

    /// The summary's marker for this region, and its rank: failures are listed first.
    fn marker(&self) -> (&'static str, u8) {
        match (self.status.as_str(), self.fatal) {
            ("match", _) => ("ok", 3),
            ("expected-difference", _) => ("note", 2),
            (_, true) => ("FAIL", 0),
            (_, false) => ("warn", 1),
        }
    }
}

/// Render the comparison report for the terminal.
fn summary(report: &Report, ami_id: &str, info: &AmiInfo, verbose: bool) -> String {
    let mut out = Vec::new();
    let shorten = |text: &str| {
        if verbose {
            text.to_string()
        } else {
            shorten_hashes(text)
        }
    };
    out.push(String::new());
    out.push(format!(
        "Verification of {ami_id} ({} {} v{}, commit {})",
        info.variant, info.arch, info.version, info.build_id
    ));

    let mut root_role = None;
    let images = std::iter::once(("OS image", &report.os))
        .chain(report.data.as_ref().map(|d| ("Data image", d)));
    for (title, image) in images {
        out.push(String::new());
        out.push(title.to_string());
        let mut regions: Vec<&RegionReport> = image.regions.iter().collect();
        regions.sort_by_key(|r| r.marker().1);
        let (identical, differing): (Vec<_>, Vec<_>) =
            regions.into_iter().partition(|r| r.status == "match");
        for region in differing {
            out.push(format!(
                "  {:<5} {:<12} {}",
                region.marker().0,
                region.name,
                shorten(&region.detail)
            ));
            let mut hidden = 0;
            for file in region.files.iter().filter(|f| f.status != "match") {
                if file.status == "expected-difference" && file.path.ends_with(TUF_ROOT_ROLE) {
                    root_role = Some(file);
                }
                if file.status == "mismatch" {
                    out.push(format!("          {}", file.path));
                    out.push(format!("            {}", shorten(&file.detail)));
                } else if verbose {
                    out.push(format!("          {}", file.path));
                    out.push(format!("            expected difference: {}", file.detail));
                } else {
                    hidden += 1;
                }
            }
            if hidden > 0 {
                let s = if hidden == 1 { "" } else { "s" };
                out.push(format!(
                    "          + {hidden} expected difference{s} (shown with --verbose)"
                ));
            }
        }
        if !identical.is_empty() {
            let names: Vec<&str> = identical.iter().map(|r| r.name.as_str()).collect();
            out.push(format!(
                "  {:<5} {}",
                "ok",
                wrap(&format!("{} identical", names.join(", ")), 8)
            ));
        }
    }

    if let Some(file) = root_role {
        let published = file
            .detail
            .find("sha512 ")
            .map_or(file.detail.as_str(), |i| &file.detail[i..]);
        out.push(String::new());
        out.push("Check by hand".to_string());
        out.push(format!(
            "  {}",
            wrap(
                "The TUF root role (/usr/share/updog/root.json) cannot be rebuilt without the \
                 release keys. Check that the AMI's root role is the one your repository \
                 publishes (for Bottlerocket, https://cache.bottlerocket.aws/root.json):",
                2
            )
        ));
        // "sha512 <digest>, version <n>, expires <time>, keys <id>, <id>": one field per line.
        for field in published.split(", ") {
            match field.split_once(' ') {
                Some((label, value)) if ROOT_ROLE_FIELDS.contains(&label) => {
                    out.push(format!("    {label:<8} {value}"));
                }
                _ => out.push(format!("    {:<8} {field}", "")),
            }
        }
    }

    out.push(String::new());
    if verbose {
        for note in &report.notes {
            out.push(format!("Note: {}", wrap(note, 6)));
        }
    } else {
        out.push(wrap(
            "FAIL fails verification. warn and note are differences that per-build signing \
             keys or random salts can explain; they do not fail verification. The report \
             explains each check, and --verbose shows more detail.",
            0,
        ));
    }

    out.push(String::new());
    let failed: Vec<&str> = std::iter::once(&report.os)
        .chain(&report.data)
        .flat_map(|image| &image.regions)
        .filter(|r| r.failed())
        .map(|r| r.name.as_str())
        .collect();
    if report.verdict == "verified" {
        out.push("Result: VERIFIED".to_string());
    } else if failed.is_empty() {
        out.push("Result: FAILED".to_string());
    } else {
        out.push(format!(
            "Result: FAILED ({} differ{} from the rebuilt image)",
            failed.join(", "),
            if failed.len() == 1 { "s" } else { "" }
        ));
    }
    out.push(String::new());
    out.join("\n")
}

/// Shorten hex strings of at least `LONG_HASH` characters to their first 12.
fn shorten_hashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(|c: char| c.is_ascii_hexdigit()) {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let len = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        if len >= LONG_HASH {
            out.push_str(&rest[..12]);
            out.push('…');
        } else {
            out.push_str(&rest[..len]);
        }
        rest = &rest[len..];
    }
    out.push_str(rest);
    out
}

/// Wrap `text` to `WRAP_WIDTH`, indenting continuation lines by `indent` spaces.
fn wrap(text: &str, indent: usize) -> String {
    let mut out = String::new();
    let mut column = indent;
    for word in text.split_whitespace() {
        if column > indent && column + 1 + word.len() > WRAP_WIDTH {
            out.push('\n');
            out.push_str(&" ".repeat(indent));
            column = indent;
        } else if column > indent {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += word.chars().count();
    }
    out
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mock_reprosys(dir: &Path, code: i32) -> Reprosys {
        let path = dir.join("reprosys");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n\
                 test /proc/self/fd/2 -ef /proc/$PPID/fd/2 || exit 99\n\
                 printf '{{\"verdict\":\"not-verified\"}}'\n\
                 exit {code}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Reprosys {
            path,
            aws_args: Vec::new(),
        }
    }

    fn region(
        name: &str,
        status: &str,
        fatal: bool,
        detail: &str,
        files: &[(&str, &str, &str)],
    ) -> serde_json::Value {
        let files: Vec<_> = files
            .iter()
            .map(|(path, status, detail)| {
                serde_json::json!({ "path": path, "status": status, "detail": detail })
            })
            .collect();
        serde_json::json!({
            "name": name, "status": status, "fatal": fatal, "detail": detail, "files": files,
        })
    }

    fn report(root_a_status: &str) -> Report {
        let sha = "a9f9a4d30f465f0846e4d73f6d77ad669100410ef5241097ea40932329a1f99f";
        let root_role = format!(
            "TUF root role; rebuilds generate their own because the release root role keys are \
             not available. Check the published root role against the one your repository \
             publishes: sha512 {sha}{sha}, version 1, expires 2027-10-12T17:12:35Z, keys {sha}"
        );
        let mut root_files = vec![(
            "/x86_64-bottlerocket-linux-gnu/sys-root/usr/share/updog/root.json",
            "expected-difference",
            root_role.as_str(),
        )];
        let sbom =
            format!("contents differ (7204612 bytes, sha256 {sha} vs 7204612 bytes, sha256 {sha})");
        if root_a_status == "mismatch" {
            root_files.push((
                "/x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/spdx-sbom.json",
                "mismatch",
                sbom.as_str(),
            ));
        }
        serde_json::from_value(serde_json::json!({
            "verdict": if root_a_status == "mismatch" { "failed" } else { "verified" },
            "os": { "regions": [
                region("GPT", "match", true, "identical", &[]),
                region("EFI-A", "mismatch", false, "files differ beyond signing-dependent content", &[
                    ("/EFI/BOOT/grubx64.efi", "mismatch", "differs in sections .pubkey"),
                    ("/EFI/BOOT/db.crt", "expected-difference", "signing artifact"),
                ]),
                region("BOOT-A", "expected-difference", false, "files differ only in signing-dependent content", &[
                    ("/vmlinuz", "expected-difference", "signatures differ"),
                    ("/grub/grub.cfg.sig", "expected-difference", "signing artifact"),
                ]),
                region("ROOT-A", root_a_status, true, "differing files", &root_files),
                region("PRIVATE", "match", true, "identical", &[]),
            ]},
            "data": { "regions": [region("DATA", "match", true, "identical", &[])] },
            "notes": ["A note."],
        }))
        .unwrap()
    }

    fn info() -> AmiInfo {
        serde_json::from_value(serde_json::json!({
            "ami_name": "bottlerocket", "variant": "aws-dev", "arch": "x86_64",
            "version": "1.67.0", "build_id": "d2569283", "filename_prefix": "bottlerocket",
            "owner": "123", "owned_by_caller": true,
        }))
        .unwrap()
    }

    #[test]
    fn summary_lists_failures_first_and_hides_expected_differences() {
        let text = summary(&report("mismatch"), "ami-1", &info(), false);
        println!("{text}");
        let lines: Vec<&str> = text.lines().collect();
        let position = |prefix: &str| {
            lines
                .iter()
                .position(|l| l.trim_start().starts_with(prefix))
                .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{text}"))
        };
        assert!(position("FAIL  ROOT-A") < position("warn  EFI-A"));
        assert!(position("warn  EFI-A") < position("note  BOOT-A"));
        assert!(position("note  BOOT-A") < position("ok    GPT, PRIVATE identical"));
        assert!(text.contains("  ok    DATA identical"));
        assert!(text.contains("/EFI/BOOT/grubx64.efi"));
        assert!(!text.contains("/EFI/BOOT/db.crt"));
        assert!(text.contains("+ 2 expected differences (shown with --verbose)"));
        assert!(text.contains("sha256 a9f9a4d30f46… vs"));
        // The root role is listed in full to check by hand.
        let sha = "a9f9a4d30f465f0846e4d73f6d77ad669100410ef5241097ea40932329a1f99f";
        assert!(text.contains(&format!("\n    sha512   {sha}{sha}\n    version  1\n")));
        assert!(text.contains(&format!("\n    keys     {sha}\n")));
        assert!(!text.contains("Note: A note."));
        assert!(text.ends_with("Result: FAILED (ROOT-A differs from the rebuilt image)\n"));
    }

    #[test]
    fn verbose_summary_lists_everything() {
        let text = summary(&report("expected-difference"), "ami-1", &info(), true);
        assert!(text.contains("/EFI/BOOT/db.crt"));
        assert!(text.contains("expected difference: signing artifact"));
        assert!(!text.contains('…'));
        assert!(text.contains("Note: A note."));
        assert!(text.contains("Check by hand"));
        assert!(text.ends_with("Result: VERIFIED\n"));
    }

    #[test]
    fn shortens_only_long_hashes() {
        let long = "d91c430f8a647c11171f08308a21275f61fc991267a092253108bd24ae074fb6";
        assert_eq!(
            shorten_hashes(&format!("root hash {long}; snap-012c07623fe00054c")),
            "root hash d91c430f8a64…; snap-012c07623fe00054c"
        );
    }

    #[test]
    fn wraps_with_indent() {
        let text = "word ".repeat(30);
        let wrapped = wrap(&text, 4);
        assert!(wrapped.lines().all(|l| l.len() <= WRAP_WIDTH));
        assert!(wrapped.lines().skip(1).all(|l| l.starts_with("    w")));
        assert_eq!(wrapped.split_whitespace().count(), 30);
    }

    #[tokio::test]
    async fn detects_erofs_root() {
        let dir = TempDir::new().unwrap();
        let variant = dir.path().join("variants/aws-dev");
        std::fs::create_dir_all(&variant).unwrap();
        assert!(!uses_erofs_root(dir.path(), "aws-dev").await.unwrap());
        std::fs::write(
            variant.join("Cargo.toml"),
            "[package.metadata.build-variant.image-features]\nerofs-root-partition = true\n",
        )
        .unwrap();
        assert!(uses_erofs_root(dir.path(), "aws-dev").await.unwrap());
        std::fs::write(
            variant.join("Cargo.toml"),
            "[package]\nname = \"aws-dev\"\n",
        )
        .unwrap();
        assert!(!uses_erofs_root(dir.path(), "aws-dev").await.unwrap());
    }

    #[tokio::test]
    async fn reprosys_inherits_stderr_and_captures_stdout() {
        let dir = TempDir::new().unwrap();
        let reprosys = mock_reprosys(dir.path(), 0);
        let output = reprosys.run(&["resolve"]).await.unwrap();
        assert_eq!(output, br#"{"verdict":"not-verified"}"#);
    }

    #[tokio::test]
    async fn reprosys_preserves_exit_code_handling() {
        let dir = TempDir::new().unwrap();
        let reprosys = mock_reprosys(dir.path(), REPROSYS_NOT_VERIFIED);
        let error = reprosys.run(&["compare"]).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "reprosys compare failed with exit code 2"
        );
        let output = reprosys
            .run_allowing(&["compare"], &[REPROSYS_NOT_VERIFIED])
            .await
            .unwrap();
        assert_eq!(output, br#"{"verdict":"not-verified"}"#);
    }
}
