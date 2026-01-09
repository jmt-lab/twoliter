use super::error::{self, Result};
use super::{BuildArgs, ContainerRuntime, RetryPolicy, RunArgs, ScriptBuildArgs};
use duct::cmd;
use lazy_static::lazy_static;
use nonzero_ext::nonzero;
use regex::Regex;
use semver::{Comparator, Op, Prerelease, Version, VersionReq};
use snafu::{ensure, ResultExt};
use std::num::NonZeroU16;
use std::process::Output;

lazy_static! {
    static ref DOCKER_BUILD_FRONTEND_ERROR: Regex = Regex::new(concat!(
        r#"failed to solve with frontend dockerfile.v0: "#,
        r#"failed to solve with frontend gateway.v0: "#,
        r#"frontend grpc server closed unexpectedly"#
    ))
    .unwrap();
}

lazy_static! {
    static ref DOCKER_BUILD_DEAD_RECORD_ERROR: Regex = Regex::new(concat!(
        r#"failed to solve with frontend dockerfile.v0: "#,
        r#"failed to solve with frontend gateway.v0: "#,
        r#"rpc error: code = Unknown desc = failed to build LLB: "#,
        r#"failed to get dead record"#,
    ))
    .unwrap();
}

lazy_static! {
    static ref UNEXPECTED_EOF_ERROR: Regex = Regex::new("(?m)unexpected EOF$").unwrap();
}

lazy_static! {
    static ref CREATEREPO_C_READ_HEADER_ERROR: Regex = Regex::new(&regex::escape(
        r#"C_CREATEREPOLIB: Warning: read_header: rpmReadPackageFile() error"#
    ))
    .unwrap();
}

lazy_static! {
    static ref MINIMUM_FINCH_VERSION: VersionReq = VersionReq {
        comparators: [Comparator {
            op: Op::GreaterEq,
            major: 1,
            minor: None,
            patch: None,
            pre: Prerelease::default(),
        }]
        .into()
    };
}

static FINCH_BUILD_MAX_ATTEMPTS: NonZeroU16 = nonzero!(10u16);

/// Finch-based container runtime implementation.
///
/// Implements the ContainerRuntime trait using the `finch` CLI.
/// Finch is AWS's open-source container development tool for macOS,
/// providing Docker-compatible commands backed by Lima and nerdctl.
///
/// Finch-specific behaviors:
/// - Uses `--init` flag for proper signal handling (unlike Podman)
/// - Platform detection uses `finch info` instead of `finch version`
/// - Architecture naming may differ (aarch64 vs arm64)
#[derive(Debug, Clone, Default)]
pub struct FinchRuntime;

impl FinchRuntime {
    pub fn new() -> Self {
        Self
    }

    fn exec(&self, args: &[String], retry: RetryPolicy) -> Result<Output> {
        let max_attempts: u16 = match retry {
            RetryPolicy::BuildRetry => FINCH_BUILD_MAX_ATTEMPTS.into(),
            RetryPolicy::None => 1,
        };
        let mut attempt = 1;
        loop {
            let output = cmd("finch", args)
                .stderr_to_stdout()
                .stdout_capture()
                .unchecked()
                .run()
                .context(error::CommandStartSnafu)?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{}", &stdout);
            if output.status.success() {
                return Ok(output);
            }

            let should_retry = matches!(retry, RetryPolicy::BuildRetry)
                && attempt < max_attempts
                && (DOCKER_BUILD_FRONTEND_ERROR.is_match(&stdout)
                    || DOCKER_BUILD_DEAD_RECORD_ERROR.is_match(&stdout)
                    || UNEXPECTED_EOF_ERROR.is_match(&stdout)
                    || CREATEREPO_C_READ_HEADER_ERROR.is_match(&stdout));

            ensure!(
                should_retry,
                error::CommandExecutionSnafu {
                    runtime: "finch",
                    args: args.join(" ")
                }
            );

            attempt += 1;
        }
    }
}

impl ContainerRuntime for FinchRuntime {
    fn name(&self) -> &'static str {
        "finch"
    }

    fn build(&self, args: &BuildArgs) -> Result<Output> {
        let mut cmd_args = vec![
            "build".into(),
            args.context.clone(),
            "--target".into(),
            args.target.clone(),
            "--tag".into(),
            args.tag.clone(),
            "--network".into(),
            args.network.clone(),
            "--file".into(),
            args.dockerfile.clone(),
        ];

        if !args.no_cache_filter.is_empty() {
            cmd_args.push("--no-cache-filter".into());
            cmd_args.push(args.no_cache_filter.join(","));
        }

        cmd_args.extend(args.build_args.clone());
        cmd_args.extend(args.secrets_args.clone());

        self.exec(&cmd_args, RetryPolicy::BuildRetry)
    }

    fn run(&self, args: &RunArgs) -> Result<Output> {
        let mut cmd_args = vec!["run".into()];

        cmd_args.push("--name".into());
        cmd_args.push(args.name.clone());

        if args.rm {
            cmd_args.push("--rm".into());
        }
        if args.detach {
            cmd_args.push("--detach".into());
        }
        if args.init {
            cmd_args.push("--init".into());
        }
        if let Some(ref net) = args.net {
            cmd_args.push("--net".into());
            cmd_args.push(net.clone());
        }
        if let Some(ref pid) = args.pid {
            cmd_args.push("--pid".into());
            cmd_args.push(pid.clone());
        }
        if let Some(ref user) = args.user {
            cmd_args.push("-u".into());
            cmd_args.push(user.clone());
        }

        for vol in &args.volumes {
            cmd_args.push("-v".into());
            let mount = if vol.readonly {
                format!("{}:{}:ro", vol.host, vol.container)
            } else {
                format!("{}:{}", vol.host, vol.container)
            };
            cmd_args.push(mount);
        }

        cmd_args.push(args.image.clone());
        cmd_args.extend(args.command.clone());

        self.exec(&cmd_args, RetryPolicy::None)
    }

    fn remove_image(&self, image: &str) -> Result<Output> {
        self.exec(&["rmi".into(), "--force".into(), image.into()], RetryPolicy::None)
    }

    fn remove_container(&self, container: &str) -> Result<Output> {
        self.exec(&["rm".into(), "--force".into(), container.into()], RetryPolicy::None)
    }

    fn version(&self) -> Result<Version> {
        let output = cmd("finch", ["info", "--format", "{{.ServerVersion}}"])
            .stderr_to_stdout()
            .stdout_capture()
            .unchecked()
            .run()
            .context(error::CommandStartSnafu)?;

        let version_str = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.contains("level="))
            .collect::<Vec<_>>()
            .join("")
            .trim()
            .to_string();
        Version::parse(&version_str).context(error::VersionParseSnafu { version_str })
    }

    fn check_version(&self) -> Result<()> {
        let version = self.version()?;
        ensure!(
            MINIMUM_FINCH_VERSION.matches(&version),
            error::VersionRequirementSnafu {
                runtime: self.name(),
                installed: version,
                required: MINIMUM_FINCH_VERSION.clone()
            }
        );
        Ok(())
    }

    fn run_script(&self, args: &ScriptBuildArgs) -> Result<Output> {
        let mut cmd_args = vec!["run".into(), "--rm".into()];

        if let Some(ref user) = args.user {
            cmd_args.push("-u".into());
            cmd_args.push(user.clone());
        }

        if let Some(ref workdir) = args.workdir {
            cmd_args.push("-w".into());
            cmd_args.push(workdir.clone());
        }

        for (k, v) in &args.env {
            cmd_args.push("-e".into());
            cmd_args.push(format!("{}={}", k, v));
        }

        for vol in &args.mounts {
            cmd_args.push("-v".into());
            let mount = if vol.readonly {
                format!("{}:{}:ro", vol.host, vol.container)
            } else {
                format!("{}:{}", vol.host, vol.container)
            };
            cmd_args.push(mount);
        }

        cmd_args.push(args.image.clone());
        cmd_args.push("bash".into());
        cmd_args.push("-c".into());
        cmd_args.push(args.script.clone());

        self.exec(&cmd_args, RetryPolicy::None)
    }
}
