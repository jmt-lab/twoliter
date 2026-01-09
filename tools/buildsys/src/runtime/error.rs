use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Failed to start command: {}", source))]
    CommandStart { source: std::io::Error },

    #[snafu(display("Failed to execute command: '{} {}'", runtime, args))]
    CommandExecution { runtime: &'static str, args: String },

    #[snafu(display(
        "Runtime '{}' version '{}' does not meet minimum requirement '{}'",
        runtime, installed, required
    ))]
    VersionRequirement {
        runtime: &'static str,
        installed: semver::Version,
        required: semver::VersionReq,
    },

    #[snafu(display("Failed to parse version '{}': {}", version_str, source))]
    VersionParse {
        source: semver::Error,
        version_str: String,
    },

    #[snafu(display("No compatible container runtime found. Install Docker 23+ or Podman 4+"))]
    NoRuntimeFound,
}

pub type Result<T> = std::result::Result<T, Error>;
