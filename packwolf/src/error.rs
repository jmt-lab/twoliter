use std::path::PathBuf;

use snafu::Snafu;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("Failed to create file for extraction at '{}': {source}", path.display()))]
    Create {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to decompress file: {source}"))]
    Decompress { source: std::io::Error },
    #[snafu(display("Failed to compress file: {source}"))]
    Compress { source: std::io::Error },
    #[snafu(display("Error occurred while setting mode for executable: {source}"))]
    ModeSetCommand { source: std::io::Error },
    #[snafu(display("Failed to set mode for executable at '{}'", path.display()))]
    ModeSetStatus { path: PathBuf },
    #[snafu(display("Failed to read artifact at '{}': {source}", path.display()))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to write to file at '{}': {source}", path.display()))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to read configuration: {source}"))]
    ReadConfig { source: std::io::Error },
    #[snafu(display("Failed to create sealed command: {source}"))]
    Sealed { source: std::io::Error },
    #[snafu(display("Failed to deserialize configuration: {source}"))]
    Deserialize { source: toml::de::Error },
    #[snafu(display("Failed to trigger build of cargo package {package} in workspace at {}: {source}", path.display()))]
    TriggerBuild {
        package: String,
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to build cargo package {package}"))]
    Build { package: String },
    #[snafu(display("Failed to trigger script: {source}"))]
    TriggerScript { source: std::io::Error },
    #[snafu(display("Script failed"))]
    Script,
    #[snafu(display("Failed to create temporary directory for crate install: {source}"))]
    Temp { source: std::io::Error },
    #[snafu(display("Failed to trigger crate install: {source}"))]
    TriggerInstall { source: std::io::Error },
    #[snafu(display("Failed to install crate"))]
    Install,
}
