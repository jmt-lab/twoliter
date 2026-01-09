use snafu::Snafu;
use std::path::PathBuf;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub(crate) enum Error {
    #[snafu(display("Failed to create directory '{}': {}", path.display(), source))]
    DirectoryCreate { path: PathBuf, source: std::io::Error },

    #[snafu(display("Runtime error: {source}"))]
    Runtime { source: buildsys::runtime::Error },
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
