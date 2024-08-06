use crate::{error, error::Result, pack};
use glob::Pattern;
#[cfg(feature = "sealed")]
use pentacle::SealedCommand;
use serde::Deserialize;
use snafu::{ensure, ResultExt};
use std::fs::{create_dir_all, read, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;
use std::{
    collections::HashMap,
    env,
    io::{copy, Cursor},
    path::{Path, PathBuf},
};
use tar::Archive;
use tempfile::TempDir;
use zstd::{encode_all, Decoder};

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub embed: HashMap<String, Tool>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Tool {
    pub extract_to: PathBuf,
    pub source: Source,
}

impl Tool {
    pub fn is_binary(&self) -> bool {
        matches!(
            self.source,
            Source::Binary { .. } | Source::Crate { .. } | Source::Script { .. }
        )
    }

    pub fn is_archive(&self) -> bool {
        matches!(self.source, Source::Archive { .. })
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Source {
    Binary {
        path: PathBuf,
    },
    Crate {
        workspace: PathBuf,
        package: String,
        binary: String,
    },
    RemoteCrate {
        name: String,
        version: String,
        binary: String,
    },
    Archive {
        files: HashMap<PathBuf, PathBuf>,
    },
    Script {
        script: PathBuf,
        output: PathBuf,
    },
}

impl Source {
    pub fn load(&self) -> Result<Vec<u8>> {
        let raw_data = match self {
            Self::Binary { path, .. } => {
                let file_path = if path.starts_with("/") {
                    path.clone()
                } else {
                    let workspace_path = env::var_os("CARGO_MANIFEST_DIR").unwrap();
                    let workspace_path = workspace_path.to_string_lossy();
                    let workspace_path = Path::new(workspace_path.as_ref());
                    workspace_path.join(path)
                };
                read(file_path).context(error::ReadSnafu { path })
            }
            Self::Crate {
                workspace,
                package,
                binary,
            } => {
                let cmd = Command::new("cargo")
                    .current_dir(workspace)
                    .arg("build")
                    .arg("--release")
                    .arg("--package")
                    .arg(package)
                    .arg("--bin")
                    .arg(binary)
                    .spawn()
                    .context(error::TriggerBuildSnafu {
                        package,
                        path: workspace,
                    })?
                    .wait()
                    .context(error::TriggerBuildSnafu {
                        package,
                        path: workspace,
                    })?;
                ensure!(cmd.success(), error::BuildSnafu { package });
                let binary_file = workspace.join("target/release").join(binary);
                read(&binary_file).context(error::ReadSnafu {
                    path: binary_file.clone(),
                })
            }
            Self::RemoteCrate {
                name,
                version,
                binary,
            } => {
                let tmp_dir = TempDir::new().context(error::TempSnafu)?;
                let cmd = Command::new("cargo")
                    .current_dir(tmp_dir.path())
                    .arg("install")
                    .arg("--root")
                    .arg(tmp_dir.path())
                    .arg("--locked")
                    .arg("--bin")
                    .arg(binary)
                    .arg(format!("{}@{}", name, version))
                    .spawn()
                    .context(error::TriggerInstallSnafu)?
                    .wait()
                    .context(error::TriggerInstallSnafu)?;
                ensure!(cmd.success(), error::InstallSnafu {});
                let binary_file = tmp_dir.path().join("bin").join(binary);
                read(&binary_file).context(error::ReadSnafu {
                    path: binary_file.clone(),
                })
            }
            Self::Script { script, output } => {
                let cmd = Command::new(script)
                    .spawn()
                    .context(error::TriggerScriptSnafu)?
                    .wait()
                    .context(error::TriggerScriptSnafu)?;
                ensure!(cmd.success(), error::ScriptSnafu);
                read(output).context(error::ReadSnafu { path: output })
            }
            Self::Archive { files } => {
                let mut buffer: Vec<u8> = Vec::new();
                let mut cursor = Cursor::new(&mut buffer);
                let mut archive = tar::Builder::new(&mut cursor);
                for (src_file, target_path) in files {
                    let file_path = if src_file.starts_with("/") {
                        src_file.clone()
                    } else {
                        let workspace_path = env::var_os("CARGO_MANIFEST_DIR").unwrap();
                        let workspace_path = workspace_path.to_string_lossy();
                        let workspace_path = Path::new(workspace_path.as_ref());
                        workspace_path.join(src_file)
                    };
                    let mut reader = File::open(&file_path).context(error::ReadSnafu {
                        path: file_path.clone(),
                    })?;
                    archive
                        .append_file(target_path, &mut reader)
                        .context(error::ReadSnafu {
                            path: file_path.clone(),
                        })?;
                }
                archive.finish().unwrap();
                drop(archive);
                Ok(buffer.clone())
            }
        }?;
        let bytes = encode_all(Cursor::new(raw_data), zstd::DEFAULT_COMPRESSION_LEVEL)
            .context(error::CompressSnafu)?;
        Ok(bytes)
    }
}

pub struct Embed {
    pub name: &'static str,
    pub path: &'static str,
    pub is_executable: bool,
    pub is_archive: bool,
    pub binary: &'static [u8],
}

impl Embed {
    pub fn extract<P>(&self, path: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let out_dir = path.as_ref().join(self.path);
        let target_path = out_dir.join(self.name);
        if !out_dir.exists() {
            create_dir_all(&out_dir).context(error::WriteSnafu {
                path: out_dir.clone(),
            })?;
        }
        let mut cursor: Cursor<&[u8]> = Cursor::new(self.binary.as_ref());
        let mut decoder = Decoder::new(&mut cursor).context(error::DecompressSnafu)?;
        if self.is_archive {
            let mut archive = tar::Archive::new(&mut decoder);
            archive.unpack(&out_dir).context(error::WriteSnafu {
                path: out_dir.clone(),
            })?;
        } else {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(false)
                .write(true)
                .mode(0o755)
                .open(&target_path)
                .context(error::CreateSnafu {
                    path: target_path.clone(),
                })?;
            copy(&mut decoder, &mut file).context(error::WriteSnafu {
                path: target_path.clone(),
            })?;
        }

        Ok(())
    }

    #[cfg(feature = "sealed")]
    pub fn sealed(&self) -> Result<SealedCommand> {
        let mut cursor: Cursor<&[u8]> = Cursor::new(self.binary.as_ref());
        let mut decoder = Decoder::new(&mut cursor).context(error::DecompressSnafu)?;
        SealedCommand::new(&mut decoder).context(error::SealedSnafu)
    }
}
