use config::Config;
use snafu::ResultExt;
use std::fs::write;
use std::{env, fs::read_to_string, path::Path};

pub mod config;
pub mod error;

pub use config::Embed;

pub fn pack<P>(config_path: P, out_dir: P) -> error::Result<()>
where
    P: AsRef<Path>,
{
    let config_str = read_to_string(config_path.as_ref()).context(error::ReadConfigSnafu)?;
    let config: Config = toml::from_str(config_str.as_str()).context(error::DeserializeSnafu)?;
    let cargo_target = env::var_os("TARGET").unwrap();
    let cargo_target = cargo_target.to_string_lossy();
    let mut embed_objects = Vec::new();
    for (name, tool) in config.embed {
        let path = tool.extract_to.to_string_lossy();
        let binary = tool.source.load()?;
        let out_path = out_dir.as_ref().join(name.clone());
        write(&out_path, binary.as_slice()).context(error::WriteSnafu {
            path: out_path.clone(),
        })?;

        let is_executable = tool.is_binary();
        let is_archive = tool.is_archive();
        let embed_name = name.clone();
        let var_name = name.to_ascii_uppercase().replace('-', "_");
        let path_name = format!("/{}", name.clone());
        embed_objects.push(format!(
            r###"
pub(crate) const {var_name}: packwolf::Embed = packwolf::Embed {{
  name: "{embed_name}",
  path: "{path}",
  is_executable: {is_executable},
  is_archive: {is_archive},
  binary: include_bytes!(concat!(env!("OUT_DIR"), "/{path_name}")),
}};
        "###
        ));
    }
    let target_file = out_dir.as_ref().join("embedded.rs");
    println!("cargo:rerun-if-changed={}", config_path.as_ref().display());
    let file_contents = embed_objects.join("\n");
    write(&target_file, file_contents).context(error::WriteSnafu {
        path: target_file.clone(),
    })?;
    Ok(())
}
