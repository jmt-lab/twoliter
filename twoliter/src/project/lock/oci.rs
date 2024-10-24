use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, ensure, Context};
use oci_cli_wrapper::{DockerArchitecture, ImageTool};
use tar::Archive;
use tokio::fs::read_dir;

use crate::{
    docker::ImageUri,
    project::{lock::views::ManifestView, Image},
};

use super::views::ManifestListView;

#[derive(Debug)]
pub(crate) enum OCI {
    Remote(ImageUri),
    Local(PathBuf),
}

async fn digest_for_archive<P>(path: P) -> Result<String>
where
    P: AsRef<Path>,
{
    let mut hash = Sha256::default();
    let mut reader = File::open(path)
        .await
        .context("failed to open local oci archive for calculating digest")?;
    tokio::io::copy(&mut reader, &mut hash)
        .await
        .context("failed to calculate sha256 hash")?;
    let hash_bytes = hash.finalize();
    let new_digest = format!("sha256:{}", base16::encode_lower(hash_bytes));
    *digest = Some(new_digest);
    Ok(new_digest.clone())
}

impl OCI {
    pub(crate) fn from_uri(uri: &ImageUri) -> Self {
        Self::Remote(uri.clone())
    }

    pub(crate) fn from_path<P>(path: P) -> Self
    where
        P: AsRef<Path>,
    {
        Self::Local(path.as_ref().to_path_buf())
    }

    async fn get_local_archives(&self) -> Result<HashMap<DockerArchitecture, PathBuf>> {
        match self {
            Self::Remote(_) => Err(anyhow!("cannot get local archives of a remote image")),
            Self::Local(path) => {
                let walker = read_dir(&path)
                    .await
                    .context("failed to read contents of directory")?;
                let mut archives = HashMap::new();
                while let Some(entry) = walker
                    .next_entry()
                    .await
                    .context("failed to walk contents of directory")?
                {
                    // Check if this entry is a file and ends with eitther -x86_64.tar or -aarch64.tar
                    let entry_path = entry.path();
                    if entry_path.is_file()
                        && (entry_path.ends_with("-x86_64.tar")
                            || entry_path.ends_with("-aarch64.tar"))
                    {
                        let docker_arch = if entry_path.ends_with("-x86_64.tar") {
                            DockerArchitecture::Amd64
                        } else {
                            DockerArchitecture::Arm64
                        };
                        archives.insert(docker_arch, entry_path.clone());
                    }
                }
                Ok(archives)
            }
        }
    }

    pub(crate) async fn get_manifest(&self, image_tool: &ImageTool) -> Result<Vec<u8>> {
        // TODO: canonical json test
        match self {
            Self::Remote(uri) => {
                let uri = uri.to_string();
                debug!(uri, "Fetching image manifest.");
                let manifest_bytes = image_tool.get_manifest(uri.as_str()).await?;
                serde_json::from_slice(&manifest_bytes.as_slice())
                    .context("failed to deserialize manifest list")
            }
            Self::Local(path) => {
                // If we have a local oci image we recreated the manifest using the files present in the directory
                let archives = self.get_local_archives().await?;
                ensure!(
                    !archives.is_empty(),
                    "no oci images were discovered in provided path: {}",
                    path.display()
                );
                let mut manifests = Vec::new();
                for (arch, archive_path) in archives.iter() {
                    manifests.push(ManifestView {
                        digest: digest_for_archive(&archive_path).await?,
                        platform: Some(arch.clone()),
                    });
                }
                Ok(ManifestListView { manifests })
            }
        }
    }

    pub(crate) async fn pull_image<P>(
        &self,
        arch: &DockerArchitecture,
        manifest: &ManifestListView,
        image_tool: &ImageTool,
        cache_dir: P,
    ) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let digest = manifest
            .manifests
            .iter()
            .find(|x| x.platform == Some(arch))
            .context(format!("no image for architecture '{}' exists", arch))?;
        let oci_archive_path = cache_dir.as_ref().join(digest.digest.replace(':', "-"));
        match self {
            Self::Remote(image_uri) => {
                let digest_uri = format!(
                    "{}/{}@{}",
                    image_uri.registry, image_uri.repo, digest.digest
                );
                debug!("Pulling image '{}'", digest_uri);
                if !oci_archive_path.exists() {
                    create_dir_all(&oci_archive_path).await?;
                    image_tool
                        .pull_oci_image(&oci_archive_path, digest_uri.as_str())
                        .await?;
                } else {
                    debug!(
                        "Image from '{}' already present -- no need to pull.",
                        digest_uri
                    );
                }
            }
            Self::Local(path) => {
                let archives = self.get_local_archives().await?;
                let archive_path = archives
                    .get(arch)
                    .context(format!("no image for architecture '{}' exists", arch))?;
                let mut reader =
                    std::fs::File::open(&archive_path).context("failed to open oci archive")?;
                let mut archive = Archive::new(&mut reader);
                archive
                    .unpack(&oci_archive_path)
                    .context("failed to unpack oci archive")?;
            }
        }
        Ok(())
    }

    #[instrument(
        level = "trace",
        skip_all,
        fields(registry = %self.registry, repository = %self.repository, digest = %self.digest, out_dir = %out_dir.as_ref().display()),
    )]
    pub async fn unpack_layers<P>(
        &self,
        manifest: &ManifestListView,
        cache_dir: P,
        out_dir: P,
    ) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let path = out_dir.as_ref();
        let digest_file = path.join("digest");
        if digest_file.exists() {
            let digest = read_to_string(&digest_file).await.context(format!(
                "failed to read digest file at {}",
                digest_file.display()
            ))?;
            if digest == self.digest {
                trace!(
                    "Found existing digest file for image at '{}'",
                    digest_file.display()
                );
                return Ok(());
            }
        }

        let digest = manifest
            .manifests
            .iter()
            .find(|x| x.platform == Some(arch))
            .context(format!("no image for architecture '{}' exists", arch))?;
        let oci_archive_path = cache_dirl.as_ref().join(digest.digest.replace(':', "-"));

        debug!("Unpacking layers for image from '{}'", digest_uri);
        remove_dir_all(path).await?;
        create_dir_all(path).await?;
        let index_bytes = read(oci_archive_path.join("index.json")).await?;
        let index: IndexView = serde_json::from_slice(index_bytes.as_slice())
            .context("failed to deserialize oci image index")?;

        // Read the manifest so we can get the layer digests
        trace!(from = %digest_uri, "Extracting layer digests from image manifest");
        let digest = index
            .manifests
            .first()
            .context("empty oci image")?
            .digest
            .replace(':', "/");
        let manifest_bytes = read(oci_archive_path.join(format!("blobs/{digest}")))
            .await
            .context("failed to read manifest blob")?;
        let manifest_layout: ManifestLayoutView = serde_json::from_slice(manifest_bytes.as_slice())
            .context("failed to deserialize oci manifest")?;

        // Extract each layer into the target directory
        trace!(from = %digest_uri, "Extracting image layers");
        for layer in manifest_layout.layers {
            let digest = layer.digest.to_string().replace(':', "/");
            let layer_blob = File::open(oci_archive_path.join(format!("blobs/{digest}")))
                .context("failed to read layer of oci image")?;
            let mut layer_archive = TarArchive::new(layer_blob);
            layer_archive
                .unpack(path)
                .context("failed to unpack layer to disk")?;
        }
        write(&digest_file, digest.as_str()).await.context(format!(
            "failed to record digest to {}",
            digest_file.display()
        ))?;

        Ok(())
    }
}
